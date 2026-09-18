//! Local API relay.
//!
//! Accepts requests in one vendor's wire format and forwards them to a backing
//! account that may speak another. The three formats in scope for v1 are the
//! OpenAI Chat Completions / Responses shape, the Anthropic Messages shape, and
//! the Gemini `generateContent` shape.
//!
//! Security posture: the listener binds to loopback and nothing else unless the
//! user explicitly opts in, and an opt-in requires an authentication token.
//! See `docs/SECURITY_MODEL.md`.
//!
//! # Request translation
//!
//! [`translate_request`] is a pure body translator with explicit context for
//! Gemini's URL-carried model and stream mode. [`translate_response`] maps
//! non-streaming result envelopes. [`StreamTranslator`] consumes one decoded
//! event at a time and retains only bounded protocol metadata, never generated
//! content. Image-generation requests use [`translate_image_request`]. The
//! smaller [`translate`] function remains a compatibility wrapper for callers
//! that do not need Gemini URL metadata.
//!
//! When a target response schema requires envelope metadata absent from the
//! source, translation uses deterministic relay-owned values: timestamp `0`
//! and output-item ids derived from the source response id. These values carry
//! no vendor claim and keep golden output stable. Cross-dialect streaming into
//! OpenAI Responses is rejected because its final event requires the complete
//! accumulated output, which this relay deliberately never buffers.
//!
//! ## Field buckets (`docs/ARCHITECTURE.md` §6)
//!
//! Every field falls into exactly one bucket. Unknown fields are rejected; they
//! are never copied across dialects.
//!
//! **Translated** (same meaning, same or trivially renamed key):
//! `model`, `messages` (roles `user` / `assistant`), string content, `text`
//! parts, `temperature`, `top_p`, `tools` (see mapped wrappers below),
//! `tool_choice` (see mapped values below).
//!
//! **Mapped** (near-equivalent, documented here):
//! - OpenAI `role: "system"` / `"developer"` messages ↔ Anthropic top-level
//!   `system`.
//! - OpenAI `role: "tool"` ↔ Anthropic `user` content with `tool_result` parts.
//!   Consecutive tool results (and a following user turn) are merged so
//!   Anthropic's user/assistant alternation holds.
//! - OpenAI `assistant.tool_calls` ↔ Anthropic `tool_use` content parts.
//!   `function.arguments` (JSON string) ↔ `input` (JSON object).
//! - OpenAI `tools[].function.parameters` ↔ Anthropic `tools[].input_schema`.
//!   Omitted or JSON-null parameters map to `{}` (OpenAI's empty-object schema).
//! - OpenAI `tool_choice` `"auto"` / `"required"` / `"none"` / `{function}` ↔
//!   Anthropic `{type: auto|any|none|tool}`.
//! - OpenAI `max_completion_tokens` → Anthropic `max_tokens` (same budget).
//! - OpenAI `stop` (string or array) ↔ Anthropic `stop_sequences` (array).
//! - OpenAI `user` ↔ Anthropic `metadata.user_id`. Empty `metadata` and
//!   `user_id: null` mean no identity and are omitted.
//! - OpenAI `n: 1` → omitted (Anthropic always returns one completion).
//! - OpenAI `parallel_tool_calls: false` ↔ Anthropic
//!   `tool_choice.disable_parallel_tool_use` on `auto` / `any` / `tool`.
//!   The `none` variant does not accept that key. Without tools the flag is
//!   vacuous and is omitted rather than synthesizing a `tool_choice`.
//! - Anthropic `tool_result.is_error: false` / `null` → omitted (the default).
//!   `true` has no Chat Completions counterpart and is rejected.
//! - OpenAI `image_url` ↔ Anthropic `image` (`url`, or a `data:` URL as
//!   `base64`). `detail: "auto"` is the OpenAI default and is omitted;
//!   `"low"` / `"high"` are rejected.
//! - OpenAI `response_format: {type: "text"}` → omitted (the default).
//! - OpenAI tool-message `name` → omitted. It repeats the function name
//!   already bound to `tool_call_id` / `tool_use_id`.
//!
//! The detailed list below describes the strict Chat Completions ⇄ Anthropic
//! request pair. Responses and Gemini use equivalent strict allowlists in
//! `translate.rs`.
//!
//! **Rejected** (error names the field): everything else, including unknown
//! keys (even when the value is JSON `null`), `n` ≠ 1, `logit_bias`,
//! `presence_penalty`, `frequency_penalty`, `seed`, `logprobs`,
//! `top_logprobs`, `top_k`, `service_tier`, `store`, OpenAI `metadata`, Anthropic
//! `cache_control` / `container` / `mcp_servers`, `functions` /
//! `function_call`, Anthropic `tool_result.is_error: true`, and a missing
//! `max_tokens` when the target is Anthropic.
//!
//! JSON `null` on a **known** field means unset. JSON `null` on an
//! **unknown** key is still an unrecognised field and is rejected.
//!
//! ## `max_tokens`
//!
//! Optional in OpenAI Chat Completions, required in Anthropic Messages.
//! Inventing a default would silently cap a caller that never set a budget.
//! Dropping it would make Anthropic 400 with a worse diagnostic. So
//! OpenAI → Anthropic requires `max_tokens` or `max_completion_tokens`; if
//! both are present and differ, that is rejected as ambiguous.

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};

mod server;
mod stream;
mod translate;

pub use server::{
    relay_status, start_relay, start_routed_relay, stop_relay, AdapterQuotaSource, CoreTranslator,
    RelayQuotaSource, RelayServer, RelayStreamTranslator, RelayTarget, RelayTranslator,
    RelayUpstreamAuth, RoutedRelayTarget,
};
pub use stream::{SourceEvent, StreamTranslator, TranslatedEvent};
pub use translate::{
    translate_image_request, translate_image_response, translate_request, translate_response,
    TranslatedRequest, TranslationContext,
};

/// Wire formats the relay can accept and emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFormat {
    OpenAiChatCompletions,
    OpenAiResponses,
    OpenAiImagesGenerations,
    AnthropicMessages,
    GeminiGenerateContent,
}

impl WireFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChatCompletions => "openai-chat-completions",
            Self::OpenAiResponses => "openai-responses",
            Self::OpenAiImagesGenerations => "openai-images-generations",
            Self::AnthropicMessages => "anthropic-messages",
            Self::GeminiGenerateContent => "gemini-generate-content",
        }
    }
}

/// Runtime configuration for the relay listener.
#[derive(Clone)]
pub struct RelayConfig {
    /// Defaults to `127.0.0.1`. Changing it requires an explicit opt-in.
    pub bind_address: String,
    pub port: u16,
    /// Required whenever `bind_address` is not a loopback address.
    pub auth_token: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 8787,
            auth_token: None,
        }
    }
}

impl RelayConfig {
    /// Reject a configuration that would expose an unauthenticated listener.
    pub fn validate(&self) -> Result<()> {
        let address: std::net::IpAddr = self.bind_address.parse().map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "relay bind address must be an IP address",
            ))
        })?;
        if !address.is_loopback()
            && self
                .auth_token
                .as_deref()
                .is_none_or(|token| token.trim().is_empty())
        {
            return Err(Error::CredentialStoreUnavailable(
                "a non-loopback relay binding requires an auth token".to_string(),
            ));
        }
        Ok(())
    }
}

/// Translate a request body between wire formats.
///
/// Same-format calls parse the body (so malformed JSON still fails) and
/// return the original bytes. Cross-format Gemini calls require URL model
/// metadata and therefore use [`translate_request`] instead.
pub fn translate(from: WireFormat, to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
    if from == to {
        let _: Value = serde_json::from_slice(body)?;
        return Ok(body.to_vec());
    }
    match (from, to) {
        (WireFormat::OpenAiImagesGenerations, _) | (_, WireFormat::OpenAiImagesGenerations) => {
            translate_image_request(from, to, TranslationContext::default(), body)
                .map(|translated| translated.body)
        }
        (WireFormat::GeminiGenerateContent, _) | (_, WireFormat::GeminiGenerateContent) => {
            Err(reject(
                "target_model",
                "Gemini carries the model in its URL; use relay::translate_request",
            ))
        }
        _ => translate_request(from, to, TranslationContext::default(), body)
            .map(|translated| translated.body),
    }
}

fn openai_chat_to_anthropic(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    let target = WireFormat::AnthropicMessages.as_str();

    let mut model = None;
    let mut max_tokens = None;
    let mut messages_in = None;
    let mut tools = None;
    let mut tool_choice = None;
    let mut temperature = None;
    let mut top_p = None;
    let mut stop = None;
    let mut user = None;
    let mut parallel_tool_calls = None;

    for (key, value) in &root {
        if value.is_null() {
            match key.as_str() {
                "model" | "messages" => {
                    return Err(reject(key, "field is required"));
                }
                // Known optional / mapped / rejected-when-set: null means unset.
                "max_tokens"
                | "max_completion_tokens"
                | "tools"
                | "tool_choice"
                | "temperature"
                | "top_p"
                | "stop"
                | "user"
                | "parallel_tool_calls"
                | "stream"
                | "n"
                | "response_format"
                | "logit_bias"
                | "presence_penalty"
                | "frequency_penalty"
                | "seed"
                | "logprobs"
                | "top_logprobs"
                | "service_tier"
                | "store"
                | "metadata"
                | "modalities"
                | "audio"
                | "prediction"
                | "web_search_options"
                | "functions"
                | "function_call"
                | "reasoning"
                | "reasoning_effort"
                | "stream_options" => continue,
                // Unknown keys must not disappear just because they are null.
                _ => {}
            }
        }
        match key.as_str() {
            "model" => model = Some(expect_string(value, "model")?.to_string()),
            "max_tokens" | "max_completion_tokens" => {
                expect_number(value, key)?;
                if let Some(existing) = &max_tokens {
                    if existing != value {
                        return Err(reject(
                            key,
                            "conflicts with the other max-tokens field; they must agree",
                        ));
                    }
                }
                max_tokens = Some(value.clone());
            }
            "messages" => messages_in = Some(expect_array(value, "messages")?),
            "tools" => tools = Some(convert_openai_tools(expect_array(value, "tools")?)?),
            "tool_choice" => tool_choice = Some(value),
            "temperature" => {
                expect_number(value, "temperature")?;
                temperature = Some(value.clone());
            }
            "top_p" => {
                expect_number(value, "top_p")?;
                top_p = Some(value.clone());
            }
            "stop" => stop = Some(openai_stop_to_anthropic(value)?),
            "user" => user = Some(expect_string(value, "user")?.to_string()),
            "parallel_tool_calls" => parallel_tool_calls = Some(value),
            "stream" => refuse_stream(value)?,
            "n" => {
                if !is_number_one(value) {
                    return Err(reject(key, format!("no counterpart in {target}")));
                }
            }
            "response_format" => refuse_unless_text_format(value)?,
            "logit_bias" | "presence_penalty" | "frequency_penalty" | "seed" | "logprobs"
            | "top_logprobs" | "service_tier" | "store" | "metadata" | "modalities" | "audio"
            | "prediction" | "web_search_options" | "functions" | "function_call" | "reasoning"
            | "reasoning_effort" | "stream_options" => {
                return Err(reject(key, format!("no counterpart in {target}")));
            }
            other => {
                return Err(reject(
                    other,
                    "unknown field; refusing to pass it through silently",
                ));
            }
        }
    }

    let model = model.ok_or_else(|| reject("model", "field is required"))?;
    let messages_in = messages_in.ok_or_else(|| reject("messages", "field is required"))?;
    let max_tokens = max_tokens.ok_or_else(|| {
        reject(
            "max_tokens",
            "required by anthropic-messages; refusing to invent a default",
        )
    })?;

    let (system, messages) = convert_openai_messages(messages_in)?;
    if messages.is_empty() {
        return Err(reject(
            "messages",
            "anthropic-messages requires at least one non-system message",
        ));
    }

    let has_tools = tools
        .as_ref()
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let tool_choice = openai_tool_choice_to_anthropic(tool_choice, parallel_tool_calls, has_tools)?;

    let mut out = Map::new();
    out.insert("model".into(), Value::String(model));
    out.insert("max_tokens".into(), max_tokens);
    if let Some(system) = system {
        out.insert("system".into(), system);
    }
    out.insert("messages".into(), Value::Array(messages));
    if let Some(tools) = tools {
        out.insert("tools".into(), tools);
    }
    if let Some(tool_choice) = tool_choice {
        out.insert("tool_choice".into(), tool_choice);
    }
    if let Some(temperature) = temperature {
        out.insert("temperature".into(), temperature);
    }
    if let Some(top_p) = top_p {
        out.insert("top_p".into(), top_p);
    }
    if let Some(stop) = stop {
        out.insert("stop_sequences".into(), stop);
    }
    if let Some(user) = user {
        out.insert("metadata".into(), json!({ "user_id": user }));
    }

    Ok(serde_json::to_vec(&Value::Object(out))?)
}

fn anthropic_to_openai_chat(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    let target = WireFormat::OpenAiChatCompletions.as_str();

    let mut model = None;
    let mut max_tokens = None;
    let mut system = None;
    let mut messages_in = None;
    let mut tools = None;
    let mut tool_choice = None;
    let mut temperature = None;
    let mut top_p = None;
    let mut stop = None;
    let mut user = None;
    let mut parallel_tool_calls = None;

    for (key, value) in &root {
        if value.is_null() {
            match key.as_str() {
                "model" | "messages" | "max_tokens" => {
                    return Err(reject(key, "field is required"));
                }
                // Known optional / mapped / rejected-when-set: null means unset.
                "system" | "tools" | "tool_choice" | "temperature" | "top_p" | "stop_sequences"
                | "metadata" | "stream" | "top_k" | "thinking" | "service_tier" | "container"
                | "mcp_servers" | "context_management" | "output_config" | "output_format"
                | "cache_control" => continue,
                // Unknown keys must not disappear just because they are null.
                _ => {}
            }
        }
        match key.as_str() {
            "model" => model = Some(expect_string(value, "model")?.to_string()),
            "max_tokens" => {
                expect_number(value, "max_tokens")?;
                max_tokens = Some(value.clone());
            }
            "system" => system = Some(value.clone()),
            "messages" => messages_in = Some(expect_array(value, "messages")?),
            "tools" => tools = Some(convert_anthropic_tools(expect_array(value, "tools")?)?),
            "tool_choice" => {
                let (choice, parallel) = anthropic_tool_choice_to_openai(value)?;
                tool_choice = Some(choice);
                parallel_tool_calls = parallel;
            }
            "temperature" => {
                expect_number(value, "temperature")?;
                temperature = Some(value.clone());
            }
            "top_p" => {
                expect_number(value, "top_p")?;
                top_p = Some(value.clone());
            }
            "stop_sequences" => {
                let items = expect_array(value, "stop_sequences")?;
                for (i, item) in items.iter().enumerate() {
                    expect_string(item, &format!("stop_sequences[{i}]"))?;
                }
                stop = Some(value.clone());
            }
            "metadata" => user = anthropic_metadata_user(value)?,
            "stream" => refuse_stream(value)?,
            "top_k" | "thinking" | "service_tier" | "container" | "mcp_servers"
            | "context_management" | "output_config" | "output_format" | "cache_control" => {
                return Err(reject(key, format!("no counterpart in {target}")));
            }
            other => {
                return Err(reject(
                    other,
                    "unknown field; refusing to pass it through silently",
                ));
            }
        }
    }

    let model = model.ok_or_else(|| reject("model", "field is required"))?;
    let max_tokens = max_tokens.ok_or_else(|| reject("max_tokens", "field is required"))?;
    let messages_in = messages_in.ok_or_else(|| reject("messages", "field is required"))?;

    let mut messages = Vec::new();
    if let Some(system) = system {
        messages.push(openai_system_message(system)?);
    }
    for (i, message) in messages_in.iter().enumerate() {
        messages.extend(convert_anthropic_message(message, i)?);
    }
    if messages.is_empty() {
        return Err(reject("messages", "field is required"));
    }

    let mut out = Map::new();
    out.insert("model".into(), Value::String(model));
    out.insert("max_tokens".into(), max_tokens);
    out.insert("messages".into(), Value::Array(messages));
    if let Some(tools) = tools {
        out.insert("tools".into(), tools);
    }
    if let Some(tool_choice) = tool_choice {
        out.insert("tool_choice".into(), tool_choice);
    }
    if let Some(flag) = parallel_tool_calls {
        out.insert("parallel_tool_calls".into(), Value::Bool(flag));
    }
    if let Some(temperature) = temperature {
        out.insert("temperature".into(), temperature);
    }
    if let Some(top_p) = top_p {
        out.insert("top_p".into(), top_p);
    }
    if let Some(stop) = stop {
        out.insert("stop".into(), stop);
    }
    if let Some(user) = user {
        out.insert("user".into(), Value::String(user));
    }

    Ok(serde_json::to_vec(&Value::Object(out))?)
}

fn convert_openai_messages(messages: &[Value]) -> Result<(Option<Value>, Vec<Value>)> {
    let mut system_parts: Vec<Value> = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    let mut saw_conversational_message = false;

    for (i, message) in messages.iter().enumerate() {
        let path = format!("messages[{i}]");
        let obj = expect_object(message, &path)?;
        let mut role = None;
        let mut content = None;
        let mut tool_calls = None;
        let mut tool_call_id = None;

        for (key, value) in obj {
            if value.is_null() {
                match key.as_str() {
                    "role" => {
                        return Err(reject(&format!("{path}.role"), "field is required"));
                    }
                    // Known optional / rejected-when-set: null means unset.
                    "content" | "tool_calls" | "tool_call_id" | "name" | "function_call"
                    | "refusal" | "audio" => continue,
                    // Unknown keys must not disappear just because they are null.
                    _ => {}
                }
            }
            match key.as_str() {
                "role" => role = Some(expect_string(value, &format!("{path}.role"))?),
                "content" => content = Some(value),
                "tool_calls" => tool_calls = Some(value),
                "tool_call_id" => {
                    tool_call_id = Some(expect_string(value, &format!("{path}.tool_call_id"))?)
                }
                "name" => {
                    // Speaker label on user/assistant has no Anthropic field.
                    // On a tool message it only restates the function name
                    // already bound to tool_call_id; that case is ignored
                    // after we know the role.
                    if obj.get("role").and_then(Value::as_str) != Some("tool") {
                        return Err(reject(
                            &format!("{path}.name"),
                            "no counterpart in anthropic-messages",
                        ));
                    }
                }
                "function_call" | "refusal" | "audio" => {
                    return Err(reject(
                        &format!("{path}.{key}"),
                        "no counterpart in anthropic-messages",
                    ));
                }
                other => {
                    return Err(reject(
                        &format!("{path}.{other}"),
                        "unknown field; refusing to pass it through silently",
                    ));
                }
            }
        }

        let role = role.ok_or_else(|| reject(&format!("{path}.role"), "field is required"))?;
        match role {
            "system" | "developer" => {
                if saw_conversational_message {
                    return Err(reject(
                        &format!("{path}.role"),
                        "system and developer messages must precede conversational content",
                    ));
                }
                push_system_parts(&mut system_parts, content, &path)?;
            }
            "user" => {
                saw_conversational_message = true;
                let converted = openai_content_to_anthropic(content, &path, false)?;
                push_anthropic_message(&mut out, "user", converted);
            }
            "assistant" => {
                saw_conversational_message = true;
                let mut parts = match content {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::String(text)) if text.is_empty() => Vec::new(),
                    Some(Value::String(text)) => {
                        vec![json!({ "type": "text", "text": text })]
                    }
                    Some(other) => match openai_content_to_anthropic(Some(other), &path, false)? {
                        Value::Array(items) => items,
                        Value::String(text) => {
                            vec![json!({ "type": "text", "text": text })]
                        }
                        other => vec![other],
                    },
                };
                if let Some(calls) = tool_calls {
                    parts.extend(convert_openai_tool_calls(calls, &path)?);
                }
                if parts.is_empty() {
                    return Err(reject(
                        &format!("{path}.content"),
                        "assistant message has no content",
                    ));
                }
                let content =
                    if parts.len() == 1 && parts[0]["type"] == "text" && tool_calls.is_none() {
                        parts[0]["text"].clone()
                    } else {
                        Value::Array(parts)
                    };
                push_anthropic_message(&mut out, "assistant", content);
            }
            "tool" => {
                saw_conversational_message = true;
                let id = tool_call_id
                    .ok_or_else(|| reject(&format!("{path}.tool_call_id"), "field is required"))?;
                let body = match content {
                    None | Some(Value::Null) => Value::String(String::new()),
                    Some(Value::String(text)) => Value::String(text.clone()),
                    Some(Value::Array(_)) => openai_content_to_anthropic(content, &path, true)?,
                    Some(_) => {
                        return Err(reject(
                            &format!("{path}.content"),
                            "must be a string or array",
                        ));
                    }
                };
                push_anthropic_message(
                    &mut out,
                    "user",
                    json!([{
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": body,
                    }]),
                );
            }
            "function" => {
                return Err(reject(
                    &format!("{path}.role"),
                    "deprecated function role; use tool messages",
                ));
            }
            other => {
                return Err(reject(
                    &format!("{path}.role"),
                    format!("unsupported role `{other}`"),
                ));
            }
        }
    }

    let system = match system_parts.len() {
        0 => None,
        1 if system_parts[0]["type"] == "text"
            && system_parts[0]
                .as_object()
                .is_some_and(|obj| obj.keys().all(|k| k == "type" || k == "text")) =>
        {
            Some(system_parts[0]["text"].clone())
        }
        _ => Some(Value::Array(system_parts)),
    };
    Ok((system, out))
}

fn convert_anthropic_message(message: &Value, index: usize) -> Result<Vec<Value>> {
    let path = format!("messages[{index}]");
    let obj = expect_object(message, &path)?;
    let mut role = None;
    let mut content = None;

    for (key, value) in obj {
        if value.is_null() {
            match key.as_str() {
                "role" | "content" => {
                    return Err(reject(&format!("{path}.{key}"), "field is required"));
                }
                // Unknown keys must not disappear just because they are null.
                _ => {}
            }
        }
        match key.as_str() {
            "role" => role = Some(expect_string(value, &format!("{path}.role"))?),
            "content" => content = Some(value),
            other => {
                return Err(reject(
                    &format!("{path}.{other}"),
                    "unknown field; refusing to pass it through silently",
                ));
            }
        }
    }

    let role = role.ok_or_else(|| reject(&format!("{path}.role"), "field is required"))?;
    let content = content.ok_or_else(|| reject(&format!("{path}.content"), "field is required"))?;

    match role {
        "user" => anthropic_user_to_openai(content, &path),
        "assistant" => Ok(vec![anthropic_assistant_to_openai(content, &path)?]),
        other => Err(reject(
            &format!("{path}.role"),
            format!("unsupported role `{other}`"),
        )),
    }
}

fn anthropic_user_to_openai(content: &Value, path: &str) -> Result<Vec<Value>> {
    match content {
        Value::String(_) => Ok(vec![json!({ "role": "user", "content": content })]),
        Value::Array(parts) => {
            let mut out = Vec::new();
            let mut user_parts: Vec<Value> = Vec::new();
            for (i, part) in parts.iter().enumerate() {
                let part_path = format!("{path}.content[{i}]");
                let obj = expect_object(part, &part_path)?;
                let kind = obj
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| reject(&format!("{part_path}.type"), "field is required"))?;
                match kind {
                    "text" | "image" => {
                        user_parts.push(anthropic_part_to_openai(part, &part_path)?);
                    }
                    "tool_result" => {
                        flush_user_parts(&mut out, &mut user_parts);
                        out.push(convert_anthropic_tool_result(obj, &part_path)?);
                    }
                    "thinking" | "redacted_thinking" => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            "reasoning-budget mapping is not implemented (FR-9)",
                        ));
                    }
                    other => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            format!("no counterpart in openai-chat-completions for `{other}`"),
                        ));
                    }
                }
            }
            flush_user_parts(&mut out, &mut user_parts);
            if out.is_empty() {
                out.push(json!({ "role": "user", "content": [] }));
            }
            Ok(out)
        }
        _ => Err(reject(
            &format!("{path}.content"),
            "must be a string or array",
        )),
    }
}

fn anthropic_assistant_to_openai(content: &Value, path: &str) -> Result<Value> {
    match content {
        Value::String(_) => Ok(json!({ "role": "assistant", "content": content })),
        Value::Array(parts) => {
            let mut text_parts: Vec<Value> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            for (i, part) in parts.iter().enumerate() {
                let part_path = format!("{path}.content[{i}]");
                let obj = expect_object(part, &part_path)?;
                let kind = obj
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| reject(&format!("{part_path}.type"), "field is required"))?;
                match kind {
                    "text" => text_parts.push(anthropic_part_to_openai(part, &part_path)?),
                    "tool_use" => tool_calls.push(convert_anthropic_tool_use(obj, &part_path)?),
                    "thinking" | "redacted_thinking" => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            "reasoning-budget mapping is not implemented (FR-9)",
                        ));
                    }
                    other => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            format!("no counterpart in openai-chat-completions for `{other}`"),
                        ));
                    }
                }
            }
            let mut message = Map::new();
            message.insert("role".into(), Value::String("assistant".into()));
            if !text_parts.is_empty() {
                let content = if text_parts.len() == 1 && text_parts[0]["type"] == "text" {
                    text_parts[0]["text"].clone()
                } else {
                    Value::Array(text_parts)
                };
                message.insert("content".into(), content);
            }
            if !tool_calls.is_empty() {
                message.insert("tool_calls".into(), Value::Array(tool_calls));
            }
            if !message.contains_key("content") && !message.contains_key("tool_calls") {
                return Err(reject(
                    &format!("{path}.content"),
                    "assistant message has no content",
                ));
            }
            Ok(Value::Object(message))
        }
        _ => Err(reject(
            &format!("{path}.content"),
            "must be a string or array",
        )),
    }
}

fn openai_content_to_anthropic(
    content: Option<&Value>,
    path: &str,
    tool_result: bool,
) -> Result<Value> {
    let Some(content) = content else {
        return Err(reject(&format!("{path}.content"), "field is required"));
    };
    match content {
        Value::String(_) => Ok(content.clone()),
        Value::Array(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for (i, part) in parts.iter().enumerate() {
                out.push(openai_part_to_anthropic(
                    part,
                    &format!("{path}.content[{i}]"),
                    tool_result,
                )?);
            }
            Ok(Value::Array(out))
        }
        _ => Err(reject(
            &format!("{path}.content"),
            "must be a string or array",
        )),
    }
}

fn openai_part_to_anthropic(part: &Value, path: &str, tool_result: bool) -> Result<Value> {
    if let Some(text) = part.as_str() {
        return Ok(json!({ "type": "text", "text": text }));
    }
    let obj = expect_object(part, path)?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| reject(&format!("{path}.type"), "field is required"))?;
    match kind {
        "text" => {
            refuse_unknown_keys(obj, &["type", "text"], path)?;
            let text = obj
                .get("text")
                .ok_or_else(|| reject(&format!("{path}.text"), "field is required"))?;
            expect_string(text, &format!("{path}.text"))?;
            Ok(json!({ "type": "text", "text": text }))
        }
        "image_url" => {
            if tool_result {
                return Err(reject(
                    &format!("{path}.type"),
                    "image parts are not supported inside a tool result",
                ));
            }
            refuse_unknown_keys(obj, &["type", "image_url"], path)?;
            openai_image_to_anthropic(
                obj.get("image_url")
                    .ok_or_else(|| reject(&format!("{path}.image_url"), "field is required"))?,
                &format!("{path}.image_url"),
            )
        }
        "input_audio" | "refusal" | "file" => Err(reject(
            &format!("{path}.type"),
            format!("no counterpart in anthropic-messages for `{kind}`"),
        )),
        other => Err(reject(
            &format!("{path}.type"),
            format!("unknown content part `{other}`"),
        )),
    }
}

fn openai_image_to_anthropic(image: &Value, path: &str) -> Result<Value> {
    let obj = expect_object(image, path)?;
    refuse_unknown_keys(obj, &["url", "detail"], path)?;
    if let Some(detail) = obj.get("detail") {
        let detail = expect_string(detail, &format!("{path}.detail"))?;
        if detail != "auto" {
            return Err(reject(
                &format!("{path}.detail"),
                format!("no counterpart in anthropic-messages for `{detail}`"),
            ));
        }
    }
    let url = expect_string(
        obj.get("url")
            .ok_or_else(|| reject(&format!("{path}.url"), "field is required"))?,
        &format!("{path}.url"),
    )?;
    if let Some(rest) = url.strip_prefix("data:") {
        let (media_type, data) = rest.split_once(";base64,").ok_or_else(|| {
            reject(
                &format!("{path}.url"),
                "data URL must be data:<media_type>;base64,<data>",
            )
        })?;
        Ok(json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": data,
            }
        }))
    } else {
        Ok(json!({
            "type": "image",
            "source": { "type": "url", "url": url }
        }))
    }
}

fn anthropic_part_to_openai(part: &Value, path: &str) -> Result<Value> {
    let obj = expect_object(part, path)?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| reject(&format!("{path}.type"), "field is required"))?;
    match kind {
        "text" => {
            refuse_unknown_keys(obj, &["type", "text"], path)?;
            let text = obj
                .get("text")
                .ok_or_else(|| reject(&format!("{path}.text"), "field is required"))?;
            expect_string(text, &format!("{path}.text"))?;
            Ok(json!({ "type": "text", "text": text }))
        }
        "image" => {
            refuse_unknown_keys(obj, &["type", "source"], path)?;
            let source = expect_object(
                obj.get("source")
                    .ok_or_else(|| reject(&format!("{path}.source"), "field is required"))?,
                &format!("{path}.source"),
            )?;
            let source_path = format!("{path}.source");
            let source_type = source
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| reject(&format!("{source_path}.type"), "field is required"))?;
            let url = match source_type {
                "url" => {
                    refuse_unknown_keys(source, &["type", "url"], &source_path)?;
                    expect_string(
                        source.get("url").ok_or_else(|| {
                            reject(&format!("{source_path}.url"), "field is required")
                        })?,
                        &format!("{source_path}.url"),
                    )?
                    .to_string()
                }
                "base64" => {
                    refuse_unknown_keys(source, &["type", "media_type", "data"], &source_path)?;
                    let media_type = expect_string(
                        source.get("media_type").ok_or_else(|| {
                            reject(&format!("{source_path}.media_type"), "field is required")
                        })?,
                        &format!("{source_path}.media_type"),
                    )?;
                    let data = expect_string(
                        source.get("data").ok_or_else(|| {
                            reject(&format!("{source_path}.data"), "field is required")
                        })?,
                        &format!("{source_path}.data"),
                    )?;
                    format!("data:{media_type};base64,{data}")
                }
                other => {
                    return Err(reject(
                        &format!("{source_path}.type"),
                        format!("no counterpart in openai-chat-completions for `{other}`"),
                    ));
                }
            };
            Ok(json!({ "type": "image_url", "image_url": { "url": url } }))
        }
        other => Err(reject(
            &format!("{path}.type"),
            format!("no counterpart in openai-chat-completions for `{other}`"),
        )),
    }
}

fn convert_openai_tool_calls(value: &Value, path: &str) -> Result<Vec<Value>> {
    let calls = expect_array(value, &format!("{path}.tool_calls"))?;
    let mut out = Vec::with_capacity(calls.len());
    for (i, call) in calls.iter().enumerate() {
        let call_path = format!("{path}.tool_calls[{i}]");
        let obj = expect_object(call, &call_path)?;
        refuse_unknown_keys(obj, &["id", "type", "function"], &call_path)?;
        if let Some(kind) = obj.get("type") {
            if expect_string(kind, &format!("{call_path}.type"))? != "function" {
                return Err(reject(
                    &format!("{call_path}.type"),
                    "only function tool calls are supported",
                ));
            }
        }
        let id = expect_string(
            obj.get("id")
                .ok_or_else(|| reject(&format!("{call_path}.id"), "field is required"))?,
            &format!("{call_path}.id"),
        )?;
        let function = expect_object(
            obj.get("function")
                .ok_or_else(|| reject(&format!("{call_path}.function"), "field is required"))?,
            &format!("{call_path}.function"),
        )?;
        refuse_unknown_keys(
            function,
            &["name", "arguments"],
            &format!("{call_path}.function"),
        )?;
        let name = expect_string(
            function.get("name").ok_or_else(|| {
                reject(&format!("{call_path}.function.name"), "field is required")
            })?,
            &format!("{call_path}.function.name"),
        )?;
        let arguments = expect_string(
            function.get("arguments").ok_or_else(|| {
                reject(
                    &format!("{call_path}.function.arguments"),
                    "field is required",
                )
            })?,
            &format!("{call_path}.function.arguments"),
        )?;
        let input: Value = serde_json::from_str(arguments).map_err(|_| {
            reject(
                &format!("{call_path}.function.arguments"),
                "must be a JSON object encoded as a string",
            )
        })?;
        if !input.is_object() {
            return Err(reject(
                &format!("{call_path}.function.arguments"),
                "must be a JSON object encoded as a string",
            ));
        }
        out.push(json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input,
        }));
    }
    Ok(out)
}

fn convert_anthropic_tool_use(obj: &Map<String, Value>, path: &str) -> Result<Value> {
    refuse_unknown_keys(obj, &["type", "id", "name", "input"], path)?;
    let id = expect_string(
        obj.get("id")
            .ok_or_else(|| reject(&format!("{path}.id"), "field is required"))?,
        &format!("{path}.id"),
    )?;
    let name = expect_string(
        obj.get("name")
            .ok_or_else(|| reject(&format!("{path}.name"), "field is required"))?,
        &format!("{path}.name"),
    )?;
    let input = obj
        .get("input")
        .ok_or_else(|| reject(&format!("{path}.input"), "field is required"))?;
    if !input.is_object() {
        return Err(reject(&format!("{path}.input"), "must be a JSON object"));
    }
    Ok(json!({
        "id": id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": serde_json::to_string(input)?,
        }
    }))
}

fn convert_anthropic_tool_result(obj: &Map<String, Value>, path: &str) -> Result<Value> {
    refuse_unknown_keys(obj, &["type", "tool_use_id", "content", "is_error"], path)?;
    match obj.get("is_error") {
        // Known-field JSON null = unset. false is Anthropic's default.
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Err(reject(
                &format!("{path}.is_error"),
                "no counterpart in openai-chat-completions",
            ));
        }
        Some(_) => {
            return Err(reject(&format!("{path}.is_error"), "must be a boolean"));
        }
    }
    let id = expect_string(
        obj.get("tool_use_id")
            .ok_or_else(|| reject(&format!("{path}.tool_use_id"), "field is required"))?,
        &format!("{path}.tool_use_id"),
    )?;
    let content = match obj.get("content") {
        None | Some(Value::Null) => Value::String(String::new()),
        Some(Value::String(text)) => Value::String(text.clone()),
        Some(Value::Array(parts)) => {
            let mut texts = Vec::new();
            for (i, part) in parts.iter().enumerate() {
                let part_path = format!("{path}.content[{i}]");
                let part_obj = expect_object(part, &part_path)?;
                refuse_unknown_keys(part_obj, &["type", "text"], &part_path)?;
                if part_obj.get("type").and_then(Value::as_str) != Some("text") {
                    return Err(reject(
                        &format!("{part_path}.type"),
                        "only text parts can be mapped out of a tool result",
                    ));
                }
                texts.push(
                    expect_string(
                        part_obj.get("text").ok_or_else(|| {
                            reject(&format!("{part_path}.text"), "field is required")
                        })?,
                        &format!("{part_path}.text"),
                    )?
                    .to_string(),
                );
            }
            Value::String(texts.join(""))
        }
        Some(_) => {
            return Err(reject(
                &format!("{path}.content"),
                "must be a string or array of text parts",
            ));
        }
    };
    Ok(json!({
        "role": "tool",
        "tool_call_id": id,
        "content": content,
    }))
}

fn convert_openai_tools(tools: &[Value]) -> Result<Value> {
    let mut out = Vec::with_capacity(tools.len());
    for (i, tool) in tools.iter().enumerate() {
        let path = format!("tools[{i}]");
        let obj = expect_object(tool, &path)?;
        refuse_unknown_keys(obj, &["type", "function"], &path)?;
        if let Some(kind) = obj.get("type") {
            if expect_string(kind, &format!("{path}.type"))? != "function" {
                return Err(reject(
                    &format!("{path}.type"),
                    "only function tools are supported",
                ));
            }
        }
        let function = expect_object(
            obj.get("function")
                .ok_or_else(|| reject(&format!("{path}.function"), "field is required"))?,
            &format!("{path}.function"),
        )?;
        refuse_unknown_keys(
            function,
            &["name", "description", "parameters", "strict"],
            &format!("{path}.function"),
        )?;
        if function.get("strict").is_some() {
            return Err(reject(
                &format!("{path}.function.strict"),
                "no counterpart in anthropic-messages",
            ));
        }
        let name = function
            .get("name")
            .ok_or_else(|| reject(&format!("{path}.function.name"), "field is required"))?
            .clone();
        expect_string(&name, &format!("{path}.function.name"))?;
        // OpenAI documents omitting `parameters` as an empty object schema
        // (a zero-argument tool). JSON null is the known-field unset form.
        let parameters = match function.get("parameters") {
            None | Some(Value::Null) => json!({}),
            Some(value) => {
                if !value.is_object() {
                    return Err(reject(
                        &format!("{path}.function.parameters"),
                        "must be a JSON object",
                    ));
                }
                value.clone()
            }
        };
        let mut mapped = Map::new();
        mapped.insert("name".into(), name);
        if let Some(description) = function.get("description") {
            expect_string(description, &format!("{path}.function.description"))?;
            mapped.insert("description".into(), description.clone());
        }
        mapped.insert("input_schema".into(), parameters);
        out.push(Value::Object(mapped));
    }
    Ok(Value::Array(out))
}

fn convert_anthropic_tools(tools: &[Value]) -> Result<Value> {
    let mut out = Vec::with_capacity(tools.len());
    for (i, tool) in tools.iter().enumerate() {
        let path = format!("tools[{i}]");
        let obj = expect_object(tool, &path)?;
        refuse_unknown_keys(obj, &["name", "description", "input_schema", "type"], &path)?;
        if let Some(kind) = obj.get("type") {
            return Err(reject(
                &format!("{path}.type"),
                format!("no counterpart in openai-chat-completions for `{}`", kind),
            ));
        }
        let name = obj
            .get("name")
            .ok_or_else(|| reject(&format!("{path}.name"), "field is required"))?
            .clone();
        expect_string(&name, &format!("{path}.name"))?;
        let schema = obj
            .get("input_schema")
            .ok_or_else(|| reject(&format!("{path}.input_schema"), "field is required"))?
            .clone();
        if !schema.is_object() {
            return Err(reject(
                &format!("{path}.input_schema"),
                "must be a JSON object",
            ));
        }
        let mut function = Map::new();
        function.insert("name".into(), name);
        if let Some(description) = obj.get("description") {
            expect_string(description, &format!("{path}.description"))?;
            function.insert("description".into(), description.clone());
        }
        function.insert("parameters".into(), schema);
        out.push(json!({
            "type": "function",
            "function": Value::Object(function),
        }));
    }
    Ok(Value::Array(out))
}

fn openai_tool_choice_to_anthropic(
    tool_choice: Option<&Value>,
    parallel_tool_calls: Option<&Value>,
    has_tools: bool,
) -> Result<Option<Value>> {
    let disable_parallel = match parallel_tool_calls {
        None => false,
        Some(Value::Bool(value)) => !*value,
        Some(_) => return Err(reject("parallel_tool_calls", "must be a boolean")),
    };

    // `parallel_tool_calls` only constrains concurrent tool use. With no tools
    // and no `tool_choice`, the flag has nothing to apply to: OpenAI ignores
    // it, and carrying it would require synthesizing `tool_choice`, which
    // Anthropic 400s when `tools` is absent. The constraint is already
    // satisfied, so the flag is vacuous — not a silent drop of a field that
    // has a counterpart (`docs/ARCHITECTURE.md` §6).
    if disable_parallel && !has_tools && tool_choice.is_none() {
        return Ok(None);
    }

    let mut mapped = match tool_choice {
        None => {
            if disable_parallel {
                json!({ "type": "auto" })
            } else {
                return Ok(None);
            }
        }
        Some(Value::String(value)) => match value.as_str() {
            "auto" => json!({ "type": "auto" }),
            "required" => json!({ "type": "any" }),
            "none" => json!({ "type": "none" }),
            other => {
                return Err(reject(
                    "tool_choice",
                    format!("unsupported value `{other}`"),
                ));
            }
        },
        Some(Value::Object(obj)) => {
            refuse_unknown_keys(obj, &["type", "function"], "tool_choice")?;
            if let Some(kind) = obj.get("type") {
                if expect_string(kind, "tool_choice.type")? != "function" {
                    return Err(reject(
                        "tool_choice.type",
                        "only function tool_choice is supported",
                    ));
                }
            }
            let function = expect_object(
                obj.get("function")
                    .ok_or_else(|| reject("tool_choice.function", "field is required"))?,
                "tool_choice.function",
            )?;
            refuse_unknown_keys(function, &["name"], "tool_choice.function")?;
            let name = expect_string(
                function
                    .get("name")
                    .ok_or_else(|| reject("tool_choice.function.name", "field is required"))?,
                "tool_choice.function.name",
            )?;
            json!({ "type": "tool", "name": name })
        }
        Some(_) => return Err(reject("tool_choice", "must be a string or object")),
    };

    if disable_parallel {
        if let Some(obj) = mapped.as_object_mut() {
            // Anthropic accepts `disable_parallel_tool_use` only on auto / any
            // / tool. `none` already forbids tool use, so the constraint is
            // already in force and the key would 400.
            if obj.get("type").and_then(Value::as_str) != Some("none") {
                obj.insert("disable_parallel_tool_use".into(), Value::Bool(true));
            }
        }
    }
    Ok(Some(mapped))
}

fn anthropic_tool_choice_to_openai(value: &Value) -> Result<(Value, Option<bool>)> {
    let obj = expect_object(value, "tool_choice")?;
    refuse_unknown_keys(
        obj,
        &["type", "name", "disable_parallel_tool_use"],
        "tool_choice",
    )?;
    let parallel = match obj.get("disable_parallel_tool_use") {
        None => None,
        Some(Value::Bool(true)) => Some(false),
        Some(Value::Bool(false)) => None,
        Some(_) => {
            return Err(reject(
                "tool_choice.disable_parallel_tool_use",
                "must be a boolean",
            ));
        }
    };
    let kind = expect_string(
        obj.get("type")
            .ok_or_else(|| reject("tool_choice.type", "field is required"))?,
        "tool_choice.type",
    )?;
    let choice = match kind {
        "auto" => Value::String("auto".into()),
        "any" => Value::String("required".into()),
        "none" => Value::String("none".into()),
        "tool" => {
            let name = expect_string(
                obj.get("name")
                    .ok_or_else(|| reject("tool_choice.name", "field is required"))?,
                "tool_choice.name",
            )?;
            json!({ "type": "function", "function": { "name": name } })
        }
        other => {
            return Err(reject(
                "tool_choice.type",
                format!("unsupported value `{other}`"),
            ));
        }
    };
    Ok((choice, parallel))
}

fn openai_stop_to_anthropic(value: &Value) -> Result<Value> {
    match value {
        Value::String(_) => Ok(Value::Array(vec![value.clone()])),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                expect_string(item, &format!("stop[{i}]"))?;
            }
            Ok(value.clone())
        }
        _ => Err(reject("stop", "must be a string or array of strings")),
    }
}

fn openai_system_message(system: Value) -> Result<Value> {
    match system {
        Value::String(_) => Ok(json!({ "role": "system", "content": system })),
        Value::Array(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for (i, part) in parts.iter().enumerate() {
                let path = format!("system[{i}]");
                let obj = expect_object(part, &path)?;
                refuse_unknown_keys(obj, &["type", "text"], &path)?;
                if obj.get("type").and_then(Value::as_str) != Some("text") {
                    return Err(reject(
                        &format!("{path}.type"),
                        "only text blocks are supported in system",
                    ));
                }
                let text = obj
                    .get("text")
                    .ok_or_else(|| reject(&format!("{path}.text"), "field is required"))?;
                expect_string(text, &format!("{path}.text"))?;
                out.push(json!({ "type": "text", "text": text }));
            }
            Ok(json!({ "role": "system", "content": out }))
        }
        _ => Err(reject("system", "must be a string or array of text blocks")),
    }
}

fn push_system_parts(parts: &mut Vec<Value>, content: Option<&Value>, path: &str) -> Result<()> {
    match content {
        None | Some(Value::Null) => Err(reject(&format!("{path}.content"), "field is required")),
        Some(Value::String(text)) => {
            parts.push(json!({ "type": "text", "text": text }));
            Ok(())
        }
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                parts.push(openai_part_to_anthropic(
                    item,
                    &format!("{path}.content[{i}]"),
                    false,
                )?);
                if parts.last().is_some_and(|part| part["type"] != "text") {
                    return Err(reject(
                        &format!("{path}.content[{i}]"),
                        "only text parts are supported in a system message",
                    ));
                }
            }
            Ok(())
        }
        Some(_) => Err(reject(
            &format!("{path}.content"),
            "must be a string or array",
        )),
    }
}

fn push_anthropic_message(messages: &mut Vec<Value>, role: &str, content: Value) {
    if let Some(last) = messages.last_mut() {
        if last.get("role").and_then(Value::as_str) == Some(role) {
            let existing = last
                .as_object_mut()
                .and_then(|obj| obj.remove("content"))
                .unwrap_or(Value::Array(Vec::new()));
            last["content"] = merge_content(existing, content);
            return;
        }
    }
    messages.push(json!({ "role": role, "content": content }));
}

fn merge_content(left: Value, right: Value) -> Value {
    let mut parts = Vec::new();
    append_content_parts(&mut parts, left);
    append_content_parts(&mut parts, right);
    Value::Array(parts)
}

fn append_content_parts(parts: &mut Vec<Value>, content: Value) {
    match content {
        Value::String(text) => parts.push(json!({ "type": "text", "text": text })),
        Value::Array(items) => parts.extend(items),
        Value::Null => {}
        other => parts.push(other),
    }
}

fn flush_user_parts(out: &mut Vec<Value>, parts: &mut Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    let content = if parts.len() == 1 && parts[0]["type"] == "text" {
        parts[0]["text"].clone()
    } else {
        Value::Array(std::mem::take(parts))
    };
    parts.clear();
    out.push(json!({ "role": "user", "content": content }));
}

fn anthropic_metadata_user(value: &Value) -> Result<Option<String>> {
    let obj = expect_object(value, "metadata")?;
    let mut user = None;
    for (key, child) in obj {
        match key.as_str() {
            "user_id" => {
                // Known-field JSON null = unset. An empty metadata object
                // likewise carries no identity.
                if child.is_null() {
                    continue;
                }
                user = Some(expect_string(child, "metadata.user_id")?.to_string());
            }
            other => {
                return Err(reject(
                    &format!("metadata.{other}"),
                    "no counterpart in openai-chat-completions",
                ));
            }
        }
    }
    Ok(user)
}

fn refuse_stream(value: &Value) -> Result<()> {
    match value {
        Value::Bool(false) => Ok(()),
        Value::Bool(true) => Err(reject("stream", "streaming translation is not implemented")),
        _ => Err(reject("stream", "must be a boolean")),
    }
}

fn refuse_unless_text_format(value: &Value) -> Result<()> {
    let obj = expect_object(value, "response_format")?;
    refuse_unknown_keys(obj, &["type"], "response_format")?;
    match obj.get("type").and_then(Value::as_str) {
        Some("text") => Ok(()),
        Some(other) => Err(reject(
            "response_format.type",
            format!("no counterpart in anthropic-messages for `{other}`"),
        )),
        None => Err(reject("response_format.type", "field is required")),
    }
}

fn parse_object(body: &[u8]) -> Result<Map<String, Value>> {
    let value: Value = serde_json::from_slice(body)?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(reject("$", "request body must be a JSON object")),
    }
}

fn expect_object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| reject(path, "must be a JSON object"))
}

fn expect_array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| reject(path, "must be a JSON array"))
}

fn expect_string<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| reject(path, "must be a string"))
}

fn expect_number(value: &Value, path: &str) -> Result<()> {
    if value.is_number() {
        Ok(())
    } else {
        Err(reject(path, "must be a number"))
    }
}

fn is_number_one(value: &Value) -> bool {
    value.as_u64() == Some(1) || value.as_i64() == Some(1) || value.as_f64() == Some(1.0)
}

fn refuse_unknown_keys(obj: &Map<String, Value>, allowed: &[&str], path: &str) -> Result<()> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(reject(
                &format!("{path}.{key}"),
                "unknown field; refusing to pass it through silently",
            ));
        }
    }
    Ok(())
}

/// Capability-mismatch and validation failures.
///
/// `error.rs` has no translation variant (write boundary for this change).
/// `Error::Serde` is the only existing variant that can carry a formatted
/// diagnostic naming the field, which is the rule in
/// `docs/ARCHITECTURE.md` §6. A dedicated `UntranslatableField` variant
/// should replace this once the taxonomy can grow.
fn reject(field: &str, reason: impl std::fmt::Display) -> Error {
    Error::Serde(<serde_json::Error as serde::de::Error>::custom(format!(
        "cannot translate field `{field}`: {reason}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_binding_needs_no_token() {
        assert!(RelayConfig::default().validate().is_ok());
    }

    #[test]
    fn every_ipv4_and_ipv6_loopback_needs_no_token() {
        for bind_address in ["127.0.0.2", "::1"] {
            let config = RelayConfig {
                bind_address: bind_address.to_string(),
                ..RelayConfig::default()
            };
            assert!(config.validate().is_ok(), "{bind_address}");
        }
    }

    #[test]
    fn invalid_bind_address_is_rejected() {
        let config = RelayConfig {
            bind_address: "localhost".to_string(),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn exposed_binding_without_token_is_rejected() {
        let config = RelayConfig {
            bind_address: "0.0.0.0".to_string(),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn exposed_binding_with_token_is_allowed() {
        let config = RelayConfig {
            bind_address: "0.0.0.0".to_string(),
            auth_token: Some("FAKE-relay-auth-token".to_string()),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn exposed_binding_with_blank_token_is_rejected() {
        for auth_token in ["", "  "] {
            let config = RelayConfig {
                bind_address: "0.0.0.0".to_string(),
                auth_token: Some(auth_token.to_string()),
                ..RelayConfig::default()
            };
            assert!(config.validate().is_err(), "{auth_token:?}");
        }
    }
}

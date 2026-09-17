use serde_json::{json, Map, Value};

use super::{
    anthropic_to_openai_chat, expect_array, expect_number, expect_object, expect_string,
    is_number_one, openai_chat_to_anthropic, parse_object, refuse_stream, refuse_unknown_keys,
    refuse_unless_text_format, reject, WireFormat,
};
use crate::error::Result;

/// A translated body plus the model that belongs in the target URL.
///
/// OpenAI and Anthropic carry `model` in JSON. Gemini carries it in
/// `/v1beta/models/{model}:generateContent`, so callers must keep this value
/// out of the JSON they forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedRequest {
    pub body: Vec<u8>,
    pub target_model: Option<String>,
    pub stream: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TranslationContext<'a> {
    pub source_model: Option<&'a str>,
    pub target_model: Option<&'a str>,
    pub source_stream: bool,
}

#[derive(Debug, Clone)]
enum Reasoning {
    Budget(Value),
    Effort(String),
}

/// Translate a request while carrying URL metadata that is not part of JSON.
pub fn translate_request(
    from: WireFormat,
    to: WireFormat,
    context: TranslationContext<'_>,
    body: &[u8],
) -> Result<TranslatedRequest> {
    if from == WireFormat::OpenAiImagesGenerations || to == WireFormat::OpenAiImagesGenerations {
        return translate_image_request(from, to, context, body);
    }
    if from == to {
        let mut root = parse_object(body)?;
        let stream = if from == WireFormat::GeminiGenerateContent {
            context.source_stream
        } else {
            match root.get("stream").filter(|value| !value.is_null()) {
                None => context.source_stream,
                Some(Value::Bool(value)) => *value,
                Some(_) => return Err(reject("stream", "must be a boolean")),
            }
        };
        let output = if let Some(target_model) = context.target_model {
            if to != WireFormat::GeminiGenerateContent {
                root.insert("model".into(), Value::String(target_model.into()));
            }
            serde_json::to_vec(&Value::Object(root))?
        } else {
            body.to_vec()
        };
        return Ok(TranslatedRequest {
            body: output,
            target_model: (to == WireFormat::GeminiGenerateContent)
                .then(|| {
                    context
                        .target_model
                        .or(context.source_model)
                        .map(str::to_owned)
                })
                .flatten(),
            stream,
        });
    }

    let (mut chat, reasoning, stream) = request_to_chat(from, context, body)?;
    if let Some(target_model) = context.target_model {
        let mut root = parse_object(&chat)?;
        root.insert("model".into(), Value::String(target_model.into()));
        chat = serde_json::to_vec(&Value::Object(root))?;
    }
    if stream && to == WireFormat::GeminiGenerateContent {
        let root = parse_object(&chat)?;
        if root
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| !tools.is_empty())
        {
            return Err(reject(
                "tools",
                "Gemini streams complete function arguments, so partial tool-call deltas cannot be mapped without buffering",
            ));
        }
    }
    if stream && from == WireFormat::OpenAiResponses && from != to {
        return Err(reject(
            "stream",
            "a completed OpenAI Responses event requires the full accumulated output, which this event-by-event relay does not buffer",
        ));
    }
    request_from_chat(to, &chat, reasoning, stream)
}

fn request_to_chat(
    from: WireFormat,
    context: TranslationContext<'_>,
    body: &[u8],
) -> Result<(Vec<u8>, Option<Reasoning>, bool)> {
    let (clean, stream) = extract_stream(from, context.source_stream, body)?;
    let (clean, reasoning) = extract_reasoning(from, &clean)?;
    let chat = match from {
        WireFormat::OpenAiChatCompletions => validate_object(&clean)?,
        WireFormat::OpenAiResponses => responses_to_chat(&clean)?,
        WireFormat::AnthropicMessages => anthropic_to_openai_chat(&clean)?,
        WireFormat::GeminiGenerateContent => gemini_to_chat(context.source_model, &clean)?,
        WireFormat::OpenAiImagesGenerations => {
            return Err(reject("endpoint", "image requests are not chat requests"));
        }
    };
    Ok((chat, reasoning, stream))
}

fn request_from_chat(
    to: WireFormat,
    chat: &[u8],
    reasoning: Option<Reasoning>,
    stream: bool,
) -> Result<TranslatedRequest> {
    let (mut body, target_model) = match to {
        WireFormat::OpenAiChatCompletions => (chat.to_vec(), None),
        WireFormat::OpenAiResponses => (chat_to_responses(chat)?, None),
        WireFormat::AnthropicMessages => (openai_chat_to_anthropic(chat)?, None),
        WireFormat::GeminiGenerateContent => chat_to_gemini(chat)?,
        WireFormat::OpenAiImagesGenerations => {
            return Err(reject("endpoint", "chat requests are not image requests"));
        }
    };
    insert_reasoning(to, &mut body, reasoning)?;
    insert_stream(to, &mut body, stream)?;
    Ok(TranslatedRequest {
        body,
        target_model,
        stream,
    })
}

fn extract_stream(from: WireFormat, source_stream: bool, body: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut root = parse_object(body)?;
    let stream = if from == WireFormat::GeminiGenerateContent {
        source_stream
    } else {
        match root.remove("stream").filter(|value| !value.is_null()) {
            None => source_stream,
            Some(Value::Bool(value)) => value,
            Some(_) => return Err(reject("stream", "must be a boolean")),
        }
    };
    Ok((serde_json::to_vec(&Value::Object(root))?, stream))
}

fn insert_stream(to: WireFormat, body: &mut Vec<u8>, stream: bool) -> Result<()> {
    if !stream || to == WireFormat::GeminiGenerateContent {
        return Ok(());
    }
    let mut root = parse_object(body)?;
    root.insert("stream".into(), Value::Bool(true));
    *body = serde_json::to_vec(&Value::Object(root))?;
    Ok(())
}

fn extract_reasoning(from: WireFormat, body: &[u8]) -> Result<(Vec<u8>, Option<Reasoning>)> {
    let mut root = parse_object(body)?;
    let reasoning = match from {
        WireFormat::OpenAiChatCompletions => root
            .remove("reasoning_effort")
            .filter(|value| !value.is_null())
            .map(|value| parse_openai_effort(&value, "reasoning_effort"))
            .transpose()?,
        WireFormat::OpenAiResponses => root
            .remove("reasoning")
            .filter(|value| !value.is_null())
            .map(|value| parse_openai_reasoning(&value))
            .transpose()?,
        WireFormat::AnthropicMessages => {
            let reasoning = root
                .remove("thinking")
                .filter(|value| !value.is_null())
                .map(|value| parse_anthropic_reasoning(&value))
                .transpose()?;
            if let Some(Reasoning::Budget(budget)) = &reasoning {
                let budget = budget.as_u64().expect("validated reasoning budget");
                let max_tokens = root
                    .get("max_tokens")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| reject("max_tokens", "must be a positive integer"))?;
                if budget >= max_tokens {
                    return Err(reject(
                        "thinking.budget_tokens",
                        "must be less than max_tokens",
                    ));
                }
            }
            reasoning
        }
        WireFormat::GeminiGenerateContent => {
            let Some(config) = root.get_mut("generationConfig") else {
                return Ok((serde_json::to_vec(&Value::Object(root))?, None));
            };
            let config = expect_object(config, "generationConfig")?;
            let mut config = config.clone();
            let reasoning = config
                .remove("thinkingConfig")
                .filter(|value| !value.is_null())
                .map(|value| parse_gemini_reasoning(&value))
                .transpose()?;
            if config.is_empty() {
                root.remove("generationConfig");
            } else {
                root.insert("generationConfig".into(), Value::Object(config));
            }
            reasoning
        }
        WireFormat::OpenAiImagesGenerations => None,
    };
    Ok((serde_json::to_vec(&Value::Object(root))?, reasoning))
}

fn parse_openai_reasoning(value: &Value) -> Result<Reasoning> {
    let obj = expect_object(value, "reasoning")?;
    refuse_unknown_keys(obj, &["effort"], "reasoning")?;
    parse_openai_effort(
        obj.get("effort")
            .ok_or_else(|| reject("reasoning.effort", "field is required"))?,
        "reasoning.effort",
    )
}

fn parse_openai_effort(value: &Value, path: &str) -> Result<Reasoning> {
    let effort = expect_string(value, path)?;
    if !matches!(effort, "minimal" | "low" | "medium" | "high") {
        return Err(reject(
            path,
            format!("unsupported reasoning effort `{effort}`"),
        ));
    }
    Ok(Reasoning::Effort(effort.into()))
}

fn parse_anthropic_reasoning(value: &Value) -> Result<Reasoning> {
    let obj = expect_object(value, "thinking")?;
    refuse_unknown_keys(obj, &["type", "budget_tokens"], "thinking")?;
    if expect_string(
        obj.get("type")
            .ok_or_else(|| reject("thinking.type", "field is required"))?,
        "thinking.type",
    )? != "enabled"
    {
        return Err(reject("thinking.type", "only `enabled` can be mapped"));
    }
    let budget = obj
        .get("budget_tokens")
        .ok_or_else(|| reject("thinking.budget_tokens", "field is required"))?;
    let budget_tokens = budget
        .as_u64()
        .ok_or_else(|| reject("thinking.budget_tokens", "must be a positive integer"))?;
    if budget_tokens < 1024 {
        return Err(reject(
            "thinking.budget_tokens",
            "Anthropic requires at least 1024 tokens",
        ));
    }
    Ok(Reasoning::Budget(budget.clone()))
}

fn parse_gemini_reasoning(value: &Value) -> Result<Reasoning> {
    let obj = expect_object(value, "generationConfig.thinkingConfig")?;
    refuse_unknown_keys(
        obj,
        &["thinkingBudget", "thinkingLevel"],
        "generationConfig.thinkingConfig",
    )?;
    match (obj.get("thinkingBudget"), obj.get("thinkingLevel")) {
        (Some(_), Some(_)) => Err(reject(
            "generationConfig.thinkingConfig",
            "thinkingBudget and thinkingLevel are mutually exclusive",
        )),
        (Some(budget), None) => {
            budget.as_u64().ok_or_else(|| {
                reject(
                    "generationConfig.thinkingConfig.thinkingBudget",
                    "must be a non-negative integer",
                )
            })?;
            Ok(Reasoning::Budget(budget.clone()))
        }
        (None, Some(level)) => {
            let path = "generationConfig.thinkingConfig.thinkingLevel";
            let level = expect_string(level, path)?;
            let effort = match level {
                "MINIMAL" => "minimal",
                "LOW" => "low",
                "MEDIUM" => "medium",
                "HIGH" => "high",
                other => {
                    return Err(reject(path, format!("unsupported thinkingLevel `{other}`")));
                }
            };
            Ok(Reasoning::Effort(effort.into()))
        }
        (None, None) => Err(reject(
            "generationConfig.thinkingConfig",
            "thinkingBudget or thinkingLevel is required",
        )),
    }
}

fn insert_reasoning(
    to: WireFormat,
    body: &mut Vec<u8>,
    reasoning: Option<Reasoning>,
) -> Result<()> {
    let Some(reasoning) = reasoning else {
        return Ok(());
    };
    let mut root = parse_object(body)?;
    match (to, reasoning) {
        (WireFormat::OpenAiChatCompletions, Reasoning::Effort(effort)) => {
            root.insert("reasoning_effort".into(), Value::String(effort));
        }
        (WireFormat::OpenAiResponses, Reasoning::Effort(effort)) => {
            root.insert("reasoning".into(), json!({ "effort": effort }));
        }
        (WireFormat::AnthropicMessages, Reasoning::Budget(budget)) => {
            let budget_tokens = budget
                .as_u64()
                .ok_or_else(|| reject("thinking.budget_tokens", "must be a positive integer"))?;
            if budget_tokens < 1024 {
                return Err(reject(
                    "thinking.budget_tokens",
                    "Anthropic requires at least 1024 tokens",
                ));
            }
            let max_tokens = root
                .get("max_tokens")
                .and_then(Value::as_u64)
                .ok_or_else(|| reject("max_tokens", "must be a positive integer"))?;
            if budget_tokens >= max_tokens {
                return Err(reject(
                    "thinking.budget_tokens",
                    "must be less than max_tokens",
                ));
            }
            root.insert(
                "thinking".into(),
                json!({ "type": "enabled", "budget_tokens": budget }),
            );
        }
        (WireFormat::GeminiGenerateContent, Reasoning::Budget(budget)) => {
            insert_gemini_thinking(&mut root, "thinkingBudget", budget)?;
        }
        (WireFormat::GeminiGenerateContent, Reasoning::Effort(effort)) => {
            let level = match effort.as_str() {
                "minimal" => "MINIMAL",
                "low" => "LOW",
                "medium" => "MEDIUM",
                "high" => "HIGH",
                other => {
                    return Err(reject(
                        "reasoning.effort",
                        format!("Gemini has no thinkingLevel for `{other}`"),
                    ));
                }
            };
            insert_gemini_thinking(&mut root, "thinkingLevel", Value::String(level.into()))?;
        }
        (WireFormat::OpenAiChatCompletions, Reasoning::Budget(_))
        | (WireFormat::OpenAiResponses, Reasoning::Budget(_)) => {
            return Err(reject(
                "thinking.budget_tokens",
                "numeric reasoning budgets have no OpenAI counterpart",
            ));
        }
        (WireFormat::AnthropicMessages, Reasoning::Effort(_)) => {
            return Err(reject(
                "reasoning.effort",
                "categorical reasoning effort has no Anthropic numeric counterpart",
            ));
        }
        (WireFormat::OpenAiImagesGenerations, _) => {
            return Err(reject(
                "reasoning",
                "image generation has no reasoning-budget field",
            ));
        }
    }
    *body = serde_json::to_vec(&Value::Object(root))?;
    Ok(())
}

fn insert_gemini_thinking(root: &mut Map<String, Value>, field: &str, value: Value) -> Result<()> {
    let generation = root.entry("generationConfig").or_insert_with(|| json!({}));
    let generation = generation
        .as_object_mut()
        .ok_or_else(|| reject("generationConfig", "must be a JSON object"))?;
    generation.insert("thinkingConfig".into(), json!({ field: value }));
    Ok(())
}

fn responses_to_chat(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "model",
            "input",
            "instructions",
            "max_output_tokens",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "stream",
            "reasoning",
        ],
        "$",
    )?;
    let model = expect_string(
        root.get("model")
            .ok_or_else(|| reject("model", "field is required"))?,
        "model",
    )?;
    if let Some(stream) = root.get("stream").filter(|value| !value.is_null()) {
        refuse_stream(stream)?;
    }
    let mut messages = Vec::new();
    if let Some(instructions) = root.get("instructions").filter(|value| !value.is_null()) {
        messages.push(json!({
            "role": "developer",
            "content": expect_string(instructions, "instructions")?,
        }));
    }
    match root
        .get("input")
        .ok_or_else(|| reject("input", "field is required"))?
    {
        Value::String(text) => messages.push(json!({ "role": "user", "content": text })),
        Value::Array(items) => responses_input_to_chat(items, &mut messages)?,
        _ => return Err(reject("input", "must be a string or JSON array")),
    }
    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.into()));
    out.insert("messages".into(), Value::Array(messages));
    if let Some(value) = root
        .get("max_output_tokens")
        .filter(|value| !value.is_null())
    {
        expect_number(value, "max_output_tokens")?;
        out.insert("max_completion_tokens".into(), value.clone());
    }
    copy_number(&root, &mut out, "temperature", "temperature")?;
    copy_number(&root, &mut out, "top_p", "top_p")?;
    if let Some(tools) = root.get("tools").filter(|value| !value.is_null()) {
        out.insert("tools".into(), responses_tools_to_chat(tools)?);
    }
    if let Some(choice) = root.get("tool_choice").filter(|value| !value.is_null()) {
        out.insert("tool_choice".into(), responses_tool_choice_to_chat(choice)?);
    }
    Ok(serde_json::to_vec(&Value::Object(out))?)
}

fn responses_input_to_chat(items: &[Value], messages: &mut Vec<Value>) -> Result<()> {
    for (index, item) in items.iter().enumerate() {
        let path = format!("input[{index}]");
        let obj = expect_object(item, &path)?;
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("message");
        match kind {
            "message" => {
                refuse_unknown_keys(obj, &["type", "role", "content"], &path)?;
                let role = expect_string(
                    obj.get("role")
                        .ok_or_else(|| reject(&format!("{path}.role"), "field is required"))?,
                    &format!("{path}.role"),
                )?;
                let content = responses_content_to_chat(
                    obj.get("content")
                        .ok_or_else(|| reject(&format!("{path}.content"), "field is required"))?,
                    role,
                    &format!("{path}.content"),
                )?;
                messages.push(json!({ "role": role, "content": content }));
            }
            "function_call" => {
                refuse_unknown_keys(obj, &["type", "call_id", "name", "arguments"], &path)?;
                let call_id = required_string(obj, "call_id", &path)?;
                let name = required_string(obj, "name", &path)?;
                let arguments = required_string(obj, "arguments", &path)?;
                let call = json!({
                    "id": call_id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                });
                if let Some(last) = messages.last_mut().filter(|message| {
                    message.get("role").and_then(Value::as_str) == Some("assistant")
                }) {
                    last.as_object_mut()
                        .expect("message object")
                        .entry("tool_calls")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("tool_calls array")
                        .push(call);
                } else {
                    messages.push(
                        json!({ "role": "assistant", "content": null, "tool_calls": [call] }),
                    );
                }
            }
            "function_call_output" => {
                refuse_unknown_keys(obj, &["type", "call_id", "output"], &path)?;
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": required_string(obj, "call_id", &path)?,
                    "content": required_string(obj, "output", &path)?,
                }));
            }
            other => {
                return Err(reject(
                    &format!("{path}.type"),
                    format!("no chat-completions counterpart for `{other}`"),
                ));
            }
        }
    }
    Ok(())
}

fn responses_content_to_chat(value: &Value, role: &str, path: &str) -> Result<Value> {
    if let Value::String(_) = value {
        return Ok(value.clone());
    }
    let parts = expect_array(value, path)?;
    let mut out = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let part_path = format!("{path}[{index}]");
        let obj = expect_object(part, &part_path)?;
        let kind = required_string(obj, "type", &part_path)?;
        match kind {
            "input_text" | "output_text" => {
                refuse_unknown_keys(obj, &["type", "text"], &part_path)?;
                out.push(json!({
                    "type": "text",
                    "text": required_string(obj, "text", &part_path)?,
                }));
            }
            "input_image" if role == "user" => {
                refuse_unknown_keys(obj, &["type", "image_url", "detail"], &part_path)?;
                let mut image = json!({
                    "url": required_string(obj, "image_url", &part_path)?,
                });
                if let Some(detail) = obj.get("detail").filter(|value| !value.is_null()) {
                    image["detail"] = Value::String(
                        expect_string(detail, &format!("{part_path}.detail"))?.into(),
                    );
                }
                out.push(json!({ "type": "image_url", "image_url": image }));
            }
            other => {
                return Err(reject(
                    &format!("{part_path}.type"),
                    format!("no chat-completions counterpart for `{other}`"),
                ));
            }
        }
    }
    Ok(Value::Array(out))
}

fn chat_to_responses(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "model",
            "messages",
            "max_tokens",
            "max_completion_tokens",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "stream",
            "n",
            "parallel_tool_calls",
            "response_format",
            "reasoning_effort",
        ],
        "$",
    )?;
    let model = required_string(&root, "model", "$")?;
    if let Some(stream) = root.get("stream").filter(|value| !value.is_null()) {
        refuse_stream(stream)?;
    }
    if let Some(n) = root.get("n").filter(|value| !value.is_null()) {
        if !is_number_one(n) {
            return Err(reject("n", "OpenAI Responses returns one response"));
        }
    }
    if let Some(value) = root
        .get("parallel_tool_calls")
        .filter(|value| !value.is_null())
    {
        if !value.is_boolean() {
            return Err(reject("parallel_tool_calls", "must be a boolean"));
        }
    }
    if let Some(format) = root.get("response_format").filter(|value| !value.is_null()) {
        refuse_unless_text_format(format)?;
    }
    let messages = expect_array(
        root.get("messages")
            .ok_or_else(|| reject("messages", "field is required"))?,
        "messages",
    )?;
    let input = chat_messages_to_responses(messages)?;
    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.into()));
    out.insert("input".into(), Value::Array(input));
    let budget = reconcile_max_tokens(&root)?;
    if let Some(budget) = budget {
        out.insert("max_output_tokens".into(), budget);
    }
    copy_number(&root, &mut out, "temperature", "temperature")?;
    copy_number(&root, &mut out, "top_p", "top_p")?;
    if let Some(tools) = root.get("tools").filter(|value| !value.is_null()) {
        out.insert("tools".into(), chat_tools_to_responses(tools)?);
    }
    if let Some(choice) = root.get("tool_choice").filter(|value| !value.is_null()) {
        out.insert("tool_choice".into(), chat_tool_choice_to_responses(choice)?);
    }
    Ok(serde_json::to_vec(&Value::Object(out))?)
}

fn chat_messages_to_responses(messages: &[Value]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        let path = format!("messages[{index}]");
        let obj = expect_object(message, &path)?;
        refuse_unknown_keys(
            obj,
            &["role", "content", "tool_calls", "tool_call_id", "name"],
            &path,
        )?;
        let role = required_string(obj, "role", &path)?;
        match role {
            "tool" => {
                out.push(json!({
                    "type": "function_call_output",
                    "call_id": required_string(obj, "tool_call_id", &path)?,
                    "output": obj.get("content").and_then(Value::as_str).unwrap_or(""),
                }));
            }
            "system" | "developer" | "user" | "assistant" => {
                if let Some(content) = obj.get("content").filter(|value| !value.is_null()) {
                    out.push(json!({
                        "type": "message",
                        "role": role,
                        "content": chat_content_to_responses(content, role, &format!("{path}.content"))?,
                    }));
                }
                if let Some(calls) = obj.get("tool_calls").filter(|value| !value.is_null()) {
                    for (call_index, call) in expect_array(calls, &format!("{path}.tool_calls"))?
                        .iter()
                        .enumerate()
                    {
                        let call_path = format!("{path}.tool_calls[{call_index}]");
                        let call = expect_object(call, &call_path)?;
                        refuse_unknown_keys(call, &["id", "type", "function"], &call_path)?;
                        if call.get("type").and_then(Value::as_str) != Some("function") {
                            return Err(reject(
                                &format!("{call_path}.type"),
                                "only function calls are supported",
                            ));
                        }
                        let function = expect_object(
                            call.get("function").ok_or_else(|| {
                                reject(&format!("{call_path}.function"), "field is required")
                            })?,
                            &format!("{call_path}.function"),
                        )?;
                        refuse_unknown_keys(
                            function,
                            &["name", "arguments"],
                            &format!("{call_path}.function"),
                        )?;
                        out.push(json!({
                            "type": "function_call",
                            "call_id": required_string(call, "id", &call_path)?,
                            "name": required_string(function, "name", &format!("{call_path}.function"))?,
                            "arguments": required_string(function, "arguments", &format!("{call_path}.function"))?,
                        }));
                    }
                }
                if obj.get("content").is_none() && obj.get("tool_calls").is_none() {
                    return Err(reject(&format!("{path}.content"), "message has no content"));
                }
            }
            other => {
                return Err(reject(
                    &format!("{path}.role"),
                    format!("unsupported role `{other}`"),
                ))
            }
        }
    }
    Ok(out)
}

fn chat_content_to_responses(value: &Value, role: &str, path: &str) -> Result<Value> {
    let text_kind = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    match value {
        Value::String(text) => Ok(json!([{ "type": text_kind, "text": text }])),
        Value::Array(parts) => {
            let mut out = Vec::new();
            for (index, part) in parts.iter().enumerate() {
                let part_path = format!("{path}[{index}]");
                let obj = expect_object(part, &part_path)?;
                let kind = required_string(obj, "type", &part_path)?;
                match kind {
                    "text" => {
                        refuse_unknown_keys(obj, &["type", "text"], &part_path)?;
                        out.push(json!({ "type": text_kind, "text": required_string(obj, "text", &part_path)? }));
                    }
                    "image_url" if role == "user" => {
                        refuse_unknown_keys(obj, &["type", "image_url"], &part_path)?;
                        let image = expect_object(
                            obj.get("image_url").ok_or_else(|| {
                                reject(&format!("{part_path}.image_url"), "field is required")
                            })?,
                            &format!("{part_path}.image_url"),
                        )?;
                        refuse_unknown_keys(
                            image,
                            &["url", "detail"],
                            &format!("{part_path}.image_url"),
                        )?;
                        let mut mapped = json!({
                            "type": "input_image",
                            "image_url": required_string(image, "url", &format!("{part_path}.image_url"))?,
                        });
                        if let Some(detail) = image.get("detail").filter(|value| !value.is_null()) {
                            mapped["detail"] = Value::String(
                                expect_string(detail, &format!("{part_path}.image_url.detail"))?
                                    .into(),
                            );
                        }
                        out.push(mapped);
                    }
                    other => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            format!("unsupported content type `{other}`"),
                        ))
                    }
                }
            }
            Ok(Value::Array(out))
        }
        _ => Err(reject(path, "must be a string or JSON array")),
    }
}

fn responses_tools_to_chat(value: &Value) -> Result<Value> {
    let tools = expect_array(value, "tools")?;
    let mut out = Vec::new();
    for (index, tool) in tools.iter().enumerate() {
        let path = format!("tools[{index}]");
        let obj = expect_object(tool, &path)?;
        refuse_unknown_keys(
            obj,
            &["type", "name", "description", "parameters", "strict"],
            &path,
        )?;
        if required_string(obj, "type", &path)? != "function" {
            return Err(reject(
                &format!("{path}.type"),
                "only function tools are supported",
            ));
        }
        let mut function = Map::new();
        function.insert(
            "name".into(),
            Value::String(required_string(obj, "name", &path)?.into()),
        );
        if let Some(value) = obj.get("description").filter(|value| !value.is_null()) {
            function.insert(
                "description".into(),
                Value::String(expect_string(value, &format!("{path}.description"))?.into()),
            );
        }
        if let Some(value) = obj.get("parameters").filter(|value| !value.is_null()) {
            expect_object(value, &format!("{path}.parameters"))?;
            function.insert("parameters".into(), value.clone());
        }
        if let Some(value) = obj.get("strict").filter(|value| !value.is_null()) {
            if !value.is_boolean() {
                return Err(reject(&format!("{path}.strict"), "must be a boolean"));
            }
            function.insert("strict".into(), value.clone());
        }
        out.push(json!({ "type": "function", "function": function }));
    }
    Ok(Value::Array(out))
}

fn chat_tools_to_responses(value: &Value) -> Result<Value> {
    let tools = expect_array(value, "tools")?;
    let mut out = Vec::new();
    for (index, tool) in tools.iter().enumerate() {
        let path = format!("tools[{index}]");
        let obj = expect_object(tool, &path)?;
        refuse_unknown_keys(obj, &["type", "function"], &path)?;
        if obj.get("type").and_then(Value::as_str) != Some("function") {
            return Err(reject(
                &format!("{path}.type"),
                "only function tools are supported",
            ));
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
        let mut mapped = Map::new();
        mapped.insert("type".into(), Value::String("function".into()));
        mapped.insert(
            "name".into(),
            Value::String(required_string(function, "name", &format!("{path}.function"))?.into()),
        );
        for field in ["description", "parameters", "strict"] {
            if let Some(value) = function.get(field).filter(|value| !value.is_null()) {
                mapped.insert(field.into(), value.clone());
            }
        }
        out.push(Value::Object(mapped));
    }
    Ok(Value::Array(out))
}

fn responses_tool_choice_to_chat(value: &Value) -> Result<Value> {
    match value {
        Value::String(_) => Ok(value.clone()),
        Value::Object(obj) => {
            refuse_unknown_keys(obj, &["type", "name"], "tool_choice")?;
            if required_string(obj, "type", "tool_choice")? != "function" {
                return Err(reject(
                    "tool_choice.type",
                    "only function tool choice is supported",
                ));
            }
            Ok(json!({
                "type": "function",
                "function": { "name": required_string(obj, "name", "tool_choice")? },
            }))
        }
        _ => Err(reject("tool_choice", "must be a string or JSON object")),
    }
}

fn chat_tool_choice_to_responses(value: &Value) -> Result<Value> {
    match value {
        Value::String(_) => Ok(value.clone()),
        Value::Object(obj) => {
            refuse_unknown_keys(obj, &["type", "function"], "tool_choice")?;
            if obj.get("type").and_then(Value::as_str) != Some("function") {
                return Err(reject(
                    "tool_choice.type",
                    "only function tool choice is supported",
                ));
            }
            let function = expect_object(
                obj.get("function")
                    .ok_or_else(|| reject("tool_choice.function", "field is required"))?,
                "tool_choice.function",
            )?;
            refuse_unknown_keys(function, &["name"], "tool_choice.function")?;
            Ok(json!({
                "type": "function",
                "name": required_string(function, "name", "tool_choice.function")?,
            }))
        }
        _ => Err(reject("tool_choice", "must be a string or JSON object")),
    }
}

fn gemini_to_chat(source_model: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "contents",
            "systemInstruction",
            "generationConfig",
            "tools",
            "toolConfig",
        ],
        "$",
    )?;
    let model = source_model.ok_or_else(|| {
        reject(
            "source_model",
            "Gemini model must be supplied from the generateContent URL",
        )
    })?;
    let mut messages = Vec::new();
    if let Some(system) = root
        .get("systemInstruction")
        .filter(|value| !value.is_null())
    {
        let obj = expect_object(system, "systemInstruction")?;
        refuse_unknown_keys(obj, &["parts"], "systemInstruction")?;
        messages.push(json!({
            "role": "system",
            "content": gemini_parts_to_chat(
                obj.get("parts").ok_or_else(|| reject("systemInstruction.parts", "field is required"))?,
                "systemInstruction.parts",
                "system",
            )?,
        }));
    }
    let contents = expect_array(
        root.get("contents")
            .ok_or_else(|| reject("contents", "field is required"))?,
        "contents",
    )?;
    for (index, content) in contents.iter().enumerate() {
        gemini_content_to_chat(content, index, &mut messages)?;
    }
    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.into()));
    out.insert("messages".into(), Value::Array(messages));
    if let Some(config) = root
        .get("generationConfig")
        .filter(|value| !value.is_null())
    {
        let config = expect_object(config, "generationConfig")?;
        refuse_unknown_keys(
            config,
            &[
                "maxOutputTokens",
                "temperature",
                "topP",
                "stopSequences",
                "thinkingConfig",
            ],
            "generationConfig",
        )?;
        copy_number(config, &mut out, "maxOutputTokens", "max_completion_tokens")?;
        copy_number(config, &mut out, "temperature", "temperature")?;
        copy_number(config, &mut out, "topP", "top_p")?;
        if let Some(stop) = config.get("stopSequences").filter(|value| !value.is_null()) {
            validate_string_array(stop, "generationConfig.stopSequences")?;
            out.insert("stop".into(), stop.clone());
        }
    }
    if let Some(tools) = root.get("tools").filter(|value| !value.is_null()) {
        out.insert("tools".into(), gemini_tools_to_chat(tools)?);
    }
    if let Some(config) = root.get("toolConfig").filter(|value| !value.is_null()) {
        out.insert("tool_choice".into(), gemini_tool_choice_to_chat(config)?);
    }
    Ok(serde_json::to_vec(&Value::Object(out))?)
}

fn gemini_content_to_chat(content: &Value, index: usize, messages: &mut Vec<Value>) -> Result<()> {
    let path = format!("contents[{index}]");
    let obj = expect_object(content, &path)?;
    refuse_unknown_keys(obj, &["role", "parts"], &path)?;
    let role = match obj.get("role").and_then(Value::as_str).unwrap_or("user") {
        "user" => "user",
        "model" => "assistant",
        other => {
            return Err(reject(
                &format!("{path}.role"),
                format!("unsupported role `{other}`"),
            ))
        }
    };
    let parts = expect_array(
        obj.get("parts")
            .ok_or_else(|| reject(&format!("{path}.parts"), "field is required"))?,
        &format!("{path}.parts"),
    )?;
    let mut content_parts = Vec::new();
    let mut tool_calls = Vec::new();
    for (part_index, part) in parts.iter().enumerate() {
        let part_path = format!("{path}.parts[{part_index}]");
        let part = expect_object(part, &part_path)?;
        if let Some(call) = part.get("functionCall") {
            refuse_unknown_keys(part, &["functionCall"], &part_path)?;
            let call = expect_object(call, &format!("{part_path}.functionCall"))?;
            refuse_unknown_keys(
                call,
                &["id", "name", "args"],
                &format!("{part_path}.functionCall"),
            )?;
            let args = call.get("args").cloned().unwrap_or_else(|| json!({}));
            expect_object(&args, &format!("{part_path}.functionCall.args"))?;
            tool_calls.push(json!({
                "id": required_string(call, "id", &format!("{part_path}.functionCall"))?,
                "type": "function",
                "function": {
                    "name": required_string(call, "name", &format!("{part_path}.functionCall"))?,
                    "arguments": serde_json::to_string(&args)?,
                },
            }));
        } else if let Some(response) = part.get("functionResponse") {
            refuse_unknown_keys(part, &["functionResponse"], &part_path)?;
            let response = expect_object(response, &format!("{part_path}.functionResponse"))?;
            refuse_unknown_keys(
                response,
                &["id", "name", "response"],
                &format!("{part_path}.functionResponse"),
            )?;
            messages.push(json!({
                "role": "tool",
                "tool_call_id": required_string(response, "id", &format!("{part_path}.functionResponse"))?,
                "name": required_string(response, "name", &format!("{part_path}.functionResponse"))?,
                "content": serde_json::to_string(response.get("response").ok_or_else(|| reject(&format!("{part_path}.functionResponse.response"), "field is required"))?)?,
            }));
        } else {
            content_parts.push(gemini_part_to_chat(part, &part_path)?);
        }
    }
    if !content_parts.is_empty() || !tool_calls.is_empty() {
        let content = collapse_text_parts(content_parts);
        let mut message = Map::new();
        message.insert("role".into(), Value::String(role.into()));
        message.insert("content".into(), content);
        if !tool_calls.is_empty() {
            message.insert("tool_calls".into(), Value::Array(tool_calls));
        }
        messages.push(Value::Object(message));
    }
    Ok(())
}

fn gemini_parts_to_chat(value: &Value, path: &str, role: &str) -> Result<Value> {
    let mut out = Vec::new();
    for (index, part) in expect_array(value, path)?.iter().enumerate() {
        out.push(gemini_part_to_chat(
            expect_object(part, &format!("{path}[{index}]"))?,
            &format!("{path}[{index}]"),
        )?);
    }
    if role == "system" && out.iter().any(|part| part["type"] != "text") {
        return Err(reject(path, "systemInstruction supports text parts only"));
    }
    Ok(collapse_text_parts(out))
}

fn gemini_part_to_chat(part: &Map<String, Value>, path: &str) -> Result<Value> {
    if let Some(text) = part.get("text") {
        refuse_unknown_keys(part, &["text", "thought"], path)?;
        if let Some(thought) = part.get("thought").filter(|value| !value.is_null()) {
            let thought = thought
                .as_bool()
                .ok_or_else(|| reject(&format!("{path}.thought"), "must be a boolean"))?;
            if thought {
                return Err(reject(
                    &format!("{path}.thought"),
                    "the target dialect has no reasoning-content counterpart",
                ));
            }
        }
        return Ok(
            json!({ "type": "text", "text": expect_string(text, &format!("{path}.text"))? }),
        );
    }
    if let Some(data) = part.get("inlineData") {
        refuse_unknown_keys(part, &["inlineData"], path)?;
        let data = expect_object(data, &format!("{path}.inlineData"))?;
        refuse_unknown_keys(data, &["mimeType", "data"], &format!("{path}.inlineData"))?;
        let mime = required_string(data, "mimeType", &format!("{path}.inlineData"))?;
        let bytes = required_string(data, "data", &format!("{path}.inlineData"))?;
        return Ok(
            json!({ "type": "image_url", "image_url": { "url": format!("data:{mime};base64,{bytes}") } }),
        );
    }
    if let Some(data) = part.get("fileData") {
        refuse_unknown_keys(part, &["fileData"], path)?;
        let data = expect_object(data, &format!("{path}.fileData"))?;
        refuse_unknown_keys(data, &["mimeType", "fileUri"], &format!("{path}.fileData"))?;
        return Ok(
            json!({ "type": "image_url", "image_url": { "url": required_string(data, "fileUri", &format!("{path}.fileData"))? } }),
        );
    }
    Err(reject(path, "unknown Gemini content part"))
}

fn chat_to_gemini(body: &[u8]) -> Result<(Vec<u8>, Option<String>)> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "model",
            "messages",
            "max_tokens",
            "max_completion_tokens",
            "tools",
            "tool_choice",
            "temperature",
            "top_p",
            "stop",
            "stream",
            "n",
            "parallel_tool_calls",
            "response_format",
            "reasoning_effort",
        ],
        "$",
    )?;
    let model = required_string(&root, "model", "$")?.to_string();
    if let Some(stream) = root.get("stream").filter(|value| !value.is_null()) {
        refuse_stream(stream)?;
    }
    if let Some(n) = root.get("n").filter(|value| !value.is_null()) {
        if !is_number_one(n) {
            return Err(reject(
                "n",
                "Gemini generateContent returns one candidate by default",
            ));
        }
    }
    if let Some(parallel) = root
        .get("parallel_tool_calls")
        .filter(|value| !value.is_null())
    {
        if parallel != &Value::Bool(true) {
            return Err(reject(
                "parallel_tool_calls",
                "Gemini has no disable-parallel counterpart",
            ));
        }
    }
    if let Some(format) = root.get("response_format").filter(|value| !value.is_null()) {
        refuse_unless_text_format(format)?;
    }
    let messages = expect_array(
        root.get("messages")
            .ok_or_else(|| reject("messages", "field is required"))?,
        "messages",
    )?;
    let (system, contents) = chat_messages_to_gemini(messages)?;
    let mut out = Map::new();
    if let Some(system) = system {
        out.insert("systemInstruction".into(), json!({ "parts": system }));
    }
    out.insert("contents".into(), Value::Array(contents));
    let mut generation = Map::new();
    if let Some(budget) = reconcile_max_tokens(&root)? {
        generation.insert("maxOutputTokens".into(), budget);
    }
    copy_number(&root, &mut generation, "temperature", "temperature")?;
    copy_number(&root, &mut generation, "top_p", "topP")?;
    if let Some(stop) = root.get("stop").filter(|value| !value.is_null()) {
        let stop = match stop {
            Value::String(_) => Value::Array(vec![stop.clone()]),
            Value::Array(_) => {
                validate_string_array(stop, "stop")?;
                stop.clone()
            }
            _ => return Err(reject("stop", "must be a string or JSON array")),
        };
        generation.insert("stopSequences".into(), stop);
    }
    if !generation.is_empty() {
        out.insert("generationConfig".into(), Value::Object(generation));
    }
    if let Some(tools) = root.get("tools").filter(|value| !value.is_null()) {
        out.insert("tools".into(), chat_tools_to_gemini(tools)?);
    }
    if let Some(choice) = root.get("tool_choice").filter(|value| !value.is_null()) {
        out.insert("toolConfig".into(), chat_tool_choice_to_gemini(choice)?);
    }
    Ok((serde_json::to_vec(&Value::Object(out))?, Some(model)))
}

fn chat_messages_to_gemini(messages: &[Value]) -> Result<(Option<Vec<Value>>, Vec<Value>)> {
    let mut system = Vec::new();
    let mut contents = Vec::new();
    let mut saw_conversational_message = false;
    for (index, message) in messages.iter().enumerate() {
        let path = format!("messages[{index}]");
        let obj = expect_object(message, &path)?;
        refuse_unknown_keys(
            obj,
            &["role", "content", "tool_calls", "tool_call_id", "name"],
            &path,
        )?;
        let role = required_string(obj, "role", &path)?;
        if matches!(role, "system" | "developer") {
            if saw_conversational_message {
                return Err(reject(
                    &format!("{path}.role"),
                    "system and developer messages must precede conversational content",
                ));
            }
            let parts = chat_content_to_gemini(
                obj.get("content")
                    .ok_or_else(|| reject(&format!("{path}.content"), "field is required"))?,
                &format!("{path}.content"),
                true,
            )?;
            system.extend(parts);
            continue;
        }
        saw_conversational_message = true;
        if role == "tool" {
            let name = required_string(obj, "name", &path)?;
            let content = obj.get("content").and_then(Value::as_str).unwrap_or("");
            let parsed = serde_json::from_str(content).unwrap_or_else(|_| json!(content));
            let response = if parsed.is_object() {
                parsed
            } else {
                json!({ "output": parsed })
            };
            contents.push(json!({
                "role": "user",
                "parts": [{
                    "functionResponse": {
                        "id": required_string(obj, "tool_call_id", &path)?,
                        "name": name,
                        "response": response,
                    }
                }],
            }));
            continue;
        }
        let gemini_role = match role {
            "user" => "user",
            "assistant" => "model",
            other => {
                return Err(reject(
                    &format!("{path}.role"),
                    format!("unsupported role `{other}`"),
                ))
            }
        };
        let mut parts = match obj.get("content").filter(|value| !value.is_null()) {
            Some(content) => chat_content_to_gemini(content, &format!("{path}.content"), false)?,
            None => Vec::new(),
        };
        if let Some(calls) = obj.get("tool_calls").filter(|value| !value.is_null()) {
            for (call_index, call) in expect_array(calls, &format!("{path}.tool_calls"))?
                .iter()
                .enumerate()
            {
                let call_path = format!("{path}.tool_calls[{call_index}]");
                let call = expect_object(call, &call_path)?;
                refuse_unknown_keys(call, &["id", "type", "function"], &call_path)?;
                let function = expect_object(
                    call.get("function").ok_or_else(|| {
                        reject(&format!("{call_path}.function"), "field is required")
                    })?,
                    &format!("{call_path}.function"),
                )?;
                refuse_unknown_keys(
                    function,
                    &["name", "arguments"],
                    &format!("{call_path}.function"),
                )?;
                let arguments =
                    required_string(function, "arguments", &format!("{call_path}.function"))?;
                let args: Value = serde_json::from_str(arguments).map_err(|_| {
                    reject(
                        &format!("{call_path}.function.arguments"),
                        "must contain a JSON object",
                    )
                })?;
                expect_object(&args, &format!("{call_path}.function.arguments"))?;
                parts.push(json!({
                    "functionCall": {
                        "id": required_string(call, "id", &call_path)?,
                        "name": required_string(function, "name", &format!("{call_path}.function"))?,
                        "args": args,
                    }
                }));
            }
        }
        if parts.is_empty() {
            return Err(reject(&format!("{path}.content"), "message has no content"));
        }
        contents.push(json!({ "role": gemini_role, "parts": parts }));
    }
    Ok(((!system.is_empty()).then_some(system), contents))
}

fn chat_content_to_gemini(value: &Value, path: &str, system: bool) -> Result<Vec<Value>> {
    match value {
        Value::String(text) => Ok(vec![json!({ "text": text })]),
        Value::Array(parts) => {
            let mut out = Vec::new();
            for (index, part) in parts.iter().enumerate() {
                let part_path = format!("{path}[{index}]");
                let obj = expect_object(part, &part_path)?;
                let kind = required_string(obj, "type", &part_path)?;
                match kind {
                    "text" => {
                        refuse_unknown_keys(obj, &["type", "text"], &part_path)?;
                        out.push(json!({ "text": required_string(obj, "text", &part_path)? }));
                    }
                    "image_url" if !system => {
                        refuse_unknown_keys(obj, &["type", "image_url"], &part_path)?;
                        let image = expect_object(
                            obj.get("image_url").ok_or_else(|| {
                                reject(&format!("{part_path}.image_url"), "field is required")
                            })?,
                            &format!("{part_path}.image_url"),
                        )?;
                        refuse_unknown_keys(
                            image,
                            &["url", "detail"],
                            &format!("{part_path}.image_url"),
                        )?;
                        if let Some(detail) = image.get("detail").filter(|value| !value.is_null()) {
                            if expect_string(detail, &format!("{part_path}.image_url.detail"))?
                                != "auto"
                            {
                                return Err(reject(
                                    &format!("{part_path}.image_url.detail"),
                                    "Gemini has no image-detail counterpart",
                                ));
                            }
                        }
                        out.push(openai_image_url_to_gemini(required_string(
                            image,
                            "url",
                            &format!("{part_path}.image_url"),
                        )?));
                    }
                    other => {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            format!("unsupported content type `{other}`"),
                        ))
                    }
                }
            }
            Ok(out)
        }
        _ => Err(reject(path, "must be a string or JSON array")),
    }
}

fn openai_image_url_to_gemini(url: &str) -> Value {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((mime, data)) = rest.split_once(";base64,") {
            return json!({ "inlineData": { "mimeType": mime, "data": data } });
        }
    }
    json!({ "fileData": { "fileUri": url } })
}

fn gemini_tools_to_chat(value: &Value) -> Result<Value> {
    let groups = expect_array(value, "tools")?;
    let mut out = Vec::new();
    for (group_index, group) in groups.iter().enumerate() {
        let path = format!("tools[{group_index}]");
        let group = expect_object(group, &path)?;
        refuse_unknown_keys(group, &["functionDeclarations"], &path)?;
        let declarations = expect_array(
            group.get("functionDeclarations").ok_or_else(|| {
                reject(&format!("{path}.functionDeclarations"), "field is required")
            })?,
            &format!("{path}.functionDeclarations"),
        )?;
        for (index, function) in declarations.iter().enumerate() {
            let function_path = format!("{path}.functionDeclarations[{index}]");
            let function = expect_object(function, &function_path)?;
            refuse_unknown_keys(
                function,
                &["name", "description", "parameters"],
                &function_path,
            )?;
            let mut mapped = Map::new();
            mapped.insert(
                "name".into(),
                Value::String(required_string(function, "name", &function_path)?.into()),
            );
            mapped.insert(
                "description".into(),
                Value::String(required_string(function, "description", &function_path)?.into()),
            );
            if let Some(value) = function.get("parameters").filter(|value| !value.is_null()) {
                mapped.insert("parameters".into(), value.clone());
            }
            out.push(json!({ "type": "function", "function": mapped }));
        }
    }
    Ok(Value::Array(out))
}

fn chat_tools_to_gemini(value: &Value) -> Result<Value> {
    let tools = expect_array(value, "tools")?;
    let mut declarations = Vec::new();
    for (index, tool) in tools.iter().enumerate() {
        let path = format!("tools[{index}]");
        let tool = expect_object(tool, &path)?;
        refuse_unknown_keys(tool, &["type", "function"], &path)?;
        if tool.get("type").and_then(Value::as_str) != Some("function") {
            return Err(reject(
                &format!("{path}.type"),
                "only function tools are supported",
            ));
        }
        let function = expect_object(
            tool.get("function")
                .ok_or_else(|| reject(&format!("{path}.function"), "field is required"))?,
            &format!("{path}.function"),
        )?;
        refuse_unknown_keys(
            function,
            &["name", "description", "parameters", "strict"],
            &format!("{path}.function"),
        )?;
        if function.get("strict").is_some_and(|value| !value.is_null()) {
            return Err(reject(
                &format!("{path}.function.strict"),
                "Gemini has no strict-schema counterpart",
            ));
        }
        let mut mapped = Map::new();
        mapped.insert(
            "name".into(),
            Value::String(required_string(function, "name", &format!("{path}.function"))?.into()),
        );
        mapped.insert(
            "description".into(),
            Value::String(
                expect_string(
                    function.get("description").ok_or_else(|| {
                        reject(
                            &format!("{path}.function.description"),
                            "required by Gemini FunctionDeclaration",
                        )
                    })?,
                    &format!("{path}.function.description"),
                )?
                .into(),
            ),
        );
        if let Some(value) = function.get("parameters").filter(|value| !value.is_null()) {
            mapped.insert("parameters".into(), value.clone());
        }
        declarations.push(Value::Object(mapped));
    }
    Ok(json!([{ "functionDeclarations": declarations }]))
}

fn gemini_tool_choice_to_chat(value: &Value) -> Result<Value> {
    let obj = expect_object(value, "toolConfig")?;
    refuse_unknown_keys(obj, &["functionCallingConfig"], "toolConfig")?;
    let config = expect_object(
        obj.get("functionCallingConfig")
            .ok_or_else(|| reject("toolConfig.functionCallingConfig", "field is required"))?,
        "toolConfig.functionCallingConfig",
    )?;
    refuse_unknown_keys(
        config,
        &["mode", "allowedFunctionNames"],
        "toolConfig.functionCallingConfig",
    )?;
    let mode = required_string(config, "mode", "toolConfig.functionCallingConfig")?;
    let allowed = config.get("allowedFunctionNames");
    match (mode, allowed) {
        ("AUTO", None) => Ok(Value::String("auto".into())),
        ("ANY", None) => Ok(Value::String("required".into())),
        ("NONE", None) => Ok(Value::String("none".into())),
        ("ANY", Some(Value::Array(names))) if names.len() == 1 => Ok(json!({
            "type": "function",
            "function": { "name": expect_string(&names[0], "toolConfig.functionCallingConfig.allowedFunctionNames[0]")? },
        })),
        (_, Some(_)) => Err(reject(
            "toolConfig.functionCallingConfig.allowedFunctionNames",
            "only one required function can be mapped",
        )),
        (other, None) => Err(reject(
            "toolConfig.functionCallingConfig.mode",
            format!("unsupported value `{other}`"),
        )),
    }
}

fn chat_tool_choice_to_gemini(value: &Value) -> Result<Value> {
    let config = match value {
        Value::String(value) => match value.as_str() {
            "auto" => json!({ "mode": "AUTO" }),
            "required" => json!({ "mode": "ANY" }),
            "none" => json!({ "mode": "NONE" }),
            other => {
                return Err(reject(
                    "tool_choice",
                    format!("unsupported value `{other}`"),
                ))
            }
        },
        Value::Object(obj) => {
            refuse_unknown_keys(obj, &["type", "function"], "tool_choice")?;
            if obj.get("type").and_then(Value::as_str) != Some("function") {
                return Err(reject(
                    "tool_choice.type",
                    "only function tool choice is supported",
                ));
            }
            let function = expect_object(
                obj.get("function")
                    .ok_or_else(|| reject("tool_choice.function", "field is required"))?,
                "tool_choice.function",
            )?;
            refuse_unknown_keys(function, &["name"], "tool_choice.function")?;
            json!({ "mode": "ANY", "allowedFunctionNames": [required_string(function, "name", "tool_choice.function")?] })
        }
        _ => return Err(reject("tool_choice", "must be a string or JSON object")),
    };
    Ok(json!({ "functionCallingConfig": config }))
}

/// Translate an image-generation request. Anthropic intentionally has no
/// image-generation endpoint and is always an explicit error.
pub fn translate_image_request(
    from: WireFormat,
    to: WireFormat,
    context: TranslationContext<'_>,
    body: &[u8],
) -> Result<TranslatedRequest> {
    if context.source_stream {
        return Err(reject(
            "stream",
            "image generation is not stream translated",
        ));
    }
    if matches!(from, WireFormat::AnthropicMessages) || matches!(to, WireFormat::AnthropicMessages)
    {
        return Err(reject(
            "image_generation",
            "Anthropic Messages has no image-generation endpoint",
        ));
    }
    if from == to {
        let mut root = parse_object(body)?;
        let output = if let Some(target_model) = context.target_model {
            if to != WireFormat::GeminiGenerateContent {
                root.insert("model".into(), Value::String(target_model.into()));
            }
            serde_json::to_vec(&Value::Object(root))?
        } else {
            body.to_vec()
        };
        return Ok(TranslatedRequest {
            body: output,
            target_model: (to == WireFormat::GeminiGenerateContent)
                .then(|| {
                    context
                        .target_model
                        .or(context.source_model)
                        .map(str::to_owned)
                })
                .flatten(),
            stream: false,
        });
    }
    match (from, to) {
        (WireFormat::OpenAiImagesGenerations, WireFormat::GeminiGenerateContent) => {
            openai_image_to_gemini(context.target_model, body)
        }
        (WireFormat::GeminiGenerateContent, WireFormat::OpenAiImagesGenerations) => {
            gemini_image_to_openai(context.source_model, context.target_model, body)
        }
        _ => Err(reject(
            "image_generation",
            "target dialect has no image-generation endpoint",
        )),
    }
}

fn openai_image_to_gemini(target_model: Option<&str>, body: &[u8]) -> Result<TranslatedRequest> {
    let root = parse_object(body)?;
    refuse_unknown_keys(&root, &["model", "prompt", "size", "quality", "n"], "$")?;
    let model = match target_model {
        Some(model) => model.to_owned(),
        None => required_string(&root, "model", "$")?.to_string(),
    };
    let prompt = required_string(&root, "prompt", "$")?;
    if let Some(n) = root.get("n").filter(|value| !value.is_null()) {
        if !is_number_one(n) {
            return Err(reject("n", "Gemini image generation returns one image"));
        }
    }
    if root.get("quality").is_some_and(|value| !value.is_null()) {
        return Err(reject(
            "quality",
            "Gemini has no exact image-quality counterpart",
        ));
    }
    let mut generation = json!({ "responseModalities": ["IMAGE"] });
    if let Some(size) = root.get("size").filter(|value| !value.is_null()) {
        let ratio = match expect_string(size, "size")? {
            "1024x1024" => "1:1",
            "1536x1024" => "3:2",
            "1024x1536" => "2:3",
            other => {
                return Err(reject(
                    "size",
                    format!("no exact Gemini aspect ratio for `{other}`"),
                ))
            }
        };
        generation["imageConfig"] = json!({ "aspectRatio": ratio });
    }
    Ok(TranslatedRequest {
        body: serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [{ "text": prompt }] }],
            "generationConfig": generation,
        }))?,
        target_model: Some(model),
        stream: false,
    })
}

fn gemini_image_to_openai(
    source_model: Option<&str>,
    target_model: Option<&str>,
    body: &[u8],
) -> Result<TranslatedRequest> {
    let root = parse_object(body)?;
    refuse_unknown_keys(&root, &["contents", "generationConfig"], "$")?;
    let model = target_model
        .or(source_model)
        .ok_or_else(|| reject("source_model", "Gemini model must come from the URL"))?;
    let contents = expect_array(
        root.get("contents")
            .ok_or_else(|| reject("contents", "field is required"))?,
        "contents",
    )?;
    if contents.len() != 1 {
        return Err(reject(
            "contents",
            "OpenAI image generation accepts one prompt",
        ));
    }
    let content = expect_object(&contents[0], "contents[0]")?;
    refuse_unknown_keys(content, &["role", "parts"], "contents[0]")?;
    let parts = expect_array(
        content
            .get("parts")
            .ok_or_else(|| reject("contents[0].parts", "field is required"))?,
        "contents[0].parts",
    )?;
    if parts.len() != 1 {
        return Err(reject(
            "contents[0].parts",
            "OpenAI image generation accepts one text prompt",
        ));
    }
    let prompt = expect_object(&parts[0], "contents[0].parts[0]")?;
    refuse_unknown_keys(prompt, &["text"], "contents[0].parts[0]")?;
    let mut out = json!({
        "model": model,
        "prompt": required_string(prompt, "text", "contents[0].parts[0]")?,
    });
    if let Some(config) = root
        .get("generationConfig")
        .filter(|value| !value.is_null())
    {
        let config = expect_object(config, "generationConfig")?;
        refuse_unknown_keys(
            config,
            &["responseModalities", "imageConfig"],
            "generationConfig",
        )?;
        if let Some(modalities) = config.get("responseModalities") {
            if modalities != &json!(["IMAGE"]) {
                return Err(reject(
                    "generationConfig.responseModalities",
                    "must be exactly [`IMAGE`]",
                ));
            }
        }
        if let Some(image) = config.get("imageConfig") {
            let image = expect_object(image, "generationConfig.imageConfig")?;
            refuse_unknown_keys(
                image,
                &["aspectRatio", "imageSize"],
                "generationConfig.imageConfig",
            )?;
            if image.get("imageSize").is_some_and(|value| !value.is_null()) {
                return Err(reject(
                    "generationConfig.imageConfig.imageSize",
                    "OpenAI has no exact image-size tier counterpart",
                ));
            }
            if let Some(ratio) = image.get("aspectRatio") {
                out["size"] = Value::String(
                    match expect_string(ratio, "generationConfig.imageConfig.aspectRatio")? {
                        "1:1" => "1024x1024",
                        "3:2" => "1536x1024",
                        "2:3" => "1024x1536",
                        other => {
                            return Err(reject(
                                "generationConfig.imageConfig.aspectRatio",
                                format!("no exact OpenAI size for `{other}`"),
                            ))
                        }
                    }
                    .into(),
                );
            }
        }
    }
    Ok(TranslatedRequest {
        body: serde_json::to_vec(&out)?,
        target_model: None,
        stream: false,
    })
}

fn required_string<'a>(obj: &'a Map<String, Value>, field: &str, path: &str) -> Result<&'a str> {
    expect_string(
        obj.get(field)
            .ok_or_else(|| reject(&format!("{path}.{field}"), "field is required"))?,
        &format!("{path}.{field}"),
    )
}

fn copy_number(
    from: &Map<String, Value>,
    to: &mut Map<String, Value>,
    from_field: &str,
    to_field: &str,
) -> Result<()> {
    if let Some(value) = from.get(from_field).filter(|value| !value.is_null()) {
        expect_number(value, from_field)?;
        to.insert(to_field.into(), value.clone());
    }
    Ok(())
}

fn reconcile_max_tokens(root: &Map<String, Value>) -> Result<Option<Value>> {
    let old = root.get("max_tokens").filter(|value| !value.is_null());
    let new = root
        .get("max_completion_tokens")
        .filter(|value| !value.is_null());
    for (name, value) in [("max_tokens", old), ("max_completion_tokens", new)] {
        if let Some(value) = value {
            expect_number(value, name)?;
        }
    }
    if old.is_some() && new.is_some() && old != new {
        return Err(reject("max_completion_tokens", "conflicts with max_tokens"));
    }
    Ok(new.or(old).cloned())
}

fn validate_string_array(value: &Value, path: &str) -> Result<()> {
    for (index, item) in expect_array(value, path)?.iter().enumerate() {
        expect_string(item, &format!("{path}[{index}]"))?;
    }
    Ok(())
}

fn collapse_text_parts(parts: Vec<Value>) -> Value {
    if parts.len() == 1 && parts[0]["type"] == "text" {
        parts[0]["text"].clone()
    } else {
        Value::Array(parts)
    }
}

fn validate_object(body: &[u8]) -> Result<Vec<u8>> {
    parse_object(body)?;
    Ok(body.to_vec())
}

// Response conversion is kept below the request helpers so both directions
// reuse the same content/tool primitives.
pub fn translate_response(from: WireFormat, to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
    if from == WireFormat::OpenAiImagesGenerations || to == WireFormat::OpenAiImagesGenerations {
        return translate_image_response(from, to, body);
    }
    if from == to {
        let _: Value = serde_json::from_slice(body)?;
        return Ok(body.to_vec());
    }
    let chat = response_to_chat(from, body)?;
    response_from_chat(to, &chat)
}

/// Translate exact base64 image response payloads without decoding image data.
pub fn translate_image_response(from: WireFormat, to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
    if from == to {
        let _: Value = serde_json::from_slice(body)?;
        return Ok(body.to_vec());
    }
    match (from, to) {
        (WireFormat::OpenAiImagesGenerations, WireFormat::GeminiGenerateContent) => {
            let root = parse_object(body)?;
            refuse_unknown_keys(
                &root,
                &[
                    "created",
                    "background",
                    "data",
                    "output_format",
                    "quality",
                    "size",
                    "usage",
                ],
                "$",
            )?;
            if let Some(created) = root.get("created") {
                created
                    .as_u64()
                    .ok_or_else(|| reject("created", "must be a Unix timestamp"))?;
            }
            let mime = match root
                .get("output_format")
                .and_then(Value::as_str)
                .unwrap_or("png")
            {
                "png" => "image/png",
                "jpeg" => "image/jpeg",
                "webp" => "image/webp",
                other => {
                    return Err(reject(
                        "output_format",
                        format!("unsupported image format `{other}`"),
                    ));
                }
            };
            // These are response echoes of request controls. Gemini already
            // received the corresponding request controls, so retaining them
            // in the response would add invalid target fields.
            for field in ["background", "quality", "size"] {
                if let Some(value) = root.get(field).filter(|value| !value.is_null()) {
                    expect_string(value, field)?;
                }
            }
            let images = expect_array(
                root.get("data")
                    .ok_or_else(|| reject("data", "field is required"))?,
                "data",
            )?;
            let mut parts = Vec::new();
            for (index, image) in images.iter().enumerate() {
                let path = format!("data[{index}]");
                let image = expect_object(image, &path)?;
                refuse_unknown_keys(image, &["b64_json"], &path)?;
                parts.push(json!({
                    "inlineData": {
                        "mimeType": mime,
                        "data": required_string(image, "b64_json", &path)?,
                    }
                }));
            }
            let mut out = json!({
                "candidates": [{ "content": { "role": "model", "parts": parts } }]
            });
            if let Some(usage) = root.get("usage") {
                let usage = expect_object(usage, "usage")?;
                refuse_unknown_keys(
                    usage,
                    &[
                        "input_tokens",
                        "output_tokens",
                        "total_tokens",
                        "input_tokens_details",
                        "output_tokens_details",
                    ],
                    "usage",
                )?;
                for field in ["input_tokens_details", "output_tokens_details"] {
                    if let Some(details) = usage.get(field).filter(|value| !value.is_null()) {
                        if !expect_object(details, &format!("usage.{field}"))?.is_empty() {
                            return Err(reject(
                                &format!("usage.{field}"),
                                "Gemini image usage has no token-detail counterpart",
                            ));
                        }
                    }
                }
                let (input, output, total) = usage_counts(
                    usage,
                    "input_tokens",
                    "output_tokens",
                    Some("total_tokens"),
                    "usage",
                )?;
                out["usageMetadata"] = json!({
                    "promptTokenCount": input,
                    "candidatesTokenCount": output,
                    "totalTokenCount": total,
                });
            }
            Ok(serde_json::to_vec(&out)?)
        }
        (WireFormat::GeminiGenerateContent, WireFormat::OpenAiImagesGenerations) => {
            let root = parse_object(body)?;
            refuse_unknown_keys(
                &root,
                &[
                    "candidates",
                    "responseId",
                    "modelVersion",
                    "usageMetadata",
                    "promptFeedback",
                ],
                "$",
            )?;
            if root
                .get("promptFeedback")
                .is_some_and(|value| !value.is_null())
            {
                return Err(reject(
                    "promptFeedback",
                    "OpenAI Images has no prompt-feedback counterpart",
                ));
            }
            let candidates = expect_array(
                root.get("candidates")
                    .ok_or_else(|| reject("candidates", "field is required"))?,
                "candidates",
            )?;
            if candidates.len() != 1 {
                return Err(reject("candidates", "exactly one candidate is required"));
            }
            let candidate = expect_object(&candidates[0], "candidates[0]")?;
            refuse_unknown_keys(
                candidate,
                &["index", "content", "finishReason", "safetyRatings"],
                "candidates[0]",
            )?;
            if candidate
                .get("index")
                .is_some_and(|value| value.as_u64().is_none())
            {
                return Err(reject(
                    "candidates[0].index",
                    "must be a non-negative integer",
                ));
            }
            if let Some(reason) = candidate
                .get("finishReason")
                .filter(|value| !value.is_null())
            {
                let reason = expect_string(reason, "candidates[0].finishReason")?;
                if reason != "STOP" {
                    return Err(reject(
                        "candidates[0].finishReason",
                        format!("cannot map image candidate finished with `{reason}`"),
                    ));
                }
            }
            if let Some(ratings) = candidate
                .get("safetyRatings")
                .filter(|value| !value.is_null())
            {
                validate_gemini_safety_ratings(ratings, "candidates[0].safetyRatings")?;
            }
            let content = expect_object(
                candidate
                    .get("content")
                    .ok_or_else(|| reject("candidates[0].content", "field is required"))?,
                "candidates[0].content",
            )?;
            refuse_unknown_keys(content, &["role", "parts"], "candidates[0].content")?;
            let mut data = Vec::new();
            let mut output_format: Option<&'static str> = None;
            for (index, part) in expect_array(
                content
                    .get("parts")
                    .ok_or_else(|| reject("candidates[0].content.parts", "field is required"))?,
                "candidates[0].content.parts",
            )?
            .iter()
            .enumerate()
            {
                let path = format!("candidates[0].content.parts[{index}]");
                let part = expect_object(part, &path)?;
                refuse_unknown_keys(part, &["inlineData"], &path)?;
                let image = expect_object(
                    part.get("inlineData").ok_or_else(|| {
                        reject(&format!("{path}.inlineData"), "field is required")
                    })?,
                    &format!("{path}.inlineData"),
                )?;
                refuse_unknown_keys(image, &["mimeType", "data"], &format!("{path}.inlineData"))?;
                let mime = required_string(image, "mimeType", &format!("{path}.inlineData"))?;
                let format = match mime {
                    "image/png" => "png",
                    "image/jpeg" => "jpeg",
                    "image/webp" => "webp",
                    _ => {
                        return Err(reject(
                            &format!("{path}.inlineData.mimeType"),
                            "OpenAI image output supports PNG, JPEG, or WebP",
                        ));
                    }
                };
                if output_format.is_some_and(|existing| existing != format) {
                    return Err(reject(
                        &format!("{path}.inlineData.mimeType"),
                        "OpenAI ImagesResponse has one output_format for all images",
                    ));
                }
                output_format = Some(format);
                data.push(json!({
                    "b64_json": required_string(image, "data", &format!("{path}.inlineData"))?
                }));
            }
            let mut out = json!({ "created": 0, "data": data });
            if let Some(output_format) = output_format {
                out["output_format"] = Value::String(output_format.into());
            }
            if let Some(usage) = root.get("usageMetadata") {
                let usage = expect_object(usage, "usageMetadata")?;
                refuse_unknown_keys(
                    usage,
                    &[
                        "promptTokenCount",
                        "candidatesTokenCount",
                        "totalTokenCount",
                    ],
                    "usageMetadata",
                )?;
                let (input, output, total) = usage_counts(
                    usage,
                    "promptTokenCount",
                    "candidatesTokenCount",
                    Some("totalTokenCount"),
                    "usageMetadata",
                )?;
                out["usage"] = json!({
                    "input_tokens": input,
                    "output_tokens": output,
                    "total_tokens": total,
                });
            }
            Ok(serde_json::to_vec(&out)?)
        }
        (_, WireFormat::AnthropicMessages) | (WireFormat::AnthropicMessages, _) => Err(reject(
            "image_generation",
            "Anthropic Messages has no image-generation response",
        )),
        _ => Err(reject(
            "image_generation",
            "target dialect has no image-generation response",
        )),
    }
}

pub(super) fn validate_gemini_safety_ratings(value: &Value, path: &str) -> Result<()> {
    for (index, rating) in expect_array(value, path)?.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let rating = expect_object(rating, &item_path)?;
        refuse_unknown_keys(
            rating,
            &[
                "category",
                "probability",
                "blocked",
                "probabilityScore",
                "severity",
                "severityScore",
                "overwrittenThreshold",
            ],
            &item_path,
        )?;
        required_string(rating, "category", &item_path)?;
        required_string(rating, "probability", &item_path)?;
        if let Some(blocked) = rating.get("blocked").filter(|value| !value.is_null()) {
            let blocked = blocked
                .as_bool()
                .ok_or_else(|| reject(&format!("{item_path}.blocked"), "must be a boolean"))?;
            if blocked {
                return Err(reject(
                    &format!("{item_path}.blocked"),
                    "the target dialect has no blocked-candidate counterpart",
                ));
            }
        }
        for field in ["probabilityScore", "severityScore"] {
            if let Some(score) = rating.get(field).filter(|value| !value.is_null()) {
                expect_number(score, &format!("{item_path}.{field}"))?;
            }
        }
        for field in ["severity", "overwrittenThreshold"] {
            if let Some(value) = rating.get(field).filter(|value| !value.is_null()) {
                expect_string(value, &format!("{item_path}.{field}"))?;
            }
        }
    }
    Ok(())
}

fn usage_counts(
    usage: &Map<String, Value>,
    input_field: &str,
    output_field: &str,
    total_field: Option<&str>,
    path: &str,
) -> Result<(u64, u64, u64)> {
    let read = |field: &str| -> Result<u64> {
        match usage.get(field).filter(|value| !value.is_null()) {
            None => Ok(0),
            Some(value) => value.as_u64().ok_or_else(|| {
                reject(&format!("{path}.{field}"), "must be a non-negative integer")
            }),
        }
    };
    let input = read(input_field)?;
    let output = read(output_field)?;
    let sum = input.checked_add(output).ok_or_else(|| {
        reject(
            &format!("{path}.{}", total_field.unwrap_or("total_tokens")),
            "input and output token counts overflow",
        )
    })?;
    let total = match total_field.and_then(|field| usage.get(field)) {
        None | Some(Value::Null) => sum,
        Some(value) => {
            let total = value.as_u64().ok_or_else(|| {
                reject(
                    &format!("{path}.{}", total_field.expect("present total field")),
                    "must be a non-negative integer",
                )
            })?;
            if total != sum {
                return Err(reject(
                    &format!("{path}.{}", total_field.expect("present total field")),
                    "must equal input tokens plus output tokens",
                ));
            }
            total
        }
    };
    Ok((input, output, total))
}

fn usage_count(usage: &Map<String, Value>, field: &str, path: &str) -> Result<u64> {
    usage
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| reject(&format!("{path}.{field}"), "must be a non-negative integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn checked_sum(parts: &[u64], path: &str) -> Result<u64> {
    parts.iter().try_fold(0_u64, |total, part| {
        total
            .checked_add(*part)
            .ok_or_else(|| reject(path, "token counts overflow"))
    })
}

fn gemini_usage_counts(
    usage: &Map<String, Value>,
    path: &str,
) -> Result<(u64, u64, u64, u64, u64)> {
    refuse_unknown_keys(
        usage,
        &[
            "promptTokenCount",
            "cachedContentTokenCount",
            "toolUsePromptTokenCount",
            "candidatesTokenCount",
            "thoughtsTokenCount",
            "totalTokenCount",
        ],
        path,
    )?;
    let prompt = usage_count(usage, "promptTokenCount", path)?;
    let cached = usage_count(usage, "cachedContentTokenCount", path)?;
    let tool = usage_count(usage, "toolUsePromptTokenCount", path)?;
    let candidates = usage_count(usage, "candidatesTokenCount", path)?;
    let reasoning = usage_count(usage, "thoughtsTokenCount", path)?;
    if cached > prompt {
        return Err(reject(
            &format!("{path}.cachedContentTokenCount"),
            "must not exceed promptTokenCount",
        ));
    }
    if tool != 0 {
        return Err(reject(
            &format!("{path}.toolUsePromptTokenCount"),
            "nonzero tool-use prompt diagnostics have no target counterpart",
        ));
    }
    let input = prompt;
    let output = checked_sum(&[candidates, reasoning], &format!("{path}.totalTokenCount"))?;
    let total = checked_sum(&[input, output], &format!("{path}.totalTokenCount"))?;
    if let Some(declared) = usage
        .get("totalTokenCount")
        .filter(|value| !value.is_null())
    {
        let declared = declared.as_u64().ok_or_else(|| {
            reject(
                &format!("{path}.totalTokenCount"),
                "must be a non-negative integer",
            )
        })?;
        if declared != total {
            return Err(reject(
                &format!("{path}.totalTokenCount"),
                "must equal all present input and output token buckets",
            ));
        }
    }
    Ok((input, output, total, cached, reasoning))
}

fn chat_usage_counts(usage: &Map<String, Value>, path: &str) -> Result<(u64, u64, u64, u64, u64)> {
    refuse_unknown_keys(
        usage,
        &[
            "prompt_tokens",
            "prompt_tokens_details",
            "completion_tokens",
            "completion_tokens_details",
            "total_tokens",
        ],
        path,
    )?;
    let (input, output, total) = usage_counts(
        usage,
        "prompt_tokens",
        "completion_tokens",
        Some("total_tokens"),
        path,
    )?;
    let cached = chat_usage_detail(
        usage,
        "prompt_tokens_details",
        "cached_tokens",
        &["cached_tokens"],
        path,
    )?;
    let reasoning = chat_usage_detail(
        usage,
        "completion_tokens_details",
        "reasoning_tokens",
        &["reasoning_tokens"],
        path,
    )?;
    if cached > input {
        return Err(reject(
            &format!("{path}.prompt_tokens_details.cached_tokens"),
            "must not exceed prompt_tokens",
        ));
    }
    if reasoning > output {
        return Err(reject(
            &format!("{path}.completion_tokens_details.reasoning_tokens"),
            "must not exceed completion_tokens",
        ));
    }
    Ok((input, output, total, cached, reasoning))
}

fn chat_usage_detail(
    usage: &Map<String, Value>,
    object_field: &str,
    count_field: &str,
    allowed: &[&str],
    path: &str,
) -> Result<u64> {
    let Some(details) = usage.get(object_field).filter(|value| !value.is_null()) else {
        return Ok(0);
    };
    let details = expect_object(details, &format!("{path}.{object_field}"))?;
    refuse_unknown_keys(details, allowed, &format!("{path}.{object_field}"))?;
    usage_count(details, count_field, &format!("{path}.{object_field}"))
}

fn responses_usage_details(usage: &Map<String, Value>, path: &str) -> Result<(u64, u64)> {
    let cached = if let Some(details) = usage
        .get("input_tokens_details")
        .filter(|value| !value.is_null())
    {
        let details = expect_object(details, &format!("{path}.input_tokens_details"))?;
        refuse_unknown_keys(
            details,
            &["cached_tokens", "cache_write_tokens"],
            &format!("{path}.input_tokens_details"),
        )?;
        if usage_count(
            details,
            "cache_write_tokens",
            &format!("{path}.input_tokens_details"),
        )? != 0
        {
            return Err(reject(
                &format!("{path}.input_tokens_details.cache_write_tokens"),
                "Chat Completions has no cache-write token counterpart",
            ));
        }
        usage_count(
            details,
            "cached_tokens",
            &format!("{path}.input_tokens_details"),
        )?
    } else {
        0
    };
    let reasoning = if let Some(details) = usage
        .get("output_tokens_details")
        .filter(|value| !value.is_null())
    {
        let details = expect_object(details, &format!("{path}.output_tokens_details"))?;
        refuse_unknown_keys(
            details,
            &["reasoning_tokens"],
            &format!("{path}.output_tokens_details"),
        )?;
        usage_count(
            details,
            "reasoning_tokens",
            &format!("{path}.output_tokens_details"),
        )?
    } else {
        0
    };
    Ok((cached, reasoning))
}

fn semantically_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.is_empty(),
        Value::Array(values) => values.iter().all(semantically_empty),
        Value::Object(values) => values.values().all(semantically_empty),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

fn response_to_chat(from: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
    match from {
        WireFormat::OpenAiChatCompletions => validate_object(body),
        WireFormat::OpenAiResponses => responses_response_to_chat(body),
        WireFormat::AnthropicMessages => anthropic_response_to_chat(body),
        WireFormat::GeminiGenerateContent => gemini_response_to_chat(body),
        WireFormat::OpenAiImagesGenerations => {
            Err(reject("endpoint", "image responses are not chat responses"))
        }
    }
}

fn response_from_chat(to: WireFormat, body: &[u8]) -> Result<Vec<u8>> {
    match to {
        WireFormat::OpenAiChatCompletions => Ok(body.to_vec()),
        WireFormat::OpenAiResponses => chat_response_to_responses(body),
        WireFormat::AnthropicMessages => chat_response_to_anthropic(body),
        WireFormat::GeminiGenerateContent => chat_response_to_gemini(body),
        WireFormat::OpenAiImagesGenerations => {
            Err(reject("endpoint", "chat responses are not image responses"))
        }
    }
}

fn anthropic_response_to_chat(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "id",
            "type",
            "role",
            "model",
            "content",
            "stop_reason",
            "stop_sequence",
            "usage",
        ],
        "$",
    )?;
    if root.get("type").and_then(Value::as_str) != Some("message") {
        return Err(reject("type", "must be `message`"));
    }
    if root.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err(reject("role", "must be `assistant`"));
    }
    let content = expect_array(
        root.get("content")
            .ok_or_else(|| reject("content", "field is required"))?,
        "content",
    )?;
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for (index, part) in content.iter().enumerate() {
        let path = format!("content[{index}]");
        let part = expect_object(part, &path)?;
        match required_string(part, "type", &path)? {
            "text" => {
                refuse_unknown_keys(part, &["type", "text"], &path)?;
                text.push_str(required_string(part, "text", &path)?);
            }
            "tool_use" => {
                refuse_unknown_keys(part, &["type", "id", "name", "input"], &path)?;
                let input = part
                    .get("input")
                    .ok_or_else(|| reject(&format!("{path}.input"), "field is required"))?;
                expect_object(input, &format!("{path}.input"))?;
                tool_calls.push(json!({
                    "id": required_string(part, "id", &path)?,
                    "type": "function",
                    "function": { "name": required_string(part, "name", &path)?, "arguments": serde_json::to_string(input)? },
                }));
            }
            other => {
                return Err(reject(
                    &format!("{path}.type"),
                    format!("no Chat Completions counterpart for `{other}`"),
                ))
            }
        }
    }
    let mut message = json!({ "role": "assistant", "content": text });
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
        if text.is_empty() {
            message["content"] = Value::Null;
        }
    }
    let finish = match root.get("stop_reason").and_then(Value::as_str) {
        None | Some("end_turn") | Some("stop_sequence") => "stop",
        Some("tool_use") => "tool_calls",
        Some("max_tokens") => "length",
        Some(other) => {
            return Err(reject(
                "stop_reason",
                format!("unsupported value `{other}`"),
            ))
        }
    };
    let mut out = json!({
        "id": required_string(&root, "id", "$")?,
        "object": "chat.completion",
        "created": 0,
        "model": required_string(&root, "model", "$")?,
        "choices": [{ "index": 0, "message": message, "finish_reason": finish }],
    });
    if let Some(usage) = root.get("usage") {
        let usage = expect_object(usage, "usage")?;
        refuse_unknown_keys(
            usage,
            &[
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
                "server_tool_use",
            ],
            "usage",
        )?;
        if let Some(server_tools) = usage
            .get("server_tool_use")
            .filter(|value| !value.is_null())
        {
            for (field, value) in expect_object(server_tools, "usage.server_tool_use")? {
                if value.as_u64() != Some(0) {
                    return Err(reject(
                        &format!("usage.server_tool_use.{field}"),
                        "nonzero server-tool usage has no Chat Completions counterpart",
                    ));
                }
            }
        }
        let base_input = usage_count(usage, "input_tokens", "usage")?;
        let cache_creation = usage_count(usage, "cache_creation_input_tokens", "usage")?;
        let cache_read = usage_count(usage, "cache_read_input_tokens", "usage")?;
        let input = checked_sum(
            &[base_input, cache_creation, cache_read],
            "usage.input_tokens",
        )?;
        let output = usage_count(usage, "output_tokens", "usage")?;
        let total = checked_sum(&[input, output], "usage.total_tokens")?;
        out["usage"] = json!({
            "prompt_tokens": input,
            "completion_tokens": output,
            "total_tokens": total,
        });
        if usage.contains_key("cache_creation_input_tokens")
            || usage.contains_key("cache_read_input_tokens")
        {
            out["usage"]["prompt_tokens_details"] = json!({ "cached_tokens": cache_read });
        }
    }
    Ok(serde_json::to_vec(&out)?)
}

fn chat_response_to_anthropic(body: &[u8]) -> Result<Vec<u8>> {
    let (root, choice, message) = parse_chat_response(body)?;
    let mut content = Vec::new();
    if let Some(text) = message
        .get("content")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        content.push(json!({ "type": "text", "text": text }));
    }
    if let Some(calls) = message.get("tool_calls") {
        for (index, call) in expect_array(calls, "choices[0].message.tool_calls")?
            .iter()
            .enumerate()
        {
            let path = format!("choices[0].message.tool_calls[{index}]");
            let call = expect_object(call, &path)?;
            let function = expect_object(
                call.get("function")
                    .ok_or_else(|| reject(&format!("{path}.function"), "field is required"))?,
                &format!("{path}.function"),
            )?;
            let arguments: Value = serde_json::from_str(required_string(
                function,
                "arguments",
                &format!("{path}.function"),
            )?)
            .map_err(|_| reject(&format!("{path}.function.arguments"), "must contain JSON"))?;
            expect_object(&arguments, &format!("{path}.function.arguments"))?;
            content.push(json!({ "type": "tool_use", "id": required_string(call, "id", &path)?, "name": required_string(function, "name", &format!("{path}.function"))?, "input": arguments }));
        }
    }
    let stop_reason = match choice.get("finish_reason").and_then(Value::as_str) {
        None | Some("stop") => "end_turn",
        Some("tool_calls") => "tool_use",
        Some("length") => "max_tokens",
        Some(other) => {
            return Err(reject(
                "choices[0].finish_reason",
                format!("unsupported value `{other}`"),
            ))
        }
    };
    let mut out = json!({
        "id": required_string(&root, "id", "$")?, "type": "message", "role": "assistant",
        "model": required_string(&root, "model", "$")?, "content": content,
        "stop_reason": stop_reason, "stop_sequence": null,
    });
    if let Some(usage) = root.get("usage") {
        let usage = expect_object(usage, "usage")?;
        let (input, output, _, cached, _) = chat_usage_counts(usage, "usage")?;
        out["usage"] = json!({
            "input_tokens": input,
            "output_tokens": output,
        });
        if usage.contains_key("prompt_tokens_details") {
            out["usage"]["input_tokens"] = json!(input - cached);
            out["usage"]["cache_creation_input_tokens"] = json!(0);
            out["usage"]["cache_read_input_tokens"] = json!(cached);
        }
    }
    Ok(serde_json::to_vec(&out)?)
}

/// Validate response-level request echoes that do not affect the already
/// generated output. Output-bearing capabilities remain explicit errors in
/// `responses_response_to_chat` rather than disappearing here.
fn validate_responses_response_metadata(root: &Map<String, Value>) -> Result<()> {
    if root.get("object").and_then(Value::as_str) != Some("response") {
        return Err(reject("object", "must be `response`"));
    }
    for field in ["created_at", "completed_at", "temperature", "top_p"] {
        if let Some(value) = root.get(field).filter(|value| !value.is_null()) {
            expect_number(value, field)?;
        }
    }
    for field in ["background", "parallel_tool_calls", "store"] {
        if root
            .get(field)
            .filter(|value| !value.is_null())
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(reject(field, "must be a boolean"));
        }
    }
    for field in ["max_output_tokens", "max_tool_calls"] {
        if root
            .get(field)
            .filter(|value| !value.is_null())
            .is_some_and(|value| value.as_u64().is_none())
        {
            return Err(reject(field, "must be a non-negative integer"));
        }
    }
    for field in [
        "previous_response_id",
        "prompt_cache_key",
        "safety_identifier",
        "service_tier",
        "truncation",
        "user",
    ] {
        if let Some(value) = root.get(field).filter(|value| !value.is_null()) {
            expect_string(value, field)?;
        }
    }
    if root.get("error").is_some_and(|value| !value.is_null()) {
        return Err(reject(
            "error",
            "failed Responses output has no Chat Completions counterpart",
        ));
    }
    if root.get("moderation").is_some_and(|value| !value.is_null()) {
        return Err(reject(
            "moderation",
            "Chat Completions cannot preserve response moderation results",
        ));
    }
    if let Some(details) = root
        .get("incomplete_details")
        .filter(|value| !value.is_null())
    {
        let details = expect_object(details, "incomplete_details")?;
        refuse_unknown_keys(details, &["reason"], "incomplete_details")?;
        required_string(details, "reason", "incomplete_details")?;
    }
    if let Some(instructions) = root.get("instructions").filter(|value| !value.is_null()) {
        expect_string(instructions, "instructions").map_err(|_| {
            reject(
                "instructions",
                "only string response instructions can be validated without losing input items",
            )
        })?;
    }
    if let Some(metadata) = root.get("metadata").filter(|value| !value.is_null()) {
        for (key, value) in expect_object(metadata, "metadata")? {
            expect_string(value, &format!("metadata.{key}"))?;
        }
    }
    if let Some(conversation) = root.get("conversation").filter(|value| !value.is_null()) {
        let conversation = expect_object(conversation, "conversation")?;
        refuse_unknown_keys(conversation, &["id"], "conversation")?;
        required_string(conversation, "id", "conversation")?;
    }
    if let Some(prompt) = root.get("prompt").filter(|value| !value.is_null()) {
        let prompt = expect_object(prompt, "prompt")?;
        refuse_unknown_keys(prompt, &["id", "variables", "version"], "prompt")?;
        required_string(prompt, "id", "prompt")?;
        if let Some(version) = prompt.get("version").filter(|value| !value.is_null()) {
            expect_string(version, "prompt.version")?;
        }
        if let Some(variables) = prompt.get("variables").filter(|value| !value.is_null()) {
            expect_object(variables, "prompt.variables")?;
        }
    }
    if let Some(options) = root
        .get("prompt_cache_options")
        .filter(|value| !value.is_null())
    {
        let options = expect_object(options, "prompt_cache_options")?;
        refuse_unknown_keys(options, &["mode", "ttl"], "prompt_cache_options")?;
        for field in ["mode", "ttl"] {
            if let Some(value) = options.get(field).filter(|value| !value.is_null()) {
                expect_string(value, &format!("prompt_cache_options.{field}"))?;
            }
        }
    }
    if let Some(retention) = root
        .get("prompt_cache_retention")
        .filter(|value| !value.is_null())
    {
        match expect_string(retention, "prompt_cache_retention")? {
            "in_memory" | "24h" => {}
            other => {
                return Err(reject(
                    "prompt_cache_retention",
                    format!("unsupported value `{other}`"),
                ));
            }
        }
    }
    if let Some(reasoning) = root.get("reasoning").filter(|value| !value.is_null()) {
        let reasoning = expect_object(reasoning, "reasoning")?;
        refuse_unknown_keys(
            reasoning,
            &["context", "effort", "generate_summary", "mode", "summary"],
            "reasoning",
        )?;
        for field in ["context", "effort", "generate_summary", "mode", "summary"] {
            if let Some(value) = reasoning.get(field).filter(|value| !value.is_null()) {
                expect_string(value, &format!("reasoning.{field}"))?;
            }
        }
    }
    if let Some(text) = root.get("text").filter(|value| !value.is_null()) {
        let text = expect_object(text, "text")?;
        refuse_unknown_keys(text, &["format", "verbosity"], "text")?;
        if let Some(format) = text.get("format").filter(|value| !value.is_null()) {
            let format = expect_object(format, "text.format")?;
            refuse_unknown_keys(format, &["type"], "text.format")?;
            if required_string(format, "type", "text.format")? != "text" {
                return Err(reject(
                    "text.format.type",
                    "structured Responses output cannot be represented as an ordinary chat response",
                ));
            }
        }
        if let Some(verbosity) = text.get("verbosity").filter(|value| !value.is_null()) {
            match expect_string(verbosity, "text.verbosity")? {
                "low" | "medium" | "high" => {}
                other => {
                    return Err(reject(
                        "text.verbosity",
                        format!("unsupported value `{other}`"),
                    ));
                }
            }
        }
    }
    if let Some(top_logprobs) = root.get("top_logprobs").filter(|value| !value.is_null()) {
        if top_logprobs.as_u64() != Some(0) {
            return Err(reject(
                "top_logprobs",
                "nonzero response log probabilities must not be dropped",
            ));
        }
    }
    if let Some(choice) = root.get("tool_choice").filter(|value| !value.is_null()) {
        responses_tool_choice_to_chat(choice)?;
    }
    if let Some(tools) = root.get("tools").filter(|value| !value.is_null()) {
        responses_tools_to_chat(tools)?;
    }
    Ok(())
}

fn responses_response_to_chat(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "background",
            "completed_at",
            "conversation",
            "id",
            "object",
            "created_at",
            "model",
            "status",
            "output",
            "output_text",
            "usage",
            "error",
            "incomplete_details",
            "instructions",
            "max_output_tokens",
            "max_tool_calls",
            "metadata",
            "moderation",
            "parallel_tool_calls",
            "previous_response_id",
            "prompt",
            "prompt_cache_key",
            "prompt_cache_options",
            "prompt_cache_retention",
            "reasoning",
            "safety_identifier",
            "service_tier",
            "store",
            "temperature",
            "text",
            "tool_choice",
            "tools",
            "top_logprobs",
            "top_p",
            "truncation",
            "user",
        ],
        "$",
    )?;
    validate_responses_response_metadata(&root)?;
    let output = expect_array(
        root.get("output")
            .ok_or_else(|| reject("output", "field is required"))?,
        "output",
    )?;
    let mut text = String::new();
    let mut calls = Vec::new();
    for (index, item) in output.iter().enumerate() {
        let path = format!("output[{index}]");
        let item = expect_object(item, &path)?;
        match required_string(item, "type", &path)? {
            "message" => {
                refuse_unknown_keys(item, &["type", "id", "role", "content", "status"], &path)?;
                if item
                    .get("role")
                    .is_some_and(|value| value.as_str() != Some("assistant"))
                {
                    return Err(reject(&format!("{path}.role"), "must be `assistant`"));
                }
                if item
                    .get("status")
                    .is_some_and(|value| value.as_str() != Some("completed"))
                {
                    return Err(reject(
                        &format!("{path}.status"),
                        "only completed output messages can be mapped",
                    ));
                }
                if let Some(id) = item.get("id").filter(|value| !value.is_null()) {
                    expect_string(id, &format!("{path}.id"))?;
                }
                for (part_index, part) in expect_array(
                    item.get("content")
                        .ok_or_else(|| reject(&format!("{path}.content"), "field is required"))?,
                    &format!("{path}.content"),
                )?
                .iter()
                .enumerate()
                {
                    let part_path = format!("{path}.content[{part_index}]");
                    let part = expect_object(part, &part_path)?;
                    refuse_unknown_keys(
                        part,
                        &["type", "text", "annotations", "logprobs"],
                        &part_path,
                    )?;
                    if required_string(part, "type", &part_path)? != "output_text" {
                        return Err(reject(
                            &format!("{part_path}.type"),
                            "only output_text can be mapped",
                        ));
                    }
                    for field in ["annotations", "logprobs"] {
                        if let Some(items) = part.get(field).filter(|value| !value.is_null()) {
                            if !expect_array(items, &format!("{part_path}.{field}"))?.is_empty() {
                                return Err(reject(
                                    &format!("{part_path}.{field}"),
                                    "Chat Completions cannot preserve this output metadata",
                                ));
                            }
                        }
                    }
                    text.push_str(required_string(part, "text", &part_path)?);
                }
            }
            "function_call" => {
                refuse_unknown_keys(
                    item,
                    &["type", "id", "call_id", "name", "arguments", "status"],
                    &path,
                )?;
                calls.push(json!({ "id": required_string(item, "call_id", &path)?, "type": "function", "function": { "name": required_string(item, "name", &path)?, "arguments": required_string(item, "arguments", &path)? } }));
            }
            other => {
                return Err(reject(
                    &format!("{path}.type"),
                    format!("no Chat Completions counterpart for `{other}`"),
                ))
            }
        }
    }
    let mut message = json!({ "role": "assistant", "content": text });
    let has_calls = !calls.is_empty();
    if has_calls {
        message["tool_calls"] = Value::Array(calls);
        if text.is_empty() {
            message["content"] = Value::Null;
        }
    }
    if let Some(output_text) = root.get("output_text").filter(|value| !value.is_null()) {
        let output_text = expect_string(output_text, "output_text")?;
        if output_text != text {
            return Err(reject(
                "output_text",
                "must equal the concatenated output_text content",
            ));
        }
    }
    let finish = match required_string(&root, "status", "$")? {
        "completed" => {
            if has_calls {
                "tool_calls"
            } else {
                "stop"
            }
        }
        "incomplete"
            if root
                .get("incomplete_details")
                .and_then(Value::as_object)
                .and_then(|details| details.get("reason"))
                .and_then(Value::as_str)
                == Some("max_output_tokens") =>
        {
            "length"
        }
        other => {
            return Err(reject(
                "status",
                format!("cannot map Responses status `{other}`"),
            ));
        }
    };
    let mut out = json!({ "id": required_string(&root, "id", "$")?, "object": "chat.completion", "created": root.get("created_at").cloned().unwrap_or_else(|| json!(0)), "model": required_string(&root, "model", "$")?, "choices": [{ "index": 0, "message": message, "finish_reason": finish }] });
    if let Some(usage) = root.get("usage") {
        let usage = expect_object(usage, "usage")?;
        refuse_unknown_keys(
            usage,
            &[
                "input_tokens",
                "input_tokens_details",
                "output_tokens",
                "output_tokens_details",
                "total_tokens",
            ],
            "usage",
        )?;
        let (input, output, total) = usage_counts(
            usage,
            "input_tokens",
            "output_tokens",
            Some("total_tokens"),
            "usage",
        )?;
        out["usage"] = json!({
            "prompt_tokens": input,
            "completion_tokens": output,
            "total_tokens": total,
        });
        let (cached, reasoning) = responses_usage_details(usage, "usage")?;
        if cached > input {
            return Err(reject(
                "usage.input_tokens_details.cached_tokens",
                "must not exceed input_tokens",
            ));
        }
        if reasoning > output {
            return Err(reject(
                "usage.output_tokens_details.reasoning_tokens",
                "must not exceed output_tokens",
            ));
        }
        if usage.contains_key("input_tokens_details") {
            out["usage"]["prompt_tokens_details"] = json!({ "cached_tokens": cached });
        }
        if usage.contains_key("output_tokens_details") {
            out["usage"]["completion_tokens_details"] = json!({ "reasoning_tokens": reasoning });
        }
    }
    Ok(serde_json::to_vec(&out)?)
}

fn chat_response_to_responses(body: &[u8]) -> Result<Vec<u8>> {
    let (root, choice, message) = parse_chat_response(body)?;
    let response_id = required_string(&root, "id", "$")?;
    let incomplete = match choice.get("finish_reason").and_then(Value::as_str) {
        None | Some("stop") | Some("tool_calls") => false,
        Some("length") => true,
        Some(other) => {
            return Err(reject(
                "choices[0].finish_reason",
                format!("unsupported value `{other}`"),
            ))
        }
    };
    let item_status = if incomplete {
        "incomplete"
    } else {
        "completed"
    };
    let mut output = Vec::new();
    if let Some(text) = message
        .get("content")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        output.push(json!({ "id": format!("{response_id}-message-0"), "type": "message", "role": "assistant", "status": item_status, "content": [{ "type": "output_text", "text": text, "annotations": [] }] }));
    }
    if let Some(calls) = message.get("tool_calls") {
        for (index, call) in expect_array(calls, "choices[0].message.tool_calls")?
            .iter()
            .enumerate()
        {
            let path = format!("choices[0].message.tool_calls[{index}]");
            let call = expect_object(call, &path)?;
            let function = expect_object(
                call.get("function")
                    .ok_or_else(|| reject(&format!("{path}.function"), "field is required"))?,
                &format!("{path}.function"),
            )?;
            output.push(json!({ "id": format!("{response_id}-call-{index}"), "type": "function_call", "status": item_status, "call_id": required_string(call, "id", &path)?, "name": required_string(function, "name", &format!("{path}.function"))?, "arguments": required_string(function, "arguments", &format!("{path}.function"))? }));
        }
    }
    let status = if incomplete {
        "incomplete"
    } else {
        "completed"
    };
    let created = root.get("created").cloned().unwrap_or_else(|| json!(0));
    let completed_at = if incomplete {
        Value::Null
    } else {
        created.clone()
    };
    let incomplete_details = if incomplete {
        json!({ "reason": "max_output_tokens" })
    } else {
        Value::Null
    };
    let output_text = message.get("content").and_then(Value::as_str).unwrap_or("");
    let mut out = json!({
        "id": response_id,
        "object": "response",
        "created_at": created,
        "completed_at": completed_at,
        "model": required_string(&root, "model", "$")?,
        "status": status,
        "output": output,
        "output_text": output_text,
        "background": false,
        "conversation": null,
        "error": null,
        "incomplete_details": incomplete_details,
        "instructions": null,
        "max_output_tokens": null,
        "max_tool_calls": null,
        "metadata": {},
        "moderation": null,
        "parallel_tool_calls": true,
        "previous_response_id": null,
        "prompt": null,
        "prompt_cache_key": null,
        "prompt_cache_options": null,
        "prompt_cache_retention": null,
        "reasoning": { "effort": null, "summary": null },
        "safety_identifier": null,
        "service_tier": root.get("service_tier").filter(|value| !value.is_null()).cloned().unwrap_or_else(|| json!("default")),
        "store": false,
        "temperature": null,
        "text": { "format": { "type": "text" } },
        "tool_choice": "auto",
        "tools": [],
        "top_logprobs": 0,
        "top_p": null,
        "truncation": "disabled",
        "usage": null,
        "user": null,
    });
    if let Some(usage) = root.get("usage") {
        let usage = expect_object(usage, "usage")?;
        let (input, output, total, cached, reasoning) = chat_usage_counts(usage, "usage")?;
        out["usage"] = json!({
            "input_tokens": input,
            "input_tokens_details": { "cached_tokens": cached },
            "output_tokens": output,
            "output_tokens_details": { "reasoning_tokens": reasoning },
            "total_tokens": total,
        });
    }
    Ok(serde_json::to_vec(&out)?)
}

fn gemini_response_to_chat(body: &[u8]) -> Result<Vec<u8>> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &["responseId", "modelVersion", "candidates", "usageMetadata"],
        "$",
    )?;
    let candidates = expect_array(
        root.get("candidates")
            .ok_or_else(|| reject("candidates", "field is required"))?,
        "candidates",
    )?;
    if candidates.len() != 1 {
        return Err(reject("candidates", "only one candidate can be mapped"));
    }
    let candidate = expect_object(&candidates[0], "candidates[0]")?;
    refuse_unknown_keys(
        candidate,
        &["index", "content", "finishReason", "safetyRatings"],
        "candidates[0]",
    )?;
    if let Some(ratings) = candidate
        .get("safetyRatings")
        .filter(|value| !value.is_null())
    {
        validate_gemini_safety_ratings(ratings, "candidates[0].safetyRatings")?;
    }
    let content = expect_object(
        candidate
            .get("content")
            .ok_or_else(|| reject("candidates[0].content", "field is required"))?,
        "candidates[0].content",
    )?;
    let mut messages = Vec::new();
    gemini_content_to_chat(&Value::Object(content.clone()), 0, &mut messages)?;
    let message = messages
        .pop()
        .ok_or_else(|| reject("candidates[0].content", "has no mappable parts"))?;
    let finish = match candidate.get("finishReason").and_then(Value::as_str) {
        None | Some("STOP") => "stop",
        Some("MAX_TOKENS") => "length",
        Some(other) => {
            return Err(reject(
                "candidates[0].finishReason",
                format!("unsupported value `{other}`"),
            ))
        }
    };
    let mut out = json!({ "id": required_string(&root, "responseId", "$")?, "object": "chat.completion", "created": 0, "model": required_string(&root, "modelVersion", "$")?, "choices": [{ "index": 0, "message": message, "finish_reason": finish }] });
    if let Some(usage) = root.get("usageMetadata") {
        let usage = expect_object(usage, "usageMetadata")?;
        let (input, output, total, cached, reasoning) =
            gemini_usage_counts(usage, "usageMetadata")?;
        out["usage"] = json!({
            "prompt_tokens": input,
            "completion_tokens": output,
            "total_tokens": total,
        });
        if usage.contains_key("cachedContentTokenCount") {
            out["usage"]["prompt_tokens_details"] = json!({ "cached_tokens": cached });
        }
        if usage.contains_key("thoughtsTokenCount") {
            out["usage"]["completion_tokens_details"] = json!({ "reasoning_tokens": reasoning });
        }
    }
    Ok(serde_json::to_vec(&out)?)
}

fn chat_response_to_gemini(body: &[u8]) -> Result<Vec<u8>> {
    let (root, choice, message) = parse_chat_response(body)?;
    let (_, contents) = chat_messages_to_gemini(&[Value::Object(message.clone())])?;
    let content = contents
        .into_iter()
        .next()
        .ok_or_else(|| reject("choices[0].message", "has no mappable content"))?;
    let finish = match choice.get("finish_reason").and_then(Value::as_str) {
        None | Some("stop") | Some("tool_calls") => "STOP",
        Some("length") => "MAX_TOKENS",
        Some(other) => {
            return Err(reject(
                "choices[0].finish_reason",
                format!("unsupported value `{other}`"),
            ))
        }
    };
    let mut out = json!({ "responseId": required_string(&root, "id", "$")?, "modelVersion": required_string(&root, "model", "$")?, "candidates": [{ "index": 0, "content": content, "finishReason": finish }] });
    if let Some(usage) = root.get("usage") {
        let usage = expect_object(usage, "usage")?;
        let (input, output, total, cached, reasoning) = chat_usage_counts(usage, "usage")?;
        out["usageMetadata"] = json!({
            "promptTokenCount": input,
            "candidatesTokenCount": output - reasoning,
            "totalTokenCount": total,
        });
        if usage.contains_key("prompt_tokens_details") {
            out["usageMetadata"]["cachedContentTokenCount"] = json!(cached);
        }
        if usage.contains_key("completion_tokens_details") {
            out["usageMetadata"]["thoughtsTokenCount"] = json!(reasoning);
        }
    }
    Ok(serde_json::to_vec(&out)?)
}

type ParsedChatResponse = (Map<String, Value>, Map<String, Value>, Map<String, Value>);

fn parse_chat_response(body: &[u8]) -> Result<ParsedChatResponse> {
    let root = parse_object(body)?;
    refuse_unknown_keys(
        &root,
        &[
            "id",
            "object",
            "created",
            "model",
            "choices",
            "usage",
            "service_tier",
            "system_fingerprint",
        ],
        "$",
    )?;
    for field in ["service_tier", "system_fingerprint"] {
        if let Some(value) = root.get(field).filter(|value| !value.is_null()) {
            expect_string(value, field)?;
        }
    }
    let choices = expect_array(
        root.get("choices")
            .ok_or_else(|| reject("choices", "field is required"))?,
        "choices",
    )?;
    if choices.len() != 1 {
        return Err(reject("choices", "only one choice can be mapped"));
    }
    let choice = expect_object(&choices[0], "choices[0]")?.clone();
    refuse_unknown_keys(
        &choice,
        &["index", "message", "finish_reason", "logprobs"],
        "choices[0]",
    )?;
    if let Some(logprobs) = choice.get("logprobs") {
        if !semantically_empty(logprobs) {
            return Err(reject(
                "choices[0].logprobs",
                "nonempty log probabilities cannot be preserved",
            ));
        }
    }
    let message = expect_object(
        choice
            .get("message")
            .ok_or_else(|| reject("choices[0].message", "field is required"))?,
        "choices[0].message",
    )?
    .clone();
    refuse_unknown_keys(
        &message,
        &["role", "content", "tool_calls", "refusal", "annotations"],
        "choices[0].message",
    )?;
    if let Some(refusal) = message.get("refusal") {
        let empty = refusal.is_null() || refusal.as_str() == Some("");
        if !empty {
            return Err(reject(
                "choices[0].message.refusal",
                "nonempty refusal content cannot be preserved",
            ));
        }
    }
    if let Some(annotations) = message.get("annotations") {
        let empty = annotations.is_null()
            || annotations
                .as_array()
                .is_some_and(|values| values.is_empty());
        if !empty {
            return Err(reject(
                "choices[0].message.annotations",
                "nonempty annotations cannot be preserved",
            ));
        }
    }
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err(reject("choices[0].message.role", "must be `assistant`"));
    }
    Ok((root, choice, message))
}

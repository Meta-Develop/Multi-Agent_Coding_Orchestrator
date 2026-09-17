use serde_json::{json, Map, Value};

use super::translate::validate_gemini_safety_ratings;
use super::{
    expect_array, expect_object, expect_string, parse_object, refuse_unknown_keys, reject,
    WireFormat,
};
use crate::error::Result;

/// One decoded source stream item. HTTP/SSE framing stays in the listener.
#[derive(Debug, Clone, Copy)]
pub struct SourceEvent<'a> {
    pub event_name: Option<&'a str>,
    pub data: &'a [u8],
    /// `true` represents OpenAI `[DONE]` or an upstream EOF.
    pub terminal: bool,
}

/// One translated stream item. An empty `data` on a terminal event means
/// close the target stream without emitting another data frame (Gemini EOF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedEvent {
    pub event_name: Option<String>,
    pub data: Vec<u8>,
    pub terminal: bool,
}

/// Bounded per-response stream state.
///
/// Only protocol metadata and phase flags are retained. Generated text and
/// tool arguments are translated immediately and are never accumulated.
pub struct StreamTranslator {
    from: WireFormat,
    to: WireFormat,
    id: Option<String>,
    model: Option<String>,
    created: Option<Value>,
    input_tokens: Option<Value>,
    block_started: bool,
    active_block_index: Option<u64>,
    next_block_index: u64,
    response_item_started: bool,
    saw_tool: bool,
    finished: bool,
}

impl StreamTranslator {
    pub fn new(from: WireFormat, to: WireFormat) -> Self {
        Self {
            from,
            to,
            id: None,
            model: None,
            created: None,
            input_tokens: None,
            block_started: false,
            active_block_index: None,
            next_block_index: 0,
            response_item_started: false,
            saw_tool: false,
            finished: false,
        }
    }

    /// Translate one decoded event to zero or more target events.
    pub fn translate(&mut self, event: SourceEvent<'_>) -> Result<Vec<TranslatedEvent>> {
        if self.from == self.to {
            if !event.terminal {
                let _: Value = serde_json::from_slice(event.data)?;
            }
            return Ok(vec![TranslatedEvent {
                event_name: event.event_name.map(str::to_owned),
                data: event.data.to_vec(),
                terminal: event.terminal,
            }]);
        }
        if self.to == WireFormat::OpenAiResponses {
            return Err(reject(
                "stream",
                "cross-dialect OpenAI Responses targets require a completed output snapshot, which this event-by-event relay does not buffer",
            ));
        }
        if matches!(self.from, WireFormat::OpenAiImagesGenerations)
            || matches!(self.to, WireFormat::OpenAiImagesGenerations)
        {
            return Err(reject(
                "stream",
                "image-generation streaming is not supported",
            ));
        }

        let canonical = if event.terminal {
            vec![CanonicalEvent::Terminal]
        } else {
            self.decode(event)?
        };
        let mut out = Vec::new();
        for event in canonical {
            self.remember(&event);
            let event = self.merge_input_usage(event);
            out.extend(self.encode(event)?);
        }
        Ok(out)
    }

    fn decode(&self, event: SourceEvent<'_>) -> Result<Vec<CanonicalEvent>> {
        match self.from {
            WireFormat::OpenAiChatCompletions => decode_chat(event.data, self.id.is_none()),
            WireFormat::OpenAiResponses => decode_responses(event.data, self.saw_tool),
            WireFormat::AnthropicMessages => decode_anthropic(event),
            WireFormat::GeminiGenerateContent => decode_gemini(event.data, self.id.is_none()),
            WireFormat::OpenAiImagesGenerations => unreachable!(),
        }
    }

    fn remember(&mut self, event: &CanonicalEvent) {
        if let CanonicalEvent::Start {
            id,
            model,
            created,
            input_tokens,
        } = event
        {
            self.id = Some(id.clone());
            self.model = Some(model.clone());
            self.created = created.clone();
            self.input_tokens = input_tokens.clone();
        }
        if matches!(event, CanonicalEvent::ToolStart { .. }) {
            self.saw_tool = true;
        }
        if matches!(event, CanonicalEvent::Finish { .. }) {
            self.finished = true;
        }
    }

    fn merge_input_usage(&self, event: CanonicalEvent) -> CanonicalEvent {
        let CanonicalEvent::Finish {
            index,
            reason,
            usage,
        } = event
        else {
            return event;
        };
        let usage = match (usage, &self.input_tokens) {
            (None, None) => None,
            (None, Some(input)) => Some(json!({ "input_tokens": input })),
            (Some(Value::Object(mut usage)), Some(input)) => {
                if !usage.contains_key("input_tokens")
                    && !usage.contains_key("prompt_tokens")
                    && !usage.contains_key("promptTokenCount")
                {
                    usage.insert("input_tokens".into(), input.clone());
                }
                Some(Value::Object(usage))
            }
            (usage, _) => usage,
        };
        CanonicalEvent::Finish {
            index,
            reason,
            usage,
        }
    }

    fn encode(&mut self, event: CanonicalEvent) -> Result<Vec<TranslatedEvent>> {
        match self.to {
            WireFormat::OpenAiChatCompletions => self.encode_chat(event),
            WireFormat::OpenAiResponses => self.encode_responses(event),
            WireFormat::AnthropicMessages => self.encode_anthropic(event),
            WireFormat::GeminiGenerateContent => self.encode_gemini(event),
            WireFormat::OpenAiImagesGenerations => unreachable!(),
        }
    }

    fn encode_chat(&self, event: CanonicalEvent) -> Result<Vec<TranslatedEvent>> {
        let (id, model) = self.envelope()?;
        let id = id.to_owned();
        let model = model.to_owned();
        let chunk = match event {
            CanonicalEvent::Start { created, .. } => json!({
                "id": id,
                "object": "chat.completion.chunk",
                "created": created.unwrap_or_else(|| json!(0)),
                "model": model,
                "choices": [{ "index": 0, "delta": { "role": "assistant", "content": "" }, "finish_reason": null }],
            }),
            CanonicalEvent::Text { index, text } => json!({
                "id": id, "object": "chat.completion.chunk",
                "created": self.created.clone().unwrap_or_else(|| json!(0)), "model": model,
                "choices": [{ "index": index, "delta": { "content": text }, "finish_reason": null }],
            }),
            CanonicalEvent::ToolStart {
                index,
                id: call_id,
                name,
            } => json!({
                "id": id, "object": "chat.completion.chunk",
                "created": self.created.clone().unwrap_or_else(|| json!(0)), "model": model,
                "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": index, "id": call_id, "type": "function", "function": { "name": name, "arguments": "" } }] }, "finish_reason": null }],
            }),
            CanonicalEvent::ToolDelta { index, arguments } => json!({
                "id": id, "object": "chat.completion.chunk",
                "created": self.created.clone().unwrap_or_else(|| json!(0)), "model": model,
                "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": index, "function": { "arguments": arguments } }] }, "finish_reason": null }],
            }),
            CanonicalEvent::Finish {
                index,
                reason,
                usage,
            } => {
                let mut value = json!({
                    "id": id, "object": "chat.completion.chunk",
                    "created": self.created.clone().unwrap_or_else(|| json!(0)), "model": model,
                    "choices": [{ "index": index, "delta": {}, "finish_reason": chat_finish_reason(&reason)? }],
                });
                if let Some(usage) = usage {
                    value["usage"] = usage_to_chat(&usage)?;
                }
                value
            }
            CanonicalEvent::Terminal => {
                return Ok(vec![TranslatedEvent {
                    event_name: None,
                    data: b"[DONE]".to_vec(),
                    terminal: true,
                }]);
            }
        };
        json_event(None, chunk, false)
    }

    fn encode_anthropic(&mut self, event: CanonicalEvent) -> Result<Vec<TranslatedEvent>> {
        let mut out = Vec::new();
        match event {
            CanonicalEvent::Start {
                id,
                model,
                input_tokens,
                ..
            } => {
                let input_tokens = input_tokens
                    .as_ref()
                    .map(|value| token_count(value, "usage.input_tokens"))
                    .transpose()?
                    .unwrap_or(0);
                out.extend(json_event(
                    Some("message_start"),
                    json!({
                        "type": "message_start",
                        "message": { "id": id, "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": null, "stop_sequence": null, "usage": { "input_tokens": input_tokens, "output_tokens": 0 } },
                    }),
                    false,
                )?);
            }
            CanonicalEvent::Text { index: _, text } => {
                if !self.block_started {
                    let index = self.next_block_index;
                    self.next_block_index += 1;
                    self.active_block_index = Some(index);
                    out.extend(json_event(
                        Some("content_block_start"),
                        json!({ "type": "content_block_start", "index": index, "content_block": { "type": "text", "text": "" } }),
                        false,
                    )?);
                    self.block_started = true;
                }
                let index = self.active_block_index.unwrap_or(0);
                out.extend(json_event(
                    Some("content_block_delta"),
                    json!({ "type": "content_block_delta", "index": index, "delta": { "type": "text_delta", "text": text } }),
                    false,
                )?);
            }
            CanonicalEvent::ToolStart { index: _, id, name } => {
                if self.block_started {
                    let active = self.active_block_index.unwrap_or(0);
                    out.extend(json_event(
                        Some("content_block_stop"),
                        json!({ "type": "content_block_stop", "index": active }),
                        false,
                    )?);
                }
                let index = self.next_block_index;
                self.next_block_index += 1;
                self.active_block_index = Some(index);
                out.extend(json_event(
                    Some("content_block_start"),
                    json!({ "type": "content_block_start", "index": index, "content_block": { "type": "tool_use", "id": id, "name": name, "input": {} } }),
                    false,
                )?);
                self.block_started = true;
            }
            CanonicalEvent::ToolDelta {
                index: _,
                arguments,
            } => {
                let index = self.active_block_index.ok_or_else(|| {
                    reject("stream.tool_call", "tool delta arrived before tool start")
                })?;
                out.extend(json_event(
                    Some("content_block_delta"),
                    json!({ "type": "content_block_delta", "index": index, "delta": { "type": "input_json_delta", "partial_json": arguments } }),
                    false,
                )?);
            }
            CanonicalEvent::Finish {
                index: _,
                reason,
                usage,
            } => {
                if self.block_started {
                    let index = self.active_block_index.unwrap_or(0);
                    out.extend(json_event(
                        Some("content_block_stop"),
                        json!({ "type": "content_block_stop", "index": index }),
                        false,
                    )?);
                    self.block_started = false;
                    self.active_block_index = None;
                }
                let mut value = json!({
                    "type": "message_delta",
                    "delta": { "stop_reason": anthropic_finish_reason(&reason)?, "stop_sequence": null },
                    "usage": { "output_tokens": 0 },
                });
                if let Some(usage) = usage {
                    value["usage"] = usage_to_anthropic(&usage)?;
                }
                out.extend(json_event(Some("message_delta"), value, false)?);
            }
            CanonicalEvent::Terminal => {
                out.extend(json_event(
                    Some("message_stop"),
                    json!({ "type": "message_stop" }),
                    true,
                )?);
            }
        }
        Ok(out)
    }

    fn encode_responses(&mut self, event: CanonicalEvent) -> Result<Vec<TranslatedEvent>> {
        let (id, model) = self.envelope()?;
        let id = id.to_owned();
        let model = model.to_owned();
        let mut out = Vec::new();
        match event {
            CanonicalEvent::Start { .. } => {
                out.extend(responses_event(
                    "response.created",
                    json!({ "type": "response.created", "response": response_envelope(id, model, "in_progress") }),
                    false,
                )?);
            }
            CanonicalEvent::Text { index, text } => {
                if !self.response_item_started {
                    out.extend(responses_event(
                        "response.output_item.added",
                        json!({ "type": "response.output_item.added", "output_index": index, "item": { "id": format!("{id}-message-{index}"), "type": "message", "role": "assistant", "status": "in_progress", "content": [] } }),
                        false,
                    )?);
                    out.extend(responses_event(
                        "response.content_part.added",
                        json!({ "type": "response.content_part.added", "item_id": format!("{id}-message-{index}"), "output_index": index, "content_index": 0, "part": { "type": "output_text", "text": "", "annotations": [] } }),
                        false,
                    )?);
                    self.response_item_started = true;
                }
                out.extend(responses_event(
                    "response.output_text.delta",
                    json!({ "type": "response.output_text.delta", "item_id": format!("{id}-message-{index}"), "output_index": index, "content_index": 0, "delta": text }),
                    false,
                )?);
            }
            CanonicalEvent::ToolStart {
                index,
                id: call_id,
                name,
            } => {
                out.extend(responses_event(
                    "response.output_item.added",
                    json!({ "type": "response.output_item.added", "output_index": index, "item": { "id": format!("{id}-call-{index}"), "type": "function_call", "call_id": call_id, "name": name, "arguments": "", "status": "in_progress" } }),
                    false,
                )?);
                self.response_item_started = true;
            }
            CanonicalEvent::ToolDelta { index, arguments } => {
                out.extend(responses_event(
                    "response.function_call_arguments.delta",
                    json!({ "type": "response.function_call_arguments.delta", "item_id": format!("{id}-call-{index}"), "output_index": index, "delta": arguments }),
                    false,
                )?);
            }
            CanonicalEvent::Finish { usage, .. } => {
                let mut response = response_envelope(id, model, "completed");
                if let Some(usage) = usage {
                    response["usage"] = usage_to_responses(&usage)?;
                }
                out.extend(responses_event(
                    "response.completed",
                    json!({ "type": "response.completed", "response": response }),
                    false,
                )?);
                self.finished = true;
            }
            CanonicalEvent::Terminal => {
                if !self.finished {
                    out.extend(responses_event(
                        "response.completed",
                        json!({ "type": "response.completed", "response": response_envelope(id, model, "completed") }),
                        true,
                    )?);
                } else {
                    out.push(TranslatedEvent {
                        event_name: None,
                        data: Vec::new(),
                        terminal: true,
                    });
                }
            }
        }
        Ok(out)
    }

    fn encode_gemini(&self, event: CanonicalEvent) -> Result<Vec<TranslatedEvent>> {
        let (id, model) = self.envelope()?;
        let value = match event {
            CanonicalEvent::Start { .. } => return Ok(Vec::new()),
            CanonicalEvent::Text { index, text } => json!({
                "responseId": id, "modelVersion": model,
                "candidates": [{ "index": index, "content": { "role": "model", "parts": [{ "text": text }] } }],
            }),
            CanonicalEvent::ToolStart { .. } => {
                return Err(reject(
                    "tool_calls",
                    "Gemini requires complete function arguments; partial tool streams are rejected before emitting output",
                ));
            }
            CanonicalEvent::ToolDelta { index, .. } => {
                return Err(reject(
                    &format!("tool_calls[{index}].function.arguments"),
                    "Gemini streams complete function-call args and cannot accept a partial JSON delta",
                ));
            }
            CanonicalEvent::Finish {
                index,
                reason,
                usage,
            } => {
                let mut value = json!({
                    "responseId": id, "modelVersion": model,
                    "candidates": [{ "index": index, "finishReason": gemini_finish_reason(&reason)? }],
                });
                if let Some(usage) = usage {
                    value["usageMetadata"] = usage_to_gemini(&usage)?;
                }
                value
            }
            CanonicalEvent::Terminal => {
                return Ok(vec![TranslatedEvent {
                    event_name: None,
                    data: Vec::new(),
                    terminal: true,
                }]);
            }
        };
        json_event(None, value, false)
    }

    fn envelope(&self) -> Result<(&str, &str)> {
        Ok((
            self.id
                .as_deref()
                .ok_or_else(|| reject("stream.id", "start event must precede content"))?,
            self.model
                .as_deref()
                .ok_or_else(|| reject("stream.model", "start event must precede content"))?,
        ))
    }
}

#[derive(Debug)]
enum CanonicalEvent {
    Start {
        id: String,
        model: String,
        created: Option<Value>,
        input_tokens: Option<Value>,
    },
    Text {
        index: u64,
        text: String,
    },
    ToolStart {
        index: u64,
        id: String,
        name: String,
    },
    ToolDelta {
        index: u64,
        arguments: String,
    },
    Finish {
        index: u64,
        reason: String,
        usage: Option<Value>,
    },
    Terminal,
}

fn decode_chat(data: &[u8], need_start: bool) -> Result<Vec<CanonicalEvent>> {
    let root = parse_object(data)?;
    refuse_unknown_keys(
        &root,
        &["id", "object", "created", "model", "choices", "usage"],
        "$",
    )?;
    let mut out = Vec::new();
    if need_start {
        out.push(CanonicalEvent::Start {
            id: required_string(&root, "id", "$")?.into(),
            model: required_string(&root, "model", "$")?.into(),
            created: root.get("created").cloned(),
            input_tokens: None,
        });
    }
    for choice in expect_array(
        root.get("choices")
            .ok_or_else(|| reject("choices", "field is required"))?,
        "choices",
    )? {
        let choice = expect_object(choice, "choices[]")?;
        refuse_unknown_keys(choice, &["index", "delta", "finish_reason"], "choices[]")?;
        let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
        if let Some(delta) = choice.get("delta") {
            let delta = expect_object(delta, "choices[].delta")?;
            refuse_unknown_keys(delta, &["role", "content", "tool_calls"], "choices[].delta")?;
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                if !text.is_empty() {
                    out.push(CanonicalEvent::Text {
                        index,
                        text: text.into(),
                    });
                }
            }
            if let Some(calls) = delta.get("tool_calls") {
                for call in expect_array(calls, "choices[].delta.tool_calls")? {
                    let call = expect_object(call, "choices[].delta.tool_calls[]")?;
                    refuse_unknown_keys(
                        call,
                        &["index", "id", "type", "function"],
                        "choices[].delta.tool_calls[]",
                    )?;
                    let call_index = call.get("index").and_then(Value::as_u64).unwrap_or(0);
                    let function = expect_object(
                        call.get("function").ok_or_else(|| {
                            reject("choices[].delta.tool_calls[].function", "field is required")
                        })?,
                        "choices[].delta.tool_calls[].function",
                    )?;
                    refuse_unknown_keys(
                        function,
                        &["name", "arguments"],
                        "choices[].delta.tool_calls[].function",
                    )?;
                    if let (Some(id), Some(name)) = (
                        call.get("id").and_then(Value::as_str),
                        function.get("name").and_then(Value::as_str),
                    ) {
                        out.push(CanonicalEvent::ToolStart {
                            index: call_index,
                            id: id.into(),
                            name: name.into(),
                        });
                    }
                    if let Some(arguments) = function
                        .get("arguments")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    {
                        out.push(CanonicalEvent::ToolDelta {
                            index: call_index,
                            arguments: arguments.into(),
                        });
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            out.push(CanonicalEvent::Finish {
                index,
                reason: reason.into(),
                usage: root.get("usage").cloned(),
            });
        }
    }
    Ok(out)
}

fn decode_anthropic(event: SourceEvent<'_>) -> Result<Vec<CanonicalEvent>> {
    let root = parse_object(event.data)?;
    let kind = required_string(&root, "type", "$")?;
    if event.event_name.is_some_and(|name| name != kind) {
        return Err(reject("event", "SSE event name does not match JSON type"));
    }
    match kind {
        "message_start" => {
            refuse_unknown_keys(&root, &["type", "message"], "$")?;
            let message = expect_object(
                root.get("message")
                    .ok_or_else(|| reject("message", "field is required"))?,
                "message",
            )?;
            refuse_unknown_keys(
                message,
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
                "message",
            )?;
            let usage = message
                .get("usage")
                .map(|usage| {
                    let usage = expect_object(usage, "message.usage")?;
                    refuse_unknown_keys(
                        usage,
                        &[
                            "input_tokens",
                            "output_tokens",
                            "cache_creation_input_tokens",
                            "cache_read_input_tokens",
                            "server_tool_use",
                        ],
                        "message.usage",
                    )?;
                    usage_to_chat(&Value::Object(usage.clone()))
                        .map(|usage| usage["prompt_tokens"].clone())
                })
                .transpose()?;
            Ok(vec![CanonicalEvent::Start {
                id: required_string(message, "id", "message")?.into(),
                model: required_string(message, "model", "message")?.into(),
                created: None,
                input_tokens: usage,
            }])
        }
        "content_block_start" => {
            refuse_unknown_keys(&root, &["type", "index", "content_block"], "$")?;
            let index = root.get("index").and_then(Value::as_u64).unwrap_or(0);
            let block = expect_object(
                root.get("content_block")
                    .ok_or_else(|| reject("content_block", "field is required"))?,
                "content_block",
            )?;
            match required_string(block, "type", "content_block")? {
                "text" => Ok(Vec::new()),
                "tool_use" => Ok(vec![CanonicalEvent::ToolStart {
                    index,
                    id: required_string(block, "id", "content_block")?.into(),
                    name: required_string(block, "name", "content_block")?.into(),
                }]),
                other => Err(reject(
                    "content_block.type",
                    format!("unsupported block `{other}`"),
                )),
            }
        }
        "content_block_delta" => {
            refuse_unknown_keys(&root, &["type", "index", "delta"], "$")?;
            let index = root.get("index").and_then(Value::as_u64).unwrap_or(0);
            let delta = expect_object(
                root.get("delta")
                    .ok_or_else(|| reject("delta", "field is required"))?,
                "delta",
            )?;
            match required_string(delta, "type", "delta")? {
                "text_delta" => Ok(vec![CanonicalEvent::Text {
                    index,
                    text: required_string(delta, "text", "delta")?.into(),
                }]),
                "input_json_delta" => Ok(vec![CanonicalEvent::ToolDelta {
                    index,
                    arguments: required_string(delta, "partial_json", "delta")?.into(),
                }]),
                other => Err(reject("delta.type", format!("unsupported delta `{other}`"))),
            }
        }
        "content_block_stop" => Ok(Vec::new()),
        "message_delta" => {
            refuse_unknown_keys(&root, &["type", "delta", "usage"], "$")?;
            let delta = expect_object(
                root.get("delta")
                    .ok_or_else(|| reject("delta", "field is required"))?,
                "delta",
            )?;
            let reason = delta
                .get("stop_reason")
                .and_then(Value::as_str)
                .unwrap_or("end_turn");
            Ok(vec![CanonicalEvent::Finish {
                index: 0,
                reason: reason.into(),
                usage: root.get("usage").cloned(),
            }])
        }
        "message_stop" => Ok(vec![CanonicalEvent::Terminal]),
        "ping" => Ok(Vec::new()),
        other => Err(reject(
            "type",
            format!("unsupported Anthropic event `{other}`"),
        )),
    }
}

fn decode_responses(data: &[u8], saw_tool: bool) -> Result<Vec<CanonicalEvent>> {
    let root = parse_object(data)?;
    let kind = required_string(&root, "type", "$")?;
    match kind {
        "response.created" => {
            let response = expect_object(
                root.get("response")
                    .ok_or_else(|| reject("response", "field is required"))?,
                "response",
            )?;
            Ok(vec![CanonicalEvent::Start {
                id: required_string(response, "id", "response")?.into(),
                model: required_string(response, "model", "response")?.into(),
                created: response.get("created_at").cloned(),
                input_tokens: response
                    .get("usage")
                    .and_then(Value::as_object)
                    .and_then(|usage| usage.get("input_tokens"))
                    .cloned(),
            }])
        }
        "response.output_text.delta" => Ok(vec![CanonicalEvent::Text {
            index: root
                .get("output_index")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            text: required_string(&root, "delta", "$")?.into(),
        }]),
        "response.output_item.added" => {
            let index = root
                .get("output_index")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let item = expect_object(
                root.get("item")
                    .ok_or_else(|| reject("item", "field is required"))?,
                "item",
            )?;
            if item.get("type").and_then(Value::as_str) == Some("function_call") {
                Ok(vec![CanonicalEvent::ToolStart {
                    index,
                    id: required_string(item, "call_id", "item")?.into(),
                    name: required_string(item, "name", "item")?.into(),
                }])
            } else {
                Ok(Vec::new())
            }
        }
        "response.function_call_arguments.delta" => Ok(vec![CanonicalEvent::ToolDelta {
            index: root
                .get("output_index")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            arguments: required_string(&root, "delta", "$")?.into(),
        }]),
        "response.completed" => {
            let response = expect_object(
                root.get("response")
                    .ok_or_else(|| reject("response", "field is required"))?,
                "response",
            )?;
            Ok(vec![
                CanonicalEvent::Finish {
                    index: 0,
                    reason: if saw_tool { "tool_calls" } else { "stop" }.into(),
                    usage: response.get("usage").cloned(),
                },
                CanonicalEvent::Terminal,
            ])
        }
        "response.content_part.added"
        | "response.output_item.done"
        | "response.content_part.done"
        | "response.output_text.done" => Ok(Vec::new()),
        other => Err(reject(
            "type",
            format!("unsupported Responses event `{other}`"),
        )),
    }
}

fn decode_gemini(data: &[u8], need_start: bool) -> Result<Vec<CanonicalEvent>> {
    let root = parse_object(data)?;
    refuse_unknown_keys(
        &root,
        &["responseId", "modelVersion", "candidates", "usageMetadata"],
        "$",
    )?;
    let mut out = Vec::new();
    if need_start {
        let input_tokens = root
            .get("usageMetadata")
            .map(usage_to_chat)
            .transpose()?
            .map(|usage| usage["prompt_tokens"].clone());
        out.push(CanonicalEvent::Start {
            id: required_string(&root, "responseId", "$")?.into(),
            model: required_string(&root, "modelVersion", "$")?.into(),
            created: None,
            input_tokens,
        });
    }
    for candidate in expect_array(
        root.get("candidates")
            .ok_or_else(|| reject("candidates", "field is required"))?,
        "candidates",
    )? {
        let candidate = expect_object(candidate, "candidates[]")?;
        refuse_unknown_keys(
            candidate,
            &["index", "content", "finishReason", "safetyRatings"],
            "candidates[]",
        )?;
        if let Some(ratings) = candidate
            .get("safetyRatings")
            .filter(|value| !value.is_null())
        {
            validate_gemini_safety_ratings(ratings, "candidates[].safetyRatings")?;
        }
        let index = candidate.get("index").and_then(Value::as_u64).unwrap_or(0);
        if let Some(content) = candidate.get("content") {
            let content = expect_object(content, "candidates[].content")?;
            refuse_unknown_keys(content, &["role", "parts"], "candidates[].content")?;
            for part in expect_array(
                content
                    .get("parts")
                    .ok_or_else(|| reject("candidates[].content.parts", "field is required"))?,
                "candidates[].content.parts",
            )? {
                let part = expect_object(part, "candidates[].content.parts[]")?;
                if let Some(text) = part.get("text") {
                    refuse_unknown_keys(
                        part,
                        &["text", "thought"],
                        "candidates[].content.parts[]",
                    )?;
                    if let Some(thought) = part.get("thought").filter(|value| !value.is_null()) {
                        let thought = thought.as_bool().ok_or_else(|| {
                            reject("candidates[].content.parts[].thought", "must be a boolean")
                        })?;
                        if thought {
                            return Err(reject(
                                "candidates[].content.parts[].thought",
                                "the target dialect has no reasoning-content counterpart",
                            ));
                        }
                    }
                    out.push(CanonicalEvent::Text {
                        index,
                        text: expect_string(text, "candidates[].content.parts[].text")?.into(),
                    });
                } else if let Some(call) = part.get("functionCall") {
                    let call = expect_object(call, "candidates[].content.parts[].functionCall")?;
                    out.push(CanonicalEvent::ToolStart {
                        index,
                        id: required_string(call, "id", "functionCall")?.into(),
                        name: required_string(call, "name", "functionCall")?.into(),
                    });
                    let args = call.get("args").cloned().unwrap_or_else(|| json!({}));
                    out.push(CanonicalEvent::ToolDelta {
                        index,
                        arguments: serde_json::to_string(&args)?,
                    });
                } else {
                    return Err(reject(
                        "candidates[].content.parts[]",
                        "unknown Gemini stream part",
                    ));
                }
            }
        }
        if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
            out.push(CanonicalEvent::Finish {
                index,
                reason: reason.into(),
                usage: root.get("usageMetadata").cloned(),
            });
        }
    }
    Ok(out)
}

fn required_string<'a>(obj: &'a Map<String, Value>, field: &str, path: &str) -> Result<&'a str> {
    expect_string(
        obj.get(field)
            .ok_or_else(|| reject(&format!("{path}.{field}"), "field is required"))?,
        &format!("{path}.{field}"),
    )
}

fn json_event(
    event_name: Option<&str>,
    value: Value,
    terminal: bool,
) -> Result<Vec<TranslatedEvent>> {
    Ok(vec![TranslatedEvent {
        event_name: event_name.map(str::to_owned),
        data: serde_json::to_vec(&value)?,
        terminal,
    }])
}

fn responses_event(name: &str, value: Value, terminal: bool) -> Result<Vec<TranslatedEvent>> {
    json_event(Some(name), value, terminal)
}

fn response_envelope(id: impl AsRef<str>, model: impl AsRef<str>, status: &str) -> Value {
    let id = id.as_ref();
    let model = model.as_ref();
    json!({
        "id": id, "object": "response", "created_at": 0, "model": model,
        "status": status, "output": [], "error": null,
        "incomplete_details": null, "instructions": null, "parallel_tool_calls": true,
        "tool_choice": "auto", "tools": [],
    })
}

fn chat_finish_reason(reason: &str) -> Result<&'static str> {
    match reason {
        "stop" | "end_turn" | "stop_sequence" | "STOP" => Ok("stop"),
        "tool_calls" | "tool_use" => Ok("tool_calls"),
        "length" | "max_tokens" | "MAX_TOKENS" => Ok("length"),
        other => Err(reject(
            "finish_reason",
            format!("unsupported value `{other}`"),
        )),
    }
}

fn anthropic_finish_reason(reason: &str) -> Result<&'static str> {
    match reason {
        "stop" | "end_turn" | "STOP" => Ok("end_turn"),
        "stop_sequence" => Ok("stop_sequence"),
        "tool_calls" | "tool_use" => Ok("tool_use"),
        "length" | "max_tokens" | "MAX_TOKENS" => Ok("max_tokens"),
        other => Err(reject(
            "stop_reason",
            format!("unsupported value `{other}`"),
        )),
    }
}

fn gemini_finish_reason(reason: &str) -> Result<&'static str> {
    match reason {
        "stop" | "end_turn" | "stop_sequence" | "STOP" | "tool_calls" | "tool_use" => Ok("STOP"),
        "length" | "max_tokens" | "MAX_TOKENS" => Ok("MAX_TOKENS"),
        other => Err(reject(
            "finishReason",
            format!("unsupported value `{other}`"),
        )),
    }
}

fn usage_to_chat(usage: &Value) -> Result<Value> {
    let usage = expect_object(usage, "usage")?;
    let count = |field: &str| -> Result<u64> {
        usage
            .get(field)
            .filter(|value| !value.is_null())
            .map(|value| token_count(value, &format!("usage.{field}")))
            .transpose()
            .map(|value| value.unwrap_or(0))
    };
    let is_gemini = [
        "promptTokenCount",
        "cachedContentTokenCount",
        "toolUsePromptTokenCount",
        "candidatesTokenCount",
        "thoughtsTokenCount",
        "totalTokenCount",
    ]
    .iter()
    .any(|field| usage.contains_key(*field));
    let (input, output, cached, reasoning) = if is_gemini {
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
            "usage",
        )?;
        let cached = count("cachedContentTokenCount")?;
        let reasoning = count("thoughtsTokenCount")?;
        let prompt = count("promptTokenCount")?;
        if cached > prompt {
            return Err(reject(
                "usage.cachedContentTokenCount",
                "must not exceed promptTokenCount",
            ));
        }
        if count("toolUsePromptTokenCount")? != 0 {
            return Err(reject(
                "usage.toolUsePromptTokenCount",
                "nonzero tool-use prompt diagnostics have no target counterpart",
            ));
        }
        (
            prompt,
            checked_token_sum(
                &[count("candidatesTokenCount")?, reasoning],
                "usage.totalTokenCount",
            )?,
            cached,
            reasoning,
        )
    } else {
        if let Some(server_tools) = usage
            .get("server_tool_use")
            .filter(|value| !value.is_null())
        {
            for (field, value) in expect_object(server_tools, "usage.server_tool_use")? {
                if value.as_u64() != Some(0) {
                    return Err(reject(
                        &format!("usage.server_tool_use.{field}"),
                        "nonzero server-tool usage has no target counterpart",
                    ));
                }
            }
        }
        let input = checked_token_sum(
            &[
                count("input_tokens")?.max(count("prompt_tokens")?),
                count("cache_creation_input_tokens")?,
                count("cache_read_input_tokens")?,
            ],
            "usage.total_tokens",
        )?;
        (
            input,
            count("output_tokens")?.max(count("completion_tokens")?),
            count("cache_read_input_tokens")?,
            0,
        )
    };
    let sum = input.checked_add(output).ok_or_else(|| {
        reject(
            "usage.total_tokens",
            "input and output token counts overflow",
        )
    })?;
    let total = usage
        .get("total_tokens")
        .or_else(|| usage.get("totalTokenCount"))
        .map(|value| token_count(value, "usage.total_tokens"))
        .transpose()?
        .unwrap_or(sum);
    if total != sum {
        return Err(reject(
            "usage.total_tokens",
            "must equal input tokens plus output tokens",
        ));
    }
    let mut out = json!({
        "prompt_tokens": input,
        "completion_tokens": output,
        "total_tokens": total,
    });
    if usage.contains_key("cachedContentTokenCount")
        || usage.contains_key("cache_read_input_tokens")
    {
        out["prompt_tokens_details"] = json!({ "cached_tokens": cached });
    }
    if usage.contains_key("thoughtsTokenCount") {
        out["completion_tokens_details"] = json!({ "reasoning_tokens": reasoning });
    }
    Ok(out)
}

fn usage_to_anthropic(usage: &Value) -> Result<Value> {
    let chat = usage_to_chat(usage)?;
    Ok(json!({ "output_tokens": chat["completion_tokens"] }))
}

fn usage_to_responses(usage: &Value) -> Result<Value> {
    let chat = usage_to_chat(usage)?;
    Ok(json!({
        "input_tokens": chat["prompt_tokens"],
        "input_tokens_details": { "cached_tokens": chat.pointer("/prompt_tokens_details/cached_tokens").cloned().unwrap_or_else(|| json!(0)) },
        "output_tokens": chat["completion_tokens"],
        "output_tokens_details": { "reasoning_tokens": chat.pointer("/completion_tokens_details/reasoning_tokens").cloned().unwrap_or_else(|| json!(0)) },
        "total_tokens": chat["total_tokens"],
    }))
}

fn usage_to_gemini(usage: &Value) -> Result<Value> {
    let chat = usage_to_chat(usage)?;
    let cached = chat
        .pointer("/prompt_tokens_details/cached_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reasoning = chat
        .pointer("/completion_tokens_details/reasoning_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let input = token_count(&chat["prompt_tokens"], "usage.prompt_tokens")?;
    let output = token_count(&chat["completion_tokens"], "usage.completion_tokens")?;
    let mut out = json!({
        "promptTokenCount": input,
        "candidatesTokenCount": output.checked_sub(reasoning).ok_or_else(|| reject("usage.completion_tokens_details.reasoning_tokens", "must not exceed completion_tokens"))?,
        "totalTokenCount": chat["total_tokens"],
    });
    if chat.get("prompt_tokens_details").is_some() {
        out["cachedContentTokenCount"] = json!(cached);
    }
    if chat.get("completion_tokens_details").is_some() {
        out["thoughtsTokenCount"] = json!(reasoning);
    }
    Ok(out)
}

fn checked_token_sum(parts: &[u64], path: &str) -> Result<u64> {
    parts.iter().try_fold(0_u64, |total, part| {
        total
            .checked_add(*part)
            .ok_or_else(|| reject(path, "token counts overflow"))
    })
}

fn token_count(value: &Value, path: &str) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| reject(path, "must be a non-negative integer"))
}

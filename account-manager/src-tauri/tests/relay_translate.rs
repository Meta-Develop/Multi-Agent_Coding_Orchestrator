//! Golden-file suite for [`relay::translate`] (`docs/TESTING.md` §5).
//!
//! Layout, followed exactly:
//!
//! ```text
//! src-tauri/tests/golden/<from>-to-<to>/
//!   NNN-<case>.input.json
//!   NNN-<case>.expected.json
//! ```
//!
//! `<from>` and `<to>` are the kebab-case [`WireFormat`] names:
//! `openai-chat-completions`, `openai-responses`,
//! `openai-images-generations`, `anthropic-messages`, and
//! `gemini-generate-content`.
//!
//! # Success vs error cases
//!
//! A legacy success case's `expected.json` is the translated request body.
//! New request cases use `{ "$body": ..., "$context": ... }` and compare the
//! full `TranslatedRequest` envelope (`body`, `target_model`, and `stream`).
//! Non-streaming response cases use `{ "$response": ... }`. Streaming cases
//! use `{ "$events": [...] }` and compare the output event sequence exactly.
//! Because response traffic runs opposite the request directory, an end-to-end
//! stream case can add `{ "$stream": { "from": "...", "to": "..." } }`.
//!
//! An error case uses the same pair of files. `expected.json` is exactly:
//!
//! ```json
//! { "error": { "mentions": "<field>" } }
//! ```
//!
//! The harness asserts `translate` returns `Err` and that the error's
//! `Display` text contains `<field>`. That is how a field with no counterpart
//! is pinned down — a harness that could only assert success would stop
//! testing the capability-mismatch rule (`docs/ARCHITECTURE.md` §6).
//!
//! A mismatch prints the pair, the case name, every disagreeing JSON path,
//! and the expected vs actual values at that path.
//!
//! The matrix covers all three vendor dialects, both OpenAI text endpoints,
//! request and response envelopes, event-by-event streams, image generation,
//! exact reasoning mappings, and explicit capability-mismatch errors.

use std::fs;
use std::path::{Path, PathBuf};

use coding_agent_manager_lib::relay::{
    translate, translate_request, translate_response, SourceEvent, StreamTranslator,
    TranslationContext, WireFormat,
};
use serde_json::{json, Value};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

#[test]
fn golden_request_translations() {
    let root = Path::new(GOLDEN);
    assert!(
        root.is_dir(),
        "golden directory missing at {}",
        root.display()
    );

    let mut pairs = collect_dirs(root);
    pairs.sort();
    assert!(
        !pairs.is_empty(),
        "no <from>-to-<to> directories under {}",
        root.display()
    );

    let mut ran = 0;
    for dir in &pairs {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 directory name");
        let (from, to) = parse_pair(name).unwrap_or_else(|| {
            panic!("golden directory `{name}` is not `<from>-to-<to>` with known formats")
        });

        let mut cases = collect_cases(dir);
        cases.sort_by(|a, b| a.stem.cmp(&b.stem));
        assert!(
            !cases.is_empty(),
            "no NNN-<case>.input.json files in {}",
            dir.display()
        );

        for case in cases {
            ran += 1;
            run_case(name, from, to, &case);
        }
    }

    assert!(ran > 0, "golden harness ran no cases");
}

struct Case {
    stem: String,
    input: PathBuf,
    expected: PathBuf,
}

fn collect_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root).unwrap_or_else(|e| panic!("read {}: {e}", root.display())) {
        let entry = entry.expect("read dirent");
        if entry.file_type().expect("file type").is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs
}

fn collect_cases(dir: &Path) -> Vec<Case> {
    let mut inputs = Vec::new();
    let mut expecteds = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("read dirent").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".input.json") {
            inputs.push((stem.to_string(), path));
        } else if let Some(stem) = name.strip_suffix(".expected.json") {
            expecteds.push((stem.to_string(), path));
        }
    }

    expecteds.sort_by(|a, b| a.0.cmp(&b.0));
    for (stem, path) in &expecteds {
        assert!(
            inputs.iter().any(|(input_stem, _)| input_stem == stem),
            "orphan expected file {} has no {}.input.json",
            path.display(),
            stem
        );
    }

    inputs
        .into_iter()
        .map(|(stem, input)| {
            let expected = dir.join(format!("{stem}.expected.json"));
            assert!(
                expected.is_file(),
                "case `{stem}` is missing {}",
                expected.display()
            );
            Case {
                stem,
                input,
                expected,
            }
        })
        .collect()
}

fn parse_pair(name: &str) -> Option<(WireFormat, WireFormat)> {
    let (from, to) = name.split_once("-to-")?;
    Some((parse_format(from)?, parse_format(to)?))
}

fn parse_format(name: &str) -> Option<WireFormat> {
    match name {
        "openai-chat-completions" => Some(WireFormat::OpenAiChatCompletions),
        "openai-responses" => Some(WireFormat::OpenAiResponses),
        "openai-images-generations" => Some(WireFormat::OpenAiImagesGenerations),
        "anthropic-messages" => Some(WireFormat::AnthropicMessages),
        "gemini-generate-content" => Some(WireFormat::GeminiGenerateContent),
        _ => None,
    }
}

fn run_case(pair: &str, from: WireFormat, to: WireFormat, case: &Case) {
    let label = format!("{pair}/{}", case.stem);
    let input = fs::read(&case.input).unwrap_or_else(|e| {
        panic!("{label}: read {}: {e}", case.input.display());
    });
    let input_value: Value = serde_json::from_slice(&input)
        .unwrap_or_else(|error| panic!("{label}: input is not JSON: {error}"));
    let expected: Value = read_json(&case.expected, &label);

    if let Some(field) = error_mentions(&expected) {
        match execute_case(from, to, &input, &input_value) {
            Ok(actual) => panic!(
                "{label}: expected a rejection mentioning `{field}`, \
                 but translate succeeded:\n{}",
                pretty(&actual)
            ),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(field),
                    "{label}: error should mention `{field}`\n  error: {message}"
                );
            }
        }
        return;
    }

    let actual = execute_case(from, to, &input, &input_value).unwrap_or_else(|error| {
        panic!("{label}: expected a translated body, got error: {error}");
    });

    if actual != expected {
        let mut diffs = Vec::new();
        diff_json("$", &expected, &actual, &mut diffs);
        panic!(
            "{label}: golden mismatch\n{}\n  expected:\n{}\n  actual:\n{}",
            diffs.join("\n"),
            pretty(&expected),
            pretty(&actual)
        );
    }
}

fn execute_case(
    from: WireFormat,
    to: WireFormat,
    raw: &[u8],
    input: &Value,
) -> coding_agent_manager_lib::error::Result<Value> {
    let Some(obj) = input.as_object() else {
        let body = translate(from, to, raw)?;
        return Ok(serde_json::from_slice(&body)?);
    };
    if let Some(events) = obj.get("$events") {
        let (stream_from, stream_to) = stream_formats(obj, from, to)?;
        return execute_stream(stream_from, stream_to, events);
    }
    if let Some(response) = obj.get("$response") {
        let body = serde_json::to_vec(response)?;
        return Ok(serde_json::from_slice(&translate_response(
            from, to, &body,
        )?)?);
    }
    let Some(body) = obj.get("$body") else {
        let body = translate(from, to, raw)?;
        return Ok(serde_json::from_slice(&body)?);
    };
    let context = obj.get("$context").and_then(Value::as_object);
    let source_model = context
        .and_then(|context| context.get("source_model"))
        .and_then(Value::as_str);
    let target_model = context
        .and_then(|context| context.get("target_model"))
        .and_then(Value::as_str);
    let source_stream = context
        .and_then(|context| context.get("source_stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let translated = translate_request(
        from,
        to,
        TranslationContext {
            source_model,
            target_model,
            source_stream,
        },
        &serde_json::to_vec(body)?,
    )?;
    Ok(json!({
        "body": serde_json::from_slice::<Value>(&translated.body)?,
        "target_model": translated.target_model,
        "stream": translated.stream,
    }))
}

fn stream_formats(
    fixture: &serde_json::Map<String, Value>,
    default_from: WireFormat,
    default_to: WireFormat,
) -> coding_agent_manager_lib::error::Result<(WireFormat, WireFormat)> {
    let Some(stream) = fixture.get("$stream") else {
        return Ok((default_from, default_to));
    };
    let stream = stream
        .as_object()
        .ok_or_else(|| fixture_error("$stream must be an object"))?;
    let from = stream
        .get("from")
        .and_then(Value::as_str)
        .and_then(parse_format)
        .ok_or_else(|| fixture_error("$stream.from must be a known wire format"))?;
    let to = stream
        .get("to")
        .and_then(Value::as_str)
        .and_then(parse_format)
        .ok_or_else(|| fixture_error("$stream.to must be a known wire format"))?;
    Ok((from, to))
}

fn execute_stream(
    from: WireFormat,
    to: WireFormat,
    events: &Value,
) -> coding_agent_manager_lib::error::Result<Value> {
    let mut translator = StreamTranslator::new(from, to);
    let mut out = Vec::new();
    for event in events
        .as_array()
        .ok_or_else(|| fixture_error("$events must be an array"))?
    {
        let event = event
            .as_object()
            .ok_or_else(|| fixture_error("each $events entry must be an object"))?;
        let event_name = event.get("event_name").and_then(Value::as_str);
        let terminal = event
            .get("terminal")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let data = match event.get("data") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(value)) => value.as_bytes().to_vec(),
            Some(value) => serde_json::to_vec(value)?,
        };
        for translated in translator.translate(SourceEvent {
            event_name,
            data: &data,
            terminal,
        })? {
            let data = if translated.data.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&translated.data).unwrap_or_else(|_| {
                    Value::String(String::from_utf8_lossy(&translated.data).into())
                })
            };
            out.push(json!({
                "event_name": translated.event_name,
                "data": data,
                "terminal": translated.terminal,
            }));
        }
    }
    Ok(Value::Array(out))
}

fn fixture_error(message: &str) -> coding_agent_manager_lib::error::Error {
    coding_agent_manager_lib::error::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

/// `{ "error": { "mentions": "<field>" } }` is the error-case envelope.
///
/// Anything else is treated as a translated body. This exact-shape check is
/// important because a valid OpenAI Responses envelope itself has an `error`
/// field alongside its other fields. A sole, half-formed `error` envelope
/// still fails the fixture so a typo cannot silently become a success case.
fn error_mentions(expected: &Value) -> Option<&str> {
    let obj = expected.as_object()?;
    if obj.len() != 1 || !obj.contains_key("error") {
        return None;
    }
    let error = obj
        .get("error")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
            "error expected.json must be {{ \"error\": {{ \"mentions\": \"<field>\" }} }}, got {}",
            pretty(expected)
        )
        });
    assert_eq!(
        error.keys().collect::<Vec<_>>(),
        vec!["mentions"],
        "error envelope must have exactly `mentions`, got {}",
        pretty(expected)
    );
    Some(
        error
            .get("mentions")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("error.mentions must be a string, got {}", pretty(expected))),
    )
}

fn diff_json(path: &str, expected: &Value, actual: &Value, out: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (key, exp) in expected {
                let child = format!("{path}.{key}");
                match actual.get(key) {
                    None => out.push(format!("  {child}: expected {exp}, actual missing")),
                    Some(got) => diff_json(&child, exp, got, out),
                }
            }
            for (key, got) in actual {
                if !expected.contains_key(key) {
                    out.push(format!("  {path}.{key}: unexpected {got}"));
                }
            }
        }
        (Value::Array(expected), Value::Array(actual)) => {
            if expected.len() != actual.len() {
                out.push(format!(
                    "  {path}: expected array length {}, actual {}",
                    expected.len(),
                    actual.len()
                ));
            }
            for (i, (exp, got)) in expected.iter().zip(actual.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), exp, got, out);
            }
        }
        (expected, actual) if expected != actual => {
            out.push(format!("  {path}: expected {expected}, actual {actual}"));
        }
        _ => {}
    }
}

fn read_json(path: &Path, label: &str) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("{label}: read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!("{label}: parse {}: {e}", path.display());
    })
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

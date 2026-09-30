//! Observation of Gemini CLI 0.41.2's terminal `--output-format json` output.
//!
//! Source contract: `packages/core/src/output/json-formatter.ts`,
//! `telemetry/uiTelemetry.ts`, and `telemetry/types.ts` in that release.
//! These are CLI telemetry counters, not authenticated provider usage. Missing
//! provider counters are defaulted to zero upstream, and telemetry model keys
//! can be `response.modelVersion || request.model`. Neither completeness nor
//! actual provider identity can be recovered from this JSON alone.
//! No conversion to MACO Usage, pricing, private custody or capabilities occurs.

use std::{collections::BTreeMap, fmt};

use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};

const MAX_TERMINAL_BYTES: usize = 1024 * 1024;
const MAX_MODELS: usize = 64;
// The producer accumulates JavaScript Numbers, so larger integers are inexact
// even when the JSON parser could represent them as u64.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Pure native observations never establish complete invocation billing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeminiUsageObservation {
    NotProcessObservable,
    Incomplete,
    Native(GeminiNativeUsage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiNativeUsage {
    /// Keys from `stats.models`, NOT verified provider model identities.
    pub telemetry_models: BTreeMap<String, GeminiModelUsage>,
}

/// Exact producer fields; no summing across models or role sub-breakdowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiModelUsage {
    pub total_requests: u64,
    pub tokens: GeminiTokens,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeminiTokens {
    /// Uncached input: upstream computes max(0, prompt - cached).
    pub input: u64,
    /// Full prompt count, already including cached input.
    pub prompt: u64,
    pub candidates: u64,
    pub total: u64,
    pub cached: u64,
    pub thoughts: u64,
    pub tool: u64,
}

/// Observe a single bounded terminal document, not streaming JSON. The caller's
/// process/capture flags only downgrade observations; they grant no authority.
/// `Native` means structurally usable CLI counters, NOT proven complete usage:
/// upstream loses the distinction between absent metadata and measured zero.
pub fn observe_gemini_terminal_usage(
    bytes: &[u8],
    process_succeeded: bool,
    capture_truncated: bool,
) -> GeminiUsageObservation {
    if !process_succeeded || capture_truncated || bytes.len() > MAX_TERMINAL_BYTES {
        return GeminiUsageObservation::Incomplete;
    }
    if bytes.is_empty() {
        return GeminiUsageObservation::NotProcessObservable;
    }
    let Ok(UniqueJson(document)) = serde_json::from_slice(bytes) else {
        return GeminiUsageObservation::Incomplete;
    };
    observe_document(document).unwrap_or(GeminiUsageObservation::Incomplete)
}

fn observe_document(document: Value) -> Option<GeminiUsageObservation> {
    let object = document.as_object()?;
    if object.contains_key("error") || !object.get("response")?.is_string() {
        return None;
    }
    let Some(stats) = object.get("stats") else {
        return Some(GeminiUsageObservation::NotProcessObservable);
    };
    let models = stats.as_object()?.get("models")?.as_object()?;
    if models.is_empty() {
        return Some(GeminiUsageObservation::NotProcessObservable);
    }
    if models.len() > MAX_MODELS {
        return None;
    }
    let mut telemetry_models = BTreeMap::new();
    for (key, value) in models {
        if key.is_empty()
            || key.len() > 256
            || key.trim() != key
            || key.chars().any(char::is_control)
        {
            return None;
        }
        let api = value.get("api")?.as_object()?;
        let total_requests = safe_integer(api.get("totalRequests")?)?;
        if total_requests == 0 || safe_integer(api.get("totalErrors")?)? != 0 {
            return None;
        }
        let latency = api.get("totalLatencyMs")?.as_f64()?;
        if !latency.is_finite() || latency < 0.0 || latency > MAX_SAFE_INTEGER as f64 {
            return None;
        }
        let tokens: GeminiTokens = serde_json::from_value(value.get("tokens")?.clone()).ok()?;
        if [
            tokens.input,
            tokens.prompt,
            tokens.candidates,
            tokens.total,
            tokens.cached,
            tokens.thoughts,
            tokens.tool,
        ]
        .into_iter()
        .any(|count| count > MAX_SAFE_INTEGER)
            || tokens.cached > tokens.prompt
            || tokens.input.checked_add(tokens.cached)? != tokens.prompt
            || [
                tokens.prompt,
                tokens.candidates,
                tokens.thoughts,
                tokens.tool,
            ]
            .into_iter()
            .any(|count| count > tokens.total)
        {
            return None;
        }
        // Do not assert an invented additive identity between provider counters.
        // In particular input/cached are already included in prompt, and role
        // metrics repeat the model counters rather than adding another usage.
        telemetry_models.insert(
            key.clone(),
            GeminiModelUsage {
                total_requests,
                tokens,
            },
        );
    }
    Some(GeminiUsageObservation::Native(GeminiNativeUsage {
        telemetry_models,
    }))
}

fn safe_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|count| *count <= MAX_SAFE_INTEGER)
}

// Value's normal last-key-wins behavior would conceal duplicated models,
// counters or envelopes. Reject duplicates at every depth before interpretation.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = UniqueJson;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(
                    serde_json::Number::from_f64(value)
                        .ok_or_else(|| E::custom("nonfinite number"))?,
                )))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.into())))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Synthetic document in the installed 0.41.2 formatter/telemetry shape,
    // not a provider capture. Roles are overlapping breakdowns, not extra spend.
    const DOCUMENT: &str = r#"{
      "session_id":"local-shape-test", "response":"Inspected the supplied source.",
      "stats":{"models":{"gemini-request-or-version-key":{
        "api":{"totalRequests":2,"totalErrors":0,"totalLatencyMs":12.5},
        "tokens":{"input":70,"prompt":100,"candidates":20,"total":125,"cached":30,"thoughts":5,"tool":0},
        "roles":{"main":{"totalRequests":2,"totalErrors":0,"totalLatencyMs":12.5,
          "tokens":{"input":70,"prompt":100,"candidates":20,"total":125,"cached":30,"thoughts":5,"tool":0}}}
      }},"tools":{"totalCalls":0},"files":{"totalLinesAdded":0,"totalLinesRemoved":0}}
    }"#;

    fn observe(value: &Value) -> GeminiUsageObservation {
        observe_gemini_terminal_usage(&serde_json::to_vec(value).unwrap(), true, false)
    }

    #[test]
    fn native_json_preserves_model_keys_and_overlapping_native_counters() {
        let GeminiUsageObservation::Native(usage) =
            observe_gemini_terminal_usage(DOCUMENT.as_bytes(), true, false)
        else {
            panic!("native observation")
        };
        assert_eq!(usage.telemetry_models.len(), 1);
        let model = &usage.telemetry_models["gemini-request-or-version-key"];
        assert_eq!(model.total_requests, 2);
        assert_eq!(
            model.tokens,
            GeminiTokens {
                input: 70,
                prompt: 100,
                candidates: 20,
                total: 125,
                cached: 30,
                thoughts: 5,
                tool: 0
            }
        );
        let capabilities = crate::runtime_adapter::RuntimeId::GeminiCli.capabilities();
        assert_eq!(
            capabilities.usage_reporting,
            crate::runtime_adapter::UsageReporting::None
        );
        assert_eq!(
            capabilities.side_effect_confinement,
            crate::runtime_adapter::SideEffectConfinement::Unverified
        );
    }

    #[test]
    fn native_json_keeps_distinct_models_without_summing_or_resolving_identity() {
        let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
        let model = value["stats"]["models"]["gemini-request-or-version-key"].clone();
        value["stats"]["models"]["second-request-key"] = model;
        let GeminiUsageObservation::Native(usage) = observe(&value) else {
            panic!("native observation")
        };
        assert_eq!(usage.telemetry_models.len(), 2);
        assert!(usage
            .telemetry_models
            .values()
            .all(|m| m.tokens.total == 125));
    }

    #[test]
    fn native_json_missing_usage_is_not_observable_not_measured_zero() {
        for bytes in [
            b"".as_slice(),
            br#"{"response":"ok"}"#,
            br#"{"response":"ok","stats":{"models":{}}}"#,
        ] {
            assert_eq!(
                observe_gemini_terminal_usage(bytes, true, false),
                GeminiUsageObservation::NotProcessObservable
            );
        }
        let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
        value["stats"]["models"]["gemini-request-or-version-key"]
            .as_object_mut()
            .unwrap()
            .remove("tokens");
        assert_eq!(observe(&value), GeminiUsageObservation::Incomplete);
    }

    #[test]
    fn native_json_failed_or_truncated_capture_never_yields_native_usage() {
        for (success, truncated) in [(false, false), (true, true), (false, true)] {
            assert_eq!(
                observe_gemini_terminal_usage(DOCUMENT.as_bytes(), success, truncated),
                GeminiUsageObservation::Incomplete
            );
        }
        for error in [json!(null), json!({"type":"ApiError","message":"failed"})] {
            let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
            value["error"] = error;
            assert_eq!(observe(&value), GeminiUsageObservation::Incomplete);
        }
        let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
        value["stats"]["models"]["gemini-request-or-version-key"]["api"]["totalErrors"] = json!(1);
        assert_eq!(observe(&value), GeminiUsageObservation::Incomplete);
    }

    #[test]
    fn native_json_rejects_duplicates_at_envelope_model_and_counter_depths() {
        for (old, new) in [
            ("\"response\":", "\"response\":\"hidden\",\"response\":"),
            ("\"models\":{", "\"models\":{},\"models\":{"),
            ("\"input\":70", "\"input\":0,\"input\":70"),
            ("\"api\":{", "\"api\":{},\"api\":{"),
        ] {
            let bytes = DOCUMENT.replacen(old, new, 1);
            assert_eq!(
                observe_gemini_terminal_usage(bytes.as_bytes(), true, false),
                GeminiUsageObservation::Incomplete
            );
        }
        let value: Value = serde_json::from_str(DOCUMENT).unwrap();
        let model = &value["stats"]["models"]["gemini-request-or-version-key"];
        let duplicate = format!(
            r#"{{"response":"ok","stats":{{"models":{{"same":{model},"same":{model}}}}}}}"#
        );
        assert_eq!(
            observe_gemini_terminal_usage(duplicate.as_bytes(), true, false),
            GeminiUsageObservation::Incomplete
        );
    }

    #[test]
    fn native_json_rejects_invalid_overflow_and_inconsistent_counters() {
        for (key, bad) in [
            ("input", json!(-1)),
            ("prompt", json!("100")),
            ("candidates", json!(1.5)),
            ("cached", json!(101)),
            ("input", json!(71)),
            ("total", json!(99)),
            ("total", json!(u64::MAX)),
            ("total", json!(MAX_SAFE_INTEGER + 1)),
            ("tool", json!(null)),
        ] {
            let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
            value["stats"]["models"]["gemini-request-or-version-key"]["tokens"][key] = bad;
            assert_eq!(observe(&value), GeminiUsageObservation::Incomplete, "{key}");
        }
        let overflow = DOCUMENT.replace("\"total\":125", "\"total\":18446744073709551616");
        assert_eq!(
            observe_gemini_terminal_usage(overflow.as_bytes(), true, false),
            GeminiUsageObservation::Incomplete
        );
    }

    #[test]
    fn native_json_rejects_malformed_streaming_and_oversized_documents() {
        for bytes in [
            b"not json".as_slice(),
            b"{",
            b"[]",
            br#"{"response":"ok"} {"response":"second"}"#,
            br#"{"type":"result","status":"success","stats":{"total_tokens":125}}"#,
        ] {
            assert_eq!(
                observe_gemini_terminal_usage(bytes, true, false),
                GeminiUsageObservation::Incomplete
            );
        }
        assert_eq!(
            observe_gemini_terminal_usage(&vec![b' '; MAX_TERMINAL_BYTES + 1], true, false),
            GeminiUsageObservation::Incomplete
        );
        let mut value: Value = serde_json::from_str(DOCUMENT).unwrap();
        let model = value["stats"]["models"]["gemini-request-or-version-key"].clone();
        value["stats"]["models"] = Value::Object(
            (0..=MAX_MODELS)
                .map(|i| (format!("model-{i}"), model.clone()))
                .collect(),
        );
        assert_eq!(observe(&value), GeminiUsageObservation::Incomplete);
    }
}

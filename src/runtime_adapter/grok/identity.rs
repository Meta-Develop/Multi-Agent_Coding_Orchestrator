//! Identity projection from native terminal metadata. Requested controls and
//! arbitrary text/tool output never supply served identity.

use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

/// Descriptive projection of an owned streaming-json terminal. Wire copies do
/// not recreate the private usage observation or authorize publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrokServedIdentityEvidence {
    pub source: GrokIdentitySource,
    pub observed_models: Vec<String>,
    /// Grok 1.0.60 has no observed-effort field in this protocol. Always null
    /// for native observations; neither argv nor model suffixes fill this gap.
    pub observed_effort: Option<String>,
    /// Completeness of the model projection only; effort can still be unknown.
    pub model_observation_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrokIdentitySource {
    #[serde(rename = "streaming_json_end_model_usage_keys")]
    TerminalModelUsageKeys,
}

impl GrokServedIdentityEvidence {
    pub(crate) fn from_terminal(line: &[u8], stream_complete: bool) -> Self {
        #[derive(Deserialize)]
        struct Terminal {
            #[serde(default, rename = "modelUsage")]
            model_usage: Option<ModelUsageKeys>,
        }
        let projected = serde_json::from_slice::<Terminal>(line);
        let (models, valid) = match projected {
            Ok(Terminal {
                model_usage: Some(models),
            }) => (models.0, true),
            _ => (Vec::new(), false),
        };
        Self {
            source: GrokIdentitySource::TerminalModelUsageKeys,
            observed_models: models,
            observed_effort: None,
            model_observation_complete: stream_complete && valid,
        }
    }

    pub(crate) fn publication_refusal(
        &self,
        requested_model: Option<&str>,
        requested_effort: Option<&str>,
    ) -> Option<&'static str> {
        if !self.model_observation_complete || self.observed_models.is_empty() {
            return Some("Grok served model identity is missing or incomplete");
        }
        if self.observed_models.len() != 1 {
            return Some("Grok served model identity is ambiguous");
        }
        if !requested_model
            .is_some_and(|model| served_model_matches(model, &self.observed_models[0]))
        {
            return Some("Grok served model does not match the admitted request under the qualified label mapping");
        }
        if !requested_effort.is_some_and(canonical_effort) {
            return Some("Grok admitted effort is missing or unknown");
        }
        match self.observed_effort.as_deref() {
            // Preserve the existing standard headless xhigh contracts. This is
            // an evidence gate, not selection eligibility: new model/effort
            // lanes (including #688 low) still require observed effort.
            None if matches!(
                (requested_model, requested_effort),
                (Some("grok-4.6" | "grok-4.7"), Some("xhigh"))
            ) => None,
            None => Some("Grok served effort is unknown; qualification-only writable lanes require observed effort (#688)"),
            Some(effort) if !canonical_effort(effort) => Some("Grok served effort is unknown"),
            Some(effort) if Some(effort) != requested_effort => {
                Some("Grok served effort does not match the admitted request")
            }
            Some(_) => None,
        }
    }
}

// Explicit receipt-backed label equivalences, not a suffix normalization rule.
// 4.6: CLI 1.0.60 retained terminal digest ef06c217147682fb3e1d8e29bc4c511b8bd401fb29c916cde06c0f6af8d5a3a2.
// 4.7: https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/616#issuecomment-5827977323
// See docs/qualification/grok-lower-effort.md for scope and provenance.
const MODEL_LABELS: [(&str, &str); 2] = [
    ("grok-4.6", "grok-4.6-build"),
    ("grok-4.7", "grok-4.7-build"),
];

pub(crate) fn served_model_matches(requested: &str, observed: &str) -> bool {
    MODEL_LABELS.iter().any(|(standard, build)| {
        [*standard, *build].contains(&requested) && [*standard, *build].contains(&observed)
    })
}

fn canonical_effort(effort: &str) -> bool {
    matches!(
        effort,
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
    )
}

/// Keep repeated map keys rather than silently collapsing an ambiguous model
/// observation. Only bounded slug labels are retained; entry contents are ignored.
struct ModelUsageKeys(Vec<String>);

impl<'de> Deserialize<'de> for ModelUsageKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ModelUsageKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a native modelUsage object")
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut models = Vec::new();
                while let Some((model, _)) =
                    map.next_entry::<String, BTreeMap<String, de::IgnoredAny>>()?
                {
                    if models.len() >= super::GROK_CATALOG_MAX_MODELS
                        || model.is_empty()
                        || model.len() > super::GROK_MODEL_SLUG_MAX_BYTES
                        || !model.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                    {
                        return Err(de::Error::custom("invalid native modelUsage label"));
                    }
                    models.push(model);
                }
                Ok(ModelUsageKeys(models))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity(models: serde_json::Value) -> GrokServedIdentityEvidence {
        GrokServedIdentityEvidence::from_terminal(
            &serde_json::to_vec(&json!({"modelUsage": models})).unwrap(),
            true,
        )
    }

    #[test]
    fn retained_cli_projection_preserves_exact_model_and_unknown_effort() {
        let projection: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/runtime_adapter/grok/headless-cli-1.0.60-identity.json"
        ))
        .unwrap();
        // Construct metadata from a field-name-only retained projection, not a
        // claimed complete native stream or an invented served-effort receipt.
        let model = projection["model_usage_keys"][0].as_str().unwrap();
        let observed = identity(json!({model: {}}));
        assert_eq!(observed.observed_models, ["grok-4.6-build"]);
        assert_eq!(observed.observed_effort, None);
        let wire = serde_json::to_value(&observed).unwrap();
        assert_eq!(wire["observed_effort"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_value::<GrokServedIdentityEvidence>(wire).unwrap(),
            observed
        );
        assert!(observed
            .publication_refusal(Some(model), Some("low"))
            .unwrap()
            .contains("served effort is unknown"));
    }

    #[test]
    fn receipt_backed_labels_preserve_existing_xhigh_unknown_effort() {
        for (standard, build) in MODEL_LABELS {
            for label in [standard, build] {
                let observed = identity(json!({label: {}}));
                assert!(observed
                    .publication_refusal(Some(standard), Some("xhigh"))
                    .is_none());
                assert_eq!(observed.observed_models, [label]);
                assert_eq!(observed.observed_effort, None);
                assert!(served_model_matches(build, standard));
            }
        }
        for label in [
            "grok-4.7-build",
            "grok-4.6-build-fast",
            "grok-4.6-build-build",
            "unknown",
        ] {
            assert!(identity(json!({label: {}}))
                .publication_refusal(Some("grok-4.6"), Some("xhigh"))
                .unwrap()
                .contains("does not match"));
        }
        assert!(!served_model_matches("unknown", "unknown"));
    }

    #[test]
    fn qualification_only_lanes_require_observed_effort() {
        let observed = identity(json!({"grok-4.6-build": {}}));
        for effort in ["none", "minimal", "low", "medium", "high", "max"] {
            assert!(observed
                .publication_refusal(Some("grok-4.6"), Some(effort))
                .unwrap()
                .contains("qualification-only"));
        }
        // A newly requested label is not grandfathered by the model mapping.
        assert!(observed
            .publication_refusal(Some("grok-4.6-build"), Some("xhigh"))
            .unwrap()
            .contains("qualification-only"));
    }

    #[test]
    fn served_identity_rejects_missing_mismatched_and_ambiguous_models() {
        for terminal in [
            json!({}),
            json!({"modelUsage": null}),
            json!({"modelUsage": []}),
        ] {
            let observed = GrokServedIdentityEvidence::from_terminal(
                &serde_json::to_vec(&terminal).unwrap(),
                true,
            );
            assert!(observed
                .publication_refusal(Some("grok-4.6"), Some("xhigh"))
                .is_some());
        }
        for models in [
            json!({}),
            json!({"grok-4.7": {}}),
            json!({"grok-4.6-build-fast": {}}),
            json!({"grok-4.6": {}, "grok-4.6-build": {}}),
            json!({"grok-4.6": {}, "grok-4.7": {}}),
        ] {
            assert!(identity(models)
                .publication_refusal(Some("grok-4.6"), Some("xhigh"))
                .is_some());
        }
        let duplicate = GrokServedIdentityEvidence::from_terminal(
            br#"{"modelUsage":{"grok-4.6":{},"grok-4.6":{}}}"#,
            true,
        );
        assert_eq!(duplicate.observed_models.len(), 2);
        assert!(duplicate
            .publication_refusal(Some("grok-4.6"), Some("xhigh"))
            .unwrap()
            .contains("ambiguous"));
    }

    #[test]
    fn served_identity_rejects_mismatched_unknown_and_aliased_effort() {
        let mut synthetic = identity(json!({"grok-4.6": {}}));
        // Comparison regression only. Native parsing cannot create this value:
        // no effort field is qualified for this CLI's streaming-json protocol.
        synthetic.observed_effort = Some("xhigh".into());
        assert!(synthetic
            .publication_refusal(Some("grok-4.6"), Some("low"))
            .unwrap()
            .contains("does not match"));
        for effort in ["deep", "unknown", "LOW", ""] {
            synthetic.observed_effort = Some(effort.into());
            assert!(synthetic
                .publication_refusal(Some("grok-4.6"), Some("low"))
                .unwrap()
                .contains("unknown"));
            assert!(synthetic
                .publication_refusal(Some("grok-4.6"), Some("xhigh"))
                .unwrap()
                .contains("unknown"));
            assert!(synthetic
                .publication_refusal(Some("grok-4.6"), Some(effort))
                .is_some());
        }
        assert!(synthetic
            .publication_refusal(Some("grok-4.6"), None)
            .is_some());
        synthetic.observed_effort = Some("low".into());
        assert!(synthetic
            .publication_refusal(Some("grok-4.6"), Some("xhigh"))
            .unwrap()
            .contains("does not match"));
        assert!(synthetic
            .publication_refusal(Some("grok-4.6"), Some("low"))
            .is_none());
    }

    #[test]
    fn unqualified_fields_truncation_and_malformed_labels_cannot_supply_identity() {
        for terminal in [
            json!({"model":"grok-4.6","effort":"low"}),
            json!({"modelUsage":{"grok-4.6":{}},"reasoning_effort":"low"}),
            json!({"modelUsage":{"grok-4.6":{}},"effort":"low"}),
            json!({"modelUsage":{"invalid label":{}}}),
            json!({"modelUsage":{"grok-4.6":null}}),
        ] {
            let observed = GrokServedIdentityEvidence::from_terminal(
                &serde_json::to_vec(&terminal).unwrap(),
                true,
            );
            assert_eq!(observed.observed_effort, None);
            assert!(observed
                .publication_refusal(Some("grok-4.6"), Some("low"))
                .is_some());
        }
        let truncated =
            GrokServedIdentityEvidence::from_terminal(br#"{"modelUsage":{"grok-4.6":{}}}"#, false);
        assert!(!truncated.model_observation_complete);
        assert!(truncated
            .publication_refusal(Some("grok-4.6"), Some("low"))
            .is_some());
        let duplicate_field = GrokServedIdentityEvidence::from_terminal(
            br#"{"modelUsage":{},"modelUsage":{"grok-4.6":{}}}"#,
            true,
        );
        assert!(!duplicate_field.model_observation_complete);
    }
}

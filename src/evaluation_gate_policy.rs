//! Gate-policy evaluation corpus for Issue #26.
//!
//! Materializes a versioned labeled corpus from allowlisted raw rows. Evidence
//! is synthetic/fake and ineligible for production defaults.

use crate::{artifacts::state_auth::sha256_hex, evaluation::EvaluationError, llm::Redactor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const GATE_POLICY_RAW_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const GATE_POLICY_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const GATE_POLICY_SOURCE_PROVENANCE_SCHEMA_VERSION: u32 = 1;
pub const MAX_GATE_POLICY_CASES: usize = 10_000;
const MAX_GATE_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGatePolicyCorpus {
    pub raw_source_version: u32,
    pub corpus_version: u32,
    pub policy_version: u32,
    pub label_version: u32,
    pub redaction_version: u32,
    pub materialization_version: u32,
    pub corpus_id: String,
    pub cases: Vec<RawGatePolicyCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGatePolicyCase {
    pub user_intent: String,
    pub proposed_action: String,
    pub permitted_read_only_context: String,
    pub expected_decision: GatePolicyDecision,
    pub category: GatePolicyCaseCategory,
    pub source: GatePolicySourceBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicyDecision {
    Allow,
    Block,
    HumanReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicyCaseCategory {
    PermittedReadOnly,
    RequiresHumanReview,
    SecretRead,
    ProductionData,
    UntrustedInstruction,
    ClaimEscape,
    HighImpactSideEffect,
    ClassifierTimeout,
    ClassifierParseFailure,
    ClassifierProtocolFailure,
    MalformedToolCall,
    EnvironmentFailure,
    SandboxFailure,
    GateDenial,
    DeferredRequiredEdit,
    RewardHackingSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicySourceKind {
    SyntheticAuthored,
    RegressionFixture,
    RetainedFailure,
    RedactedJournal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicyPrivacyDisposition {
    SyntheticProjectOwned,
    RedactedBeforeIngest,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicyLicensingDisposition {
    ProjectOwned,
    ApprovedForEvaluation,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatePolicySourceBinding {
    pub provenance_version: u32,
    pub kind: GatePolicySourceKind,
    pub privacy: GatePolicyPrivacyDisposition,
    pub licensing: GatePolicyLicensingDisposition,
    pub source_id: String,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatePolicyCorpusCase {
    pub user_intent: String,
    pub proposed_action: String,
    pub permitted_read_only_context: String,
    pub expected_decision: GatePolicyDecision,
    pub category: GatePolicyCaseCategory,
    pub sources: Vec<GatePolicySourceBinding>,
    pub occurrence_count: u32,
    pub semantic_digest: String,
    pub binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatePolicyCorpus {
    pub version: u32,
    pub policy_version: u32,
    pub label_version: u32,
    pub redaction_version: u32,
    pub materialization_version: u32,
    pub corpus_id: String,
    pub cases: Vec<GatePolicyCorpusCase>,
    pub binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct GatePolicySemanticKey {
    version: u32,
    policy_version: u32,
    label_version: u32,
    redaction_version: u32,
    materialization_version: u32,
    user_intent: String,
    proposed_action: String,
    permitted_read_only_context: String,
    category: GatePolicyCaseCategory,
}

#[derive(Serialize)]
struct GatePolicyLabeledBinding<'a> {
    semantic: &'a GatePolicySemanticKey,
    expected_decision: GatePolicyDecision,
}

#[derive(Serialize)]
struct GatePolicySourceDigestBinding<'a> {
    semantic_digest: &'a str,
    sources: &'a [GatePolicySourceBinding],
    occurrence_count: u32,
}

struct PendingGatePolicyCase {
    key: GatePolicySemanticKey,
    expected_decision: GatePolicyDecision,
    sources: Vec<GatePolicySourceBinding>,
}

impl GatePolicyCorpus {
    pub fn validate(&self) -> Result<(), EvaluationError> {
        if self.version != GATE_POLICY_CORPUS_SCHEMA_VERSION {
            return Err(invalid_gate_corpus(
                "version",
                format!(
                    "unsupported version {}; supported version is {GATE_POLICY_CORPUS_SCHEMA_VERSION}",
                    self.version
                ),
            ));
        }
        validate_gate_versions(
            self.policy_version,
            self.label_version,
            self.redaction_version,
            self.materialization_version,
        )?;
        validate_gate_text("corpus_id", &self.corpus_id)?;
        if self.cases.is_empty() || self.cases.len() > MAX_GATE_POLICY_CASES {
            return Err(invalid_gate_corpus(
                "cases",
                format!("must contain between 1 and {MAX_GATE_POLICY_CASES} cases"),
            ));
        }
        let mut categories = BTreeSet::new();
        let mut source_coordinates = BTreeSet::new();
        let mut previous_digest: Option<&str> = None;
        for case in &self.cases {
            validate_gate_text("cases.user_intent", &case.user_intent)?;
            validate_gate_text("cases.proposed_action", &case.proposed_action)?;
            validate_gate_text(
                "cases.permitted_read_only_context",
                &case.permitted_read_only_context,
            )?;
            if previous_digest.is_some_and(|previous| previous >= case.semantic_digest.as_str()) {
                return Err(invalid_gate_corpus(
                    "cases",
                    "must be strictly ordered by semantic_digest without duplicates",
                ));
            }
            previous_digest = Some(&case.semantic_digest);
            if case.sources.is_empty()
                || case.occurrence_count as usize != case.sources.len()
                || !is_strictly_sorted(&case.sources)
            {
                return Err(invalid_gate_corpus(
                    "cases.sources",
                    "must be nonempty, strictly sorted, unique, and match occurrence_count",
                ));
            }
            for source in &case.sources {
                validate_gate_source(source)?;
                if !source_coordinates.insert((
                    source.source_id.as_str(),
                    source.line_start,
                    source.line_end,
                )) {
                    return Err(invalid_gate_corpus(
                        "cases.source",
                        "source coordinates must be globally unique independent of provenance metadata",
                    ));
                }
            }
            categories.insert(case.category);
            let key = GatePolicySemanticKey {
                version: self.version,
                policy_version: self.policy_version,
                label_version: self.label_version,
                redaction_version: self.redaction_version,
                materialization_version: self.materialization_version,
                user_intent: case.user_intent.clone(),
                proposed_action: case.proposed_action.clone(),
                permitted_read_only_context: case.permitted_read_only_context.clone(),
                category: case.category,
            };
            let semantic_digest = gate_digest(&GatePolicyLabeledBinding {
                semantic: &key,
                expected_decision: case.expected_decision,
            })?;
            if semantic_digest != case.semantic_digest {
                return Err(invalid_gate_corpus(
                    "cases.semantic_digest",
                    "does not bind the post-redaction semantic case and all policy versions",
                ));
            }
            let binding_digest = gate_digest(&GatePolicySourceDigestBinding {
                semantic_digest: &semantic_digest,
                sources: &case.sources,
                occurrence_count: case.occurrence_count,
            })?;
            if binding_digest != case.binding_digest {
                return Err(invalid_gate_corpus(
                    "cases.binding_digest",
                    "does not bind the semantic digest, sources, and occurrence count",
                ));
            }
        }
        if categories != required_gate_categories() {
            return Err(invalid_gate_corpus(
                "cases.category",
                "must cover every required positive and retained-negative category exactly through the typed vocabulary",
            ));
        }
        if gate_corpus_binding_digest(self)? != self.binding_digest {
            return Err(invalid_gate_corpus(
                "binding_digest",
                "does not bind the canonical post-redaction corpus",
            ));
        }
        Ok(())
    }
}

pub fn materialize_gate_policy_corpus(
    raw: RawGatePolicyCorpus,
    redactor: &Redactor,
) -> Result<GatePolicyCorpus, EvaluationError> {
    if raw.raw_source_version != GATE_POLICY_RAW_CORPUS_SCHEMA_VERSION {
        return Err(invalid_gate_corpus(
            "raw_source_version",
            format!(
                "unsupported version {}; supported version is {GATE_POLICY_RAW_CORPUS_SCHEMA_VERSION}",
                raw.raw_source_version
            ),
        ));
    }
    if raw.corpus_version != GATE_POLICY_CORPUS_SCHEMA_VERSION {
        return Err(invalid_gate_corpus(
            "corpus_version",
            format!(
                "unsupported version {}; supported version is {GATE_POLICY_CORPUS_SCHEMA_VERSION}",
                raw.corpus_version
            ),
        ));
    }
    validate_gate_versions(
        raw.policy_version,
        raw.label_version,
        raw.redaction_version,
        raw.materialization_version,
    )?;
    if raw.cases.is_empty() || raw.cases.len() > MAX_GATE_POLICY_CASES {
        return Err(invalid_gate_corpus(
            "cases",
            format!("must contain between 1 and {MAX_GATE_POLICY_CASES} source rows"),
        ));
    }
    let corpus_id = redact_gate_text(redactor, "corpus_id", &raw.corpus_id)?;
    let mut by_semantic: BTreeMap<GatePolicySemanticKey, PendingGatePolicyCase> = BTreeMap::new();
    let mut labels: BTreeMap<GatePolicySemanticKey, GatePolicyDecision> = BTreeMap::new();
    let mut source_coordinates = BTreeSet::new();

    for raw_case in raw.cases {
        let source = GatePolicySourceBinding {
            provenance_version: raw_case.source.provenance_version,
            kind: raw_case.source.kind,
            privacy: raw_case.source.privacy,
            licensing: raw_case.source.licensing,
            source_id: redact_gate_text(
                redactor,
                "cases.source.source_id",
                &raw_case.source.source_id,
            )?,
            line_start: raw_case.source.line_start,
            line_end: raw_case.source.line_end,
        };
        validate_gate_source(&source)?;
        if !source_coordinates.insert((
            source.source_id.clone(),
            source.line_start,
            source.line_end,
        )) {
            return Err(invalid_gate_corpus(
                "cases.source",
                "duplicate source coordinate is not a distinct occurrence",
            ));
        }
        let key = GatePolicySemanticKey {
            version: raw.corpus_version,
            policy_version: raw.policy_version,
            label_version: raw.label_version,
            redaction_version: raw.redaction_version,
            materialization_version: raw.materialization_version,
            user_intent: redact_gate_text(redactor, "cases.user_intent", &raw_case.user_intent)?,
            proposed_action: redact_gate_text(
                redactor,
                "cases.proposed_action",
                &raw_case.proposed_action,
            )?,
            permitted_read_only_context: redact_gate_text(
                redactor,
                "cases.permitted_read_only_context",
                &raw_case.permitted_read_only_context,
            )?,
            category: raw_case.category,
        };
        if labels
            .get(&key)
            .is_some_and(|label| *label != raw_case.expected_decision)
        {
            return Err(invalid_gate_corpus(
                "cases.expected_decision",
                "conflicting labels for an identical post-redaction semantic case",
            ));
        }
        labels.insert(key.clone(), raw_case.expected_decision);
        by_semantic
            .entry(key.clone())
            .and_modify(|pending| pending.sources.push(source.clone()))
            .or_insert(PendingGatePolicyCase {
                key,
                expected_decision: raw_case.expected_decision,
                sources: vec![source],
            });
    }

    let mut cases = Vec::with_capacity(by_semantic.len());
    for (_, mut pending) in by_semantic {
        pending.sources.sort();
        let occurrence_count = u32::try_from(pending.sources.len()).map_err(|_| {
            invalid_gate_corpus(
                "cases.occurrence_count",
                "source occurrence count exceeds u32",
            )
        })?;
        let semantic_digest = gate_digest(&GatePolicyLabeledBinding {
            semantic: &pending.key,
            expected_decision: pending.expected_decision,
        })?;
        let binding_digest = gate_digest(&GatePolicySourceDigestBinding {
            semantic_digest: &semantic_digest,
            sources: &pending.sources,
            occurrence_count,
        })?;
        cases.push(GatePolicyCorpusCase {
            user_intent: pending.key.user_intent,
            proposed_action: pending.key.proposed_action,
            permitted_read_only_context: pending.key.permitted_read_only_context,
            expected_decision: pending.expected_decision,
            category: pending.key.category,
            sources: pending.sources,
            occurrence_count,
            semantic_digest,
            binding_digest,
        });
    }
    cases.sort_by(|left, right| left.semantic_digest.cmp(&right.semantic_digest));
    let mut corpus = GatePolicyCorpus {
        version: raw.corpus_version,
        policy_version: raw.policy_version,
        label_version: raw.label_version,
        redaction_version: raw.redaction_version,
        materialization_version: raw.materialization_version,
        corpus_id,
        cases,
        binding_digest: String::new(),
    };
    corpus.binding_digest = gate_corpus_binding_digest(&corpus)?;
    corpus.validate()?;
    Ok(corpus)
}

#[derive(Serialize)]
struct GatePolicyCorpusDigestBinding<'a> {
    version: u32,
    policy_version: u32,
    label_version: u32,
    redaction_version: u32,
    materialization_version: u32,
    corpus_id: &'a str,
    cases: &'a [GatePolicyCorpusCase],
}

fn gate_corpus_binding_digest(corpus: &GatePolicyCorpus) -> Result<String, EvaluationError> {
    gate_digest(&GatePolicyCorpusDigestBinding {
        version: corpus.version,
        policy_version: corpus.policy_version,
        label_version: corpus.label_version,
        redaction_version: corpus.redaction_version,
        materialization_version: corpus.materialization_version,
        corpus_id: &corpus.corpus_id,
        cases: &corpus.cases,
    })
}

fn required_gate_categories() -> BTreeSet<GatePolicyCaseCategory> {
    use GatePolicyCaseCategory::*;
    BTreeSet::from([
        PermittedReadOnly,
        RequiresHumanReview,
        SecretRead,
        ProductionData,
        UntrustedInstruction,
        ClaimEscape,
        HighImpactSideEffect,
        ClassifierTimeout,
        ClassifierParseFailure,
        ClassifierProtocolFailure,
        MalformedToolCall,
        EnvironmentFailure,
        SandboxFailure,
        GateDenial,
        DeferredRequiredEdit,
        RewardHackingSignal,
    ])
}

fn validate_gate_versions(
    policy_version: u32,
    label_version: u32,
    redaction_version: u32,
    materialization_version: u32,
) -> Result<(), EvaluationError> {
    for (field, version) in [
        ("policy_version", policy_version),
        ("label_version", label_version),
        ("redaction_version", redaction_version),
        ("materialization_version", materialization_version),
    ] {
        if version == 0 {
            return Err(invalid_gate_corpus(field, "must be greater than zero"));
        }
    }
    Ok(())
}

fn validate_gate_text(field: &str, value: &str) -> Result<(), EvaluationError> {
    if value.trim().is_empty() {
        return Err(invalid_gate_corpus(
            field,
            "must not be empty or whitespace-only",
        ));
    }
    if value.len() > MAX_GATE_TEXT_BYTES {
        return Err(invalid_gate_corpus(
            field,
            format!("must not exceed {MAX_GATE_TEXT_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

fn validate_gate_source(source: &GatePolicySourceBinding) -> Result<(), EvaluationError> {
    if source.provenance_version != GATE_POLICY_SOURCE_PROVENANCE_SCHEMA_VERSION {
        return Err(invalid_gate_corpus(
            "cases.source.provenance_version",
            format!(
                "unsupported version {}; supported version is {GATE_POLICY_SOURCE_PROVENANCE_SCHEMA_VERSION}",
                source.provenance_version
            ),
        ));
    }
    let permitted_provenance = match source.kind {
        GatePolicySourceKind::RedactedJournal => {
            source.privacy == GatePolicyPrivacyDisposition::RedactedBeforeIngest
                && source.licensing == GatePolicyLicensingDisposition::ApprovedForEvaluation
        }
        GatePolicySourceKind::SyntheticAuthored
        | GatePolicySourceKind::RegressionFixture
        | GatePolicySourceKind::RetainedFailure => {
            source.privacy == GatePolicyPrivacyDisposition::SyntheticProjectOwned
                && source.licensing == GatePolicyLicensingDisposition::ProjectOwned
        }
    };
    if !permitted_provenance {
        return Err(invalid_gate_corpus(
            "cases.source.provenance",
            "source is refused or has a privacy/licensing disposition inconsistent with its source kind",
        ));
    }
    validate_gate_text("cases.source.source_id", &source.source_id)?;
    if source.line_start == 0 || source.line_end < source.line_start {
        return Err(invalid_gate_corpus(
            "cases.source",
            "line coordinates must be one-based and line_end must not precede line_start",
        ));
    }
    Ok(())
}

fn redact_gate_text(
    redactor: &Redactor,
    field: &str,
    value: &str,
) -> Result<String, EvaluationError> {
    let redacted = redactor.redact(value).text;
    validate_gate_text(field, &redacted)?;
    Ok(redacted)
}

fn gate_digest(value: &impl Serialize) -> Result<String, EvaluationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        invalid_gate_corpus(
            "binding_digest",
            format!("cannot serialize canonical binding: {error}"),
        )
    })?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn invalid_gate_corpus(field: impl Into<String>, message: impl Into<String>) -> EvaluationError {
    EvaluationError::InvalidGatePolicyCorpus {
        field: field.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_FIXTURE: &str =
        include_str!("../tests/fixtures/model_mix_evaluation/gate-policy-raw-v1.json");
    const CORPUS_FIXTURE: &str =
        include_str!("../tests/fixtures/model_mix_evaluation/gate-policy-corpus-v1.json");

    #[test]
    fn committed_raw_fixture_materializes_to_the_committed_corpus() {
        let raw: RawGatePolicyCorpus =
            serde_json::from_str(RAW_FIXTURE).expect("parse raw fixture");
        assert_eq!(raw.cases.len(), 17);
        let corpus =
            materialize_gate_policy_corpus(raw, &Redactor::new()).expect("materialize corpus");
        assert_eq!(corpus.cases.len(), 16);
        let committed: GatePolicyCorpus =
            serde_json::from_str(CORPUS_FIXTURE).expect("parse committed corpus");
        assert_eq!(corpus, committed);
        corpus.validate().expect("committed corpus validates");
        let categories = corpus
            .cases
            .iter()
            .map(|case| case.category)
            .collect::<BTreeSet<_>>();
        assert_eq!(categories, required_gate_categories());
    }

    #[test]
    fn conflicting_labels_for_the_same_semantic_case_fail_closed() {
        let mut raw: RawGatePolicyCorpus =
            serde_json::from_str(RAW_FIXTURE).expect("parse raw fixture");
        raw.cases[1].expected_decision = GatePolicyDecision::Block;
        let error =
            materialize_gate_policy_corpus(raw, &Redactor::new()).expect_err("conflicting labels");
        assert!(error
            .to_string()
            .contains("conflicting labels for an identical post-redaction semantic case"));
    }
}

//! Shared design-decision claims and contradiction detection.
//!
//! [`DecisionRegistry`] is intentionally an in-memory coordination substrate. Its validated
//! [`DecisionRegistrySnapshot`] boundary is the persistence seam for a future repository-bound,
//! authenticated snapshot store like the existing semantic coordination store.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

pub const MAX_DECISION_QUESTION_KEY_BYTES: usize = 256;
pub const MAX_DECISION_QUESTION_BYTES: usize = 16 * 1024;
pub const MAX_DECISION_ASSIGNMENT_BYTES: usize = 128;
pub const MAX_DECISION_RESOLUTION_BYTES: usize = 16 * 1024;
pub const MAX_DECISION_SCOPE_KEY_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionClaimStatus {
    Open,
    Resolved,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionClaim {
    question_key: String,
    question: String,
    owning_assignment: String,
    status: DecisionClaimStatus,
    resolution: Option<String>,
}

impl DecisionClaim {
    pub fn question_key(&self) -> &str {
        &self.question_key
    }

    pub fn question(&self) -> &str {
        &self.question
    }

    pub fn owning_assignment(&self) -> &str {
        &self.owning_assignment
    }

    pub fn status(&self) -> DecisionClaimStatus {
        self.status
    }

    pub fn resolution(&self) -> Option<&str> {
        self.resolution.as_deref()
    }

    fn open(
        question_key: impl AsRef<str>,
        question: impl AsRef<str>,
        owning_assignment: impl AsRef<str>,
    ) -> Result<Self> {
        Ok(Self {
            question_key: normalize_stable_key(
                question_key.as_ref(),
                DecisionInputField::QuestionKey,
                MAX_DECISION_QUESTION_KEY_BYTES,
            )?,
            question: normalize_text(
                question.as_ref(),
                DecisionInputField::Question,
                MAX_DECISION_QUESTION_BYTES,
            )?,
            owning_assignment: normalize_stable_key(
                owning_assignment.as_ref(),
                DecisionInputField::Assignment,
                MAX_DECISION_ASSIGNMENT_BYTES,
            )?,
            status: DecisionClaimStatus::Open,
            resolution: None,
        })
    }

    fn validate(self) -> Result<Self> {
        let question_key = normalize_stable_key(
            &self.question_key,
            DecisionInputField::QuestionKey,
            MAX_DECISION_QUESTION_KEY_BYTES,
        )?;
        let question = normalize_text(
            &self.question,
            DecisionInputField::Question,
            MAX_DECISION_QUESTION_BYTES,
        )?;
        let owning_assignment = normalize_stable_key(
            &self.owning_assignment,
            DecisionInputField::Assignment,
            MAX_DECISION_ASSIGNMENT_BYTES,
        )?;
        let resolution = self
            .resolution
            .as_deref()
            .map(normalize_resolution)
            .transpose()?;

        match (self.status, resolution.as_ref()) {
            (DecisionClaimStatus::Open, Some(_)) => {
                return Err(DecisionClaimError::InvalidClaimState {
                    status: self.status,
                    message: "an open claim cannot carry a resolution",
                });
            }
            (DecisionClaimStatus::Resolved, None) => {
                return Err(DecisionClaimError::InvalidClaimState {
                    status: self.status,
                    message: "a resolved claim must carry a resolution",
                });
            }
            (DecisionClaimStatus::Open, None)
            | (DecisionClaimStatus::Resolved, Some(_))
            | (DecisionClaimStatus::Superseded, _) => {}
        }

        Ok(Self {
            question_key,
            question,
            owning_assignment,
            status: self.status,
            resolution,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionScope {
    pub modules: BTreeSet<String>,
    pub symbols: BTreeSet<String>,
    pub topics: BTreeSet<String>,
}

impl DecisionScope {
    pub fn new(
        modules: impl IntoIterator<Item = String>,
        symbols: impl IntoIterator<Item = String>,
        topics: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let scope = Self {
            modules: normalize_scope_keys(modules, DecisionInputField::ModuleScopeKey)?,
            symbols: normalize_scope_keys(symbols, DecisionInputField::SymbolScopeKey)?,
            topics: normalize_scope_keys(topics, DecisionInputField::TopicScopeKey)?,
        };
        if scope.is_empty() {
            return Err(DecisionClaimError::EmptyScope);
        }
        Ok(scope)
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty() && self.symbols.is_empty() && self.topics.is_empty()
    }

    fn intersection(&self, other: &Self) -> Self {
        Self {
            modules: self.modules.intersection(&other.modules).cloned().collect(),
            symbols: self.symbols.intersection(&other.symbols).cloned().collect(),
            topics: self.topics.intersection(&other.topics).cloned().collect(),
        }
    }

    fn validate(self) -> Result<Self> {
        Self::new(self.modules, self.symbols, self.topics)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    question_key: String,
    resolution: String,
    deciding_assignment: String,
    scope: DecisionScope,
}

impl DecisionRecord {
    pub fn new(
        question_key: impl AsRef<str>,
        resolution: impl AsRef<str>,
        deciding_assignment: impl AsRef<str>,
        scope: DecisionScope,
    ) -> Result<Self> {
        Ok(Self {
            question_key: normalize_stable_key(
                question_key.as_ref(),
                DecisionInputField::QuestionKey,
                MAX_DECISION_QUESTION_KEY_BYTES,
            )?,
            resolution: normalize_resolution(resolution.as_ref())?,
            deciding_assignment: normalize_stable_key(
                deciding_assignment.as_ref(),
                DecisionInputField::Assignment,
                MAX_DECISION_ASSIGNMENT_BYTES,
            )?,
            scope: scope.validate()?,
        })
    }

    pub fn question_key(&self) -> &str {
        &self.question_key
    }

    pub fn resolution(&self) -> &str {
        &self.resolution
    }

    pub fn deciding_assignment(&self) -> &str {
        &self.deciding_assignment
    }

    pub fn scope(&self) -> &DecisionScope {
        &self.scope
    }

    fn validate(self) -> Result<Self> {
        Self::new(
            self.question_key,
            self.resolution,
            self.deciding_assignment,
            self.scope,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecordIdentity {
    pub question_key: String,
    pub deciding_assignment: String,
}

impl From<&DecisionRecord> for DecisionRecordIdentity {
    fn from(record: &DecisionRecord) -> Self {
        Self {
            question_key: record.question_key.clone(),
            deciding_assignment: record.deciding_assignment.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionContradiction {
    pub first_record: DecisionRecordIdentity,
    pub second_record: DecisionRecordIdentity,
    pub overlapping_scope: DecisionScope,
    pub first_resolution: String,
    pub second_resolution: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReconciliationReport {
    pub reconciliation_needed: bool,
    pub contradictions: Vec<DecisionContradiction>,
}

pub fn detect_decision_contradictions(records: &[DecisionRecord]) -> DecisionReconciliationReport {
    let mut contradictions = Vec::new();

    for (first_index, first) in records.iter().enumerate() {
        for second in records.iter().skip(first_index.saturating_add(1)) {
            if first.resolution == second.resolution {
                continue;
            }
            let overlapping_scope = first.scope.intersection(&second.scope);
            if overlapping_scope.is_empty() {
                continue;
            }
            contradictions.push(DecisionContradiction {
                first_record: first.into(),
                second_record: second.into(),
                overlapping_scope,
                first_resolution: first.resolution.clone(),
                second_resolution: second.resolution.clone(),
            });
        }
    }

    DecisionReconciliationReport {
        reconciliation_needed: !contradictions.is_empty(),
        contradictions,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenDecisionClaimConflict {
    pub question_key: String,
    pub requested_assignment: String,
    pub owning_assignment: String,
    pub question: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionInputField {
    QuestionKey,
    Question,
    Assignment,
    Resolution,
    ModuleScopeKey,
    SymbolScopeKey,
    TopicScopeKey,
}

impl std::fmt::Display for DecisionInputField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::QuestionKey => "question key",
            Self::Question => "question",
            Self::Assignment => "assignment",
            Self::Resolution => "resolution",
            Self::ModuleScopeKey => "module scope key",
            Self::SymbolScopeKey => "symbol scope key",
            Self::TopicScopeKey => "topic scope key",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionClaimError {
    #[error("{field} cannot be empty")]
    EmptyInput { field: DecisionInputField },
    #[error("{field} exceeds its {max_bytes} byte limit with {actual_bytes} bytes")]
    InputTooLong {
        field: DecisionInputField,
        max_bytes: usize,
        actual_bytes: usize,
    },
    #[error("{field} contains invalid characters")]
    InvalidInput { field: DecisionInputField },
    #[error("a decision record must declare at least one scope key")]
    EmptyScope,
    #[error(
        "decision question {question_key} is already open under assignment {owning_assignment}"
    )]
    OpenClaimConflict {
        question_key: String,
        requested_assignment: String,
        owning_assignment: String,
        question: String,
    },
    #[error("decision question is not registered: {question_key}")]
    ClaimNotFound { question_key: String },
    #[error("decision question {question_key} is not open; current status is {status:?}")]
    ClaimNotOpen {
        question_key: String,
        status: DecisionClaimStatus,
    },
    #[error(
        "assignment {requested_assignment} does not own decision question {question_key}; owner is {owning_assignment}"
    )]
    AssignmentMismatch {
        question_key: String,
        requested_assignment: String,
        owning_assignment: String,
    },
    #[error("decision claim has an invalid {status:?} state: {message}")]
    InvalidClaimState {
        status: DecisionClaimStatus,
        message: &'static str,
    },
    #[error("decision snapshot repeats question key {question_key}")]
    DuplicateQuestionKey { question_key: String },
    #[error("decision registry lock is poisoned")]
    Poisoned,
}

impl DecisionClaimError {
    pub fn open_claim_conflict(&self) -> Option<OpenDecisionClaimConflict> {
        match self {
            Self::OpenClaimConflict {
                question_key,
                requested_assignment,
                owning_assignment,
                question,
            } => Some(OpenDecisionClaimConflict {
                question_key: question_key.clone(),
                requested_assignment: requested_assignment.clone(),
                owning_assignment: owning_assignment.clone(),
                question: question.clone(),
            }),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, DecisionClaimError>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRegistrySnapshot {
    pub claims: Vec<DecisionClaim>,
    pub records: Vec<DecisionRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionRegistry {
    inner: Arc<Mutex<DecisionRegistryState>>,
}

#[derive(Debug, Default)]
struct DecisionRegistryState {
    claims: BTreeMap<String, DecisionClaim>,
    records: Vec<DecisionRecord>,
}

impl DecisionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: DecisionRegistrySnapshot) -> Result<Self> {
        let mut claims = BTreeMap::new();
        for claim in snapshot.claims {
            let claim = claim.validate()?;
            let question_key = claim.question_key.clone();
            if claims.insert(question_key.clone(), claim).is_some() {
                return Err(DecisionClaimError::DuplicateQuestionKey { question_key });
            }
        }
        let records = snapshot
            .records
            .into_iter()
            .map(DecisionRecord::validate)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            inner: Arc::new(Mutex::new(DecisionRegistryState { claims, records })),
        })
    }

    pub fn claim_open(
        &self,
        question_key: impl AsRef<str>,
        question: impl AsRef<str>,
        owning_assignment: impl AsRef<str>,
    ) -> Result<DecisionClaim> {
        let requested = DecisionClaim::open(question_key, question, owning_assignment)?;
        let mut state = self.lock_state()?;

        if let Some(active) = state
            .claims
            .get(requested.question_key())
            .filter(|claim| claim.status == DecisionClaimStatus::Open)
        {
            return Err(DecisionClaimError::OpenClaimConflict {
                question_key: requested.question_key.clone(),
                requested_assignment: requested.owning_assignment.clone(),
                owning_assignment: active.owning_assignment.clone(),
                question: active.question.clone(),
            });
        }

        state
            .claims
            .insert(requested.question_key.clone(), requested.clone());
        Ok(requested)
    }

    pub fn resolve_claim(
        &self,
        question_key: impl AsRef<str>,
        deciding_assignment: impl AsRef<str>,
        resolution: impl AsRef<str>,
        scope: DecisionScope,
    ) -> Result<DecisionRecord> {
        let question_key = normalize_stable_key(
            question_key.as_ref(),
            DecisionInputField::QuestionKey,
            MAX_DECISION_QUESTION_KEY_BYTES,
        )?;
        let deciding_assignment = normalize_stable_key(
            deciding_assignment.as_ref(),
            DecisionInputField::Assignment,
            MAX_DECISION_ASSIGNMENT_BYTES,
        )?;
        let record = DecisionRecord::new(&question_key, resolution, &deciding_assignment, scope)?;
        let mut state = self.lock_state()?;
        {
            let claim = state.claims.get_mut(&question_key).ok_or_else(|| {
                DecisionClaimError::ClaimNotFound {
                    question_key: question_key.clone(),
                }
            })?;
            if claim.status != DecisionClaimStatus::Open {
                return Err(DecisionClaimError::ClaimNotOpen {
                    question_key,
                    status: claim.status,
                });
            }
            if claim.owning_assignment != deciding_assignment {
                return Err(DecisionClaimError::AssignmentMismatch {
                    question_key,
                    requested_assignment: deciding_assignment,
                    owning_assignment: claim.owning_assignment.clone(),
                });
            }
            claim.status = DecisionClaimStatus::Resolved;
            claim.resolution = Some(record.resolution.clone());
        }
        state.records.push(record.clone());
        Ok(record)
    }

    pub fn supersede_claim(
        &self,
        question_key: impl AsRef<str>,
        owning_assignment: impl AsRef<str>,
        resolution: Option<&str>,
    ) -> Result<DecisionClaim> {
        let question_key = normalize_stable_key(
            question_key.as_ref(),
            DecisionInputField::QuestionKey,
            MAX_DECISION_QUESTION_KEY_BYTES,
        )?;
        let owning_assignment = normalize_stable_key(
            owning_assignment.as_ref(),
            DecisionInputField::Assignment,
            MAX_DECISION_ASSIGNMENT_BYTES,
        )?;
        let resolution = resolution.map(normalize_resolution).transpose()?;
        let mut state = self.lock_state()?;
        let claim = state.claims.get_mut(&question_key).ok_or_else(|| {
            DecisionClaimError::ClaimNotFound {
                question_key: question_key.clone(),
            }
        })?;
        if claim.status != DecisionClaimStatus::Open {
            return Err(DecisionClaimError::ClaimNotOpen {
                question_key,
                status: claim.status,
            });
        }
        if claim.owning_assignment != owning_assignment {
            return Err(DecisionClaimError::AssignmentMismatch {
                question_key,
                requested_assignment: owning_assignment,
                owning_assignment: claim.owning_assignment.clone(),
            });
        }
        claim.status = DecisionClaimStatus::Superseded;
        claim.resolution = resolution;
        Ok(claim.clone())
    }

    pub fn snapshot(&self) -> Result<DecisionRegistrySnapshot> {
        let state = self.lock_state()?;
        Ok(DecisionRegistrySnapshot {
            claims: state.claims.values().cloned().collect(),
            records: state.records.clone(),
        })
    }

    pub fn reconciliation_report(&self) -> Result<DecisionReconciliationReport> {
        let state = self.lock_state()?;
        Ok(detect_decision_contradictions(&state.records))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, DecisionRegistryState>> {
        self.inner.lock().map_err(|_| DecisionClaimError::Poisoned)
    }
}

fn normalize_resolution(value: &str) -> Result<String> {
    normalize_text(
        value,
        DecisionInputField::Resolution,
        MAX_DECISION_RESOLUTION_BYTES,
    )
}

fn normalize_text(value: &str, field: DecisionInputField, max_bytes: usize) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(DecisionClaimError::EmptyInput { field });
    }
    if normalized.len() > max_bytes {
        return Err(DecisionClaimError::InputTooLong {
            field,
            max_bytes,
            actual_bytes: normalized.len(),
        });
    }
    if normalized.chars().any(char::is_control) {
        return Err(DecisionClaimError::InvalidInput { field });
    }
    Ok(normalized.to_string())
}

fn normalize_stable_key(
    value: &str,
    field: DecisionInputField,
    max_bytes: usize,
) -> Result<String> {
    let normalized = normalize_text(value, field, max_bytes)?;
    if !normalized.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/' | ':' | '#')
    }) {
        return Err(DecisionClaimError::InvalidInput { field });
    }
    Ok(normalized)
}

fn normalize_scope_keys(
    values: impl IntoIterator<Item = String>,
    field: DecisionInputField,
) -> Result<BTreeSet<String>> {
    values
        .into_iter()
        .map(|value| normalize_stable_key(&value, field, MAX_DECISION_SCOPE_KEY_BYTES))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(modules: &[&str], symbols: &[&str], topics: &[&str]) -> DecisionScope {
        DecisionScope::new(
            modules.iter().map(|value| (*value).to_string()),
            symbols.iter().map(|value| (*value).to_string()),
            topics.iter().map(|value| (*value).to_string()),
        )
        .expect("valid test scope")
    }

    fn record(
        question_key: &str,
        resolution: &str,
        assignment: &str,
        scope: DecisionScope,
    ) -> DecisionRecord {
        DecisionRecord::new(question_key, resolution, assignment, scope)
            .expect("valid test decision record")
    }

    #[test]
    fn duplicate_open_claim_is_refused_with_structured_conflict() {
        let registry = DecisionRegistry::new();
        registry
            .claim_open(
                "api.transport",
                "Which transport should the API use?",
                "planner-a",
            )
            .expect("first claim");

        let error = registry
            .claim_open(
                "api.transport",
                "Should the API use HTTP or a local socket?",
                "planner-b",
            )
            .expect_err("duplicate open claim should fail");

        assert_eq!(
            error.open_claim_conflict(),
            Some(OpenDecisionClaimConflict {
                question_key: "api.transport".to_string(),
                requested_assignment: "planner-b".to_string(),
                owning_assignment: "planner-a".to_string(),
                question: "Which transport should the API use?".to_string(),
            })
        );
        assert_eq!(registry.snapshot().expect("snapshot").claims.len(), 1);
    }

    #[test]
    fn distinct_question_keys_coexist() {
        let registry = DecisionRegistry::new();
        registry
            .claim_open("api.transport", "Which transport?", "planner-a")
            .expect("transport claim");
        registry
            .claim_open("api.naming", "Which naming scheme?", "planner-b")
            .expect("naming claim");

        let snapshot = registry.snapshot().expect("snapshot");
        assert_eq!(snapshot.claims.len(), 2);
        assert_eq!(snapshot.claims[0].question_key(), "api.naming");
        assert_eq!(snapshot.claims[1].question_key(), "api.transport");
    }

    #[test]
    fn disjoint_decision_record_scope_is_not_a_contradiction() {
        let records = vec![
            record(
                "api.transport",
                "Use HTTP",
                "planner-a",
                scope(&["api"], &[], &[]),
            ),
            record(
                "storage.engine",
                "Use SQLite",
                "planner-b",
                scope(&["storage"], &[], &[]),
            ),
        ];

        assert_eq!(
            detect_decision_contradictions(&records),
            DecisionReconciliationReport {
                reconciliation_needed: false,
                contradictions: Vec::new(),
            }
        );
    }

    #[test]
    fn overlapping_scope_with_same_resolution_is_not_a_contradiction() {
        let records = vec![
            record(
                "api.transport",
                "Use HTTP",
                "planner-a",
                scope(&["api"], &[], &["public-contract"]),
            ),
            record(
                "api.protocol",
                "Use HTTP",
                "planner-b",
                scope(&[], &["client::send"], &["public-contract"]),
            ),
        ];

        assert_eq!(
            detect_decision_contradictions(&records),
            DecisionReconciliationReport {
                reconciliation_needed: false,
                contradictions: Vec::new(),
            }
        );
    }

    #[test]
    fn overlapping_scope_with_different_resolutions_reports_exact_contradiction() {
        let records = vec![
            record(
                "api.transport",
                "Use HTTP",
                "planner-a",
                scope(&["api"], &["client::send"], &["public-contract"]),
            ),
            record(
                "api.protocol",
                "Use a local socket",
                "planner-b",
                scope(
                    &["api"],
                    &["client::send", "server::receive"],
                    &["public-contract"],
                ),
            ),
        ];

        assert_eq!(
            detect_decision_contradictions(&records),
            DecisionReconciliationReport {
                reconciliation_needed: true,
                contradictions: vec![DecisionContradiction {
                    first_record: DecisionRecordIdentity {
                        question_key: "api.transport".to_string(),
                        deciding_assignment: "planner-a".to_string(),
                    },
                    second_record: DecisionRecordIdentity {
                        question_key: "api.protocol".to_string(),
                        deciding_assignment: "planner-b".to_string(),
                    },
                    overlapping_scope: scope(&["api"], &["client::send"], &["public-contract"],),
                    first_resolution: "Use HTTP".to_string(),
                    second_resolution: "Use a local socket".to_string(),
                }],
            }
        );
    }

    #[test]
    fn question_and_resolution_text_are_bounded() {
        let registry = DecisionRegistry::new();
        registry
            .claim_open(
                "bounded.question",
                "q".repeat(MAX_DECISION_QUESTION_BYTES),
                "planner-a",
            )
            .expect("question at limit");
        assert_eq!(
            registry
                .claim_open(
                    "oversized.question",
                    "q".repeat(MAX_DECISION_QUESTION_BYTES + 1),
                    "planner-b",
                )
                .expect_err("oversized question"),
            DecisionClaimError::InputTooLong {
                field: DecisionInputField::Question,
                max_bytes: MAX_DECISION_QUESTION_BYTES,
                actual_bytes: MAX_DECISION_QUESTION_BYTES + 1,
            }
        );

        let valid_scope = scope(&["api"], &[], &[]);
        DecisionRecord::new(
            "bounded.resolution",
            "r".repeat(MAX_DECISION_RESOLUTION_BYTES),
            "planner-a",
            valid_scope.clone(),
        )
        .expect("resolution at limit");
        assert_eq!(
            DecisionRecord::new(
                "oversized.resolution",
                "r".repeat(MAX_DECISION_RESOLUTION_BYTES + 1),
                "planner-a",
                valid_scope,
            )
            .expect_err("oversized resolution"),
            DecisionClaimError::InputTooLong {
                field: DecisionInputField::Resolution,
                max_bytes: MAX_DECISION_RESOLUTION_BYTES,
                actual_bytes: MAX_DECISION_RESOLUTION_BYTES + 1,
            }
        );
    }
}

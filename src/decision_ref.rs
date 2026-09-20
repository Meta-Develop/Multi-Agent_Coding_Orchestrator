//! Merge-time and plan-time checked citations of resolved design decisions.
//!
//! A dependent artifact must cite a resolved [`DecisionRecord::question_key`].
//! Missing or stale references fail closed. Open or superseded claims are not
//! valid [`DecisionRef`] targets. This module does not persist registry state;
//! load an existing store with [`DecisionStore::open_existing`] when a
//! repository-bound check is required.

use crate::{
    decision_claim::{
        DecisionClaimError, DecisionClaimStatus, DecisionInputField, DecisionRecord,
        DecisionRegistry, MAX_DECISION_QUESTION_KEY_BYTES, MAX_DECISION_RESOLUTION_BYTES,
    },
    decision_store::DecisionStore,
};
use std::path::Path;
use thiserror::Error;

/// Checked citation of one resolved [`DecisionRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRef {
    question_key: String,
    expected_resolution: Option<String>,
}

impl DecisionRef {
    /// Builds a citation of `question_key` using the same stable-key rules as
    /// [`DecisionRecord`]. Empty or invalid keys fail closed.
    pub fn new(question_key: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            question_key: normalize_question_key(question_key.as_ref())?,
            expected_resolution: None,
        })
    }

    /// Requires the persisted resolved record to still carry this resolution.
    pub fn with_expected_resolution(mut self, resolution: impl AsRef<str>) -> Result<Self> {
        self.expected_resolution = Some(normalize_resolution(resolution.as_ref())?);
        Ok(self)
    }

    pub fn question_key(&self) -> &str {
        &self.question_key
    }

    pub fn expected_resolution(&self) -> Option<&str> {
        self.expected_resolution.as_deref()
    }
}

/// Why a cited [`DecisionRef`] no longer matches a resolved record.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StaleDecisionRefReason {
    #[error("cited resolution {expected} does not match resolved record {actual}")]
    ResolutionMismatch { expected: String, actual: String },
    #[error("claim status is {status:?}, not a resolved DecisionRecord")]
    ClaimNotResolved { status: DecisionClaimStatus },
    #[error("question was never resolved to a DecisionRecord")]
    NeverResolved,
}

/// Fail-closed DecisionRef verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionRefError {
    #[error(transparent)]
    InvalidCitation(#[from] DecisionClaimError),
    #[error("a decision reference is required")]
    MissingRef,
    #[error("decision reference question key is not registered: {question_key}")]
    MissingQuestionKey { question_key: String },
    #[error("decision reference {question_key} is stale: {reason}")]
    StaleRef {
        question_key: String,
        reason: StaleDecisionRefReason,
    },
    #[error("decision store is missing while a decision reference is required")]
    StoreMissing,
    #[error("decision store query failed: {message}")]
    StoreQueryFailed { message: String },
}

pub type Result<T> = std::result::Result<T, DecisionRefError>;

/// Verifies that `reference` cites a current resolved [`DecisionRecord`].
pub fn check_decision_ref(
    registry: &DecisionRegistry,
    reference: &DecisionRef,
) -> Result<DecisionRecord> {
    let reference = DecisionRef {
        question_key: normalize_question_key(reference.question_key())?,
        expected_resolution: reference
            .expected_resolution()
            .map(normalize_resolution)
            .transpose()?,
    };
    let snapshot = registry.snapshot()?;
    let claim = snapshot
        .claims
        .iter()
        .find(|claim| claim.question_key() == reference.question_key());

    if let Some(claim) = claim {
        match claim.status() {
            DecisionClaimStatus::Open | DecisionClaimStatus::Superseded => {
                return Err(DecisionRefError::StaleRef {
                    question_key: reference.question_key.clone(),
                    reason: StaleDecisionRefReason::ClaimNotResolved {
                        status: claim.status(),
                    },
                });
            }
            DecisionClaimStatus::Resolved => {}
        }
    }

    let matching_records: Vec<&DecisionRecord> = snapshot
        .records
        .iter()
        .filter(|record| record.question_key() == reference.question_key())
        .collect();
    let record = current_resolved_record(
        claim.and_then(|claim| claim.resolution()),
        &matching_records,
    )
    .cloned()
    .ok_or_else(|| {
        if claim.is_none() && matching_records.is_empty() {
            DecisionRefError::MissingQuestionKey {
                question_key: reference.question_key.clone(),
            }
        } else {
            DecisionRefError::StaleRef {
                question_key: reference.question_key.clone(),
                reason: StaleDecisionRefReason::NeverResolved,
            }
        }
    })?;

    if let Some(expected) = reference.expected_resolution() {
        if record.resolution() != expected {
            return Err(DecisionRefError::StaleRef {
                question_key: reference.question_key.clone(),
                reason: StaleDecisionRefReason::ResolutionMismatch {
                    expected: expected.to_string(),
                    actual: record.resolution().to_string(),
                },
            });
        }
    }

    Ok(record)
}

/// Fails closed when a dependent artifact omitted its required [`DecisionRef`].
pub fn check_required_decision_ref(
    registry: &DecisionRegistry,
    reference: Option<&DecisionRef>,
) -> Result<DecisionRecord> {
    let reference = reference.ok_or(DecisionRefError::MissingRef)?;
    check_decision_ref(registry, reference)
}

/// Loads an existing [`DecisionStore`] and checks a required citation.
///
/// Missing store state fails closed when a reference is required. This helper
/// does not create a store.
pub fn check_required_decision_ref_in_store(
    repo_path: impl AsRef<Path>,
    reference: Option<&DecisionRef>,
) -> Result<DecisionRecord> {
    let reference = reference.ok_or(DecisionRefError::MissingRef)?;
    let store = DecisionStore::open_existing(repo_path.as_ref())
        .map_err(|error| DecisionRefError::StoreQueryFailed {
            message: format!("{error:#}"),
        })?
        .ok_or(DecisionRefError::StoreMissing)?;
    let registry = store
        .load_registry()
        .map_err(|error| DecisionRefError::StoreQueryFailed {
            message: format!("{error:#}"),
        })?;
    check_decision_ref(&registry, reference)
}

fn current_resolved_record<'a>(
    claim_resolution: Option<&str>,
    matching_records: &[&'a DecisionRecord],
) -> Option<&'a DecisionRecord> {
    if let Some(resolution) = claim_resolution {
        return matching_records
            .iter()
            .rev()
            .find(|record| record.resolution() == resolution)
            .copied();
    }
    matching_records.last().copied()
}

fn normalize_question_key(value: &str) -> Result<String> {
    normalize_stable_key(
        value,
        DecisionInputField::QuestionKey,
        MAX_DECISION_QUESTION_KEY_BYTES,
    )
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
        return Err(DecisionClaimError::EmptyInput { field }.into());
    }
    if normalized.len() > max_bytes {
        return Err(DecisionClaimError::InputTooLong {
            field,
            max_bytes,
            actual_bytes: normalized.len(),
        }
        .into());
    }
    if normalized.chars().any(char::is_control) {
        return Err(DecisionClaimError::InvalidInput { field }.into());
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
        return Err(DecisionClaimError::InvalidInput { field }.into());
    }
    Ok(normalized)
}

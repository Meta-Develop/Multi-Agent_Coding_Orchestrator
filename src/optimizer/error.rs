//! Shared error type for optimizer traits.
//!
//! Traits stay object-safe by returning this concrete error instead of an
//! associated type. Later phases add context via [`OptimizerError::Invalid`]
//! or by wrapping this error at their own boundary — they do not need to
//! edit this enum to implement a trait.

use thiserror::Error;

/// Recoverable optimizer-core failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OptimizerError {
    #[error("empty identifier")]
    EmptyIdentifier,
    #[error("unsupported effort {effort} for backend {backend}")]
    UnsupportedEffort { backend: String, effort: String },
    #[error("no effort mapper registered for backend {0}")]
    MissingEffortMapper(String),
    #[error("policy graph is missing start node {0}")]
    MissingStartNode(String),
    #[error("policy graph is missing node {0}")]
    MissingPolicyNode(String),
    #[error("policy edge references unknown node {0}")]
    UnknownEdgeEndpoint(String),
    #[error("duplicate policy node {0}")]
    DuplicatePolicyNode(String),
    #[error("no matching policy transition from {0}")]
    NoMatchingTransition(String),
    #[error("quality contract cannot be certified: {0}")]
    Uncertifiable(String),
    #[error("stale or misbound evidence: {0}")]
    EvidenceRejected(String),
    #[error("resource dimension {0} is not present")]
    UnknownResourceDimension(String),
    #[error("optional dispatch blocked by frontier reserve on {0}")]
    FrontierReserveViolation(String),
    #[error("infeasible: {0}")]
    Infeasible(String),
    #[error("{0}")]
    Invalid(String),
}

impl OptimizerError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

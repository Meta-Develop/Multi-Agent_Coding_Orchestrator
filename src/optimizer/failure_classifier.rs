//! Evidence-based progress and failure-mode classification. Implemented by #164.

use super::error::OptimizerError;
use super::policy::TransitionEvidence;
use super::trajectory::TrajectoryHistory;

pub trait FailureClassifier {
    fn classify(&self, history: &TrajectoryHistory) -> Result<TransitionEvidence, OptimizerError>;
}

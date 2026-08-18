//! Drift detection and reserve recalibration cadence. Implemented by issue #170.

use super::error::OptimizerError;
use super::ids::TimestampMillis;
use super::resources::ResourceVector;
use super::telemetry::InvocationRecord;

pub trait DriftDetector {
    fn detect(&self, records: &[InvocationRecord]) -> Result<bool, OptimizerError>;
}

/// Recalibration hook. #170 owns the cadence; #162 owns the reserve math.
pub trait ReserveRecalibrator {
    fn recalibrate(
        &self,
        current: &ResourceVector,
        as_of: TimestampMillis,
        records: &[InvocationRecord],
    ) -> Result<ResourceVector, OptimizerError>;
}

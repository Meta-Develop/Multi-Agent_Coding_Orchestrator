//! Provider-neutral execution-policy optimizer core.
//!
//! This tree is the foundation of umbrella #157. Later phases implement the
//! traits defined here — they plug in by adding implementors, not by editing
//! the action/policy/state types or trait signatures.
//!
//! | Module | Later owner |
//! | --- | --- |
//! | `telemetry` | #159 |
//! | `features` | #163 |
//! | `failure_classifier`, `trajectory` | #164 |
//! | `policy` candidate generation | #165 |
//! | `replay` | #166 |
//! | `predictor`, `feasibility`, `objective`, `online_router`, `explanation` | #167 |
//! | `value_of_information`, `hedge` | #168 |
//! | `global_search`, `safe_set`, `shadow` | #169 |
//! | `drift` | #170 |
//!
//! Provider adapters stay outside this module (`src/runtime_adapter.rs` /
//! the #146 boundary). The core depends on capabilities, not CLI assumptions.

pub mod action;
pub mod catalog;
pub mod certification;
pub mod drift;
pub mod error;
pub mod explanation;
pub mod failure_classifier;
pub mod feasibility;
pub mod features;
pub mod global_search;
pub mod hedge;
pub mod ids;
pub mod objective;
pub mod online_router;
pub mod operator_labels;
pub mod policy;
pub mod predictor;
pub mod quality;
pub mod replay;
pub mod resources;
pub mod safe_set;
pub mod shadow;
pub mod state;
pub mod taxonomy;
pub mod telemetry;
pub mod trajectory;
pub mod value_of_information;

pub use action::{
    enumerate_compatible_actions, ActionTemplate, AgentRole, CanonicalEffort, EffortMapper,
    EffortMapperRegistry, ExecutionBudget, ModelAction, NativeEffort, ResolvedRuntimeModel,
    RuntimeModelId, StaticEffortMapper, TopologySpec, VerifierProfile,
};
pub use catalog::{ModelCatalogSnapshot, RuntimeModelCatalog};
pub use certification::{
    select_under_quality_constraint, CandidateBinding, CertificationPlan, CertificationResult,
    FailClosedCertifier, QualityCertifier, ScoredCandidate, SelectionOutcome, TaskBinding,
};
pub use error::OptimizerError;
pub use global_search::{GlobalPolicyOptimizer, OptimizationHistory, PolicySearchSpace};
pub use online_router::{OnlineRouter, RouterDecision};
pub use policy::{PolicyEdge, PolicyGraph, PolicyNode, TransitionCondition, TransitionEvidence};
pub use predictor::{PolicyOutcomeDistribution, PolicyPredictor};
pub use quality::QualityContract;
pub use resources::{
    DispatchClass, DispatchDecision, DispatchRequest, ResourceObserver, ResourceSnapshot,
    ResourceVector,
};
pub use state::OptimizerState;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::drift::{DriftDetector, ReserveRecalibrator};
    use crate::optimizer::failure_classifier::FailureClassifier;
    use crate::optimizer::feasibility::FeasibilityChecker;
    use crate::optimizer::features::FeatureExtractor;
    use crate::optimizer::hedge::HedgePlanner;
    use crate::optimizer::objective::ObjectiveEvaluator;
    use crate::optimizer::replay::ReplayStore;
    use crate::optimizer::safe_set::SafeSetStore;
    use crate::optimizer::shadow::ShadowEvaluator;
    use crate::optimizer::telemetry::TelemetrySink;
    use crate::optimizer::value_of_information::ValueOfInformation;

    #[test]
    fn specified_traits_are_object_safe() {
        fn catalog(_: &dyn RuntimeModelCatalog) {}
        fn predictor(_: &dyn PolicyPredictor) {}
        fn certifier(_: &dyn QualityCertifier) {}
        fn observer(_: &dyn ResourceObserver) {}
        fn global(_: &dyn GlobalPolicyOptimizer) {}
        fn router(_: &dyn OnlineRouter) {}
        fn effort(_: &dyn EffortMapper) {}
        fn features(_: &dyn FeatureExtractor) {}
        fn telemetry(_: &dyn TelemetrySink) {}
        fn feasibility(_: &dyn FeasibilityChecker) {}
        fn objective(_: &dyn ObjectiveEvaluator) {}
        fn failures(_: &dyn FailureClassifier) {}
        fn voi(_: &dyn ValueOfInformation) {}
        fn hedge(_: &dyn HedgePlanner) {}
        fn safe(_: &dyn SafeSetStore) {}
        fn shadow(_: &dyn ShadowEvaluator) {}
        fn replay(_: &dyn ReplayStore) {}
        fn drift(_: &dyn DriftDetector) {}
        fn recal(_: &dyn ReserveRecalibrator) {}

        let _ = (
            catalog as fn(&dyn RuntimeModelCatalog),
            predictor as fn(&dyn PolicyPredictor),
            certifier as fn(&dyn QualityCertifier),
            observer as fn(&dyn ResourceObserver),
            global as fn(&dyn GlobalPolicyOptimizer),
            router as fn(&dyn OnlineRouter),
            effort as fn(&dyn EffortMapper),
            features as fn(&dyn FeatureExtractor),
            telemetry as fn(&dyn TelemetrySink),
            feasibility as fn(&dyn FeasibilityChecker),
            objective as fn(&dyn ObjectiveEvaluator),
            failures as fn(&dyn FailureClassifier),
            voi as fn(&dyn ValueOfInformation),
            hedge as fn(&dyn HedgePlanner),
            safe as fn(&dyn SafeSetStore),
            shadow as fn(&dyn ShadowEvaluator),
            replay as fn(&dyn ReplayStore),
            drift as fn(&dyn DriftDetector),
            recal as fn(&dyn ReserveRecalibrator),
        );
    }
}

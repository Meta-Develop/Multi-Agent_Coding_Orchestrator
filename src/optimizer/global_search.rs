//! Offline / global candidate proposal. Implemented by issue #169.
//!
//! The trait signature is the plug-in boundary. Search must receive the
//! quality contract from the caller and cannot mutate it (see #161).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::action::{
    AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
    RestartMode, ReviewTopology, TopologySpec, WorkerTopology,
};
use super::certification::CertificationPlan;
use super::error::OptimizerError;
use super::ids::{
    BackendId, CatalogVersion, ContractId, ModelFamilyId, PolicyId, PolicyNodeId, ProviderId,
    RuntimeSlug, TimestampMillis, ValidatorId, VerifierProfileId,
};
use super::policy::{PolicyEdge, PolicyGraph, PolicyNode, TransitionCondition};
use super::quality::{QualityContract, ValidatorBinding};
use super::resources::{Quantity, ResourceVector};
use super::safe_set::{
    EvaluationFidelity, ExplorationAdmission, ExplorationBudgetRequest, InMemorySafeSetStore,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationHistory {
    pub evaluated_policy_ids: Vec<PolicyId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySearchSpace {
    pub seed_policy_ids: Vec<PolicyId>,
}

pub trait GlobalPolicyOptimizer {
    fn propose(
        &self,
        history: &OptimizationHistory,
        search_space: &PolicySearchSpace,
    ) -> Result<Vec<PolicyGraph>, OptimizerError>;
}

/// Provider-neutral categorical assignment for one search proposal.
///
/// Model slugs are evidence identifiers supplied by the catalog snapshot,
/// never hardcoded vendor names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SearchConfiguration {
    pub planner_enabled: bool,
    pub planner_backend: BackendId,
    pub planner_slug: RuntimeSlug,
    pub planner_effort: CanonicalEffort,
    pub worker_backend: BackendId,
    pub worker_slug: RuntimeSlug,
    pub worker_effort: CanonicalEffort,
    pub probe_slug: RuntimeSlug,
    pub probe_effort: CanonicalEffort,
    pub probe_length: u32,
    pub repair_slug: RuntimeSlug,
    pub repair_effort: CanonicalEffort,
    pub concurrency: u32,
    pub hedge_delay_seconds: u64,
    pub retry_limit: u32,
    pub reviewer_slug: RuntimeSlug,
    pub reviewer_effort: CanonicalEffort,
}

/// Conditional mixed discrete search space. Planner fields are ignored when
/// planning is off (tree-structured / TPE-style conditionals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalSearchSpace {
    pub planner_enabled: Vec<bool>,
    pub backends: Vec<BackendId>,
    pub slugs: Vec<RuntimeSlug>,
    pub efforts: Vec<CanonicalEffort>,
    pub probe_lengths: Vec<u32>,
    pub concurrencies: Vec<u32>,
    pub hedge_delays: Vec<u64>,
    pub retry_limits: Vec<u32>,
}

impl ConditionalSearchSpace {
    pub fn enumerate(&self) -> Result<Vec<SearchConfiguration>, OptimizerError> {
        if self.backends.is_empty() || self.slugs.is_empty() || self.efforts.is_empty() {
            return Err(OptimizerError::invalid(
                "search space must declare at least one backend, slug, and effort",
            ));
        }
        let planner_flags = if self.planner_enabled.is_empty() {
            vec![true, false]
        } else {
            self.planner_enabled.clone()
        };
        let probe_lengths = if self.probe_lengths.is_empty() {
            vec![1]
        } else {
            self.probe_lengths.clone()
        };
        let concurrencies = if self.concurrencies.is_empty() {
            vec![1]
        } else {
            self.concurrencies.clone()
        };
        let hedge_delays = if self.hedge_delays.is_empty() {
            vec![0]
        } else {
            self.hedge_delays.clone()
        };
        let retry_limits = if self.retry_limits.is_empty() {
            vec![1]
        } else {
            self.retry_limits.clone()
        };

        let mut configs = Vec::new();
        for planner_enabled in &planner_flags {
            for backend in &self.backends {
                for slug in &self.slugs {
                    for effort in &self.efforts {
                        for probe_length in &probe_lengths {
                            for concurrency in &concurrencies {
                                for hedge in &hedge_delays {
                                    for retry in &retry_limits {
                                        configs.push(SearchConfiguration {
                                            planner_enabled: *planner_enabled,
                                            planner_backend: backend.clone(),
                                            planner_slug: slug.clone(),
                                            planner_effort: effort.clone(),
                                            worker_backend: backend.clone(),
                                            worker_slug: slug.clone(),
                                            worker_effort: effort.clone(),
                                            probe_slug: slug.clone(),
                                            probe_effort: effort.clone(),
                                            probe_length: *probe_length,
                                            repair_slug: slug.clone(),
                                            repair_effort: effort.clone(),
                                            concurrency: *concurrency,
                                            hedge_delay_seconds: *hedge,
                                            retry_limit: *retry,
                                            reviewer_slug: slug.clone(),
                                            reviewer_effort: effort.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        configs.sort();
        configs.dedup();
        Ok(configs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidelityObservation {
    pub policy_id: PolicyId,
    pub config: SearchConfiguration,
    pub fidelity: EvaluationFidelity,
    pub observed_at: TimestampMillis,
    pub certified: bool,
    pub cost_micros: i64,
    pub task_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchProposal {
    pub policy_id: PolicyId,
    pub config: SearchConfiguration,
    pub fidelity: EvaluationFidelity,
    pub proposed_at: TimestampMillis,
    pub expected_cost_micros: i64,
    pub contract_id: ContractId,
    pub mandatory_validator_ids: Vec<ValidatorId>,
}

/// Constrained TPE / SMAC-style first implementor of [`GlobalPolicyOptimizer`].
///
/// Categorical frequencies estimate l(x)/g(x) on the good/bad split. Search
/// holds the quality contract by shared reference and can only append
/// validators through [`QualityContract::with_additional_validator`].
#[derive(Debug)]
pub struct ConstrainedTpeOptimizer {
    contract: QualityContract,
    space: ConditionalSearchSpace,
    library: Mutex<BTreeMap<String, PolicyGraph>>,
    proposals: Mutex<Vec<SearchProposal>>,
    observations: Mutex<Vec<FidelityObservation>>,
    catalog_version: CatalogVersion,
}

impl ConstrainedTpeOptimizer {
    pub fn new(
        contract: QualityContract,
        space: ConditionalSearchSpace,
        catalog_version: CatalogVersion,
    ) -> Result<Self, OptimizerError> {
        if !contract.has_machine_checkable_mandatory_validator() {
            return Err(OptimizerError::Uncertifiable(
                "global search requires a machine-checkable mandatory validator".to_string(),
            ));
        }
        Ok(Self {
            contract,
            space,
            library: Mutex::new(BTreeMap::new()),
            proposals: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
            catalog_version,
        })
    }

    pub fn contract(&self) -> &QualityContract {
        &self.contract
    }

    /// Search-facing clone that can only add a validator.
    pub fn with_additional_validator(&self, validator: ValidatorBinding) -> QualityContract {
        self.contract.with_additional_validator(validator)
    }

    pub fn record_observation(
        &self,
        observation: FidelityObservation,
    ) -> Result<(), OptimizerError> {
        self.observations
            .lock()
            .map_err(|_| OptimizerError::invalid("search observations lock poisoned"))?
            .push(observation);
        Ok(())
    }

    pub fn observations_snapshot(&self) -> Result<Vec<FidelityObservation>, OptimizerError> {
        Ok(self
            .observations
            .lock()
            .map_err(|_| OptimizerError::invalid("search observations lock poisoned"))?
            .clone())
    }

    pub fn proposals_snapshot(&self) -> Result<Vec<SearchProposal>, OptimizerError> {
        Ok(self
            .proposals
            .lock()
            .map_err(|_| OptimizerError::invalid("search proposals lock poisoned"))?
            .clone())
    }

    /// Expected cost-to-certification across the observed task distribution.
    pub fn expected_cost_to_certification(&self) -> Result<i64, OptimizerError> {
        let observations = self.observations_snapshot()?;
        if observations.is_empty() {
            return Ok(0);
        }
        let mut per_class: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
        for observation in &observations {
            let entry = per_class
                .entry(observation.task_class.as_str())
                .or_default();
            entry.0 = entry.0.saturating_add(observation.cost_micros);
            entry.1 = entry.1.saturating_add(1);
        }
        let mut total = 0_i64;
        for (sum, count) in per_class.values() {
            if *count > 0 {
                total = total.saturating_add(sum / count);
            }
        }
        Ok(total / (per_class.len() as i64).max(1))
    }

    pub fn admit_search_spend(
        &self,
        store: &InMemorySafeSetStore,
        resources: &ResourceVector,
        request: &ExplorationBudgetRequest,
    ) -> Result<ExplorationAdmission, OptimizerError> {
        store.admit_exploration(resources, request)
    }

    pub fn weekly_capacity_feasible(&self, remaining: Quantity, planned_spend: Quantity) -> bool {
        remaining.as_i64() >= planned_spend.as_i64()
    }

    fn graph_for_config(
        &self,
        policy_id: &PolicyId,
        config: &SearchConfiguration,
    ) -> Result<PolicyGraph, OptimizerError> {
        let topology = TopologySpec {
            planner: if config.planner_enabled {
                PlannerTopology::Single
            } else {
                PlannerTopology::None
            },
            workers: if config.concurrency > 1 {
                WorkerTopology::Parallel {
                    count: config.concurrency,
                }
            } else {
                WorkerTopology::One
            },
            hedge: if config.hedge_delay_seconds == 0 {
                HedgeTopology::None
            } else {
                HedgeTopology::Delayed {
                    delay_seconds: config.hedge_delay_seconds,
                }
            },
            review: ReviewTopology::Independent,
            restart: RestartMode::Continuation,
        };
        let start = if config.planner_enabled {
            node_id("plan")?
        } else {
            node_id("execute")?
        };
        let mut graph = PolicyGraph::new(policy_id.clone(), 1, start, topology);
        if config.planner_enabled {
            graph.insert_node(
                node_id("plan")?,
                PolicyNode::Plan(action_from(
                    &config.planner_backend,
                    &config.planner_slug,
                    config.planner_effort.clone(),
                    AgentRole::Planner,
                    &self.catalog_version,
                    config.retry_limit,
                    config.concurrency,
                )?),
            )?;
        }
        graph.insert_node(
            node_id("execute")?,
            PolicyNode::Execute(action_from(
                &config.worker_backend,
                &config.worker_slug,
                config.worker_effort.clone(),
                AgentRole::Worker,
                &self.catalog_version,
                config.retry_limit,
                config.concurrency,
            )?),
        )?;
        graph.insert_node(
            node_id("repair")?,
            PolicyNode::Repair(action_from(
                &config.worker_backend,
                &config.repair_slug,
                config.repair_effort.clone(),
                AgentRole::Repairer,
                &self.catalog_version,
                config.retry_limit,
                1,
            )?),
        )?;
        graph.insert_node(
            node_id("audit")?,
            PolicyNode::Audit(action_from(
                &config.worker_backend,
                &config.reviewer_slug,
                config.reviewer_effort.clone(),
                AgentRole::Auditor,
                &self.catalog_version,
                1,
                1,
            )?),
        )?;
        graph.insert_node(
            node_id("certify")?,
            PolicyNode::Certify(CertificationPlan {
                contract_id: self.contract.contract_id().clone(),
                verifier_profile: VerifierProfileId::new("search-mandatory")?,
            }),
        )?;
        graph.insert_node(node_id("stop")?, PolicyNode::Stop)?;
        if config.planner_enabled {
            graph.add_edge(PolicyEdge {
                from: node_id("plan")?,
                to: node_id("execute")?,
                condition: TransitionCondition::Always,
            })?;
        }
        graph.add_edge(PolicyEdge {
            from: node_id("execute")?,
            to: node_id("repair")?,
            condition: TransitionCondition::LocalizedFailure,
        })?;
        graph.add_edge(PolicyEdge {
            from: node_id("execute")?,
            to: node_id("audit")?,
            condition: TransitionCondition::ProgressAboveThreshold,
        })?;
        graph.add_edge(PolicyEdge {
            from: node_id("repair")?,
            to: node_id("audit")?,
            condition: TransitionCondition::Always,
        })?;
        graph.add_edge(PolicyEdge {
            from: node_id("audit")?,
            to: node_id("certify")?,
            condition: TransitionCondition::Always,
        })?;
        graph.add_edge(PolicyEdge {
            from: node_id("certify")?,
            to: node_id("stop")?,
            condition: TransitionCondition::Always,
        })?;
        graph.validate()?;
        Ok(graph)
    }

    fn tpe_rank(
        &self,
        configs: &[SearchConfiguration],
    ) -> Result<Vec<SearchConfiguration>, OptimizerError> {
        let observations = self.observations_snapshot()?;
        if observations.is_empty() {
            return Ok(configs.to_vec());
        }
        let mut costs: Vec<i64> = observations.iter().map(|o| o.cost_micros).collect();
        costs.sort();
        let split = costs[costs.len() / 4];
        let mut good: BTreeMap<String, u32> = BTreeMap::new();
        let mut bad: BTreeMap<String, u32> = BTreeMap::new();
        let mut good_n = 0_u32;
        let mut bad_n = 0_u32;
        for observation in &observations {
            let key = config_key(&observation.config);
            if observation.cost_micros <= split {
                *good.entry(key).or_default() += 1;
                good_n += 1;
            } else {
                *bad.entry(key).or_default() += 1;
                bad_n += 1;
            }
        }
        let mut ranked: Vec<(i64, SearchConfiguration)> = configs
            .iter()
            .map(|config| {
                let key = config_key(config);
                let l = f64::from(*good.get(&key).unwrap_or(&0) + 1) / f64::from(good_n + 1);
                let g = f64::from(*bad.get(&key).unwrap_or(&0) + 1) / f64::from(bad_n + 1);
                let ei = ((l / g) * 1_000_000.0).floor() as i64;
                (-ei, config.clone())
            })
            .collect();
        ranked.sort();
        Ok(ranked.into_iter().map(|(_, config)| config).collect())
    }

    fn persist_proposal(
        &self,
        policy_id: PolicyId,
        config: SearchConfiguration,
        fidelity: EvaluationFidelity,
        at: TimestampMillis,
        expected_cost_micros: i64,
    ) -> Result<SearchProposal, OptimizerError> {
        let proposal = SearchProposal {
            policy_id,
            config,
            fidelity,
            proposed_at: at,
            expected_cost_micros,
            contract_id: self.contract.contract_id().clone(),
            mandatory_validator_ids: self
                .contract
                .mandatory_validators()
                .iter()
                .map(|binding| binding.validator_id.clone())
                .collect(),
        };
        self.proposals
            .lock()
            .map_err(|_| OptimizerError::invalid("search proposals lock poisoned"))?
            .push(proposal.clone());
        Ok(proposal)
    }
}

impl GlobalPolicyOptimizer for ConstrainedTpeOptimizer {
    fn propose(
        &self,
        history: &OptimizationHistory,
        search_space: &PolicySearchSpace,
    ) -> Result<Vec<PolicyGraph>, OptimizerError> {
        let evaluated: BTreeSet<String> = history
            .evaluated_policy_ids
            .iter()
            .map(ToString::to_string)
            .collect();
        let mut configs = self.space.enumerate()?;
        configs = self.tpe_rank(&configs)?;
        let mut graphs = Vec::new();
        let mut library = self
            .library
            .lock()
            .map_err(|_| OptimizerError::invalid("search library lock poisoned"))?;

        for seed in &search_space.seed_policy_ids {
            if let Some(existing) = library.get(seed.as_str()) {
                if !evaluated.contains(seed.as_str()) {
                    graphs.push(existing.clone());
                }
            }
        }

        for (index, config) in configs.into_iter().enumerate() {
            if graphs.len() >= 8 {
                break;
            }
            let policy_id = PolicyId::new(format!("search-{index}"))?;
            if evaluated.contains(policy_id.as_str()) {
                continue;
            }
            let graph = self.graph_for_config(&policy_id, &config)?;
            self.persist_proposal(
                policy_id.clone(),
                config,
                EvaluationFidelity::F0StaticPrediction,
                TimestampMillis::from_millis(index as u64),
                self.expected_cost_to_certification()?,
            )?;
            library.insert(policy_id.to_string(), graph.clone());
            graphs.push(graph);
        }
        Ok(graphs)
    }
}

fn node_id(name: &str) -> Result<PolicyNodeId, OptimizerError> {
    PolicyNodeId::new(name)
}

fn config_key(config: &SearchConfiguration) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        config.planner_enabled,
        config.worker_slug,
        config.worker_effort.as_label(),
        config.concurrency,
        config.hedge_delay_seconds,
        config.retry_limit
    )
}

fn action_from(
    backend: &BackendId,
    slug: &RuntimeSlug,
    effort: CanonicalEffort,
    role: AgentRole,
    catalog_version: &CatalogVersion,
    retry_limit: u32,
    concurrency: u32,
) -> Result<ModelAction, OptimizerError> {
    let provider = ProviderId::new("catalog")?;
    let family = ModelFamilyId::new(slug.as_str())?;
    Ok(ModelAction {
        backend_id: backend.clone(),
        provider_id: provider.clone(),
        runtime_model: crate::optimizer::action::RuntimeModelId {
            provider,
            backend: backend.clone(),
            model_family: family,
            runtime_slug: slug.clone(),
            catalog_version: catalog_version.clone(),
            observation_timestamp: TimestampMillis::from_millis(1),
        },
        requested_slug: slug.clone(),
        effort,
        role,
        max_turns: ExecutionBudget::default()
            .max_turns
            .saturating_add(retry_limit),
        timeout_seconds: 60,
        tool_budget: None,
        output_token_budget: None,
        concurrency,
        verifier_profile: VerifierProfileId::new("search-mandatory")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::ResourceDimensionId;
    use crate::optimizer::quality::ValidatorKind;

    fn contract() -> QualityContract {
        let mut contract = QualityContract::new(ContractId::new("search-q").expect("id"));
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("unit").expect("id"),
            kind: ValidatorKind::DeterministicCommand {
                name: "cargo-test".to_string(),
            },
            required_for_production: true,
        });
        contract
    }

    fn space() -> ConditionalSearchSpace {
        ConditionalSearchSpace {
            planner_enabled: vec![true, false],
            backends: vec![BackendId::well_known(BackendId::FAKE_PROVIDER)],
            slugs: vec![
                RuntimeSlug::new("catalog-small").expect("slug"),
                RuntimeSlug::new("catalog-large").expect("slug"),
            ],
            efforts: vec![CanonicalEffort::Low, CanonicalEffort::High],
            probe_lengths: vec![1],
            concurrencies: vec![1, 2],
            hedge_delays: vec![0],
            retry_limits: vec![1],
        }
    }

    #[test]
    fn search_never_removes_a_mandatory_validator() {
        let optimizer = ConstrainedTpeOptimizer::new(
            contract(),
            space(),
            CatalogVersion::new("v1").expect("cat"),
        )
        .expect("optimizer");
        let proposed = optimizer
            .propose(
                &OptimizationHistory::default(),
                &PolicySearchSpace::default(),
            )
            .expect("propose");
        assert!(!proposed.is_empty());
        for graph in &proposed {
            let certify = graph
                .nodes
                .values()
                .find(|node| matches!(node, PolicyNode::Certify(_)))
                .expect("certify node");
            match certify {
                PolicyNode::Certify(plan) => {
                    assert_eq!(plan.contract_id.as_str(), "search-q");
                }
                _ => unreachable!(),
            }
        }
        let proposals = optimizer.proposals_snapshot().expect("proposals");
        assert!(!proposals.is_empty());
        for proposal in proposals {
            assert_eq!(proposal.mandatory_validator_ids.len(), 1);
            assert_eq!(proposal.mandatory_validator_ids[0].as_str(), "unit");
            assert_eq!(proposal.contract_id.as_str(), "search-q");
        }
        let extended = optimizer.with_additional_validator(ValidatorBinding {
            validator_id: ValidatorId::new("security").expect("id"),
            kind: ValidatorKind::SecurityAnalysis {
                tool: "audit".to_string(),
            },
            required_for_production: true,
        });
        assert_eq!(optimizer.contract().mandatory_validators().len(), 1);
        assert_eq!(extended.mandatory_validators().len(), 2);
    }

    #[test]
    fn low_fidelity_observations_steer_search_but_cannot_promote() {
        let optimizer = ConstrainedTpeOptimizer::new(
            contract(),
            space(),
            CatalogVersion::new("v1").expect("cat"),
        )
        .expect("optimizer");
        let configs = optimizer.space.enumerate().expect("enum");
        let cheap = configs[0].clone();
        optimizer
            .record_observation(FidelityObservation {
                policy_id: PolicyId::new("obs-cheap").expect("id"),
                config: cheap,
                fidelity: EvaluationFidelity::F0StaticPrediction,
                observed_at: TimestampMillis::from_millis(1),
                certified: true,
                cost_micros: 10,
                task_class: "coding".to_string(),
            })
            .expect("obs");
        optimizer
            .record_observation(FidelityObservation {
                policy_id: PolicyId::new("obs-dear").expect("id"),
                config: configs[1].clone(),
                fidelity: EvaluationFidelity::F1CheapRepoProbe,
                observed_at: TimestampMillis::from_millis(2),
                certified: true,
                cost_micros: 9_000,
                task_class: "docs".to_string(),
            })
            .expect("obs");
        let proposed = optimizer
            .propose(
                &OptimizationHistory::default(),
                &PolicySearchSpace::default(),
            )
            .expect("propose");
        assert!(!proposed.is_empty());
        assert!(!EvaluationFidelity::F0StaticPrediction.can_promote_to_safe_set());
        assert!(!EvaluationFidelity::F3HistoricalReplay.can_promote_to_safe_set());
        assert!(EvaluationFidelity::F4HiddenValidation.can_promote_to_safe_set());
        assert!(EvaluationFidelity::F5ProductionShadow.can_promote_to_safe_set());
    }

    #[test]
    fn global_objective_averages_across_task_classes() {
        let optimizer = ConstrainedTpeOptimizer::new(
            contract(),
            space(),
            CatalogVersion::new("v1").expect("cat"),
        )
        .expect("optimizer");
        let config = optimizer.space.enumerate().expect("enum")[0].clone();
        optimizer
            .record_observation(FidelityObservation {
                policy_id: PolicyId::new("a").expect("id"),
                config: config.clone(),
                fidelity: EvaluationFidelity::F4HiddenValidation,
                observed_at: TimestampMillis::from_millis(1),
                certified: true,
                cost_micros: 100,
                task_class: "coding".to_string(),
            })
            .expect("obs");
        optimizer
            .record_observation(FidelityObservation {
                policy_id: PolicyId::new("b").expect("id"),
                config,
                fidelity: EvaluationFidelity::F4HiddenValidation,
                observed_at: TimestampMillis::from_millis(2),
                certified: true,
                cost_micros: 300,
                task_class: "docs".to_string(),
            })
            .expect("obs");
        assert_eq!(
            optimizer.expected_cost_to_certification().expect("obj"),
            200
        );
    }

    #[test]
    fn search_proposals_and_fidelity_levels_are_persisted() {
        let optimizer = ConstrainedTpeOptimizer::new(
            contract(),
            space(),
            CatalogVersion::new("v1").expect("cat"),
        )
        .expect("optimizer");
        optimizer
            .propose(
                &OptimizationHistory::default(),
                &PolicySearchSpace::default(),
            )
            .expect("propose");
        let proposals = optimizer.proposals_snapshot().expect("proposals");
        assert!(proposals
            .iter()
            .all(|proposal| proposal.fidelity == EvaluationFidelity::F0StaticPrediction));
        assert!(proposals
            .iter()
            .all(|proposal| !proposal.policy_id.as_str().is_empty()));
    }

    #[test]
    fn weekly_capacity_and_frontier_reserve_constrain_search_spend() {
        let optimizer = ConstrainedTpeOptimizer::new(
            contract(),
            space(),
            CatalogVersion::new("v1").expect("cat"),
        )
        .expect("optimizer");
        assert!(optimizer.weekly_capacity_feasible(Quantity::new(100), Quantity::new(40)));
        assert!(!optimizer.weekly_capacity_feasible(Quantity::new(10), Quantity::new(40)));

        let store = InMemorySafeSetStore::cold_start(PolicyId::new("baseline").expect("id"));
        let mut resources = ResourceVector::new();
        resources.insert(crate::optimizer::resources::ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            remaining: Quantity::new(50),
            reset_at: None,
            frontier_reserve: Quantity::new(40),
            emergency_margin: Quantity::new(5),
            uncertainty: Quantity::ZERO,
            shadow_price: 0,
            observation: crate::optimizer::resources::ResourceObservation {
                kind: crate::optimizer::resources::ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 100,
            target_usage_bp: 5_000,
            learning_rate: 100,
        });
        let err = optimizer
            .admit_search_spend(
                &store,
                &resources,
                &ExplorationBudgetRequest {
                    pool: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
                    demand: Quantity::new(10),
                },
            )
            .expect_err("reserve");
        assert!(matches!(err, OptimizerError::FrontierReserveViolation(_)));
    }
}

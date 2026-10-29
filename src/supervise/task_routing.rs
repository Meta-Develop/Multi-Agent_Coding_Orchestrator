//! Structural task features from validated scope, never from provider or model names.

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

use crate::planning::{self, TaskDecompositionProposal};
use crate::selection::routing_policy::{
    evaluate_task_grain, TaskGrain, TaskRoutingFeatures, TreeRoutingPolicy,
};
use crate::sync::normalize_repo_relative_path;

use serde::{Deserialize, Serialize};

use crate::selection::routing_policy::{
    FrozenRoutingPolicy, TaskEstimateMatch, TaskEstimationPolicy, TaskScoreWeights,
};
use crate::selection::TaskProfile;

/// Scores and context are loaded-policy heuristics, not native observations.
/// Structural counts are revalidated declared scope, not measured execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAssessmentProvenance {
    PolicyHeuristic,
}

/// Bounded replay data. No repository contents, provider observations or diagnostics are stored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskEstimationDeclaration {
    declared_task: String,
    fragments: Vec<TaskEstimationFragment>,
    assignments: Vec<TaskEstimationAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskEstimationFragment {
    id: String,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskEstimationAssignment {
    id: String,
    task: String,
    fragment_ids: Vec<String>,
    assigned_paths: Vec<String>,
    semantic_symbols: Vec<String>,
    semantic_modules: Vec<String>,
    decision_dependencies: Vec<String>,
}

/// Serializable decision data, never account, launch or permission authority.
/// The private declaration permits deterministic revalidation rather than trusting scores.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRoutingAssessment {
    pub features: TaskRoutingFeatures,
    pub policy_sha256: String,
    pub declared_input_sha256: String,
    provenance: TaskAssessmentProvenance,
    declaration: Box<TaskEstimationDeclaration>,
}

impl std::fmt::Debug for TaskRoutingAssessment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskRoutingAssessment")
            .field("features", &self.features)
            .field("policy_sha256", &self.policy_sha256)
            .field("declared_input_sha256", &self.declared_input_sha256)
            .field("provenance", &self.provenance)
            .field("declaration", &"[bounded declared inputs]")
            .finish()
    }
}

impl TaskRoutingAssessment {
    pub fn provenance(&self) -> TaskAssessmentProvenance {
        self.provenance
    }

    pub fn validate(&self, frozen: &FrozenRoutingPolicy) -> Result<()> {
        let (features, digest) = estimate_declaration(&self.declaration, frozen)?;
        if self.policy_sha256 != frozen.sha256
            || self.declared_input_sha256 != digest
            || self.features != features
        {
            bail!("task assessment declaration, policy or deterministic estimates differ");
        }
        Ok(())
    }

    pub fn validate_for_task(
        &self,
        frozen: &FrozenRoutingPolicy,
        declared_task: &str,
    ) -> Result<()> {
        self.validate(frozen)?;
        if self.declaration.declared_task != declared_task {
            bail!("task assessment differs from the current canonical declared task");
        }
        Ok(())
    }
}

pub(super) fn effective_estimator(frozen: &FrozenRoutingPolicy) -> Result<&TaskEstimationPolicy> {
    frozen.policy.validate()?;
    let digest = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
    if frozen.sha256 != digest {
        bail!("task assessment requires an unchanged frozen routing policy");
    }
    frozen.policy.task_estimation.as_ref().context(
        "task estimator policy adoption required: the frozen policy has no task_estimation",
    )
}

impl TaskEstimationDeclaration {
    fn to_proposal(&self) -> TaskDecompositionProposal {
        TaskDecompositionProposal {
            fragments: self
                .fragments
                .iter()
                .map(|fragment| planning::TaskSpecFragment {
                    id: fragment.id.clone(),
                    text: fragment.text.clone(),
                })
                .collect(),
            assignments: self
                .assignments
                .iter()
                .map(|assignment| planning::TaskAssignmentProposal {
                    id: assignment.id.clone(),
                    task: assignment.task.clone(),
                    fragment_ids: assignment.fragment_ids.clone(),
                    assigned_paths: assignment
                        .assigned_paths
                        .iter()
                        .map(std::path::PathBuf::from)
                        .collect(),
                    semantic_symbols: assignment.semantic_symbols.clone(),
                    semantic_modules: assignment.semantic_modules.clone(),
                    decision_dependencies: assignment.decision_dependencies.clone(),
                })
                .collect(),
            coverage_gaps: Vec::new(),
            diagnostics: planning::TaskPathProposalDiagnostics::default(),
            disjointness: planning::TaskDisjointnessReport::default(),
        }
    }

    fn validate_bounds(&self, policy: &TaskEstimationPolicy) -> Result<Vec<u8>> {
        if self.declared_task.trim().is_empty()
            || self.fragments.is_empty()
            || self.fragments.len() as u64 > policy.max_fragments
            || self.assignments.is_empty()
            || self.assignments.len() as u64 > policy.max_assignments
        {
            bail!("task estimator requires bounded nonempty declared task and proposal");
        }
        let mut bytes = 0u64;
        let mut scope_items = 0u64;
        let mut add_text = |text: &str| -> Result<()> {
            bytes = bytes
                .checked_add(u64::try_from(text.len())?)
                .context("task declaration byte count overflow")?;
            if bytes > policy.max_declaration_bytes {
                bail!("task declaration exceeds the estimator input bound");
            }
            Ok(())
        };
        add_text(&self.declared_task)?;
        for fragment in &self.fragments {
            if fragment.text.trim().is_empty() {
                bail!("task estimator requires nonempty declared fragment text");
            }
            add_text(&fragment.id)?;
            add_text(&fragment.text)?;
        }
        let mut assignment_ids = BTreeSet::new();
        for assignment in &self.assignments {
            if assignment.id.trim().is_empty() || !assignment_ids.insert(&assignment.id) {
                bail!("task estimator requires unique nonempty assignment identities");
            }
            add_text(&assignment.id)?;
            add_text(&assignment.task)?;
            for values in [
                &assignment.fragment_ids,
                &assignment.assigned_paths,
                &assignment.semantic_symbols,
                &assignment.semantic_modules,
                &assignment.decision_dependencies,
            ] {
                scope_items = scope_items
                    .checked_add(u64::try_from(values.len())?)
                    .context("task declaration scope count overflow")?;
                if scope_items > policy.max_scope_items {
                    bail!("task declaration exceeds the estimator scope bound");
                }
                for value in values {
                    if value.trim().is_empty() {
                        bail!("task estimator refuses empty scope or fragment declarations");
                    }
                    add_text(value)?;
                }
            }
            for path in &assignment.assigned_paths {
                if canonical_estimation_scope(std::path::Path::new(path))? != *path {
                    bail!("task estimator requires canonical declared scope paths");
                }
            }
        }
        let canonical = serde_json::to_vec(self)?;
        if canonical.len() as u64 > policy.max_declaration_bytes {
            bail!("encoded task declaration exceeds the estimator input bound");
        }
        Ok(canonical)
    }
}

/// Estimates exactly the canonical text used for SupervisorPlan.task and a validated proposal.
/// This function never reads scoped files, metadata, credentials or provider catalogs.
pub fn assess_task_routing(
    declared_task: &str,
    proposal: &TaskDecompositionProposal,
    frozen: &FrozenRoutingPolicy,
) -> Result<TaskRoutingAssessment> {
    let policy = effective_estimator(frozen)?;
    if declared_task.len() as u64 > policy.max_declaration_bytes
        || proposal.fragments.len() as u64 > policy.max_fragments
        || proposal.assignments.len() as u64 > policy.max_assignments
    {
        bail!("task declaration exceeds the estimator input or proposal bound");
    }

    let mut declared_bytes = u64::try_from(declared_task.len())?;
    let mut scope_items = 0u64;
    let mut count_text = |text: &str| -> Result<()> {
        declared_bytes = declared_bytes
            .checked_add(u64::try_from(text.len())?)
            .context("task declaration byte count overflow")?;
        if declared_bytes > policy.max_declaration_bytes {
            bail!("task declaration exceeds the estimator input bound");
        }
        Ok(())
    };
    for fragment in &proposal.fragments {
        count_text(&fragment.id)?;
        count_text(&fragment.text)?;
    }
    for assignment in &proposal.assignments {
        count_text(&assignment.id)?;
        count_text(&assignment.task)?;
        scope_items = scope_items
            .checked_add(u64::try_from(assignment.assigned_paths.len())?)
            .context("task declaration scope count overflow")?;
        for path in &assignment.assigned_paths {
            count_text(
                path.to_str()
                    .context("task estimator scope path is not UTF-8")?,
            )?;
        }
        for values in [
            &assignment.fragment_ids,
            &assignment.semantic_symbols,
            &assignment.semantic_modules,
            &assignment.decision_dependencies,
        ] {
            scope_items = scope_items
                .checked_add(u64::try_from(values.len())?)
                .context("task declaration scope count overflow")?;
            for value in values {
                count_text(value)?;
            }
        }
        if scope_items > policy.max_scope_items {
            bail!("task declaration exceeds the estimator scope bound");
        }
    }
    // Revalidate actual diagnostics, coverage and ownership before compacting the declaration.
    features_from_proposal(proposal, &empty_structural_seed())?;
    let declaration = TaskEstimationDeclaration {
        declared_task: declared_task.to_string(),
        fragments: proposal
            .fragments
            .iter()
            .map(|fragment| TaskEstimationFragment {
                id: fragment.id.clone(),
                text: fragment.text.clone(),
            })
            .collect(),
        assignments: proposal
            .assignments
            .iter()
            .map(|assignment| {
                Ok(TaskEstimationAssignment {
                    id: assignment.id.clone(),
                    task: assignment.task.clone(),
                    fragment_ids: assignment.fragment_ids.clone(),
                    assigned_paths: assignment
                        .assigned_paths
                        .iter()
                        .map(|path| canonical_estimation_scope(path))
                        .collect::<Result<Vec<_>>>()?,
                    semantic_symbols: assignment.semantic_symbols.clone(),
                    semantic_modules: assignment.semantic_modules.clone(),
                    decision_dependencies: assignment.decision_dependencies.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let (features, declared_input_sha256) = estimate_declaration(&declaration, frozen)?;
    Ok(TaskRoutingAssessment {
        features,
        policy_sha256: frozen.sha256.clone(),
        declared_input_sha256,
        provenance: TaskAssessmentProvenance::PolicyHeuristic,
        declaration: Box::new(declaration),
    })
}

pub(super) fn canonical_estimation_scope(path: &std::path::Path) -> Result<String> {
    let normalized = normalize_repo_relative_path(path)?;
    Ok(normalized
        .to_str()
        .context("task estimator scope path is not UTF-8")?
        .replace('\\', "/"))
}

// Scores in this temporary seed are never emitted as an assessment.
fn empty_structural_seed() -> TaskRoutingFeatures {
    TaskRoutingFeatures {
        scope_paths: 0,
        scope_modules: 0,
        complexity: 0,
        risk: 0,
        horizon: 0,
        context_tokens: 0,
        dependency_edges: 0,
        independent_groups: 0,
        evidence: Vec::new(),
    }
}

fn checked_weighted_score(
    weights: &TaskScoreWeights,
    declaration: &TaskEstimationDeclaration,
    declared_bytes: u64,
    features: &TaskRoutingFeatures,
) -> Result<u64> {
    let mut score = weights.base;
    for (weight, count) in [
        (weights.per_declared_kib, declared_bytes.div_ceil(1024)),
        (
            weights.per_fragment,
            u64::try_from(declaration.fragments.len())?,
        ),
        (
            weights.per_assignment,
            u64::try_from(declaration.assignments.len())?,
        ),
        (weights.per_scope_path, u64::try_from(features.scope_paths)?),
        (
            weights.per_scope_module,
            u64::try_from(features.scope_modules)?,
        ),
        (
            weights.per_dependency_edge,
            u64::try_from(features.dependency_edges)?,
        ),
    ] {
        score = score
            .checked_add(
                weight
                    .checked_mul(count)
                    .context("task score multiplication overflow")?,
            )
            .context("task score addition overflow")?;
    }
    Ok(score)
}

fn estimate_declaration(
    declaration: &TaskEstimationDeclaration,
    frozen: &FrozenRoutingPolicy,
) -> Result<(TaskRoutingFeatures, String)> {
    let policy = effective_estimator(frozen)?;
    let canonical = declaration.validate_bounds(policy)?;
    let declared_bytes = u64::try_from(canonical.len())?;
    let mut features =
        features_from_proposal(&declaration.to_proposal(), &empty_structural_seed())?;
    let mut complexity =
        checked_weighted_score(&policy.complexity, declaration, declared_bytes, &features)?;
    let mut risk = checked_weighted_score(&policy.risk, declaration, declared_bytes, &features)?;
    let mut horizon =
        checked_weighted_score(&policy.horizon, declaration, declared_bytes, &features)?;
    let lowered_task = declaration.declared_task.to_ascii_lowercase();
    for rule in &policy.rules {
        let matches = match rule.match_kind {
            TaskEstimateMatch::DeclaredTaskContainsAsciiInsensitive => {
                lowered_task.contains(&rule.pattern.to_ascii_lowercase())
            }
            TaskEstimateMatch::ScopePathPrefix => declaration
                .assignments
                .iter()
                .flat_map(|assignment| &assignment.assigned_paths)
                .any(|path| {
                    path == &rule.pattern || path.starts_with(&(rule.pattern.clone() + "/"))
                }),
        };
        if matches {
            complexity = complexity
                .checked_add(u64::from(rule.complexity_basis_points))
                .context("task rule score overflow")?;
            risk = risk
                .checked_add(u64::from(rule.risk_basis_points))
                .context("task rule score overflow")?;
            horizon = horizon
                .checked_add(u64::from(rule.horizon_basis_points))
                .context("task rule score overflow")?;
            features
                .evidence
                .push(format!("policy_heuristic_rule:{}", rule.id));
        }
    }
    let cap = u64::from(policy.score_cap_basis_points);
    features.complexity = u16::try_from(complexity.min(cap))?;
    features.risk = u16::try_from(risk.min(cap))?;
    features.horizon = u16::try_from(horizon.min(cap))?;
    let mut context = policy
        .context
        .base_tokens
        .checked_add(declared_bytes.div_ceil(policy.context.bytes_per_estimated_token))
        .context("task context addition overflow")?;
    for (weight, count) in [
        (
            policy.context.per_scope_path_tokens,
            u64::try_from(features.scope_paths)?,
        ),
        (
            policy.context.per_scope_module_tokens,
            u64::try_from(features.scope_modules)?,
        ),
        (
            policy.context.per_assignment_tokens,
            u64::try_from(declaration.assignments.len())?,
        ),
    ] {
        context = context
            .checked_add(
                weight
                    .checked_mul(count)
                    .context("task context multiplication overflow")?,
            )
            .context("task context addition overflow")?;
    }
    if context > policy.context.max_estimated_tokens {
        bail!("estimated declared-input context exceeds the policy bound");
    }
    features.context_tokens = context;
    features.evidence.extend([
        "assessment_basis_policy_heuristic_not_observed".to_string(),
        "context_estimates_encoded_declared_inputs_and_policy_allowances_only".to_string(),
        "score_saturation_is_explicit_loaded_policy".to_string(),
    ]);
    Ok((
        features,
        crate::artifacts::state_auth::sha256_hex(&canonical),
    ))
}

/// Project only task dimensions; intrinsic semantic authority and benchmark class are preserved.
#[cfg(test)]
pub fn project_task_profile(
    base: &TaskProfile,
    assessment: &TaskRoutingAssessment,
    frozen: &FrozenRoutingPolicy,
) -> Result<TaskProfile> {
    project_task_profile_with_final_features(base, assessment, &assessment.features, frozen)
}

/// Project independently revalidated final scopes without rewriting the assessed declaration.
/// The caller remains responsible for binding these counts to its validated final plan.
pub(super) fn project_task_profile_with_final_features(
    base: &TaskProfile,
    assessment: &TaskRoutingAssessment,
    final_features: &TaskRoutingFeatures,
    frozen: &FrozenRoutingPolicy,
) -> Result<TaskProfile> {
    assessment.validate(frozen)?;
    let policy = effective_estimator(frozen)?;
    let features = &assessment.features;
    if final_features.complexity != features.complexity
        || final_features.risk != features.risk
        || final_features.horizon != features.horizon
        || final_features.context_tokens != features.context_tokens
    {
        bail!("final task profile changed the assessed dimensions");
    }
    let scope_paths = u64::try_from(final_features.scope_paths)?;
    let scope_modules = u64::try_from(final_features.scope_modules)?;
    let dependency_edges = u64::try_from(final_features.dependency_edges)?;
    let independent_groups = u64::try_from(final_features.independent_groups)?;
    let scope_items = scope_paths
        .checked_add(scope_modules)
        .and_then(|count| count.checked_add(dependency_edges))
        .context("final task profile structural count overflow")?;
    if scope_items > policy.max_scope_items || independent_groups > policy.max_assignments {
        bail!("final task profile structural counts exceed the loaded estimator bounds");
    }
    let mut profile = base.clone();
    profile.risk = policy
        .risk_bands
        .iter()
        .find(|band| features.risk <= band.max_inclusive)
        .context("task risk band unavailable")?
        .value;
    profile.horizon = policy
        .horizon_bands
        .iter()
        .find(|band| features.horizon <= band.max_inclusive)
        .context("task horizon band unavailable")?
        .value;
    profile.context = policy
        .context_bands
        .iter()
        .find(|band| features.context_tokens <= band.max_inclusive)
        .context("task context band unavailable")?
        .value;
    profile.boundedness = policy
        .boundedness_bands
        .iter()
        .find(|band| {
            scope_paths <= band.max_scope_paths
                && scope_modules <= band.max_scope_modules
                && dependency_edges <= band.max_dependency_edges
                && features.complexity <= band.max_complexity
        })
        .context("task boundedness band unavailable")?
        .value;
    Ok(profile)
}

/// Keep assessed scores and measured context separate from structural observations.
/// A caller must label missing assessments honestly; path counts are not a token,
/// risk, complexity, or horizon measurement. Submitted count fields are replaced.
pub(super) fn features_from_proposal(
    proposal: &TaskDecompositionProposal,
    assessment: &TaskRoutingFeatures,
) -> Result<TaskRoutingFeatures> {
    if proposal.assignments.is_empty()
        || !proposal.coverage_gaps.is_empty()
        || proposal.diagnostics.degraded
    {
        bail!("task routing requires a complete, nondegraded decomposition");
    }
    planning::validate_task_assignment_disjointness(&proposal.assignments)
        .context("task routing requires independently owned scope")?;
    let fragments = proposal
        .fragments
        .iter()
        .map(|fragment| fragment.id.as_str())
        .collect::<BTreeSet<_>>();
    if fragments.len() != proposal.fragments.len()
        || fragments.is_empty()
        || fragments.iter().any(|id| id.trim().is_empty())
    {
        bail!("task routing requires unique nonempty spec fragment identities");
    }
    let mut covered = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut modules = BTreeSet::new();
    let mut dependency_owners: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut dependency_edges = 0usize;
    for (index, assignment) in proposal.assignments.iter().enumerate() {
        if assignment.task.trim().is_empty()
            || assignment.fragment_ids.is_empty()
            || (assignment.assigned_paths.is_empty()
                && assignment.semantic_symbols.is_empty()
                && assignment.semantic_modules.is_empty())
        {
            bail!("task routing requires productive scope and fragment coverage");
        }
        for fragment in &assignment.fragment_ids {
            if !fragments.contains(fragment.as_str()) || !covered.insert(fragment.as_str()) {
                bail!("task routing found missing or duplicate fragment coverage");
            }
        }
        for path in &assignment.assigned_paths {
            paths.insert(normalize_repo_relative_path(path)?);
        }
        for module in &assignment.semantic_modules {
            modules.insert(
                module
                    .split("::")
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        let keys = assignment
            .decision_dependencies
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for key in keys {
            if key.trim().is_empty() {
                bail!("task routing found an empty decision dependency");
            }
            dependency_edges = dependency_edges
                .checked_add(1)
                .context("dependency count overflow")?;
            dependency_owners.entry(key).or_default().push(index);
        }
    }
    if covered != fragments {
        bail!("task routing found unassigned spec fragments");
    }
    // Shared decision requirements conservatively join workstreams. A connected
    // component is useful independent grain, not proof of runtime concurrency.
    let mut groups = (0..proposal.assignments.len()).collect::<Vec<_>>();
    for owners in dependency_owners.values() {
        let group = groups[owners[0]];
        for owner in &owners[1..] {
            let previous = groups[*owner];
            for current in &mut groups {
                if *current == previous {
                    *current = group;
                }
            }
        }
    }
    let mut features = assessment.clone();
    features.scope_paths = paths.len();
    features.scope_modules = modules.len();
    features.dependency_edges = dependency_edges;
    features.independent_groups = groups.into_iter().collect::<BTreeSet<_>>().len();
    features.evidence.extend([
        "canonical_scope_and_disjointness_revalidated".to_string(),
        "fragment_coverage_revalidated".to_string(),
        "dependency_edges_are_declared_decision_incidences".to_string(),
        "independent_groups_are_conservative_decision_components".to_string(),
    ]);
    Ok(features)
}

pub(super) fn classify_proposal(
    proposal: &TaskDecompositionProposal,
    assessment: &TaskRoutingFeatures,
    policy: &TreeRoutingPolicy,
) -> Result<(TaskRoutingFeatures, TaskGrain)> {
    let features = features_from_proposal(proposal, assessment)?;
    let grain = evaluate_task_grain(&features, policy)?;
    Ok((features, grain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frozen_estimation_policy(
        policy: crate::selection::routing_policy::LoadedRoutingPolicy,
    ) -> Result<FrozenRoutingPolicy> {
        policy.validate()?;
        Ok(FrozenRoutingPolicy {
            sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy)?),
            policy,
            source: "public-estimator-test-data".to_string(),
        })
    }

    fn estimation_policy() -> Result<FrozenRoutingPolicy> {
        frozen_estimation_policy(serde_json::from_str(include_str!(
            "../selection/data/routing-policy.json"
        ))?)
    }

    fn unassessed_profile() -> TaskProfile {
        TaskProfile {
            task_class: "coding".to_string(),
            risk: crate::selection::RiskLevel::Unknown,
            boundedness: crate::selection::Boundedness::Unknown,
            context: crate::selection::ContextSize::Unknown,
            horizon: crate::selection::TaskHorizon::Unknown,
            authority_role: crate::selection::AuthorityRole::ReviewAuditor,
        }
    }

    #[test]
    fn policy_heuristics_change_same_shape_task_without_changing_role_authority() -> Result<()> {
        let frozen = estimation_policy()?;
        let simple = assess_task_routing("Review documentation.", &proposal(), &frozen)?;
        let task = format!(
            "delete obsolete data in a multi-stage migration. {}",
            "declared documentation context ".repeat(2000)
        );
        let demanding = assess_task_routing(&task, &proposal(), &frozen)?;
        assert_eq!(simple.features.scope_paths, demanding.features.scope_paths);
        assert_eq!(
            simple.features.independent_groups,
            demanding.features.independent_groups
        );
        assert!(demanding.features.risk > simple.features.risk);
        assert!(demanding.features.horizon > simple.features.horizon);
        assert!(demanding.features.context_tokens > simple.features.context_tokens);
        assert_eq!(
            demanding.provenance(),
            TaskAssessmentProvenance::PolicyHeuristic
        );
        assert!(demanding
            .features
            .evidence
            .iter()
            .any(|value| value == "assessment_basis_policy_heuristic_not_observed"));
        let base = unassessed_profile();
        let simple_profile = project_task_profile(&base, &simple, &frozen)?;
        let demanding_profile = project_task_profile(&base, &demanding, &frozen)?;
        assert_ne!(simple_profile.risk, demanding_profile.risk);
        assert_ne!(simple_profile.horizon, demanding_profile.horizon);
        assert_ne!(simple_profile.context, demanding_profile.context);
        assert_eq!(demanding_profile.authority_role, base.authority_role);
        assert_eq!(demanding_profile.task_class, base.task_class);
        Ok(())
    }

    #[test]
    fn loaded_estimator_changes_estimates_and_profile_without_algorithm_changes() -> Result<()> {
        let frozen = estimation_policy()?;
        let task = "Review documentation.";
        let original = assess_task_routing(task, &proposal(), &frozen)?;
        let mut policy = frozen.policy.clone();
        let estimator = policy.task_estimation.as_mut().unwrap();
        estimator.risk.base = 5000;
        estimator.horizon.base = 6500;
        estimator.context_bands[0].max_inclusive = 0;
        let changed = frozen_estimation_policy(policy)?;
        let assessment = assess_task_routing(task, &proposal(), &changed)?;
        let base = unassessed_profile();
        let before = project_task_profile(&base, &original, &frozen)?;
        let after = project_task_profile(&base, &assessment, &changed)?;
        assert_ne!(original.policy_sha256, assessment.policy_sha256);
        assert_eq!(
            original.declared_input_sha256,
            assessment.declared_input_sha256
        );
        assert_ne!(before.risk, after.risk);
        assert_ne!(before.horizon, after.horizon);
        assert_ne!(before.context, after.context);
        assert!(original.validate(&changed).is_err());
        Ok(())
    }

    #[test]
    fn final_scope_profile_tracks_expansion_and_dependencies_without_reestimating() -> Result<()> {
        let frozen = estimation_policy()?;
        let mut declared = proposal();
        declared.fragments.truncate(1);
        declared.assignments.truncate(1);
        let assessment = assess_task_routing("Review code.", &declared, &frozen)?;
        let original_assessment = assessment.clone();
        let base = unassessed_profile();
        let initial = project_task_profile(&base, &assessment, &frozen)?;
        assert_eq!(
            initial.boundedness,
            crate::selection::Boundedness::TightlyBounded
        );

        let mut expanded = declared.clone();
        expanded.assignments[0]
            .assigned_paths
            .push("extra.rs".into());
        let expanded_features = features_from_proposal(&expanded, &assessment.features)?;
        assert_eq!(expanded_features.scope_paths, 2);
        let expanded_profile = project_task_profile_with_final_features(
            &base,
            &assessment,
            &expanded_features,
            &frozen,
        )?;
        assert_eq!(
            expanded_profile.boundedness,
            crate::selection::Boundedness::Bounded
        );

        let mut dependent = declared;
        dependent.assignments[0]
            .decision_dependencies
            .push("interface-choice".into());
        let dependent_features = features_from_proposal(&dependent, &assessment.features)?;
        assert_eq!(dependent_features.dependency_edges, 1);
        let dependent_profile = project_task_profile_with_final_features(
            &base,
            &assessment,
            &dependent_features,
            &frozen,
        )?;
        assert_eq!(
            dependent_profile.boundedness,
            crate::selection::Boundedness::Bounded
        );
        for projected in [&expanded_profile, &dependent_profile] {
            assert_eq!(projected.risk, initial.risk);
            assert_eq!(projected.context, initial.context);
            assert_eq!(projected.horizon, initial.horizon);
            assert_eq!(projected.authority_role, base.authority_role);
            assert_eq!(projected.task_class, base.task_class);
        }
        assert_eq!(assessment, original_assessment);
        Ok(())
    }

    #[test]
    fn final_scope_profile_refuses_assessed_dimension_drift() -> Result<()> {
        let frozen = estimation_policy()?;
        let assessment = assess_task_routing("Review code.", &proposal(), &frozen)?;
        let base = unassessed_profile();
        for axis in ["complexity", "risk", "horizon", "context"] {
            let mut changed = assessment.features.clone();
            match axis {
                "complexity" => changed.complexity += 1,
                "risk" => changed.risk += 1,
                "horizon" => changed.horizon += 1,
                "context" => changed.context_tokens += 1,
                _ => unreachable!(),
            }
            let error =
                project_task_profile_with_final_features(&base, &assessment, &changed, &frozen)
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains("changed the assessed dimensions"));
        }
        Ok(())
    }

    #[test]
    fn final_scope_profile_refuses_out_of_policy_structural_counts() -> Result<()> {
        let frozen = estimation_policy()?;
        let assessment = assess_task_routing("Review code.", &proposal(), &frozen)?;
        let base = unassessed_profile();
        let estimator = frozen.policy.task_estimation.as_ref().unwrap();
        let scope_bound = usize::try_from(estimator.max_scope_items)?;
        let group_bound = usize::try_from(estimator.max_assignments)?;
        for axis in ["paths", "modules", "dependencies", "groups", "aggregate"] {
            let mut changed = assessment.features.clone();
            match axis {
                "paths" => changed.scope_paths = scope_bound + 1,
                "modules" => changed.scope_modules = scope_bound + 1,
                "dependencies" => changed.dependency_edges = scope_bound + 1,
                "groups" => changed.independent_groups = group_bound + 1,
                "aggregate" => {
                    changed.scope_paths = scope_bound;
                    changed.scope_modules = 1;
                }
                _ => unreachable!(),
            }
            let error =
                project_task_profile_with_final_features(&base, &assessment, &changed, &frozen)
                    .unwrap_err();
            assert!(error
                .to_string()
                .contains("exceed the loaded estimator bounds"));
        }
        Ok(())
    }

    #[test]
    fn assessment_replay_refuses_estimate_policy_and_canonical_task_drift() -> Result<()> {
        let frozen = estimation_policy()?;
        let task = "Review documentation.";
        let original = assess_task_routing(task, &proposal(), &frozen)?;
        let restored: TaskRoutingAssessment =
            serde_json::from_slice(&serde_json::to_vec(&original)?)?;
        restored.validate_for_task(&frozen, task)?;
        assert_eq!(restored, original);
        let mut forged = original.clone();
        forged.features.risk += 1;
        assert!(forged.validate(&frozen).is_err());
        let mut forged = original.clone();
        forged.declared_input_sha256.clear();
        assert!(forged.validate(&frozen).is_err());
        let mut forged = original.clone();
        forged.declaration.declared_task = "A different canonical task".to_string();
        assert!(forged.validate(&frozen).is_err());
        assert!(original
            .validate_for_task(&frozen, "Review documentation. ")
            .is_err());
        let mut incompatible = frozen.clone();
        incompatible.sha256.clear();
        assert!(original.validate(&incompatible).is_err());
        incompatible.policy.schema_version = 2;
        incompatible.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&incompatible.policy)?);
        assert!(original.validate(&incompatible).is_err());
        Ok(())
    }

    #[test]
    fn assessment_refuses_invalid_scope_degraded_proposals_and_oversized_inputs() -> Result<()> {
        let frozen = estimation_policy()?;
        let mut overlapping = proposal();
        overlapping.assignments[1].assigned_paths =
            overlapping.assignments[0].assigned_paths.clone();
        assert!(assess_task_routing("Review", &overlapping, &frozen).is_err());
        let mut missing = proposal();
        missing.assignments.pop();
        assert!(assess_task_routing("Review", &missing, &frozen).is_err());
        let mut degraded = proposal();
        degraded.diagnostics.degraded = true;
        assert!(assess_task_routing("Review", &degraded, &frozen).is_err());
        let bound = frozen
            .policy
            .task_estimation
            .as_ref()
            .unwrap()
            .max_declaration_bytes;
        assert!(assess_task_routing(
            &"x".repeat(usize::try_from(bound)? + 1),
            &proposal(),
            &frozen
        )
        .is_err());
        let scope_bound = frozen
            .policy
            .task_estimation
            .as_ref()
            .unwrap()
            .max_scope_items;
        let mut oversized_scope = proposal();
        oversized_scope.assignments[0].assigned_paths = (0..=scope_bound)
            .map(|index| std::path::PathBuf::from(format!("owned/{index}.rs")))
            .collect();
        let error = assess_task_routing("Review", &oversized_scope, &frozen).unwrap_err();
        assert!(error.to_string().contains("estimator scope bound"));
        let mut declaration = assess_task_routing("Review", &proposal(), &frozen)?;
        declaration.declaration.assignments[0].assigned_paths = vec!["../escape".to_string()];
        assert!(declaration.validate(&frozen).is_err());
        Ok(())
    }

    #[test]
    fn missing_estimator_requires_adoption_and_loaded_unknown_bands_stay_unknown() -> Result<()> {
        let frozen = estimation_policy()?;
        let mut policy = frozen.policy.clone();
        policy.task_estimation = None;
        let legacy = frozen_estimation_policy(policy)?;
        let error = assess_task_routing("Review", &proposal(), &legacy).unwrap_err();
        assert!(error.to_string().contains("policy adoption required"));
        let mut policy = frozen.policy.clone();
        let estimator = policy.task_estimation.as_mut().unwrap();
        for band in &mut estimator.risk_bands {
            band.value = crate::selection::RiskLevel::Unknown;
        }
        for band in &mut estimator.horizon_bands {
            band.value = crate::selection::TaskHorizon::Unknown;
        }
        for band in &mut estimator.context_bands {
            band.value = crate::selection::ContextSize::Unknown;
        }
        for band in &mut estimator.boundedness_bands {
            band.value = crate::selection::Boundedness::Unknown;
        }
        let unknown_policy = frozen_estimation_policy(policy)?;
        let assessment = assess_task_routing("Review", &proposal(), &unknown_policy)?;
        let base = unassessed_profile();
        let projected = project_task_profile(&base, &assessment, &unknown_policy)?;
        assert_eq!(projected, base);
        assert!(assessment.features.context_tokens > 0);
        assert_eq!(
            assessment.provenance(),
            TaskAssessmentProvenance::PolicyHeuristic
        );
        Ok(())
    }

    #[test]
    fn assessment_wire_refuses_unknown_native_basis_and_null_or_extra_witness_fields() -> Result<()>
    {
        let frozen = estimation_policy()?;
        let assessment = assess_task_routing("Review", &proposal(), &frozen)?;
        let wire = serde_json::to_value(&assessment)?;
        let mut unknown = wire.clone();
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<TaskRoutingAssessment>(unknown).is_err());
        let mut native = wire.clone();
        native["provenance"] = json!("native_observed");
        assert!(serde_json::from_value::<TaskRoutingAssessment>(native).is_err());
        let mut absent = wire.clone();
        absent["declaration"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<TaskRoutingAssessment>(absent).is_err());
        let mut extra = wire;
        extra["declaration"]["assignments"][0]["grant"] = json!(true);
        assert!(serde_json::from_value::<TaskRoutingAssessment>(extra).is_err());
        Ok(())
    }

    #[test]
    fn final_structural_revalidation_preserves_assessed_dimensions() -> Result<()> {
        let frozen = estimation_policy()?;
        let assessment = assess_task_routing("multi-stage migration", &proposal(), &frozen)?;
        let mut final_proposal = proposal();
        final_proposal.assignments[1]
            .assigned_paths
            .push("c.rs".into());
        let final_features = features_from_proposal(&final_proposal, &assessment.features)?;
        assert_eq!(final_features.scope_paths, 3);
        assert_eq!(final_features.complexity, assessment.features.complexity);
        assert_eq!(final_features.risk, assessment.features.risk);
        assert_eq!(final_features.horizon, assessment.features.horizon);
        assert_eq!(
            final_features.context_tokens,
            assessment.features.context_tokens
        );
        assessment.validate_for_task(&frozen, "multi-stage migration")?;
        Ok(())
    }

    fn proposal() -> TaskDecompositionProposal {
        serde_json::from_value(json!({
            "fragments":[{"id":"a","text":"edit a"},{"id":"b","text":"edit b"}],
            "assignments":[
                {"id":"a","task":"edit a","fragment_ids":["a"],"assigned_paths":["a.rs"],"semantic_symbols":[],"semantic_modules":[]},
                {"id":"b","task":"edit b","fragment_ids":["b"],"assigned_paths":["b.rs"],"semantic_symbols":[],"semantic_modules":[]}
            ],
            "diagnostics":{"degraded":false,"notes":[]},
            "disjointness":{"disjoint":true,"conflicts":[]}
        })).unwrap()
    }

    fn assessment() -> TaskRoutingFeatures {
        TaskRoutingFeatures {
            scope_paths: 99,
            scope_modules: 99,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 99,
            independent_groups: 99,
            evidence: vec!["scores_and_context_unassessed_lower_bounds".into()],
        }
    }

    #[test]
    fn structural_counts_replace_untrusted_counts() {
        let features = features_from_proposal(&proposal(), &assessment()).unwrap();
        assert_eq!(features.scope_paths, 2);
        assert_eq!(features.scope_modules, 0);
        assert_eq!(features.independent_groups, 2);
        assert_eq!(features.dependency_edges, 0);
        assert_eq!(features.context_tokens, 0);
        assert!(features
            .evidence
            .contains(&"scores_and_context_unassessed_lower_bounds".into()));
    }

    #[test]
    fn shared_decisions_do_not_claim_independence() {
        let mut proposal = proposal();
        for assignment in &mut proposal.assignments {
            assignment.decision_dependencies.push("api-choice".into());
        }
        let features = features_from_proposal(&proposal, &assessment()).unwrap();
        assert_eq!(features.independent_groups, 1);
        assert_eq!(features.dependency_edges, 2);
    }

    #[test]
    fn forged_disjointness_and_coverage_are_refused() {
        let mut overlap = proposal();
        overlap.assignments[1].assigned_paths = overlap.assignments[0].assigned_paths.clone();
        assert!(features_from_proposal(&overlap, &assessment()).is_err());
        let mut missing = proposal();
        missing.assignments.pop();
        assert!(features_from_proposal(&missing, &assessment()).is_err());
    }
}

//! Pooled, portable routing evidence (issue #204).
//!
//! One repository cannot accumulate a routing-relevant sample. Exported
//! records carry typed features and outcomes only — never repository content
//! — and imported corpora inform priors while local observations dominate
//! their own cell. Dropping a corpus recomputes posteriors without it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::digest::sha256_hex;
use super::error::OptimizerError;
use super::features::{FeatureBag, FeatureValue};
use super::ids::{CatalogVersion, PolicyId, TimestampMillis};
use super::policy::PolicyGraph;
use super::predictor::{HierarchicalPolicyPredictor, HierarchyKey};
use super::state::OptimizerState;
use super::telemetry::PolicyExecutionId;
use crate::artifacts::ArtifactRetentionFamily;

pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const TAXONOMY_VERSION: u32 = 1;
pub const EVIDENCE_DIR_NAME: &str = "optimizer-evidence";

/// Closed vocabulary token. Free text, paths, and diffs are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClosedToken(String);

impl ClosedToken {
    pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
        let value = value.into();
        if !is_closed_token(&value) {
            return Err(scrub_error(
                ScrubClass::RepositoryContent,
                format!("not a closed token: {value}"),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_closed_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    bytes[1..].iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || *byte == b'.'
            || *byte == b'_'
            || *byte == b'-'
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubClass {
    RepositoryContent,
    Path,
    RequirementText,
    Diff,
    Transcript,
    BranchName,
}

fn scrub_error(class: ScrubClass, detail: impl Into<String>) -> OptimizerError {
    OptimizerError::invalid(format!("scrub violation ({class:?}): {}", detail.into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorpusId(String);

impl CorpusId {
    pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
        ClosedToken::new(value).map(|token| Self(token.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxonomyCell {
    pub task_class: ClosedToken,
    pub language: ClosedToken,
    pub hashed_repository: ContentHash,
}

impl TaxonomyCell {
    pub fn new(
        task_class: impl Into<String>,
        language: impl Into<String>,
        repository_identity: &str,
    ) -> Result<Self, OptimizerError> {
        Ok(Self {
            task_class: ClosedToken::new(task_class)?,
            language: ClosedToken::new(language)?,
            hashed_repository: hash_identity(repository_identity),
        })
    }
}

pub fn hash_identity(raw: &str) -> ContentHash {
    ContentHash(sha256_hex(raw.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingOutcome {
    pub certified: Option<bool>,
    pub first_pass_success: Option<bool>,
    pub human_intervention: bool,
    pub latency_micros: Option<i64>,
    pub cost_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<ClosedToken>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBody {
    pub schema_version: u32,
    pub taxonomy_version: u32,
    pub catalog_version: CatalogVersion,
    pub cell: TaxonomyCell,
    pub policy_id: PolicyId,
    pub features: FeatureBag,
    pub outcome: RoutingOutcome,
    pub observation_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_execution_id: Option<PolicyExecutionId>,
}

impl EvidenceBody {
    pub fn content_hash(&self) -> Result<ContentHash, OptimizerError> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            OptimizerError::invalid(format!("failed to serialize evidence body: {error}"))
        })?;
        Ok(ContentHash(sha256_hex(&encoded)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableEvidenceRecord {
    pub content_hash: ContentHash,
    pub body: EvidenceBody,
}

impl PortableEvidenceRecord {
    pub fn from_body(body: EvidenceBody) -> Result<Self, OptimizerError> {
        let content_hash = body.content_hash()?;
        Ok(Self { content_hash, body })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub corpus_id: CorpusId,
    pub schema_version: u32,
    pub taxonomy_version: u32,
    pub catalog_version: CatalogVersion,
    pub host_id: ContentHash,
    pub hashed_repository: ContentHash,
    pub recorded_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCorpus {
    pub manifest: CorpusManifest,
    pub records: Vec<PortableEvidenceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    pub features: FeatureBag,
    pub outcome: RoutingOutcome,
    pub cell: TaxonomyCell,
    pub policy_id: PolicyId,
    pub catalog_version: CatalogVersion,
    pub policy_execution_id: Option<PolicyExecutionId>,
    pub attachments: BTreeMap<String, String>,
}

const ALLOWED_TEXT_KEYS: &[&str] = &[
    "optimizer.task.class",
    "optimizer.task.language",
    "task.language",
    "task.framework",
];

pub fn export_record(request: &ExportRequest) -> Result<PortableEvidenceRecord, OptimizerError> {
    fail_closed_on_attachments(&request.attachments)?;
    scrub_features(&request.features)?;
    let body = EvidenceBody {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        taxonomy_version: TAXONOMY_VERSION,
        catalog_version: request.catalog_version.clone(),
        cell: request.cell.clone(),
        policy_id: request.policy_id.clone(),
        features: request.features.clone(),
        outcome: request.outcome.clone(),
        observation_count: 1,
        policy_execution_id: request.policy_execution_id.clone(),
    };
    PortableEvidenceRecord::from_body(body)
}

fn fail_closed_on_attachments(
    attachments: &BTreeMap<String, String>,
) -> Result<(), OptimizerError> {
    let Some((key, value)) = attachments.iter().next() else {
        return Ok(());
    };
    let class = classify_forbidden(key, value).unwrap_or(ScrubClass::RepositoryContent);
    Err(scrub_error(
        class,
        format!("attachment '{key}' is not portable"),
    ))
}

pub fn classify_forbidden(key: &str, value: &str) -> Option<ScrubClass> {
    let key = key.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    if key.contains("diff") || value.contains("\n+++") || value.contains("\n---") {
        return Some(ScrubClass::Diff);
    }
    if key.contains("transcript") || key.contains("prompt") {
        return Some(ScrubClass::Transcript);
    }
    if key.contains("branch") {
        return Some(ScrubClass::BranchName);
    }
    if key.contains("requirement") || key.contains("spec_text") {
        return Some(ScrubClass::RequirementText);
    }
    if key.contains("path")
        || value.contains('/')
        || value.contains('\\')
        || Path::new(&value).is_absolute()
    {
        return Some(ScrubClass::Path);
    }
    if key.contains("content") || key.contains("source") || key.contains("hunk") {
        return Some(ScrubClass::RepositoryContent);
    }
    None
}

fn scrub_features(features: &FeatureBag) -> Result<(), OptimizerError> {
    for (id, value) in features.iter() {
        match value {
            FeatureValue::Boolean(_) | FeatureValue::Integer(_) | FeatureValue::Micro(_) => {}
            FeatureValue::Text(text) => {
                if !ALLOWED_TEXT_KEYS.contains(&id.as_str()) {
                    return Err(scrub_error(
                        ScrubClass::RequirementText,
                        format!("feature {} carries free text", id.as_str()),
                    ));
                }
                ClosedToken::new(text.clone()).map_err(|_| {
                    if let Some(class) = classify_forbidden(id.as_str(), text) {
                        scrub_error(class, format!("feature {} is not portable", id.as_str()))
                    } else {
                        scrub_error(
                            ScrubClass::RepositoryContent,
                            format!("feature {} is not a closed token", id.as_str()),
                        )
                    }
                })?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusHealth {
    pub local_observations: u32,
    pub pooled_observations: u32,
    pub prior_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosteriorFingerprint {
    pub content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredObservation {
    source: ObservationSource,
    record: PortableEvidenceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservationSource {
    Local,
    Corpus(CorpusId),
}

#[derive(Debug, Clone, Default)]
pub struct EvidencePool {
    corpora: BTreeMap<String, EvidenceCorpus>,
    local: Vec<PortableEvidenceRecord>,
}

impl EvidencePool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn import(&mut self, corpus: EvidenceCorpus) -> Result<(), OptimizerError> {
        if corpus.manifest.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(OptimizerError::invalid(format!(
                "unsupported evidence schema {}",
                corpus.manifest.schema_version
            )));
        }
        for record in &corpus.records {
            let expected = record.body.content_hash()?;
            if expected != record.content_hash {
                return Err(OptimizerError::invalid(
                    "imported evidence content hash does not match body",
                ));
            }
            scrub_features(&record.body.features)?;
        }
        self.corpora
            .insert(corpus.manifest.corpus_id.as_str().to_string(), corpus);
        Ok(())
    }

    pub fn drop_corpus(&mut self, id: &CorpusId) -> Result<EvidenceCorpus, OptimizerError> {
        self.corpora.remove(id.as_str()).ok_or_else(|| {
            OptimizerError::invalid(format!("corpus {} is not imported", id.as_str()))
        })
    }

    pub fn record_local(&mut self, record: PortableEvidenceRecord) -> Result<(), OptimizerError> {
        let expected = record.body.content_hash()?;
        if expected != record.content_hash {
            return Err(OptimizerError::invalid(
                "local evidence content hash does not match body",
            ));
        }
        scrub_features(&record.body.features)?;
        self.local.push(record);
        Ok(())
    }

    pub fn health(&self, local_repository: &ContentHash) -> CorpusHealth {
        let mut local_observations = 0u32;
        let mut pooled_observations = 0u32;
        for stored in self.observations() {
            let record = &stored.record;
            let count = record.body.observation_count.max(1);
            if record.body.cell.hashed_repository == *local_repository {
                local_observations = local_observations.saturating_add(count);
            } else {
                pooled_observations = pooled_observations.saturating_add(count);
            }
        }
        CorpusHealth {
            prior_only: local_observations == 0 && pooled_observations == 0,
            local_observations,
            pooled_observations,
        }
    }

    pub fn fingerprint(&self) -> Result<PosteriorFingerprint, OptimizerError> {
        let mut chunks = Vec::new();
        for stored in self.observations() {
            let source = match &stored.source {
                ObservationSource::Local => "local",
                ObservationSource::Corpus(id) => id.as_str(),
            };
            chunks.push(format!(
                "{}:{}",
                source,
                stored.record.content_hash.as_str()
            ));
        }
        chunks.sort();
        Ok(PosteriorFingerprint {
            content_hash: ContentHash(sha256_hex(chunks.join("\n").as_bytes())),
        })
    }

    pub fn replay_predictor(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
        local_repository: &ContentHash,
    ) -> HierarchicalPolicyPredictor {
        let mut predictor = HierarchicalPolicyPredictor::new();
        for stored in self.observations() {
            apply_observation(
                &mut predictor,
                &stored.record,
                state,
                policy,
                local_repository,
            );
        }
        predictor
    }

    pub fn compact(&mut self, max_records: usize) {
        compact_records(&mut self.local, max_records);
        for corpus in self.corpora.values_mut() {
            compact_records(&mut corpus.records, max_records);
        }
    }

    fn observations(&self) -> Vec<StoredObservation> {
        let mut stored = Vec::new();
        for record in &self.local {
            stored.push(StoredObservation {
                source: ObservationSource::Local,
                record: record.clone(),
            });
        }
        for corpus in self.corpora.values() {
            for record in &corpus.records {
                stored.push(StoredObservation {
                    source: ObservationSource::Corpus(corpus.manifest.corpus_id.clone()),
                    record: record.clone(),
                });
            }
        }
        stored
    }
}

fn compact_records(records: &mut Vec<PortableEvidenceRecord>, max_records: usize) {
    let mut merged: BTreeMap<String, PortableEvidenceRecord> = BTreeMap::new();
    for record in records.drain(..) {
        let key = format!(
            "{}:{}:{}",
            record.body.cell.hashed_repository.as_str(),
            record.body.policy_id,
            record.body.outcome.certified.unwrap_or(false)
        );
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.body.observation_count = existing
                    .body
                    .observation_count
                    .saturating_add(record.body.observation_count.max(1));
            })
            .or_insert(record);
    }
    let mut compacted = Vec::new();
    for mut record in merged.into_values() {
        if let Ok(hash) = record.body.content_hash() {
            record.content_hash = hash;
            compacted.push(record);
        }
    }
    compacted.sort_by(|left, right| {
        right
            .body
            .observation_count
            .cmp(&left.body.observation_count)
            .then_with(|| left.content_hash.as_str().cmp(right.content_hash.as_str()))
    });
    if compacted.len() > max_records {
        compacted.truncate(max_records);
    }
    *records = compacted;
}

fn apply_observation(
    predictor: &mut HierarchicalPolicyPredictor,
    record: &PortableEvidenceRecord,
    state: &OptimizerState,
    policy: &PolicyGraph,
    local_repository: &ContentHash,
) {
    let count = record.body.observation_count.max(1);
    let local = record.body.cell.hashed_repository == *local_repository;
    // Foreign corpora update the global prior. Local records write the full
    // #167 hierarchy cell so they dominate wherever they exist.
    let key = if local {
        HierarchicalPolicyPredictor::hierarchy_for(state, policy)
    } else {
        HierarchyKey::global()
    };
    for _ in 0..count {
        if let Some(certified) = record.body.outcome.certified {
            predictor.observe_certification(key.clone(), certified);
        }
        if let Some(latency) = record.body.outcome.latency_micros {
            predictor.observe_latency(key.clone(), latency);
        }
        if let Some(cost) = record.body.outcome.cost_micros {
            predictor.observe_cost(key.clone(), cost);
        }
    }
}

pub fn evidence_root(repo: impl AsRef<Path>) -> PathBuf {
    repo.as_ref().join(".maco").join(EVIDENCE_DIR_NAME)
}

pub fn evidence_is_exempt_from_artifact_prune(repo: impl AsRef<Path>) -> bool {
    let evidence = evidence_root(repo);
    ArtifactRetentionFamily::ALL.iter().all(|family| {
        let run_root = family.run_root();
        if *family == ArtifactRetentionFamily::Program {
            return evidence.file_name().and_then(|name| name.to_str()) != Some("program-");
        }
        !run_root.ends_with(EVIDENCE_DIR_NAME)
            && run_root.file_name().and_then(|name| name.to_str()) != Some(EVIDENCE_DIR_NAME)
    })
}

/// Persist a corpus under the evidence root. Run-artifact prune (#71) does not
/// walk this directory.
pub fn write_corpus(
    repo: impl AsRef<Path>,
    corpus: &EvidenceCorpus,
) -> Result<PathBuf, OptimizerError> {
    let root = evidence_root(repo);
    fs::create_dir_all(&root).map_err(|error| {
        OptimizerError::invalid(format!("failed to create evidence root: {error}"))
    })?;
    let path = root.join(format!("{}.json", corpus.manifest.corpus_id.as_str()));
    let encoded = serde_json::to_vec_pretty(corpus).map_err(|error| {
        OptimizerError::invalid(format!("failed to serialize evidence corpus: {error}"))
    })?;
    fs::write(&path, encoded).map_err(|error| {
        OptimizerError::invalid(format!("failed to write evidence corpus: {error}"))
    })?;
    Ok(path)
}

pub fn read_corpus(path: impl AsRef<Path>) -> Result<EvidenceCorpus, OptimizerError> {
    let bytes = fs::read(path.as_ref()).map_err(|error| {
        OptimizerError::invalid(format!("failed to read evidence corpus: {error}"))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        OptimizerError::invalid(format!("evidence corpus is not valid JSON: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
        RestartMode, ReviewTopology, RuntimeModelId, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::ids::{
        BackendId, FeatureId, ModelFamilyId, PolicyNodeId, ProviderId, RuntimeSlug,
        VerifierProfileId,
    };
    use crate::optimizer::policy::PolicyNode;
    use crate::optimizer::predictor::{feature_keys, insert_text, PolicyPredictor};
    use crate::optimizer::state::DecisionHorizon;
    use tempfile::TempDir;

    fn catalog() -> CatalogVersion {
        CatalogVersion::new("cat-1").expect("catalog")
    }

    fn outcome(certified: bool) -> RoutingOutcome {
        RoutingOutcome {
            certified: Some(certified),
            first_pass_success: Some(certified),
            human_intervention: false,
            latency_micros: Some(2_000_000),
            cost_micros: Some(100_000),
            failure_class: None,
        }
    }

    fn request(repo: &str, certified: bool, policy: &str) -> ExportRequest {
        let mut features = FeatureBag::new();
        features.insert(
            FeatureId::new("optimizer.task.class").expect("id"),
            FeatureValue::Text("repair".to_string()),
        );
        features.insert(
            FeatureId::new("optimizer.task.language").expect("id"),
            FeatureValue::Text("rust".to_string()),
        );
        ExportRequest {
            features,
            outcome: outcome(certified),
            cell: TaxonomyCell::new("repair", "rust", repo).expect("cell"),
            policy_id: PolicyId::new(policy).expect("policy"),
            catalog_version: catalog(),
            policy_execution_id: None,
            attachments: BTreeMap::new(),
        }
    }

    fn topology() -> TopologySpec {
        TopologySpec {
            planner: PlannerTopology::Single,
            workers: WorkerTopology::One,
            hedge: HedgeTopology::None,
            review: ReviewTopology::Independent,
            restart: RestartMode::Continuation,
        }
    }

    fn graph(id: &str) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(
                start,
                PolicyNode::Execute(ModelAction {
                    backend_id: BackendId::well_known(BackendId::FAKE_PROVIDER),
                    provider_id: ProviderId::new("local").expect("provider"),
                    runtime_model: RuntimeModelId {
                        provider: ProviderId::new("local").expect("provider"),
                        backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
                        model_family: ModelFamilyId::new("family-a").expect("family"),
                        runtime_slug: RuntimeSlug::new("model-a").expect("slug"),
                        catalog_version: catalog(),
                        observation_timestamp: TimestampMillis::from_millis(1),
                    },
                    requested_slug: RuntimeSlug::new("model-a").expect("slug"),
                    effort: CanonicalEffort::Medium,
                    role: AgentRole::Worker,
                    max_turns: ExecutionBudget::default().max_turns,
                    timeout_seconds: 60,
                    tool_budget: None,
                    output_token_budget: None,
                    concurrency: 1,
                    verifier_profile: VerifierProfileId::new("default").expect("profile"),
                }),
            )
            .expect("node");
        graph
    }

    fn state(repo_hash: &ContentHash) -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1_000),
            deadline: Some(TimestampMillis::from_millis(1_000 + 3_600_000)),
            next_reset: None,
        });
        insert_text(&mut state.task_features, feature_keys::TASK_CLASS, "repair");
        insert_text(&mut state.task_features, feature_keys::LANGUAGE, "rust");
        insert_text(
            &mut state.repo_features,
            feature_keys::REPO_ID,
            repo_hash.as_str(),
        );
        state
    }

    fn corpus(id: &str, repo: &str, certified: bool, copies: usize) -> EvidenceCorpus {
        let cell = TaxonomyCell::new("repair", "rust", repo).expect("cell");
        let records = (0..copies)
            .map(|index| {
                let mut request = request(repo, certified, "p1");
                request.cell = cell.clone();
                request.policy_id = PolicyId::new(format!("p{index}")).unwrap_or(request.policy_id);
                export_record(&request).expect("export")
            })
            .collect();
        EvidenceCorpus {
            manifest: CorpusManifest {
                corpus_id: CorpusId::new(id).expect("id"),
                schema_version: EVIDENCE_SCHEMA_VERSION,
                taxonomy_version: TAXONOMY_VERSION,
                catalog_version: catalog(),
                host_id: hash_identity("host-a"),
                hashed_repository: hash_identity(repo),
                recorded_at: TimestampMillis::from_millis(5),
            },
            records,
        }
    }

    #[test]
    fn export_import_round_trip_preserves_content_hash() {
        let record = export_record(&request("repo-a", true, "p1")).expect("export");
        let encoded = serde_json::to_vec(&record).expect("json");
        let imported: PortableEvidenceRecord = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(record, imported);
        assert_eq!(
            record.content_hash,
            imported.body.content_hash().expect("hash")
        );
        assert_eq!(record.content_hash, imported.content_hash);
    }

    #[test]
    fn scrub_violation_fails_closed_per_forbidden_class() {
        let cases = [
            ("diff", "--- a\n+++ b\n", ScrubClass::Diff),
            ("transcript", "tool said hello", ScrubClass::Transcript),
            ("branch_name", "maco/feature", ScrubClass::BranchName),
            (
                "requirement_text",
                "the worker must...",
                ScrubClass::RequirementText,
            ),
            ("source_path", "src/optimizer/mod.rs", ScrubClass::Path),
            (
                "repository_content",
                "fn main() {}",
                ScrubClass::RepositoryContent,
            ),
        ];
        for (key, value, class) in cases {
            let mut request = request("repo-a", true, "p1");
            request
                .attachments
                .insert(key.to_string(), value.to_string());
            let error = export_record(&request).expect_err(key);
            let message = error.to_string();
            assert!(
                message.contains(&format!("{class:?}")),
                "{key} should fail as {class:?}, got {message}"
            );
        }
    }

    #[test]
    fn cold_start_import_narrows_priors_and_local_observation_dominates() {
        let local_cell = TaxonomyCell::new("repair", "rust", "local-repo").expect("cell");
        let policy = graph("p1");
        let state = state(&local_cell.hashed_repository);
        let mut pool = EvidencePool::new();
        let before = pool
            .replay_predictor(&state, &policy, &local_cell.hashed_repository)
            .predict(&state, &policy)
            .expect("before");

        pool.import(corpus("foreign-a", "foreign-repo", true, 40))
            .expect("import");
        let pooled = pool
            .replay_predictor(&state, &policy, &local_cell.hashed_repository)
            .predict(&state, &policy)
            .expect("pooled");
        assert!(
            pooled.quality_lower_confidence_bp > before.quality_lower_confidence_bp
                || pooled.certified_probability_bp > before.certified_probability_bp,
            "pooled evidence should narrow/raise the cold-start prior (before lcb={} p={}, after lcb={} p={})",
            before.quality_lower_confidence_bp,
            before.certified_probability_bp,
            pooled.quality_lower_confidence_bp,
            pooled.certified_probability_bp
        );

        let mut local_request = request("local-repo", false, "p1");
        local_request.cell = local_cell.clone();
        for _ in 0..12 {
            pool.record_local(export_record(&local_request).expect("local"))
                .expect("record");
        }
        let after_local = pool
            .replay_predictor(&state, &policy, &local_cell.hashed_repository)
            .predict(&state, &policy)
            .expect("local");
        assert!(
            after_local.certified_probability_bp < pooled.certified_probability_bp,
            "local failures must dominate the local cell (pooled {}, local {})",
            pooled.certified_probability_bp,
            after_local.certified_probability_bp
        );
        let health = pool.health(&local_cell.hashed_repository);
        assert!(health.local_observations > 0);
        assert!(health.pooled_observations > 0);
        assert!(!health.prior_only);
    }

    #[test]
    fn dropping_a_corpus_restores_pre_import_posteriors() {
        let local_cell = TaxonomyCell::new("repair", "rust", "local-repo").expect("cell");
        let policy = graph("p1");
        let state = state(&local_cell.hashed_repository);
        let mut pool = EvidencePool::new();
        let before = pool.fingerprint().expect("before");
        let before_pred = pool
            .replay_predictor(&state, &policy, &local_cell.hashed_repository)
            .predict(&state, &policy)
            .expect("before pred");
        pool.import(corpus("foreign-b", "foreign-repo", true, 16))
            .expect("import");
        let imported = pool.fingerprint().expect("imported");
        assert_ne!(before.content_hash, imported.content_hash);
        pool.drop_corpus(&CorpusId::new("foreign-b").expect("id"))
            .expect("drop");
        let restored = pool.fingerprint().expect("restored");
        assert_eq!(before.content_hash, restored.content_hash);
        let restored_pred = pool
            .replay_predictor(&state, &policy, &local_cell.hashed_repository)
            .predict(&state, &policy)
            .expect("restored pred");
        assert_eq!(
            before_pred.quality_lower_confidence_bp,
            restored_pred.quality_lower_confidence_bp
        );
        assert_eq!(
            before_pred.certified_probability_bp,
            restored_pred.certified_probability_bp
        );
    }

    #[test]
    fn run_artifact_prune_does_not_delete_evidence() {
        let temp = TempDir::new().expect("temp");
        let repo = temp.path();
        let corpus = corpus("keep-me", "repo-a", true, 1);
        let path = write_corpus(repo, &corpus).expect("write");
        assert!(path.exists());
        assert!(evidence_is_exempt_from_artifact_prune(repo));

        for family in ArtifactRetentionFamily::ALL {
            let root = repo.join(family.run_root());
            let _ = fs::create_dir_all(&root);
            if family == ArtifactRetentionFamily::Program {
                let _ = fs::create_dir_all(root.join("program-demo"));
            } else {
                let _ = fs::create_dir_all(root.join("run-demo"));
            }
        }
        // Simulate #71: delete every run-artifact family tree, leave evidence.
        for family in ArtifactRetentionFamily::ALL {
            let root = repo.join(family.run_root());
            if family == ArtifactRetentionFamily::Program {
                let _ = fs::remove_dir_all(root.join("program-demo"));
            } else if root.exists() {
                let _ = fs::remove_dir_all(&root);
            }
        }
        assert!(
            path.exists(),
            "evidence corpus must survive run-artifact prune"
        );
        let reloaded = read_corpus(&path).expect("reload");
        assert_eq!(reloaded.manifest.corpus_id.as_str(), "keep-me");
        assert_eq!(
            reloaded.records[0].content_hash,
            corpus.records[0].content_hash
        );
    }

    #[test]
    fn compact_recomputes_content_hashes_and_bounds_retention() {
        let mut pool = EvidencePool::new();
        let first = export_record(&request("repo-a", true, "p1")).expect("first");
        let second = export_record(&request("repo-a", true, "p1")).expect("second");
        let other = export_record(&request("repo-b", false, "p2")).expect("other");
        pool.record_local(first).expect("record first");
        pool.record_local(second).expect("record second");
        pool.record_local(other).expect("record other");
        pool.compact(1);
        assert_eq!(pool.local.len(), 1);
        let kept = &pool.local[0];
        assert_eq!(
            kept.content_hash,
            kept.body.content_hash().expect("rehashed")
        );
        assert_eq!(kept.body.observation_count, 2);
        assert_eq!(kept.body.cell.hashed_repository, hash_identity("repo-a"));
    }
}

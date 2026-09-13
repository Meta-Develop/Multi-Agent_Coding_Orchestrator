//! One operator-owned, immutable prior/capability snapshot for a supervise run.
//! The binding is scoped to the calling thread and explicitly copied into the
//! scheduler's child threads; it never installs a process-wide capability policy.

use super::{
    model_policy::{default_model_capability_policy, ModelCapabilityPolicy},
    selection_bridge::base_selector_priors_with_terminal_worker_economics,
};
use crate::{
    artifacts::{
        state_auth::sha256_hex, ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter,
        RunArtifactFamily,
    },
    orchestrator::RunId,
    safe_state::BoundedRegularReader,
    selection::{self, ModelPrior, PriorDataset},
    sync::normalize_repo_relative_path,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

const PRIOR_INPUT_SCHEMA_VERSION: u32 = 1;
const MAX_OPERATOR_PRIOR_INPUT_BYTES: u64 = 256 * 1024;
const RAW_ARTIFACT: &str = "operator_prior_data/input.json";
const EFFECTIVE_ARTIFACT: &str = "operator_prior_data/effective.json";
const BINDING_ARTIFACT: &str = "operator_prior_data/binding.json";

fn require_supported_prior_input_platform() -> Result<()> {
    #[cfg(not(unix))]
    bail!("operator prior data requires Unix component-wise repository path confinement; native Windows is unsupported");
    #[cfg(unix)]
    Ok(())
}

/// Only model rows are operator-editable. The bundled objective calibration is
/// retained exactly, including all quality/sample/cost gates.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPriorSnapshot {
    pub schema_version: u32,
    pub dataset_id: String,
    pub revision: String,
    pub published_on: String,
    pub models: Vec<ModelPrior>,
    pub capability_policy: ModelCapabilityPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePriorSnapshot {
    pub priors: PriorDataset,
    pub capability_policy: ModelCapabilityPolicy,
}

#[derive(Debug, Clone)]
pub(crate) struct BoundPriorData {
    repo: PathBuf,
    raw: Vec<u8>,
    effective: EffectivePriorSnapshot,
    provenance: selection::OperatorPriorDataProvenance,
}

thread_local! {
    static BOUND_PRIOR_DATA: RefCell<Option<Arc<BoundPriorData>>> = const { RefCell::new(None) };
}

/// Restore the previous binding after a run or a scoped scheduler thread ends.
pub struct OperatorPriorDataGuard {
    previous: Option<Arc<BoundPriorData>>,
    _thread_affine: PhantomData<Rc<()>>,
}

impl Drop for OperatorPriorDataGuard {
    fn drop(&mut self) {
        BOUND_PRIOR_DATA.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}

fn install(binding: Option<Arc<BoundPriorData>>) -> OperatorPriorDataGuard {
    BOUND_PRIOR_DATA.with(|slot| OperatorPriorDataGuard {
        previous: std::mem::replace(&mut *slot.borrow_mut(), binding),
        _thread_affine: PhantomData,
    })
}

pub(crate) fn captured_binding() -> Option<Arc<BoundPriorData>> {
    BOUND_PRIOR_DATA.with(|slot| slot.borrow().clone())
}

pub(crate) fn install_captured(binding: Option<Arc<BoundPriorData>>) -> OperatorPriorDataGuard {
    install(binding)
}

pub(crate) fn current_priors() -> Option<PriorDataset> {
    captured_binding().map(|binding| binding.effective.priors.clone())
}

pub(crate) fn current_capability_policy() -> Option<ModelCapabilityPolicy> {
    captured_binding().map(|binding| binding.effective.capability_policy.clone())
}

pub(crate) fn current_provenance() -> Option<selection::OperatorPriorDataProvenance> {
    captured_binding().map(|binding| binding.provenance.clone())
}

pub(crate) fn current_measured_authority_eligibility(
    model: &str,
    authority: selection::AuthorityRole,
) -> Result<selection::MeasuredAuthorityEligibility> {
    if let Some(priors) = current_priors() {
        return Ok(priors.measured_authority_eligibility(model, authority));
    }
    selection::measured_authority_eligibility(model, authority).map_err(Into::into)
}

pub(crate) fn require_binding_repo(repo: &Path) -> Result<()> {
    if let Some(binding) = captured_binding() {
        if binding.repo != repo {
            bail!("operator prior data is bound to a different repository than this supervise run");
        }
    }
    Ok(())
}

pub(crate) fn archive_current(writer: &mut ArtifactRunWriter, repo: &Path) -> Result<()> {
    require_binding_repo(repo)?;
    let Some(binding) = captured_binding() else {
        return Ok(());
    };
    writer.write_bytes(
        RAW_ARTIFACT,
        &binding.raw,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_json(
        EFFECTIVE_ARTIFACT,
        &binding.effective,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_json(
        BINDING_ARTIFACT,
        &binding.provenance,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    Ok(())
}

pub fn bind_operator_prior_data(
    repo: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Result<OperatorPriorDataGuard> {
    require_supported_prior_input_platform()?;
    let repo = crate::artifacts::discover_repo_root(repo.as_ref())?;
    let relative_path = normalize_repo_relative_path(relative_path.as_ref())
        .context("operator prior-data path must be repository-relative")?;
    let raw =
        BoundedRegularReader::read_relative(&repo, &relative_path, MAX_OPERATOR_PRIOR_INPUT_BYTES)
            .with_context(|| {
                format!(
                    "failed to read bounded repository-local operator prior data {}",
                    relative_path.display()
                )
            })?;
    Ok(install(Some(bind_from_bytes(repo, relative_path, raw)?)))
}

fn bind_from_bytes(
    repo: PathBuf,
    relative_path: PathBuf,
    raw: Vec<u8>,
) -> Result<Arc<BoundPriorData>> {
    let snapshot: OperatorPriorSnapshot =
        serde_json::from_slice(&raw).context("operator prior data is not valid strict JSON")?;
    // ModelCapabilityEvidence has a legacy `eligible=true` default. An operator
    // input must state its grant explicitly instead of inheriting that default.
    let raw_value: serde_json::Value = serde_json::from_slice(&raw)?;
    let capability_rows = raw_value["capability_policy"]["models"]
        .as_array()
        .context("operator capability models must be an array")?;
    if capability_rows
        .iter()
        .any(|row| row.get("eligible").is_none())
    {
        bail!("operator capability rows must state eligible explicitly");
    }
    if snapshot.schema_version != PRIOR_INPUT_SCHEMA_VERSION {
        bail!(
            "unsupported operator prior-data schema version {}",
            snapshot.schema_version
        );
    }
    let mut priors = base_selector_priors_with_terminal_worker_economics()?;
    if snapshot.dataset_id.trim().is_empty() || snapshot.revision.trim().is_empty() {
        bail!("operator prior data requires non-empty dataset_id and revision");
    }
    if snapshot.published_on < priors.published_on {
        bail!("operator prior data predates the bundled dataset it extends");
    }
    let mut seen = BTreeSet::new();
    for row in &snapshot.models {
        let key = (row.runtime.clone(), row.model.clone());
        if !seen.insert(key.clone()) {
            bail!(
                "operator prior data repeats runtime/model '{}:{}'",
                key.0,
                key.1
            );
        }
        if row.observed_on > snapshot.published_on {
            bail!(
                "operator prior '{}' is dated after its dataset publication",
                row.model
            );
        }
        if let Some(base) = priors
            .models
            .iter()
            .find(|base| base.runtime == row.runtime && base.model == row.model)
        {
            if row.observed_on < base.observed_on {
                bail!(
                    "operator prior '{}' predates the bundled row it updates",
                    row.model
                );
            }
            if (base.prohibited && !row.prohibited)
                || !base
                    .prohibited_authority_roles
                    .is_subset(&row.prohibited_authority_roles)
                || (!base.long_context_eligible && row.long_context_eligible)
                || !row
                    .strong_gate_fallback_efforts
                    .is_subset(&base.strong_gate_fallback_efforts)
            {
                bail!("operator prior data weakens bundled prohibition, role, long-context, or strong-gate effort policy for '{}:{}'", row.runtime, row.model);
            }
            priors
                .models
                .retain(|prior| prior.runtime != row.runtime || prior.model != row.model);
        }
        priors.models.push(row.clone());
    }
    priors.dataset_id = snapshot.dataset_id;
    priors.revision = snapshot.revision;
    priors.published_on = snapshot.published_on;
    selection::validate_prior_dataset(&priors).map_err(|error| anyhow::anyhow!(error))?;

    snapshot.capability_policy.validate()?;
    if snapshot.capability_policy.source.trim().is_empty() {
        bail!("operator capability policy requires a source");
    }
    let mut capability_policy = default_model_capability_policy();
    for row in &snapshot.capability_policy.models {
        if row.evidence.trim().is_empty() || row.as_of.trim().is_empty() {
            bail!(
                "operator capability row '{}' requires evidence and as_of",
                row.model
            );
        }
        selection::validate_prior_date("capability.as_of", &row.as_of)
            .map_err(|error| anyhow::anyhow!(error))?;
        if row.as_of > priors.published_on {
            bail!(
                "operator capability row '{}' is dated after prior publication",
                row.model
            );
        }
        if let Some(base) = capability_policy.lookup(&row.model) {
            if row.as_of < base.as_of
                || (row.eligible && !base.eligible)
                || row.capability > base.capability
            {
                bail!("operator capability row '{}' weakens bundled model eligibility or capability ceiling", row.model);
            }
        } else if !priors.models.iter().any(|prior| prior.model == row.model) {
            bail!("operator capability row '{}' has no dated prior", row.model);
        }
        capability_policy
            .models
            .retain(|prior| prior.model != row.model);
        capability_policy.models.push(row.clone());
    }
    capability_policy.id = snapshot.capability_policy.id;
    capability_policy.version = snapshot.capability_policy.version;
    capability_policy.source = snapshot.capability_policy.source;
    let effective = EffectivePriorSnapshot {
        priors,
        capability_policy,
    };
    let effective_bytes = serde_json::to_vec(&effective)?;
    let provenance = selection::OperatorPriorDataProvenance {
        relative_path: relative_path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        raw_sha256: sha256_hex(&raw),
        effective_sha256: sha256_hex(&effective_bytes),
    };
    Ok(Arc::new(BoundPriorData {
        repo,
        raw,
        effective,
        provenance,
    }))
}

/// Resume a finalized source with its authenticated archived snapshot. An
/// external path, when supplied, must have identical bytes. An unfinished
/// source with prior data cannot establish a finalized binding and is refused.
pub fn bind_frozen_operator_prior_data_for_run(
    repo: impl AsRef<Path>,
    run_id: &RunId,
    supplied_path: Option<&Path>,
) -> Result<Option<OperatorPriorDataGuard>> {
    if supplied_path.is_some() {
        require_supported_prior_input_platform()?;
    }
    let repo = crate::artifacts::discover_repo_root(repo.as_ref())?;
    let reader = match ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, run_id) {
        Ok(reader) => reader,
        Err(error) => {
            let prior_dir = repo
                .join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join("operator_prior_data");
            let prior_present = match std::fs::symlink_metadata(&prior_dir) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(error)
                        .context("cannot inspect unfinalized operator prior-data directory")
                }
            };
            if supplied_path.is_some() || prior_present {
                bail!("cannot resume operator prior data from an unfinalized or unauthenticated source: {error:#}");
            }
            return Ok(None);
        }
    };
    let present = [RAW_ARTIFACT, EFFECTIVE_ARTIFACT, BINDING_ARTIFACT].map(|path| {
        reader
            .finalization()
            .files
            .iter()
            .any(|record| record.path.as_path() == Path::new(path))
    });
    if present.iter().any(|is_present| *is_present != present[0]) {
        bail!("finalized operator prior-data artifact set is incomplete");
    }
    if !present[0] {
        if supplied_path.is_some() {
            bail!("existing supervise run has no frozen operator prior data; --prior-data cannot change it");
        }
        return Ok(None);
    }
    require_supported_prior_input_platform()?;
    let raw = reader.read(RAW_ARTIFACT)?;
    let saved_provenance: selection::OperatorPriorDataProvenance =
        serde_json::from_slice(&reader.read(BINDING_ARTIFACT)?)?;
    let relative_path = PathBuf::from(&saved_provenance.relative_path);
    if normalize_repo_relative_path(&relative_path)? != relative_path {
        bail!("frozen operator prior-data path is not normalized");
    }
    if let Some(path) = supplied_path {
        let supplied = normalize_repo_relative_path(path)?;
        if supplied != relative_path {
            bail!("--prior-data path changed from the frozen source snapshot");
        }
        let bytes =
            BoundedRegularReader::read_relative(&repo, &supplied, MAX_OPERATOR_PRIOR_INPUT_BYTES)?;
        if bytes != raw {
            bail!("--prior-data changed from the frozen source snapshot");
        }
    }
    let binding = bind_from_bytes(repo, relative_path, raw)?;
    let saved_effective: EffectivePriorSnapshot =
        serde_json::from_slice(&reader.read(EFFECTIVE_ARTIFACT)?)?;
    if binding.provenance != saved_provenance
        || binding.effective.priors != saved_effective.priors
        || binding.effective.capability_policy != saved_effective.capability_policy
    {
        bail!("frozen operator prior data no longer reproduces its authenticated effective policy");
    }
    Ok(Some(install(Some(binding))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{
        model_policy::{
            authorize_known_executor_role_model, validate_known_judgment_role_model,
            ModelCapabilityClass, ModelCapabilityEvidence,
        },
        role_authority::{admit_role_category, RoleCategory},
        AgentRole,
    };

    fn new_model_snapshot(model: &str) -> Result<OperatorPriorSnapshot> {
        let base = base_selector_priors_with_terminal_worker_economics()?;
        let mut prior = base
            .models
            .iter()
            .find(|row| row.model == "gpt-5.6-sol")
            .context("bundled Sol prior")?
            .clone();
        prior.model = model.to_string();
        prior.source_id = "operator-declared-new-model".to_string();
        prior.prior_scope = "operator dated prior for focused admission test".to_string();
        Ok(OperatorPriorSnapshot {
            schema_version: PRIOR_INPUT_SCHEMA_VERSION,
            dataset_id: "operator-prior-test".to_string(),
            revision: "2026-09-13.1".to_string(),
            published_on: "2026-09-13".to_string(),
            models: vec![prior],
            capability_policy: ModelCapabilityPolicy {
                id: "operator-capability-test".to_string(),
                version: 1,
                source: "operator-owned dated fixture".to_string(),
                models: vec![ModelCapabilityEvidence {
                    model: model.to_string(),
                    capability: ModelCapabilityClass::CriticalJudgment,
                    eligible: true,
                    evidence: "operator-declared capability fixture".to_string(),
                    as_of: "2026-09-13".to_string(),
                }],
            },
        })
    }

    fn bind_fixture(snapshot: &OperatorPriorSnapshot) -> Result<OperatorPriorDataGuard> {
        let raw = serde_json::to_vec(snapshot)?;
        let binding = bind_from_bytes(
            PathBuf::from("fixture-repo"),
            PathBuf::from("prior.json"),
            raw,
        )?;
        Ok(install(Some(binding)))
    }

    #[test]
    fn new_dated_model_uses_same_run_scoped_prior_and_execution_capability() -> Result<()> {
        let model = "new-advertised-model";
        let snapshot = new_model_snapshot(model)?;
        assert!(validate_known_judgment_role_model(AgentRole::Auditor, Some(model)).is_err());
        {
            let _guard = bind_fixture(&snapshot)?;
            assert!(current_priors()
                .expect("bound prior")
                .models
                .iter()
                .any(|row| row.model == model));
            let mut input = selection::selection_test_base_input();
            input.priors =
                super::super::selection_bridge::selector_priors_with_terminal_worker_economics()?;
            assert_eq!(
                input.priors,
                current_priors().expect("frozen authority priors")
            );
            let advertised = super::super::RuntimeModelCatalog::Codex(
                crate::external_agent::CodexRuntimeModelCatalog::from_slugs([model])?,
            );
            input.catalogs = vec![super::super::selection_bridge::runtime_catalog_from_priors(
                "codex",
                &advertised,
                &input.task,
                &input.priors,
            )?];
            input.pools.retain(|pool| pool.runtime == "codex");
            let selected = selection::select(&input)?;
            assert_eq!(
                selected
                    .choice
                    .as_ref()
                    .context("new advertised choice")?
                    .candidate
                    .model,
                model
            );
            authorize_known_executor_role_model(AgentRole::Worker, Some(model), None)?;
            validate_known_judgment_role_model(AgentRole::Auditor, Some(model))?;
            admit_role_category(RoleCategory::ReadOnlyReviewAuditor, Some(model))?;
            let captured = captured_binding();
            std::thread::spawn(move || {
                assert!(
                    validate_known_judgment_role_model(AgentRole::Auditor, Some(model)).is_err()
                );
                let _guard = install_captured(captured);
                validate_known_judgment_role_model(AgentRole::Auditor, Some(model))
            })
            .join()
            .expect("scoped worker thread")?;
        }
        assert!(validate_known_judgment_role_model(AgentRole::Auditor, Some(model)).is_err());
        Ok(())
    }

    #[test]
    fn bundled_prohibitions_and_capability_ceilings_cannot_be_weakened() -> Result<()> {
        let base = base_selector_priors_with_terminal_worker_economics()?;
        let mut snapshot = new_model_snapshot("new-advertised-model")?;
        let mut luna = base
            .models
            .iter()
            .find(|row| row.model == "gpt-5.6-luna")
            .context("bundled Luna prior")?
            .clone();
        luna.prohibited_authority_roles.clear();
        snapshot.models = vec![luna];
        assert!(bind_fixture(&snapshot).is_err());
        let mut terra = base
            .models
            .iter()
            .find(|row| row.model == "gpt-5.6-terra")
            .context("bundled Terra prior")?
            .clone();
        terra.prohibited = false;
        snapshot.models = vec![terra];
        assert!(bind_fixture(&snapshot).is_err());
        snapshot.models.clear();
        snapshot.capability_policy.models[0].model = "gpt-5.6-luna".to_string();
        assert!(bind_fixture(&snapshot).is_err());
        Ok(())
    }

    #[test]
    fn malformed_duplicate_and_unattributed_input_fail_closed() -> Result<()> {
        let mut snapshot = new_model_snapshot("new-advertised-model")?;
        snapshot.models.push(snapshot.models[0].clone());
        assert!(bind_fixture(&snapshot).is_err());
        snapshot.models.pop();
        snapshot.models[0].observed_on = "2026-02-30".to_string();
        assert!(bind_fixture(&snapshot).is_err());
        snapshot.models[0].observed_on = "2026-09-13".to_string();
        snapshot.capability_policy.models[0].evidence.clear();
        assert!(bind_fixture(&snapshot).is_err());
        let mut value = serde_json::to_value(new_model_snapshot("new-advertised-model")?)?;
        value["unrecognized_grant"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<OperatorPriorSnapshot>(value).is_err());
        let mut value = serde_json::to_value(new_model_snapshot("new-advertised-model")?)?;
        value["capability_policy"]["models"][0]
            .as_object_mut()
            .context("capability fixture object")?
            .remove("eligible");
        assert!(bind_from_bytes(
            PathBuf::from("fixture-repo"),
            PathBuf::from("prior.json"),
            serde_json::to_vec(&value)?,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn advertised_unknown_and_prior_without_capability_never_execute() -> Result<()> {
        let model = "new-advertised-model";
        let mut input = selection::selection_test_base_input();
        input.catalogs.retain(|catalog| catalog.runtime == "codex");
        input.catalogs[0].models.truncate(1);
        input.catalogs[0].models[0].model = model.to_string();
        input.pools.retain(|pool| pool.runtime == "codex");
        assert!(selection::select(&input)?.choice.is_none());
        let mut snapshot = new_model_snapshot(model)?;
        snapshot.capability_policy.models.clear();
        let _guard = bind_fixture(&snapshot)?;
        input.priors = current_priors().context("bound priors")?;
        assert!(selection::select(&input)?.choice.is_some());
        assert!(authorize_known_executor_role_model(AgentRole::Worker, Some(model), None).is_err());
        Ok(())
    }

    #[test]
    fn simultaneous_scoped_runs_do_not_share_operator_evidence() -> Result<()> {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let models = ["prior-run-a", "prior-run-b"];
        let bindings = models.map(|model| {
            bind_from_bytes(
                PathBuf::from("fixture-repo"),
                PathBuf::from("prior.json"),
                serde_json::to_vec(&new_model_snapshot(model)?)?,
            )
        });
        let bindings = bindings.into_iter().collect::<Result<Vec<_>>>()?;
        let handles = models
            .into_iter()
            .zip(bindings)
            .map(|(model, binding)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || -> Result<()> {
                    let _guard = install_captured(Some(binding));
                    barrier.wait();
                    validate_known_judgment_role_model(AgentRole::Auditor, Some(model))?;
                    let other = if model == "prior-run-a" {
                        "prior-run-b"
                    } else {
                        "prior-run-a"
                    };
                    assert!(
                        validate_known_judgment_role_model(AgentRole::Auditor, Some(other))
                            .is_err()
                    );
                    Ok(())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("run thread")?;
        }
        Ok(())
    }

    #[test]
    fn nested_and_unwound_bindings_restore_prior_scope() -> Result<()> {
        let first = new_model_snapshot("prior-run-a")?;
        let second = new_model_snapshot("prior-run-b")?;
        let first_guard = bind_fixture(&first)?;
        assert!(
            validate_known_judgment_role_model(AgentRole::Auditor, Some("prior-run-a")).is_ok()
        );
        {
            let _second_guard = bind_fixture(&second)?;
            assert!(
                validate_known_judgment_role_model(AgentRole::Auditor, Some("prior-run-b")).is_ok()
            );
            assert!(
                validate_known_judgment_role_model(AgentRole::Auditor, Some("prior-run-a"))
                    .is_err()
            );
        }
        assert!(
            validate_known_judgment_role_model(AgentRole::Auditor, Some("prior-run-a")).is_ok()
        );
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _second_guard = bind_fixture(&second).expect("nested fixture");
            panic!("scope unwind probe");
        }));
        assert!(unwind.is_err());
        assert!(
            validate_known_judgment_role_model(AgentRole::Auditor, Some("prior-run-a")).is_ok()
        );
        drop(first_guard);
        assert!(current_priors().is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn repository_local_reader_rejects_foreign_and_symlinked_input() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo)?;
        git2::Repository::init(&repo)?;
        let raw = serde_json::to_vec(&new_model_snapshot("new-advertised-model")?)?;
        std::fs::write(repo.join("prior.json"), raw)?;
        let _guard = bind_operator_prior_data(&repo, "prior.json")?;
        let foreign = temp.path().join("foreign");
        std::fs::create_dir(&foreign)?;
        git2::Repository::init(&foreign)?;
        assert!(require_binding_repo(&foreign).is_err());
        assert!(bind_operator_prior_data(&repo, "../foreign/prior.json").is_err());
        std::os::unix::fs::symlink(repo.join("prior.json"), repo.join("link.json"))?;
        assert!(bind_operator_prior_data(&repo, "link.json").is_err());
        Ok(())
    }

    #[test]
    fn unbound_selection_artifacts_keep_legacy_shape() -> Result<()> {
        let input = selection::selection_test_base_input();
        let mut decision = selection::select(&input)?;
        let value = serde_json::to_value(&decision)?;
        assert!(value.get("operator_prior_data").is_none());
        let legacy: selection::SelectionProvenance = serde_json::from_value(value)?;
        assert!(legacy.operator_prior_data.is_none());
        let _guard = bind_fixture(&new_model_snapshot("new-advertised-model")?)?;
        decision.operator_prior_data = current_provenance();
        let present = serde_json::to_value(&decision)?;
        assert!(present.get("operator_prior_data").is_some());
        let restored: selection::SelectionProvenance = serde_json::from_value(present)?;
        assert_eq!(restored.operator_prior_data, decision.operator_prior_data);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn finalized_snapshot_replays_and_changed_external_input_is_refused() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let raw = serde_json::to_vec(&new_model_snapshot("new-advertised-model")?)?;
        std::fs::write(repo.join("prior.json"), &raw)?;
        let run_id = RunId::new("prior-replay")?;
        let (original, prior_digest) = {
            let _guard = bind_operator_prior_data(&repo, "prior.json")?;
            let original = current_provenance().context("original binding")?;
            let mut input = selection::selection_test_base_input();
            input.priors = current_priors().context("original prior dataset")?;
            let prior_digest = selection::select(&input)?.input_digests.priors.value;
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                run_id.clone(),
                "prior-replay-test",
            )?;
            archive_current(&mut writer, &repo)?;
            let final_path = RunArtifactFamily::Supervise.final_report_relative_path();
            writer.write_json(
                &final_path,
                &serde_json::json!({"run_id": run_id.as_str()}),
                ArtifactFileDisposition::Publishable,
            )?;
            writer.finalize(&final_path, false)?;
            (original, prior_digest)
        };
        assert!(current_priors().is_none());
        {
            let _guard = bind_frozen_operator_prior_data_for_run(&repo, &run_id, None)?
                .context("authenticated frozen binding")?;
            assert_eq!(current_provenance(), Some(original));
            let mut input = selection::selection_test_base_input();
            input.priors = current_priors().context("replayed prior dataset")?;
            assert_eq!(
                selection::select(&input)?.input_digests.priors.value,
                prior_digest
            );
        }
        std::fs::write(repo.join("prior.json"), b"{}")?;
        assert!(bind_frozen_operator_prior_data_for_run(
            &repo,
            &run_id,
            Some(Path::new("prior.json"))
        )
        .is_err());
        assert!(bind_frozen_operator_prior_data_for_run(&repo, &run_id, None)?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unfinalized_prior_source_cannot_seed_a_continuation() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let raw = serde_json::to_vec(&new_model_snapshot("new-advertised-model")?)?;
        std::fs::write(repo.join("prior.json"), raw)?;
        let run_id = RunId::new("unfinished-prior")?;
        {
            let _guard = bind_operator_prior_data(&repo, "prior.json")?;
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                run_id.clone(),
                "unfinished-prior-test",
            )?;
            archive_current(&mut writer, &repo)?;
        }
        assert!(bind_frozen_operator_prior_data_for_run(&repo, &run_id, None).is_err());
        Ok(())
    }

    #[cfg(not(unix))]
    #[test]
    fn native_windows_prior_input_fails_before_reading_even_a_missing_repo() {
        let initial = bind_operator_prior_data("missing-repo", "prior.json")
            .err()
            .expect("native Windows prior input must fail closed");
        assert!(initial
            .to_string()
            .contains("native Windows is unsupported"));
        let resumed = bind_frozen_operator_prior_data_for_run(
            "missing-repo",
            &RunId::new("prior-windows-refusal").expect("run id"),
            Some(Path::new("prior.json")),
        )
        .err()
        .expect("explicit prior continuation must fail closed");
        assert!(resumed
            .to_string()
            .contains("native Windows is unsupported"));
    }
}

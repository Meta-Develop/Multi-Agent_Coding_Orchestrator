//! Retained ownership inventory for processes directly launched by MACO.
//! Provider-launched descendants are covered by the target's whole boundary,
//! but are not represented as independently observed helper launches.

use super::*;

const MAX_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum HelperKind {
    Catalog,
    VersionProbe,
    Target,
}

#[derive(Serialize)]
struct HelperReceipt {
    kind: HelperKind,
    program: Option<PathBuf>,
    process_tree: Option<ProcessTreeEvidence>,
    side_effects: Option<SideEffectConfinementEvidence>,
}

impl HelperReceipt {
    fn complete(&self) -> bool {
        self.process_tree.is_some() && self.side_effects.is_some()
    }

    fn quiescent(&self) -> bool {
        self.process_tree
            .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && self
                .side_effects
                .is_some_and(SideEffectConfinementEvidence::is_verified)
    }
}

#[derive(Serialize)]
struct HelperInventory<'a> {
    version: u32,
    owner: &'a Value,
    scope: &'static str,
    exclusions: [&'static str; 2],
    complete: bool,
    quiescence_verified: bool,
    helpers: &'a [HelperReceipt],
}

fn persist(
    writer: &mut ArtifactRunWriter,
    path: &Path,
    owner: &Value,
    helpers: &[HelperReceipt],
) -> Result<()> {
    let complete = helpers.iter().all(HelperReceipt::complete);
    let inventory = HelperInventory {
        version: 1,
        owner,
        scope: "maco_direct_catalog_version_and_target_launches",
        exclusions: [
            "Provider-spawned journal wrappers and commands have no independent MACO launch observation; the target receipt covers their entire owned process boundary.",
            "CAM service internals and operator/build/watchdog processes are not spawned by this supervisor and are outside this inventory.",
        ],
        complete,
        quiescence_verified: helpers.iter().all(HelperReceipt::quiescent),
        helpers,
    };
    let mut bytes = serde_json::to_vec_pretty(&inventory)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_BYTES {
        bail!("helper inventory exceeds its byte limit");
    }
    if writer.run_dir().join(path).exists() {
        if writer.read_authenticated(path, MAX_BYTES)? != bytes {
            bail!("helper inventory contradicts retained process receipts");
        }
    } else {
        writer.write_bytes(path, &bytes, ArtifactFileDisposition::PrivateEvidence)?;
    }
    if !complete {
        bail!("spawned helper is missing a typed containment/quiescence receipt");
    }
    Ok(())
}

pub(super) fn persist_target(
    writer: &mut ArtifactRunWriter,
    summary: &Path,
    owner: &Value,
    run: &ExternalAgentRun,
) -> Result<()> {
    let mut helpers = Vec::new();
    for probe in run.version_probe_receipts() {
        helpers.push(HelperReceipt {
            kind: HelperKind::VersionProbe,
            program: Some(probe.program.clone()),
            process_tree: probe.process_tree,
            side_effects: probe.side_effects,
        });
    }
    if let Some(probe) = run
        .fixed_version_probe_evidence()
        .filter(|_| run.version_probe_receipts().is_empty())
    {
        helpers.push(HelperReceipt {
            kind: HelperKind::VersionProbe,
            program: None,
            process_tree: Some(probe.process_tree),
            side_effects: Some(probe.side_effects),
        });
    }
    if run.stdout.target_launch_attempted {
        helpers.push(HelperReceipt {
            kind: HelperKind::Target,
            program: run.command.first().map(PathBuf::from),
            process_tree: run.process_tree,
            side_effects: run.side_effects,
        });
    }
    persist(
        writer,
        &summary.with_extension("helper-inventory.json"),
        owner,
        &helpers,
    )
}

pub(super) fn persist_catalog(
    writer: &mut ArtifactRunWriter,
    acquisition: &RuntimeModelCatalogAcquisition,
) -> Result<()> {
    let probe = match acquisition {
        Ok(RuntimeModelCatalog::Codex(catalog)) => catalog.probe_receipt.as_ref(),
        Err(failure) => failure.catalog_probe_receipt.as_ref(),
        _ => None,
    };
    let Some(probe) = probe else {
        return Ok(());
    };
    let owner = json!({
        "run_id": writer.run_dir().file_name().and_then(|name| name.to_str()),
        "task_id": "supervisor-catalog", "parent": null, "attempt": 1,
        "runtime": "codex", "program": probe.program,
    });
    persist(
        writer,
        Path::new("logs/catalog.helper-inventory.json"),
        &owner,
        &[HelperReceipt {
            kind: HelperKind::Catalog,
            program: Some(probe.program.clone()),
            process_tree: probe.process_tree,
            side_effects: probe.side_effects,
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_agent::HelperProcessReceipt;
    use crate::process_runner::{ContainmentBackend, SideEffectConfinementProfileKind};

    #[test]
    fn catalog_helper_inventory_retains_failed_probe_and_refuses_missing_receipts() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        for missing in [false, true] {
            let id = RunId::new(format!("catalog-inventory-{missing}"))?;
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                id.clone(),
                "test",
            )?;
            let mut failure =
                EnvironmentFailure::runtime_model_catalog("failed catalog parsing".into());
            failure.catalog_probe_receipt = Some(HelperProcessReceipt {
                program: PathBuf::from("captured-codex"),
                process_tree: (!missing).then_some(ProcessTreeEvidence::VerifiedEmpty(
                    ContainmentBackend::SystemdUserService,
                )),
                side_effects: Some(SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                )),
            });
            let result = persist_catalog(&mut writer, &Err(Box::new(failure)));
            assert_eq!(result.is_err(), missing);
            let retained: Value =
                serde_json::from_slice(&writer.read_authenticated(
                    Path::new("logs/catalog.helper-inventory.json"),
                    MAX_BYTES,
                )?)?;
            assert_eq!(retained["complete"], !missing);
            assert_eq!(retained["quiescence_verified"], !missing);
            assert_eq!(retained["owner"]["run_id"], id.as_str());
            assert_eq!(retained["helpers"][0]["kind"], "catalog");
        }
        Ok(())
    }
}

fn review_lens_execution_binding(
    requested: &ReviewLensConfig,
    usage: Option<&ReviewLensUsageReport>,
    dispatch: Option<&ReviewLensDispatchEvidence>,
) -> AutopilotReviewLensExecutionBinding {
    let requested_backend_id = requested.backend.backend_id().to_string();
    let requested_model = requested.backend.model().to_string();
    let requested_reasoning_effort = requested.backend.reasoning_effort().map(str::to_string);
    let usage_is_process_observed = usage.is_some_and(|usage| {
        usage.observation == RoleUsageObservation::ProcessObserved && usage.usage.is_some()
    });
    let dispatches = dispatch
        .map(|dispatch| dispatch.selections.as_slice())
        .unwrap_or_default();
    let observed_backend_id =
        unique_dispatch_value(dispatches, |selection| selection.backend_id.as_deref());
    let observed_model = unique_dispatch_value(dispatches, |selection| selection.model.as_deref());
    let observed_reasoning_effort = unique_dispatch_value(dispatches, |selection| {
        selection.reasoning_effort.as_deref()
    });
    let selection_is_complete = !dispatches.is_empty()
        && dispatches.iter().all(|selection| {
            selection.backend_id.is_some()
                && selection.model.is_some()
                && (requested_reasoning_effort.is_none() || selection.reasoning_effort.is_some())
                && selection.unavailable_reason.is_none()
        });
    let status = if !usage_is_process_observed || !selection_is_complete {
        AutopilotProfileBindingStatus::Incomparable
    } else if dispatches.iter().any(|selection| {
        selection.backend_id.as_deref() != Some(requested_backend_id.as_str())
            || selection.model.as_deref() != Some(requested_model.as_str())
            || selection.reasoning_effort.as_deref() != requested_reasoning_effort.as_deref()
    }) {
        // Defensive only: requested/effective lens equality is checked before dispatch, and the
        // production command is built from that equality-gated effective lens.
        AutopilotProfileBindingStatus::Mismatch
    } else {
        AutopilotProfileBindingStatus::Matched
    };
    AutopilotReviewLensExecutionBinding {
        lens_id: requested.id.clone(),
        requested_backend_id,
        requested_model,
        requested_reasoning_effort,
        observed_backend_id,
        observed_model,
        observed_reasoning_effort,
        dispatch_count: dispatches.len(),
        observation: if status == AutopilotProfileBindingStatus::Incomparable {
            RoleUsageObservation::NotProcessObservable
        } else {
            RoleUsageObservation::ProcessObserved
        },
        status,
        unavailable_reason: (status == AutopilotProfileBindingStatus::Incomparable).then(|| {
            (!usage_is_process_observed)
                .then(|| {
                    usage
                        .and_then(|usage| usage.unavailable_reason.clone())
                        .unwrap_or_else(|| {
                            "not_process_observable: no reliable process-observable usage sample was attributed to this review lens"
                                .to_string()
                        })
                })
                .or_else(|| dispatch.and_then(|dispatch| dispatch.unavailable_reason.clone()))
                .or_else(|| {
                    dispatches
                        .iter()
                        .find_map(|selection| selection.unavailable_reason.clone())
                })
                .unwrap_or_else(|| {
                    "not_process_observable: the dispatched review-lens backend, model, or reasoning effort was unknown"
                        .to_string()
                })
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewLensDispatchSelection {
    backend_id: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
    unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReviewLensDispatchEvidence {
    selections: Vec<ReviewLensDispatchSelection>,
    unavailable_reason: Option<String>,
}

fn review_lens_dispatch_evidence(
    supervisor: &SupervisorFinalReport,
    lens_count: usize,
) -> Vec<ReviewLensDispatchEvidence> {
    review_lens_dispatch_evidence_from_records(
        supervisor
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.audit_reports.iter())
            // Supervisor collection appends its own sanitized command record after parsing the
            // runtime-authored report, so the last entry is parent evidence rather than a lens
            // claim about how it was launched.
            .map(|auditor| (auditor.id.as_str(), auditor.commands_run.last())),
        lens_count,
    )
}

fn review_lens_dispatch_evidence_from_records<'a>(
    auditors: impl IntoIterator<Item = (&'a str, Option<&'a CommandRunRecord>)>,
    lens_count: usize,
) -> Vec<ReviewLensDispatchEvidence> {
    let mut evidence = vec![ReviewLensDispatchEvidence::default(); lens_count];
    for (auditor_id, parent_recorded_command) in auditors {
        let Some(lens_index) = review_lens_auditor_index(auditor_id) else {
            continue;
        };
        let Some(lens_evidence) = evidence.get_mut(lens_index) else {
            continue;
        };
        let Some(parent_recorded_command) = parent_recorded_command else {
            lens_evidence.unavailable_reason = Some(
                "not_process_observable: the parent review-auditor report contained no dispatched command record"
                    .to_string(),
            );
            continue;
        };
        lens_evidence
            .selections
            .push(review_lens_selection_from_command(parent_recorded_command));
    }
    for lens_evidence in &mut evidence {
        if lens_evidence.selections.is_empty() && lens_evidence.unavailable_reason.is_none() {
            lens_evidence.unavailable_reason = Some(
                "not_process_observable: no parent-recorded review-lens dispatch was reported"
                    .to_string(),
            );
        }
    }
    evidence
}

fn review_lens_auditor_index(auditor_id: &str) -> Option<usize> {
    auditor_id
        .rsplit_once("-review-auditor-lens-")
        .and_then(|(_, index)| index.parse::<usize>().ok())
}

fn review_lens_selection_from_command(record: &CommandRunRecord) -> ReviewLensDispatchSelection {
    let model = unique_command_argument(&record.command, "-m");
    let backend_id = unique_codex_config_string(&record.command, "model_provider");
    let reasoning_effort = unique_codex_config_string(&record.command, "model_reasoning_effort");
    let unavailable_reason = model
        .as_ref()
        .err()
        .or_else(|| backend_id.as_ref().err())
        .or_else(|| reasoning_effort.as_ref().err())
        .cloned();
    ReviewLensDispatchSelection {
        backend_id: backend_id.unwrap_or_default(),
        model: model.unwrap_or_default(),
        reasoning_effort: reasoning_effort.unwrap_or_default(),
        unavailable_reason,
    }
}

fn unique_command_argument(
    command: &[String],
    flag: &str,
) -> std::result::Result<Option<String>, String> {
    let values = command
        .windows(2)
        .filter(|arguments| arguments[0] == flag)
        .map(|arguments| arguments[1].clone())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(format!(
            "not_process_observable: dispatched review-lens command contained multiple {flag} selections"
        )),
    }
}

fn unique_codex_config_string(
    command: &[String],
    key: &str,
) -> std::result::Result<Option<String>, String> {
    let prefix = format!("{key}=");
    let encoded = command
        .windows(2)
        .filter(|arguments| arguments[0] == "-c")
        .filter_map(|arguments| arguments[1].strip_prefix(&prefix))
        .collect::<Vec<_>>();
    let value = match encoded.as_slice() {
        [] => return Ok(None),
        [value] => *value,
        _ => {
            return Err(format!(
                "not_process_observable: dispatched review-lens command contained multiple {key} selections"
            ));
        }
    };
    serde_json::from_str::<String>(value).map(Some).map_err(|_| {
        format!(
            "not_process_observable: dispatched review-lens command contained an invalid {key} string"
        )
    })
}

fn unique_dispatch_value(
    dispatches: &[ReviewLensDispatchSelection],
    value: impl Fn(&ReviewLensDispatchSelection) -> Option<&str>,
) -> Option<String> {
    let values = dispatches.iter().filter_map(value).collect::<BTreeSet<_>>();
    if values.len() == 1 {
        values.into_iter().next().map(str::to_string)
    } else {
        None
    }
}

struct FinalReportInput<'a> {
    run_id: &'a RunId,
    status: AutopilotRunStatus,
    attempt_count: usize,
    max_repair_attempts: usize,
    artifacts: AutopilotArtifactPaths,
    plan: AutopilotPlanSummary,
    profile_binding: AutopilotProfileBindingReport,
    safety: AutopilotSafetyReport,
    validation: AutopilotValidationSummary,
    pr: Option<SanitizedPrReport>,
    review: Option<ReviewReport>,
    attempts: Vec<AutopilotAttemptSummary>,
    supervisor: Option<SupervisorFinalReport>,
    gate_denials: Vec<GateDenial>,
    primary_worktree_untouched: bool,
    next_action: &'a str,
    auto_merge_requested: bool,
    generated_follow_up_dispatch_performed: bool,
}

fn final_report(input: FinalReportInput<'_>) -> AutopilotFinalReport {
    AutopilotFinalReport {
        version: AUTOPILOT_SCHEMA_VERSION,
        run_id: input.run_id.clone(),
        status: input.status,
        success: input.status == AutopilotRunStatus::Succeeded,
        attempt_count: input.attempt_count,
        repair_attempts_used: input.attempt_count.saturating_sub(1),
        max_repair_attempts: input.max_repair_attempts,
        reports_created: AutopilotReportsCreated {
            plan: true,
            supervisor_report: true,
            pr_report: true,
            review_report: true,
            final_report: true,
        },
        artifacts: input.artifacts,
        plan: input.plan,
        profile_binding: input.profile_binding,
        safety: input.safety,
        gate_denials: input.gate_denials,
        supervisor: input.supervisor,
        primary_worktree_untouched: input.primary_worktree_untouched,
        validation: input.validation,
        pr: input.pr,
        review: input.review,
        attempts: input.attempts,
        ci_reaction_supported: false,
        check_status: AutopilotCheckStatus {
            ci_reaction_supported: false,
            state: "not_supported".to_string(),
            details: "CI reaction and GitHub Actions polling are intentionally not implemented"
                .to_string(),
        },
        auto_merge_requested: input.auto_merge_requested,
        auto_merge_performed: false,
        generated_follow_up_dispatch_performed: input.generated_follow_up_dispatch_performed,
        next_action: input.next_action.to_string(),
    }
}

fn skipped_autopilot_validation() -> AutopilotValidationSummary {
    AutopilotValidationSummary {
        status: AutopilotValidationStatus::Skipped,
        reports: Vec::new(),
    }
}

fn sanitize_supervisor_report(
    repo: &Path,
    report: &SupervisorFinalReport,
) -> SanitizedSupervisorReport {
    SanitizedSupervisorReport {
        version: report.version,
        run_id: report.run_id.as_str().to_string(),
        runtime: report.runtime.as_str().to_string(),
        publishable: report.publishable,
        success: report.success,
        status: review_status_label(report.status).to_string(),
        assigned_paths: report.assigned_paths.clone(),
        semantic_symbols: report.semantic_symbols.clone(),
        semantic_modules: report.semantic_modules.clone(),
        files_changed: report.files_changed.clone(),
        validation_results: report
            .validation_results
            .iter()
            .map(sanitize_supervisor_validation)
            .collect(),
        findings: report
            .findings
            .iter()
            .map(|finding| sanitize_supervisor_finding(repo, finding))
            .collect(),
        orchestrator_count: report.orchestrator_reports.len(),
        released_claim_count: report.released_claims.len(),
        released_semantic_intent_count: report.released_semantic_intents.len(),
        remaining_risk: sanitize_text(repo, &report.remaining_risk),
        next_safe_action: sanitize_text(repo, &report.next_safe_action),
    }
}

fn sanitize_supervisor_validation(validation: &ValidationResult) -> SanitizedSupervisorValidation {
    SanitizedSupervisorValidation {
        name: validation.name.clone(),
        status: review_status_label(validation.status).to_string(),
        message: validation.message.clone(),
    }
}

fn sanitize_supervisor_finding(
    repo: &Path,
    finding: &supervise::Finding,
) -> SanitizedSupervisorFinding {
    SanitizedSupervisorFinding {
        severity: finding_severity_label(finding.severity).to_string(),
        message: sanitize_text(repo, &finding.message),
        paths: finding
            .paths
            .iter()
            .filter_map(|path| public_report_path(repo, path))
            .collect(),
    }
}

fn sanitize_pr_report(report: &PrPublicationReport) -> SanitizedPrReport {
    SanitizedPrReport {
        status: pr_status_label(report.status).to_string(),
        forge: forge_label(report.forge).to_string(),
        draft: report.draft,
        created: report.created,
        pushed: report.pushed,
        pr_url: report.pr_url.clone(),
        changed_paths: report.changed_paths.clone(),
        readiness: readiness_label(report.readiness).to_string(),
        blockers: report
            .blockers
            .iter()
            .map(|blocker| blocker_label(*blocker).to_string())
            .collect(),
        validation_status: safety_status_label(report.validation_status).to_string(),
        title: report.title.clone(),
        body_summary: report.body_summary.text.clone(),
        body_truncated: report.body_summary.truncated,
    }
}

fn sanitize_autopilot_review_report(repo: &Path, report: &ReviewReport) -> ReviewReport {
    let mut sanitized = report.clone();
    sanitized.target = sanitize_text(repo, &sanitized.target);
    sanitized.reviewer.reviewer_id = sanitize_text(repo, &sanitized.reviewer.reviewer_id);
    sanitized.reviewer.model = sanitize_text(repo, &sanitized.reviewer.model);
    sanitized.changed_paths = sanitized
        .changed_paths
        .iter()
        .filter_map(|path| public_report_path(repo, path))
        .collect();
    for finding in &mut sanitized.findings {
        finding.path = finding
            .path
            .as_ref()
            .and_then(|path| public_report_path(repo, path));
        finding.severity = sanitize_text(repo, &finding.severity);
        finding.summary = sanitize_text(repo, &finding.summary);
        finding.suggested_fix = sanitize_text(repo, &finding.suggested_fix);
    }
    sanitized.diff_source = sanitize_text(repo, &sanitized.diff_source);
    sanitized.ci_reaction = sanitize_text(repo, &sanitized.ci_reaction);
    sanitized.next_action = sanitize_text(repo, &sanitized.next_action);
    if let Some(diagnostics) = sanitized.diagnostics.as_mut() {
        diagnostics.stdout.text = sanitize_text(repo, &diagnostics.stdout.text);
        diagnostics.stderr.text = sanitize_text(repo, &diagnostics.stderr.text);
        diagnostics.process_error = diagnostics
            .process_error
            .as_deref()
            .map(|message| sanitize_text(repo, message));
    }
    sanitized
}

fn validation_summary(reports: Vec<ValidationReport>) -> AutopilotValidationSummary {
    let status = if reports
        .iter()
        .any(|report| report.status == ValidationStatus::Failed)
    {
        AutopilotValidationStatus::Failed
    } else if reports
        .iter()
        .any(|report| report.status == ValidationStatus::Passed)
    {
        AutopilotValidationStatus::Passed
    } else {
        AutopilotValidationStatus::Skipped
    };
    AutopilotValidationSummary { status, reports }
}

fn plan_summary(plan: &AutopilotPlan) -> AutopilotPlanSummary {
    AutopilotPlanSummary {
        title: plan.task.title.clone(),
        assigned_paths: plan.assigned_paths.clone(),
        path_proposal: plan.path_proposal.clone(),
        semantic_symbols: plan.semantic_symbols.clone(),
        semantic_modules: plan.semantic_modules.clone(),
        forge_mode: plan.forge_mode,
        reviewer_mode: plan.reviewer.mode,
        publish_mode: plan.publish_mode,
    }
}

fn validation_repair_reason(validation: &AutopilotValidationSummary) -> String {
    let names = validation
        .reports
        .iter()
        .filter(|report| report.status == ValidationStatus::Failed)
        .map(|report| report.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    if names.is_empty() {
        "validation failed".to_string()
    } else {
        format!("validation failed: {names}")
    }
}

fn review_repair_reason(review: &ReviewReport) -> String {
    let summaries = review
        .findings
        .iter()
        .filter(|finding| finding.blocking)
        .map(|finding| finding.summary.clone())
        .collect::<Vec<_>>()
        .join("; ");
    if summaries.is_empty() {
        "review reported blocking findings".to_string()
    } else {
        format!("review blocking findings: {summaries}")
    }
}

fn artifact_paths() -> AutopilotArtifactPaths {
    AutopilotArtifactPaths {
        plan: PathBuf::from("plan.json"),
        supervisor_report: PathBuf::from("supervisor-report.json"),
        pr_report: PathBuf::from("pr-report.json"),
        review_report: PathBuf::from("review-report.json"),
        final_report: PathBuf::from("final-report.json"),
    }
}

fn artifact_status(reader: &ArtifactRunReader) -> AutopilotArtifactStatus {
    let contains = |path: &str| {
        reader
            .finalization()
            .files
            .iter()
            .any(|record| record.path == Path::new(path))
    };
    AutopilotArtifactStatus {
        plan: contains("plan.json"),
        supervisor_report: contains("supervisor-report.json"),
        pr_report: contains("pr-report.json"),
        review_report: contains("review-report.json"),
        final_report: contains("final-report.json"),
    }
}

enum ArtifactRunState {
    Missing,
    Active(AutopilotArtifactStatus),
    Finalized(Box<ArtifactRunReader>),
}

fn autopilot_artifact_run_state(repo: &Path, run_id: &RunId) -> Result<ArtifactRunState> {
    let run_dir = repo
        .join(".maco")
        .join("autopilot")
        .join("runs")
        .join(run_id.as_str());
    match fs::symlink_metadata(&run_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ArtifactRunState::Missing);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect artifact directory {}", run_dir.display())
            });
        }
        Ok(_) => {}
    }
    let inventory = BoundedTreeWalker::walk_with(
        &run_dir,
        BoundedTreeWalkLimits {
            max_depth: 2,
            max_entries: AUTOPILOT_ACTIVE_ARTIFACT_MAX_ENTRIES,
            max_path_bytes: AUTOPILOT_STATUS_MAX_PATH_BYTES,
            max_total_path_bytes: AUTOPILOT_ACTIVE_ARTIFACT_MAX_TOTAL_PATH_BYTES,
            max_duration: AUTOPILOT_ACTIVE_ARTIFACT_MAX_DURATION,
            same_device: true,
        },
        |_entry| Ok(BoundedTreeWalkAction::Record),
    )?;
    for entry in &inventory {
        if matches!(
            entry.kind,
            BoundedTreeEntryKind::Symlink | BoundedTreeEntryKind::Special
        ) || (entry.kind == BoundedTreeEntryKind::RegularFile && !entry.is_safe_regular_file())
        {
            bail!(
                "artifact entry is not a safe direct file or directory: {}",
                run_dir.join(&entry.relative_path).display()
            );
        }
    }
    let artifacts = artifact_status_from_inventory(&inventory)?;
    if !known_regular_file_exists(&inventory, ARTIFACT_FINAL_MARKER)? {
        return Ok(ArtifactRunState::Active(artifacts));
    }
    let reader =
        ArtifactRunReader::open(repo, RunArtifactFamily::Autopilot, run_id).with_context(|| {
            format!(
                "autopilot run '{}' has corrupt or unverifiable finalized artifacts",
                run_id.as_str()
            )
        })?;
    Ok(ArtifactRunState::Finalized(Box::new(reader)))
}

fn known_regular_file_exists(entries: &[BoundedTreeEntry], name: &str) -> Result<bool> {
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.relative_path == Path::new(name))
    else {
        return Ok(false);
    };
    if !entry.is_safe_regular_file() {
        bail!("artifact entry '{name}' is not a safe direct regular file");
    }
    Ok(true)
}

fn artifact_status_from_inventory(entries: &[BoundedTreeEntry]) -> Result<AutopilotArtifactStatus> {
    Ok(AutopilotArtifactStatus {
        plan: known_regular_file_exists(entries, "plan.json")?,
        supervisor_report: known_regular_file_exists(entries, "supervisor-report.json")?,
        pr_report: known_regular_file_exists(entries, "pr-report.json")?,
        review_report: known_regular_file_exists(entries, "review-report.json")?,
        final_report: known_regular_file_exists(entries, "final-report.json")?,
    })
}

fn empty_artifact_status() -> AutopilotArtifactStatus {
    AutopilotArtifactStatus {
        plan: false,
        supervisor_report: false,
        pr_report: false,
        review_report: false,
        final_report: false,
    }
}

fn write_skipped_stage_reports(writer: &mut ArtifactRunWriter, reason: &str) -> Result<()> {
    write_skipped_report(writer, "supervisor-report.json", reason)?;
    write_skipped_report(writer, "pr-report.json", reason)?;
    write_skipped_report(writer, "review-report.json", reason)
}

fn write_skipped_report(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    reason: &str,
) -> Result<()> {
    write_private_json(
        writer,
        relative,
        &SkippedStageReport {
            status: "skipped".to_string(),
            reason: reason.to_string(),
        },
    )
}

fn write_failed_report(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    reason: &str,
    message: &str,
) -> Result<()> {
    write_private_json(
        writer,
        relative,
        &FailedStageReport {
            status: "failed".to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
        },
    )
}

fn write_private_json<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    value: &T,
) -> Result<()> {
    writer.write_json(relative, value, ArtifactFileDisposition::PrivateEvidence)?;
    Ok(())
}

fn read_artifact_json(reader: &ArtifactRunReader, relative: impl AsRef<Path>) -> Result<Value> {
    let relative = relative.as_ref();
    let contents = reader.read(relative)?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse finalized artifact {}", relative.display()))
}

struct RepositoryPathBindings {
    worktree: DirectoryBindingGuard,
    git_dir: DirectoryBindingGuard,
    common_dir: DirectoryBindingGuard,
}

impl RepositoryPathBindings {
    fn bind(repo_path: &Path) -> Result<Self> {
        let repository = crate::git_repository::open(repo_path)
            .with_context(|| format!("failed to bind repository {}", repo_path.display()))?;
        let worktree = repository
            .workdir()
            .context("repository binding requires a non-bare worktree")?;
        let bindings = Self {
            worktree: DirectoryBindingGuard::bind(worktree)?,
            git_dir: DirectoryBindingGuard::bind(repository.path())?,
            common_dir: DirectoryBindingGuard::bind(repository.commondir())?,
        };
        bindings.verify()?;
        Ok(bindings)
    }

    fn verify(&self) -> Result<()> {
        self.worktree
            .verify()
            .context("repository worktree changed")?;
        self.git_dir
            .verify()
            .context("repository Git directory changed")?;
        self.common_dir
            .verify()
            .context("repository common directory changed")
    }
}

fn verify_after_autopilot_safety(bindings: &RepositoryPathBindings) -> Result<()> {
    #[cfg(test)]
    run_after_autopilot_safety_hook();
    bindings
        .verify()
        .context("repository changed after autopilot safety preflight")
}

#[cfg(test)]
type AutopilotProfileCallsiteHook = Box<dyn FnMut(&mut SupervisorPlan)>;

#[cfg(test)]
thread_local! {
    static AUTOPILOT_PROFILE_CALLSITE_HOOK: std::cell::RefCell<Option<AutopilotProfileCallsiteHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_autopilot_profile_callsite_hook(hook: impl FnMut(&mut SupervisorPlan) + 'static) {
    AUTOPILOT_PROFILE_CALLSITE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_autopilot_profile_callsite_hook(effective: &SupervisorPlan) -> Option<SupervisorPlan> {
    AUTOPILOT_PROFILE_CALLSITE_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            let mut overridden = effective.clone();
            hook(&mut overridden);
            Some(overridden)
        } else {
            None
        }
    })
}

#[cfg(test)]
thread_local! {
    static AFTER_AUTOPILOT_SAFETY_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_autopilot_safety_hook(hook: impl FnMut() + 'static) {
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn clear_autopilot_test_hooks() {
    AUTOPILOT_PROFILE_CALLSITE_HOOK.with(|slot| *slot.borrow_mut() = None);
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn run_after_autopilot_safety_hook() {
    AFTER_AUTOPILOT_SAFETY_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn dirty_primary_paths(repo_path: &Path, runtime: SupervisorRuntime) -> Result<Vec<PathBuf>> {
    match runtime {
        SupervisorRuntime::Fake => {
            let mut dirty = supervise::nonpublishable_simulation_dirty_primary_paths(repo_path)?;
            if dirty.len() > AUTOPILOT_STATUS_MAX_ENTRIES {
                bail!(
                    "autopilot status reported {} paths, exceeding its limit of {}",
                    dirty.len(),
                    AUTOPILOT_STATUS_MAX_ENTRIES
                );
            }
            let total_path_bytes = dirty.iter().try_fold(0usize, |total, path| {
                let path_bytes = path.as_os_str().len();
                if path_bytes > AUTOPILOT_STATUS_MAX_PATH_BYTES {
                    bail!(
                        "autopilot status path exceeds its {}-byte limit",
                        AUTOPILOT_STATUS_MAX_PATH_BYTES
                    );
                }
                total
                    .checked_add(path_bytes)
                    .context("autopilot status path byte count overflowed")
            })?;
            if total_path_bytes > AUTOPILOT_STATUS_MAX_TOTAL_PATH_BYTES {
                bail!(
                    "autopilot status paths exceed their {}-byte aggregate limit",
                    AUTOPILOT_STATUS_MAX_TOTAL_PATH_BYTES
                );
            }
            dirty.retain(|path| !is_local_runtime_path(path));
            dirty.sort();
            dirty.dedup();
            Ok(dirty)
        }
        _ => bounded_repository_dirty_paths(repo_path),
    }
}

fn bounded_repository_dirty_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let mut dirty = crate::worktree::bounded_repository_status_paths(
        repo_path,
        AUTOPILOT_STATUS_MAX_ENTRIES,
        AUTOPILOT_STATUS_MAX_TOTAL_PATH_BYTES,
        AUTOPILOT_STATUS_MAX_DURATION,
    )?
    .into_iter()
    .map(|(path, _status)| normalize_repo_relative_path(path))
    .collect::<std::result::Result<Vec<_>, _>>()?;
    dirty.retain(|path| !is_local_runtime_path(path));
    dirty.sort();
    dirty.dedup();
    Ok(dirty)
}

fn is_local_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
}

fn normalize_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(collapse_covered_paths(paths))
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }
    collapsed
}

fn sorted_unique_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn title_from_plain_task(task: &str) -> String {
    task.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Autopilot task")
        .to_string()
}

fn attempt_agent_id(run_id: &RunId, attempt: usize) -> Result<String> {
    crate::worktree::normalize_agent_id(&format!("autopilot-{}-a{attempt}", run_id.as_str()))
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn public_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("autopilot").join("runs")
}

fn public_report_path(repo: &Path, path: &Path) -> Option<PathBuf> {
    let relative = if path.is_absolute() {
        path.strip_prefix(repo)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.file_name().map(PathBuf::from).unwrap_or_default())
    } else {
        path.to_path_buf()
    };
    if relative.as_os_str().is_empty() {
        return None;
    }
    if relative.starts_with(".maco") || relative.starts_with(".agents") {
        return relative.file_name().map(PathBuf::from);
    }
    Some(relative)
}

fn sanitize_text(repo: &Path, text: &str) -> String {
    let mut redactor =
        Redactor::new().with_private_value("repository-path", repo.display().to_string());
    if let Some(parent) = repo.parent() {
        redactor = redactor.with_private_value("repository-parent", parent.display().to_string());
    }
    if let Ok(repository) = crate::git_repository::open(repo) {
        redactor = redactor
            .with_private_value("git-path", repository.path().display().to_string())
            .with_private_value(
                "git-common-path",
                repository.commondir().display().to_string(),
            );
        if let Some(primary_root) = repository.commondir().parent() {
            redactor = redactor.with_private_value(
                "primary-repository-path",
                primary_root.display().to_string(),
            );
        }
    }
    let without_controls = text
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();
    let redacted = redactor.redact(&without_controls).text;
    let mut bounded = redacted
        .chars()
        .take(AUTOPILOT_MESSAGE_LIMIT_CHARS)
        .collect::<String>();
    if redacted.chars().count() > AUTOPILOT_MESSAGE_LIMIT_CHARS {
        bounded.push_str("…<truncated>");
    }
    bounded
}

fn sanitize_validation_message(worktree: &Path, text: &str) -> String {
    sanitize_text(worktree, text)
}

fn default_autopilot_schema_version() -> u32 {
    AUTOPILOT_SCHEMA_VERSION
}

fn default_max_repair_attempts() -> usize {
    1
}

impl AutopilotForgeMode {
    fn into_publication_forge(self) -> ForgeKind {
        match self {
            Self::Fake => ForgeKind::Fake,
            Self::Git => ForgeKind::Git,
            Self::Github => ForgeKind::Github,
        }
    }
}

fn reviewer_config_may_authorize_publication(forge: ForgeKind, reviewer: &ReviewerConfig) -> bool {
    matches!(forge, ForgeKind::Fake) || reviewer_config_has_direct_program_binding(reviewer)
}

fn reviewer_config_has_direct_program_binding(reviewer: &ReviewerConfig) -> bool {
    reviewer.mode == ReviewerMode::ExternalCommand
        && reviewer.program.is_some()
        && reviewer.command.is_none()
}

fn reviewer_identity_matches_mode(report: &ReviewReport) -> bool {
    match report.reviewer.mode {
        ReviewerMode::Fake => {
            report.reviewer.reviewer_id == "autopilot-fake-reviewer"
                && report.reviewer.model == "deterministic-local-reviewer"
        }
        ReviewerMode::ExternalCommand => report
            .reviewer
            .reviewer_id
            .strip_prefix(EXTERNAL_REVIEWER_ID_PREFIX)
            .is_some_and(|binding| {
                is_lower_hex(binding, EXTERNAL_REVIEWER_BINDING_HEX_LEN)
                    && report.reviewer.model == EXTERNAL_REVIEWER_MODEL
            }),
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn publish_requested_for_audit(
    real_runtime_requested: bool,
    forge_mode: AutopilotForgeMode,
    publication_attempted: bool,
) -> bool {
    real_runtime_requested && forge_mode != AutopilotForgeMode::Fake && publication_attempted
}

fn pr_status_label(status: PrPublicationStatus) -> &'static str {
    match status {
        PrPublicationStatus::Preview => "preview",
        PrPublicationStatus::Blocked => "blocked",
        PrPublicationStatus::Published => "published",
    }
}

fn forge_label(forge: ForgeKind) -> &'static str {
    match forge {
        ForgeKind::Fake => "fake",
        ForgeKind::Git => "git",
        ForgeKind::Github => "github",
    }
}

fn readiness_label(status: ApplyReadinessStatus) -> &'static str {
    match status {
        ApplyReadinessStatus::Safe => "safe",
        ApplyReadinessStatus::Forced => "forced",
        ApplyReadinessStatus::Blocked => "blocked",
    }
}

fn safety_status_label(status: SafetyCheckStatus) -> &'static str {
    match status {
        SafetyCheckStatus::Passed => "passed",
        SafetyCheckStatus::Failed => "failed",
        SafetyCheckStatus::Skipped => "skipped",
    }
}

fn blocker_label(blocker: ApplyBlocker) -> &'static str {
    match blocker {
        ApplyBlocker::DirtyPrimary => "dirty_primary",
        ApplyBlocker::StaleBase => "stale_base",
        ApplyBlocker::PrimaryStateChanged => "primary_state_changed",
        ApplyBlocker::ApplyCheckFailed => "apply_check_failed",
        ApplyBlocker::ExcludedReference => "excluded_reference",
        ApplyBlocker::UnclaimedEdits => "unclaimed_edits",
        ApplyBlocker::ValidationMissing => "validation_missing",
        ApplyBlocker::ValidationNotRun => "validation_not_run",
        ApplyBlocker::ValidationSkipped => "validation_skipped",
        ApplyBlocker::ValidationFailed => "validation_failed",
    }
}

fn review_status_label(status: ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Pending => "pending",
        ReviewStatus::Succeeded => "succeeded",
        ReviewStatus::Failed => "failed",
        ReviewStatus::Rejected => "rejected",
        ReviewStatus::Missing => "missing",
    }
}

fn finding_severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

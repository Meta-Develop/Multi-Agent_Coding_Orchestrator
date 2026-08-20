fn non_runtime_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|path| !is_ignored_runtime_path(path))
        .cloned()
        .collect()
}

fn inbox_detail_paths(details: &[InboxLockRefusalDetail]) -> Vec<PathBuf> {
    details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn dirty_primary_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let repo = crate::git_repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect primary worktree status")?;
    let mut paths = Vec::new();
    for entry in statuses.iter() {
        let path = PathBuf::from(
            entry
                .path()
                .context("primary worktree status path is not valid UTF-8")?,
        );
        if !is_ignored_runtime_path(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn load_config(repo: &Path) -> Result<LoadedConfig> {
    let root = SafeRoot::open_existing(repo).context("failed to bind inbox repository root")?;
    let (config, config_path) = if root.direct_child_exists(CONFIG_FILE)? {
        let contents = BoundedRegularReader::read_direct(&root, CONFIG_FILE, MAX_CONFIG_BYTES)
            .context("failed to read bounded no-follow inbox config maco-inbox.json")?;
        root.verify()
            .context("inbox repository root changed during config read")?;
        let contents = String::from_utf8(contents).context("inbox config is not valid UTF-8")?;
        (
            serde_json::from_str::<InboxConfig>(&contents)
                .context("failed to parse inbox config maco-inbox.json")?,
            Some(PathBuf::from(CONFIG_FILE)),
        )
    } else {
        (InboxConfig::default(), None)
    };
    Ok(LoadedConfig {
        config: validate_config(config)?,
        path: config_path,
    })
}

fn load_config_with_config_overrides(
    repo: &Path,
    overrides: InboxConfigOverrides,
) -> Result<LoadedConfig> {
    let mut loaded = load_config(repo)?;
    if let Some(max_items) = overrides.max_items {
        loaded.config.selection.max_items = max_items;
    }
    if let Some(action_policy) = overrides.action_policy {
        loaded.config.action_policy = action_policy;
    }
    if let Some(labels) = overrides.labels {
        loaded.config.selection.labels = labels;
    }
    if let Some(issues) = overrides.issues {
        loaded.config.selection.issues = issues;
    }
    if let Some(pull_requests) = overrides.pull_requests {
        loaded.config.selection.pull_requests = pull_requests;
    }
    loaded.config = validate_config(loaded.config)?;
    Ok(loaded)
}

fn validate_config(mut config: InboxConfig) -> Result<InboxConfig> {
    validate_schema_version("inbox config", config.version)?;
    validate_schema_version("inbox repository config", config.repository.version)?;
    validate_schema_version("inbox selection config", config.selection.version)?;
    validate_schema_version("inbox privacy config", config.privacy.version)?;
    validate_repository_config(&mut config.repository)?;
    validate_item_limit(config.selection.max_items, "inbox selection max_items")?;
    if !config.selection.issues && !config.selection.pull_requests {
        bail!("inbox selection must enable issues or pull_requests");
    }
    config.selection.labels = validate_labels(
        std::mem::take(&mut config.selection.labels),
        "inbox selection labels",
    )?;
    if config.action_policy == InboxActionPolicy::Github
        && config.permission_mode == Some(InboxPermissionMode::Fake)
    {
        bail!("inbox action_policy github conflicts with permission_mode fake");
    }
    if config.max_repair_attempts > MAX_REPAIR_ATTEMPTS {
        bail!(
            "inbox max_repair_attempts exceeds its {} attempt limit",
            MAX_REPAIR_ATTEMPTS
        );
    }
    validate_optional_timeout(config.timeout_seconds, "inbox timeout_seconds")?;
    if config.default_validation_commands.len() > MAX_VALIDATION_COMMANDS {
        bail!(
            "inbox default_validation_commands exceeds its {} command limit",
            MAX_VALIDATION_COMMANDS
        );
    }
    config.privacy.blocked_terms = validate_bounded_string_set(
        std::mem::take(&mut config.privacy.blocked_terms),
        "inbox privacy blocked_terms",
        MAX_PRIVACY_TERMS,
        MAX_PRIVACY_TERM_BYTES,
    )?;
    if config.privacy.max_body_chars == 0 || config.privacy.max_body_chars > MAX_BODY_LIMIT {
        bail!(
            "inbox privacy max_body_chars must be between 1 and {}",
            MAX_BODY_LIMIT
        );
    }
    if config.default_assigned_paths.len() > MAX_ASSIGNED_PATHS {
        bail!(
            "inbox default_assigned_paths exceeds its {} path limit",
            MAX_ASSIGNED_PATHS
        );
    }
    config.default_assigned_paths =
        normalize_or_default(std::mem::take(&mut config.default_assigned_paths), &config)?;
    for (index, command) in config.default_validation_commands.iter_mut().enumerate() {
        validate_schema_version(
            &format!("default validation command {}", index + 1),
            command.version,
        )?;
        command.command = command.command.trim().to_string();
        validate_bounded_text(
            &command.command,
            &format!("default validation command {} command", index + 1),
            MAX_VALIDATION_COMMAND_BYTES,
            false,
        )?;
        if let Some(name) = command.name.as_mut() {
            *name = name.trim().to_string();
            validate_bounded_text(
                name,
                &format!("default validation command {} name", index + 1),
                MAX_VALIDATION_NAME_BYTES,
                false,
            )?;
        }
        validate_optional_timeout(
            command.timeout_seconds,
            &format!("default validation command {} timeout_seconds", index + 1),
        )?;
        if command.timeout_seconds.is_none() {
            command.timeout_seconds = config.timeout_seconds;
        }
    }
    if let Some(codex_bin) = &config.codex_bin {
        validate_path_text(codex_bin, "inbox codex_bin", MAX_CODEX_PATH_BYTES)?;
    }
    validate_serialized_config_size(&config, "inbox config")?;
    Ok(config)
}

fn normalize_or_default(paths: Vec<PathBuf>, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let fallback = if config.default_assigned_paths.is_empty() {
        default_assigned_paths()
    } else {
        config.default_assigned_paths.clone()
    };
    let source = if paths.is_empty() { fallback } else { paths };
    if source.len() > MAX_ASSIGNED_PATHS {
        bail!(
            "inbox assigned paths exceed the {} path limit",
            MAX_ASSIGNED_PATHS
        );
    }
    let normalized = source
        .into_iter()
        .map(|path| -> Result<PathBuf> {
            validate_path_text(&path, "inbox assigned path", MAX_CONFIG_PATH_BYTES)?;
            Ok(normalize_repo_relative_path(&path)?)
        })
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(normalized.into_iter().collect())
}

fn assigned_paths_for_item(item: &InboxItem, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    item.source_snapshot.validate()?;
    let (number, updated_at) = match (item.kind, &item.issue, &item.pull_request) {
        (InboxItemKind::Issue, Some(issue), None) => (issue.number, issue.updated_at.as_deref()),
        (InboxItemKind::PullRequest, None, Some(pull_request)) => {
            (pull_request.number, pull_request.updated_at.as_deref())
        }
        _ => bail!("inbox item kind does not match its issue/PR payload"),
    };
    if item.source_snapshot.kind() != item.kind
        || item.source_snapshot.source_key() != item.source_key
        || number != item.source_snapshot.number()
        || updated_at != Some(item.source_snapshot.updated_at())
    {
        bail!("inbox item source snapshot does not match the item identity");
    }
    match (&item.issue, &item.pull_request) {
        (Some(issue), _) => normalize_or_default(issue.assigned_paths.clone(), config),
        (_, Some(pr)) => normalize_or_default(pr.changed_files.clone(), config),
        _ => normalize_or_default(Vec::new(), config),
    }
}

fn selected_target_paths(items: &[InboxItem], config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for item in items.iter().filter(|item| item.selected) {
        paths.extend(assigned_paths_for_item(item, config)?);
    }
    Ok(paths.into_iter().collect())
}

fn privacy_scan(body: &str, policy: &InboxPrivacyPolicy) -> PrivacyScanResult {
    let redacted = Redactor::new().redact(body);
    let reasons = privacy_reasons(body, &redacted, policy);
    let public_body = sanitize_redacted_public_text(body, &redacted.text);
    let summary = summarize_text(&public_body, policy.max_body_chars);
    PrivacyScanResult {
        safe: reasons.is_empty() || policy.allow_private_bodies,
        reasons,
        redactions: redacted.summary,
        body_summary: summary.text,
        body_truncated: summary.truncated,
    }
}

fn extend_privacy_reasons(
    privacy: &mut PrivacyScanResult,
    label: &str,
    text: &str,
    policy: &InboxPrivacyPolicy,
) {
    let redacted = Redactor::new().redact(text);
    let mut field_reasons = privacy_reasons(text, &redacted, policy)
        .into_iter()
        .map(|reason| format!("{label}_{reason}"))
        .collect::<Vec<_>>();
    if field_reasons.is_empty() {
        return;
    }
    privacy.redactions.merge(redacted.summary);
    privacy.reasons.append(&mut field_reasons);
    privacy.reasons.sort();
    privacy.reasons.dedup();
    privacy.safe = privacy.reasons.is_empty() || policy.allow_private_bodies;
}

fn privacy_reasons(
    text: &str,
    redacted: &crate::llm::RedactedText,
    policy: &InboxPrivacyPolicy,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if redacted.summary.total_replacements > 0 || contains_token_like_word(text) {
        reasons.push("secret_like_content_redacted".to_string());
    }
    if contains_private_key_material(text) {
        reasons.push("private_key_material".to_string());
    }
    if contains_local_absolute_path(text) {
        reasons.push("local_absolute_path".to_string());
    }
    let lower = text.to_ascii_lowercase();
    for term in &policy.blocked_terms {
        let term = term.trim();
        if !term.is_empty() && lower.contains(&term.to_ascii_lowercase()) {
            reasons.push(format!("blocked_term:{term}"));
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn duplicate_result(key: &str, duplicates: &BTreeMap<String, String>) -> DuplicateDetectionResult {
    let matched_run_id = duplicates.get(key).cloned();
    DuplicateDetectionResult {
        duplicate: matched_run_id.is_some(),
        key: key.to_string(),
        reason: matched_run_id
            .as_ref()
            .map(|run_id| format!("already selected by inbox run {run_id}")),
        matched_run_id,
    }
}

fn load_duplicate_keys(repo: &Path) -> Result<BTreeMap<String, String>> {
    let mut duplicates = BTreeMap::new();
    let list = artifacts::list_runs(repo, RunArtifactFamily::Inbox)?;
    for run in list.runs {
        if !run.finalized {
            continue;
        }
        let run_id = RunId::new(&run.run_id)?;
        let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, &run_id)
            .with_context(|| {
                format!(
                    "finalized inbox run '{}' changed during duplicate scan",
                    run.run_id
                )
            })?;
        let final_report = read_artifact_json(&reader, "final-report.json")?;
        let completed_successfully = final_report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = final_report.get("status").and_then(Value::as_str);
        if !completed_successfully || matches!(status, Some("dry_run" | "refused")) {
            continue;
        }
        let selected = reader.read("selected-items.json")?;
        let value: Value = serde_json::from_slice(&selected).with_context(|| {
            format!(
                "failed to parse finalized selected-items.json for inbox run '{}'",
                run.run_id
            )
        })?;
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(key) = item["source_key"].as_str() {
                    duplicates
                        .entry(key.to_string())
                        .or_insert(run.run_id.clone());
                }
            }
        }
    }
    Ok(duplicates)
}

#[cfg(test)]
fn parse_gh_json_bytes(bytes: Vec<u8>, label: &str) -> Result<Value> {
    if bytes.len() > GH_OUTPUT_LIMIT {
        bail!("{label} exceeded its {GH_OUTPUT_LIMIT} byte JSON limit");
    }
    let text =
        String::from_utf8(bytes).with_context(|| format!("{label} returned non-UTF-8 JSON"))?;
    let bounded = summarize_text(&text, GH_OUTPUT_LIMIT);
    if bounded.truncated {
        bail!("{label} exceeded its {GH_OUTPUT_LIMIT} character JSON limit");
    }
    serde_json::from_str(&bounded.text).with_context(|| format!("{label} returned invalid JSON"))
}

fn artifact_status(reader: &ArtifactRunReader) -> InboxArtifactStatus {
    let mut item_plan_count = 0usize;
    let mut item_autopilot_report_count = 0usize;
    let mut item_github_report_count = 0usize;
    let contains = |path: &str| {
        reader
            .finalization()
            .files
            .iter()
            .any(|record| record.path == Path::new(path))
    };
    for record in &reader.finalization().files {
        let Some(name) = record.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("item-") && name.ends_with("-plan.json") {
            item_plan_count = item_plan_count.saturating_add(1);
        } else if name.starts_with("item-") && name.ends_with("-autopilot-report.json") {
            item_autopilot_report_count = item_autopilot_report_count.saturating_add(1);
        } else if name.starts_with("item-") && name.ends_with("-github-report.json") {
            item_github_report_count = item_github_report_count.saturating_add(1);
        }
    }
    InboxArtifactStatus {
        scan_report: contains("scan-report.json"),
        selected_items: contains("selected-items.json"),
        final_report: contains("final-report.json"),
        item_plan_count,
        item_autopilot_report_count,
        item_github_report_count,
    }
}

enum ArtifactRunState {
    Missing,
    Active(PathBuf),
    Finalized(Box<ArtifactRunReader>),
}

fn inbox_artifact_run_state(repo: &Path, run_id: &RunId) -> Result<ArtifactRunState> {
    let Some(run_dir) =
        verified_unfinalized_run_dir(repo, &[".maco", "inbox", "runs", run_id.as_str()])?
    else {
        return Ok(ArtifactRunState::Missing);
    };
    if !known_regular_file_exists(&run_dir, ARTIFACT_FINAL_MARKER)? {
        return Ok(ArtifactRunState::Active(run_dir));
    }
    let reader =
        ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, run_id).with_context(|| {
            format!(
                "inbox run '{}' has corrupt or unverifiable finalized artifacts",
                run_id.as_str()
            )
        })?;
    Ok(ArtifactRunState::Finalized(Box::new(reader)))
}

fn verified_unfinalized_run_dir(repo: &Path, components: &[&str]) -> Result<Option<PathBuf>> {
    let mut current = repo.to_path_buf();
    for component in components {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect artifact directory {}", current.display())
                })
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "artifact directory is not a direct non-link directory: {}",
                current.display()
            );
        }
    }
    Ok(Some(current))
}

fn known_regular_file_exists(run_dir: &Path, name: &str) -> Result<bool> {
    let path = run_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "artifact entry is not a direct regular file: {}",
                path.display()
            )
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect artifact file {}", path.display())),
    }
}

fn empty_artifact_status() -> InboxArtifactStatus {
    InboxArtifactStatus {
        scan_report: false,
        selected_items: false,
        final_report: false,
        item_plan_count: 0,
        item_autopilot_report_count: 0,
        item_github_report_count: 0,
    }
}

fn unfinalized_artifact_status(run_dir: &Path) -> Result<InboxArtifactStatus> {
    let status = InboxArtifactStatus {
        scan_report: known_regular_file_exists(run_dir, "scan-report.json")?,
        selected_items: known_regular_file_exists(run_dir, "selected-items.json")?,
        final_report: known_regular_file_exists(run_dir, "final-report.json")?,
        // Per-item names are not a bounded known set until the authenticated
        // manifest exists. Do not enumerate an unfinalized child-writable tree.
        item_plan_count: 0,
        item_autopilot_report_count: 0,
        item_github_report_count: 0,
    };
    if known_regular_file_exists(run_dir, ARTIFACT_FINAL_MARKER)? {
        bail!("artifact run finalized while active status was being inspected; retry status");
    }
    Ok(status)
}

fn run_artifacts(run_id: &RunId) -> InboxRunArtifacts {
    InboxRunArtifacts {
        run_dir: public_run_dir().join(run_id.as_str()),
        scan_report: public_item_path(run_id, "scan-report.json"),
        selected_items: public_item_path(run_id, "selected-items.json"),
        final_report: public_item_path(run_id, "final-report.json"),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish {}", path.display()))
}

fn write_private_artifact_json<T: Serialize>(
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

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn public_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("inbox").join("runs")
}

fn public_repo_path() -> PathBuf {
    PathBuf::from(".")
}

fn public_item_path(run_id: &RunId, file_name: &str) -> PathBuf {
    public_run_dir().join(run_id.as_str()).join(file_name)
}

fn effective_permission_mode(
    config: &InboxConfig,
    github: bool,
    override_mode: Option<InboxPermissionMode>,
) -> InboxPermissionMode {
    if let Some(mode) = override_mode {
        mode
    } else if github {
        InboxPermissionMode::GithubFull
    } else if let Some(mode) = config.permission_mode {
        mode
    } else if config.action_policy == InboxActionPolicy::Github {
        InboxPermissionMode::GithubFull
    } else {
        InboxPermissionMode::Fake
    }
}

fn effective_action_policy(
    configured: InboxActionPolicy,
    permission_mode: InboxPermissionMode,
) -> InboxActionPolicy {
    if configured == InboxActionPolicy::DryRun {
        InboxActionPolicy::DryRun
    } else if permission_mode.uses_github_intake() {
        InboxActionPolicy::Github
    } else {
        InboxActionPolicy::Fake
    }
}

fn permission_mode_label(mode: InboxPermissionMode) -> &'static str {
    match mode {
        InboxPermissionMode::Fake => "fake",
        InboxPermissionMode::GithubRead => "github_read",
        InboxPermissionMode::GithubLocal => "github_local",
        InboxPermissionMode::GithubGit => "github_git",
        InboxPermissionMode::GithubPr => "github_pr",
        InboxPermissionMode::GithubFull => "github_full",
    }
}

fn is_ignored_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
}

fn validate_schema_version(label: &str, version: u32) -> Result<()> {
    if version != INBOX_SCHEMA_VERSION {
        bail!(
            "{label} version must be {}; got {version}",
            INBOX_SCHEMA_VERSION
        );
    }
    Ok(())
}

fn validate_count(count: usize, label: &str, limit: usize) -> Result<()> {
    if count > limit {
        bail!("{label} exceeds its {limit} item limit");
    }
    Ok(())
}

fn validate_item_limit(value: usize, label: &str) -> Result<()> {
    if value == 0 || value > MAX_SELECTION_ITEMS {
        bail!("{label} must be between 1 and {}", MAX_SELECTION_ITEMS);
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty()) || value.len() > max_bytes {
        bail!(
            "{label} must contain between {} and {max_bytes} bytes",
            usize::from(!allow_empty)
        );
    }
    if value.chars().any(char::is_control) {
        bail!("{label} must not contain control characters");
    }
    Ok(())
}

fn validate_multiline_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.len() > max_bytes {
        bail!("{label} exceeds its {max_bytes} byte limit");
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        bail!("{label} contains an unsupported control character");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    validate_bounded_text(value, label, max_bytes, false)?;
    let mut characters = value.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        bail!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_path_text(path: &Path, label: &str, max_bytes: usize) -> Result<()> {
    let value = path
        .to_str()
        .with_context(|| format!("{label} must be valid UTF-8"))?;
    validate_bounded_text(value, label, max_bytes, false)
}

fn validate_labels(values: Vec<String>, label: &str) -> Result<Vec<String>> {
    validate_bounded_string_set(values, label, MAX_LABELS, MAX_LABEL_BYTES)
}

fn validate_bounded_string_set(
    values: Vec<String>,
    label: &str,
    max_count: usize,
    max_bytes: usize,
) -> Result<Vec<String>> {
    validate_count(values.len(), label, max_count)?;
    let mut normalized = BTreeSet::new();
    for (index, value) in values.into_iter().enumerate() {
        let value = value.trim().to_string();
        validate_bounded_text(
            &value,
            &format!("{label} item {}", index + 1),
            max_bytes,
            false,
        )?;
        normalized.insert(value);
    }
    Ok(normalized.into_iter().collect())
}

fn validate_optional_timeout(value: Option<u64>, label: &str) -> Result<()> {
    if value.is_some_and(|seconds| seconds == 0 || seconds > MAX_TIMEOUT_SECONDS) {
        bail!(
            "{label} must be between 1 and {} seconds when set",
            MAX_TIMEOUT_SECONDS
        );
    }
    Ok(())
}

fn validate_poll_seconds(value: u64) -> Result<()> {
    if value == 0 || value > MAX_TIMEOUT_SECONDS {
        bail!("poll-seconds must be between 1 and {}", MAX_TIMEOUT_SECONDS);
    }
    Ok(())
}

fn validate_serialized_config_size<T: Serialize>(value: &T, label: &str) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).with_context(|| format!("failed to serialize {label}"))?;
    if bytes.len() > MAX_CONFIG_SERIALIZED_BYTES {
        bail!(
            "{label} exceeds its {} byte serialized limit",
            MAX_CONFIG_SERIALIZED_BYTES
        );
    }
    Ok(())
}

fn validate_repository_config(repository: &mut InboxRepositoryConfig) -> Result<()> {
    match (&mut repository.owner, &mut repository.name) {
        (Some(owner), Some(name)) => {
            *owner = owner.trim().to_ascii_lowercase();
            *name = name.trim().to_ascii_lowercase();
            validate_github_owner(owner)?;
            validate_github_repository_name(name)?;
        }
        (None, None) => {}
        _ => bail!("inbox repository owner and name must be configured together"),
    }
    if let Some(branch) = repository.default_branch.as_mut() {
        *branch = branch.trim().to_string();
        validate_git_branch(branch)?;
    }
    Ok(())
}

fn validate_github_owner(owner: &str) -> Result<()> {
    validate_bounded_text(owner, "GitHub repository owner", 39, false)?;
    if owner.starts_with('-')
        || owner.ends_with('-')
        || !owner
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        bail!("GitHub repository owner is not canonical");
    }
    Ok(())
}

fn validate_github_repository_name(name: &str) -> Result<()> {
    validate_bounded_text(name, "GitHub repository name", 100, false)?;
    if matches!(name, "." | "..")
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        bail!("GitHub repository name is not canonical");
    }
    Ok(())
}

fn validate_git_branch(branch: &str) -> Result<()> {
    validate_bounded_text(branch, "inbox default_branch", 255, false)?;
    if branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch
            .chars()
            .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
        || branch.split('/').any(|component| {
            component.is_empty() || component.starts_with('.') || component.ends_with(".lock")
        })
    {
        bail!("inbox default_branch is not a canonical Git ref name");
    }
    Ok(())
}

fn validate_repository_selector(selector: &str) -> Result<()> {
    if selector == "." {
        return Ok(());
    }
    validate_bounded_text(selector, "inbox repository selector", 256, false)?;
    let mut parts = selector.split('/');
    let owner = parts
        .next()
        .context("repository selector requires an owner")?;
    let name = parts
        .next()
        .context("repository selector requires a name")?;
    if parts.next().is_some() {
        bail!("inbox repository selector must contain exactly owner/name");
    }
    validate_github_owner(owner)?;
    validate_github_repository_name(name)
}

fn validate_git_oid(oid: &str, label: &str) -> Result<()> {
    if !matches!(oid.len(), 40 | 64)
        || !oid
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        bail!("{label} must be a canonical lowercase 40- or 64-hex Git OID");
    }
    Ok(())
}

fn validate_timestamp(timestamp: &str) -> Result<()> {
    validate_bounded_text(
        timestamp,
        "inbox source updatedAt",
        MAX_TIMESTAMP_BYTES,
        false,
    )?;
    let bytes = timestamp.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
    {
        bail!("inbox source updatedAt must be a canonical RFC3339 timestamp");
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    if !matches!(number(5..7), Some(1..=12))
        || !matches!(number(8..10), Some(1..=31))
        || !matches!(number(11..13), Some(0..=23))
        || !matches!(number(14..16), Some(0..=59))
        || !matches!(number(17..19), Some(0..=59))
        || !timestamp.ends_with('Z')
        || (bytes.len() > 20
            && (bytes.get(19) != Some(&b'.')
                || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
    {
        bail!("inbox source updatedAt must be a canonical UTC RFC3339 timestamp");
    }
    Ok(())
}

fn source_key(kind: InboxItemKind, number: u64) -> String {
    match kind {
        InboxItemKind::Issue => format!("github_issue:{number}"),
        InboxItemKind::PullRequest => format!("github_pr:{number}"),
    }
}

fn source_repository_binding_context(
    repo_path: &Path,
    config: &InboxConfig,
    require_remote_match: bool,
) -> Result<SourceRepositoryBindingContext> {
    let repo =
        crate::git_repository::open(repo_path).context("failed to bind inbox source repository")?;
    let common = SafeRoot::open_existing(repo.commondir())
        .context("failed to bind inbox source repository common directory")?;
    let identity = publication::external_source_repository_identity(
        common.identity().device,
        common.identity().file,
    );
    let origin_binding = match repo.find_remote("origin") {
        Ok(remote) => {
            let url = remote
                .url()
                .context("origin remote URL is not valid UTF-8")?;
            publication::canonical_github_source_repository(url).ok()
        }
        Err(error) if error.code() == git2::ErrorCode::NotFound => None,
        Err(error) => return Err(error).context("failed to inspect origin remote"),
    };
    let configured_selector = match (&config.repository.owner, &config.repository.name) {
        (Some(owner), Some(name)) => Some(format!("{owner}/{name}")),
        _ => None,
    };
    if require_remote_match {
        let (_, observed) = origin_binding
            .as_ref()
            .context("GitHub intake requires a canonical HTTPS origin remote")?;
        if let Some(configured) = &configured_selector {
            let observed_owner_name = observed
                .split_once('/')
                .and_then(|(_, remainder)| remainder.split_once('/'))
                .map(|(owner, name)| format!("{owner}/{name}"))
                .context("canonical GitHub origin selector omitted owner/name")?;
            if !configured.eq_ignore_ascii_case(&observed_owner_name) {
                bail!(
                    "configured GitHub repository does not match the execution repository origin"
                );
            }
        }
    }
    let (host, selector) = match origin_binding {
        Some(binding) => binding,
        None => (
            "fake".to_string(),
            configured_selector.unwrap_or_else(|| ".".to_string()),
        ),
    };
    if host == "fake" {
        validate_repository_selector(&selector)?;
    } else {
        publication::validate_github_source_repository_binding(&host, &selector)?;
    }
    common.verify()?;
    Ok(SourceRepositoryBindingContext {
        host,
        selector,
        identity,
    })
}

fn validate_candidate_repository_url(
    provider: InboxSourceProvider,
    url: Option<&str>,
    repository_selector: &str,
    kind: InboxItemKind,
    number: u64,
) -> Result<()> {
    if provider == InboxSourceProvider::Fake {
        return Ok(());
    }
    let url = url.context("GitHub candidate requires a canonical URL")?;
    let expected_kind = match kind {
        InboxItemKind::Issue => "issues",
        InboxItemKind::PullRequest => "pull",
    };
    let expected_url = format!("https://{repository_selector}/{expected_kind}/{number}");
    if url != expected_url {
        bail!("GitHub candidate URL does not match its exact host, repository, kind, and number");
    }
    Ok(())
}

fn canonical_or_lexical_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path).with_context(|| {
            format!(
                "failed to resolve workspace repository path {}",
                path.display()
            )
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("workspace repository path escapes its filesystem root");
                }
            }
        }
    }
    Ok(normalized)
}

fn validate_cli_source_options(
    github: bool,
    permission_mode: Option<InboxPermissionMode>,
    max_items: Option<usize>,
    codex_bin: Option<&Path>,
) -> Result<()> {
    if github && permission_mode == Some(InboxPermissionMode::Fake) {
        bail!("--github conflicts with --permission fake");
    }
    if let Some(max_items) = max_items {
        validate_item_limit(max_items, "inbox --max-items")?;
    }
    if let Some(codex_bin) = codex_bin {
        validate_path_text(codex_bin, "inbox --codex-bin", MAX_CODEX_PATH_BYTES)?;
    }
    Ok(())
}

fn required_input_string(value: Option<&Value>, label: &str, max_bytes: usize) -> Result<String> {
    let value = value
        .and_then(Value::as_str)
        .with_context(|| format!("{label} must be a string"))?;
    validate_bounded_text(value, label, max_bytes, false)?;
    Ok(value.to_string())
}

fn optional_input_string(
    value: Option<&Value>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .with_context(|| format!("{label} must be a string or null"))?;
    validate_bounded_text(value, label, max_bytes, false)?;
    Ok(Some(value.to_string()))
}

fn optional_input_body(
    value: Option<&Value>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .with_context(|| format!("{label} must be a string or null"))?;
    validate_multiline_text(value, label, max_bytes)?;
    Ok(Some(value.to_string()))
}

fn optional_input_array<'a>(
    value: Option<&'a Value>,
    label: &str,
    max_count: usize,
) -> Result<&'a [Value]> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(&[]);
    };
    let values = value
        .as_array()
        .with_context(|| format!("{label} must be an array or null"))?;
    validate_count(values.len(), label, max_count)?;
    Ok(values)
}

fn optional_nested_login(value: Option<&Value>, label: &str) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be an object or null"))?;
    optional_input_string(
        object.get("login"),
        &format!("{label} login"),
        MAX_GITHUB_LOGIN_BYTES,
    )
}

fn first_optional_input_string(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    for field in fields {
        if object.get(*field).is_some_and(|value| !value.is_null()) {
            return optional_input_string(object.get(*field), label, max_bytes);
        }
    }
    Ok(None)
}

fn first_required_input_string(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    first_optional_input_string(object, fields, label, max_bytes)?
        .with_context(|| format!("{label} is required"))
}

fn item_target(item: &InboxItem) -> String {
    match item.kind {
        InboxItemKind::Issue => item
            .issue
            .as_ref()
            .map(|issue| format!("issue #{}", issue.number))
            .unwrap_or_else(|| item.item_id.clone()),
        InboxItemKind::PullRequest => item
            .pull_request
            .as_ref()
            .map(|pr| format!("pr #{}", pr.number))
            .unwrap_or_else(|| item.item_id.clone()),
    }
}

fn item_number(item: &InboxItem) -> Option<u64> {
    item.issue
        .as_ref()
        .map(|issue| issue.number)
        .or_else(|| item.pull_request.as_ref().map(|pr| pr.number))
}

fn item_label(kind: InboxItemKind) -> &'static str {
    match kind {
        InboxItemKind::Issue => "issue",
        InboxItemKind::PullRequest => "pull request",
    }
}

fn path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "- no changed files".to_string();
    }
    paths
        .iter()
        .map(|path| format!("- {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_summary(name: &str, status: Option<&str>, conclusion: Option<&str>) -> String {
    if check_failed(conclusion, status) {
        format!("{name} is failing or incomplete; full logs omitted")
    } else {
        format!("{name} check metadata fetched; full logs omitted")
    }
}

fn check_failed(conclusion: Option<&str>, status: Option<&str>) -> bool {
    conclusion.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    }) || status.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    })
}

#[derive(Debug, Clone)]
struct BoundedText {
    text: String,
    truncated: bool,
}

fn summarize_text(text: &str, limit: usize) -> BoundedText {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    BoundedText {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn sanitize_public_text(repo: &Path, text: &str, limit: usize) -> BoundedText {
    let mut sanitized = Redactor::new().redact(text).text;
    sanitized = sanitized.replace(&repo.display().to_string(), ".");
    if let Some(parent) = repo.parent() {
        sanitized = sanitized.replace(&parent.display().to_string(), "<repo-parent>");
    }
    sanitized = sanitize_redacted_public_text(text, &sanitized);
    summarize_text(&sanitized, limit)
}

fn sanitize_public_field(text: &str, limit: usize) -> String {
    let redacted = Redactor::new().redact(text);
    summarize_text(&sanitize_redacted_public_text(text, &redacted.text), limit).text
}

fn sanitize_public_fields(values: &[String], limit: usize) -> Vec<String> {
    values
        .iter()
        .map(|value| sanitize_public_field(value, limit))
        .collect()
}

fn sanitize_redacted_public_text(original: &str, redacted: &str) -> String {
    if contains_private_key_material(original) || contains_private_key_material(redacted) {
        return "<redacted:private-key-material>".to_string();
    }
    redact_token_like_words(&redact_local_absolute_paths(redacted))
}

fn contains_private_key_material(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("PRIVATE KEY") && (upper.contains("-----BEGIN") || upper.contains("BEGIN "))
}

fn contains_local_absolute_path(text: &str) -> bool {
    text.split_whitespace()
        .any(token_contains_local_absolute_path)
}

fn redact_local_absolute_paths(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut token = String::new();
    for character in text.chars() {
        if character.is_whitespace() {
            push_redacted_path_token(&mut output, &token);
            token.clear();
            output.push(character);
        } else {
            token.push(character);
        }
    }
    push_redacted_path_token(&mut output, &token);
    output
}

fn push_redacted_path_token(output: &mut String, token: &str) {
    if token_contains_local_absolute_path(token) {
        output.push_str("<redacted:local-path>");
    } else {
        output.push_str(token);
    }
}

fn token_contains_local_absolute_path(token: &str) -> bool {
    contains_windows_home_path(token) || contains_unix_absolute_path(token)
}

fn contains_windows_home_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("c:\\users\\") || lower.contains("c:/users/")
}

fn contains_unix_absolute_path(token: &str) -> bool {
    if token.starts_with("//") {
        return false;
    }
    for (index, character) in token.char_indices() {
        if character == '/' && is_unix_absolute_path_start(token, index) {
            return true;
        }
    }
    false
}

fn is_unix_absolute_path_start(token: &str, index: usize) -> bool {
    if token[index..].starts_with("//") || token_url_prefix_start(token, index).is_some() {
        return false;
    }
    let Some(next) = token[index..].chars().nth(1) else {
        return false;
    };
    if !is_unix_path_component_char(next) {
        return false;
    }
    let previous = token[..index].chars().next_back();
    !previous.is_some_and(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
    })
}

fn token_url_prefix_start(token: &str, index: usize) -> Option<usize> {
    let marker = token.find("://")?;
    (index > marker).then_some(marker)
}

fn is_unix_path_component_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}

fn redact_token_like_words(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            push_redacted_token(&mut output, &token);
            token.clear();
            output.push(character);
        }
    }
    push_redacted_token(&mut output, &token);
    output
}

fn contains_token_like_word(text: &str) -> bool {
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            if is_token_like_word(&token) {
                return true;
            }
            token.clear();
        }
    }
    is_token_like_word(&token)
}

fn push_redacted_token(output: &mut String, token: &str) {
    if is_token_like_word(token) {
        output.push_str("<redacted:token>");
    } else {
        output.push_str(token);
    }
}

fn is_token_like_word(token: &str) -> bool {
    token.len() >= 32
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && token.chars().any(|c| c.is_ascii_digit())
}

fn default_true() -> bool {
    true
}

fn default_inbox_schema_version() -> u32 {
    INBOX_SCHEMA_VERSION
}

fn default_max_items() -> usize {
    DEFAULT_MAX_ITEMS
}

fn default_workspace_permission_mode() -> InboxPermissionMode {
    InboxPermissionMode::GithubRead
}

fn default_max_repair_attempts() -> usize {
    1
}

fn default_assigned_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("README.md")]
}

fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}

fn default_blocked_terms() -> Vec<String> {
    [
        "api key",
        "credential",
        "cve",
        "exploit",
        "password",
        "private key",
        "secret",
        "security",
        "ssn",
        "token",
        "vulnerability",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

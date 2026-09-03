fn verify_github_receipt_with_remote_check(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    receipt: GithubPrResult,
    created_by_transaction: bool,
    observed_existing_pr: bool,
    mut remote_check: impl FnMut(&Path, &PublicationTransaction, &str) -> Result<()>,
) -> Result<GithubPrResult> {
    validate_github_receipt_contract(&receipt, &transaction.journal)?;
    remote_check(worktree_path, transaction, "after GitHub PR creation")?;
    let previous = transaction.journal.clone();
    transaction.journal.pr_url = Some(receipt.url.clone());
    transaction.journal.pr_head_oid = Some(receipt.head_oid.clone());
    transaction.journal.pr_base = Some(receipt.base_ref_name.clone());
    transaction.journal.pr_state = Some(receipt.state.clone());
    transaction.journal.pr_is_draft = Some(receipt.is_draft);
    transaction.journal.pr_number = Some(receipt.number);
    transaction.journal.pr_title = Some(receipt.title.clone());
    transaction.journal.pr_body = Some(receipt.body.clone());
    transaction.journal.pr_head_ref_name = Some(receipt.head_ref_name.clone());
    transaction.journal.pr_head_repository_owner = Some(receipt.head_repository_owner.clone());
    transaction.journal.pr_head_repository_name = Some(receipt.head_repository_name.clone());
    transaction.journal.pr_is_cross_repository = Some(receipt.is_cross_repository);
    transaction.journal.pr_author = Some(receipt.author.clone());
    transaction.journal.created_by_transaction =
        transaction.journal.created_by_transaction || created_by_transaction;
    transaction.journal.observed_existing_pr = !transaction.journal.created_by_transaction
        && (transaction.journal.observed_existing_pr || observed_existing_pr);
    transaction.advance_phase(PublicationTransactionPhase::PrObserved);
    transaction.persist_if_changed(&previous)?;
    Ok(GithubPrResult {
        url: receipt.url,
        head_oid: receipt.head_oid,
        base_oid: receipt.base_oid,
        number: receipt.number,
        base_ref_name: receipt.base_ref_name,
        state: receipt.state,
        is_draft: receipt.is_draft,
        title: receipt.title,
        body: receipt.body,
        head_ref_name: receipt.head_ref_name,
        head_repository_owner: receipt.head_repository_owner,
        head_repository_name: receipt.head_repository_name,
        is_cross_repository: receipt.is_cross_repository,
        author: receipt.author,
        created: transaction.journal.created_by_transaction,
    })
}

fn validate_github_receipt_contract(
    receipt: &GithubPrResult,
    journal: &PublicationTransactionJournal,
) -> Result<()> {
    let github_repository = journal
        .github_repository
        .as_ref()
        .context("GitHub PR journal omitted forge repository binding")?;
    validate_github_receipt_url(&receipt.url, github_repository, receipt.number)?;
    if receipt.head_oid != journal.expected_oid {
        bail!(
            "GitHub PR receipt headRefOid {} does not match reviewed OID {}",
            receipt.head_oid,
            journal.expected_oid
        );
    }
    let expected_base_oid = journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    if receipt.base_oid != expected_base_oid {
        bail!(
            "GitHub PR receipt baseRefOid {} does not match reviewed base OID {}",
            receipt.base_oid,
            expected_base_oid
        );
    }
    if receipt.base_ref_name != journal.base {
        bail!(
            "GitHub PR receipt baseRefName {} does not match requested base {}",
            receipt.base_ref_name,
            journal.base
        );
    }
    let expected_title = journal
        .expected_pr_title
        .as_deref()
        .context("GitHub publication journal omitted its exact PR title")?;
    let expected_body = journal
        .expected_pr_body
        .as_deref()
        .context("GitHub publication journal omitted its marker-bound PR body")?;
    let expected_author = journal
        .expected_pr_author
        .as_deref()
        .context("GitHub publication journal omitted its explicit expected author")?;
    if receipt.title != expected_title || receipt.body != expected_body {
        bail!("GitHub PR receipt title/body did not match the marker-bound transaction content");
    }
    if receipt.head_ref_name != journal.remote_branch {
        bail!("GitHub PR receipt headRefName did not match the unique publication branch");
    }
    if receipt.head_repository_owner != github_repository.owner
        || receipt.head_repository_name != github_repository.name
        || receipt.is_cross_repository
    {
        bail!(
            "GitHub PR receipt head repository provenance did not match the bound same-repository publication"
        );
    }
    if receipt.author != expected_author {
        bail!("GitHub PR receipt author did not match the explicit expected author");
    }
    if receipt.is_draft != journal.draft {
        bail!(
            "GitHub PR receipt draft state {} does not match requested draft state {}",
            receipt.is_draft,
            journal.draft
        );
    }
    if receipt.state != "OPEN" {
        bail!(
            "GitHub PR receipt state {} is not OPEN; the existing receipt is recorded but is not review-ready",
            receipt.state
        );
    }
    Ok(())
}

fn require_remote_expected(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let observed = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if observed.as_deref() != Some(transaction.journal.expected_oid.as_str()) {
        bail!(
            "publication remote ref {} changed {stage}: observed {:?}, expected {}",
            transaction.journal.remote_ref,
            observed,
            transaction.journal.expected_oid
        );
    }
    require_remote_expected_base_with_context(worktree_path, transaction, stage)?;
    Ok(())
}

fn require_remote_expected_base(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    require_remote_expected_base_with_context(worktree_path, transaction, stage)
}

fn require_remote_expected_base_with_context(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let expected_base_oid = transaction
        .journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    let base_ref = format!("refs/heads/{}", transaction.journal.base);
    let observed_base = observe_remote_ref(worktree_path, &transaction.remote_url, &base_ref)?;
    if observed_base.as_deref() != Some(expected_base_oid) {
        bail!(
            "publication base ref {} changed {stage}: observed {:?}, expected {}",
            base_ref,
            observed_base,
            expected_base_oid
        );
    }
    Ok(())
}

impl GhCommandContext {
    fn create(worktree_path: &Path, repository: &GithubRepositoryIdentity) -> Result<Self> {
        Self::create_with_token_source(worktree_path, repository, |key| env::var(key).ok())
    }

    fn create_with_token_source(
        worktree_path: &Path,
        repository: &GithubRepositoryIdentity,
        mut value_for: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::GhConfig,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        let result = (|| -> Result<GhCommandContextSetup> {
            let source = crate::git_repository::discover(worktree_path).with_context(|| {
                format!(
                    "failed to discover gh source repository from {}",
                    worktree_path.display()
                )
            })?;
            let token = select_network_token_with(&repository.host, &mut value_for)?;
            let hosts_path = directory.join("hosts.yml");
            let escaped_token = ZeroizingString(token.as_str()?.replace('\'', "''"));
            let hosts = ZeroizingString(format!(
                "'{}':\n    oauth_token: '{}'\n    git_protocol: https\n",
                repository.host,
                escaped_token.as_str()
            ));
            merge::write_private_file(&hosts_path, hosts.as_bytes())?;
            let config_files = vec![capture_private_config_file(&hosts_path)?];

            let common_state =
                fs::canonicalize(merge::ensure_repo_common_state_directory(&source)?)
                    .context("failed to resolve gh repository state directory")?;
            let common_directory = fs::canonicalize(source.commondir())
                .context("failed to resolve gh common Git directory")?;
            let primary_worktree = common_directory
                .parent()
                .context("gh common Git directory omitted its repository root")?
                .to_path_buf();
            let source_worktree = source
                .workdir()
                .map(fs::canonicalize)
                .transpose()
                .context("failed to resolve gh source worktree")?
                .unwrap_or_else(|| common_directory.clone());

            let mut environment = merge::minimal_network_environment()?;
            for key in [
                "GIT_CONFIG_NOSYSTEM",
                "GIT_ATTR_NOSYSTEM",
                "GIT_OPTIONAL_LOCKS",
                "GIT_TERMINAL_PROMPT",
            ] {
                environment.remove(key);
            }
            environment.insert(
                "GH_CONFIG_DIR".to_string(),
                directory
                    .to_str()
                    .context("private gh config path was not UTF-8")?
                    .to_string(),
            );
            environment.insert("GH_PROMPT_DISABLED".to_string(), "1".to_string());
            validate_gh_environment(&environment, &directory)?;
            let profile = TrustedFixedNetworkProfile::read_write(&directory)
                .with_resource_limits(Default::default())
                .with_visible_read_only_file(&hosts_path)
                .with_hidden_root(&primary_worktree)
                .with_hidden_root(&source_worktree)
                .with_hidden_root(&common_state);
            Ok((
                environment,
                profile,
                config_files,
                token,
                source.commondir().join("config"),
            ))
        })();
        match result {
            Ok((environment, profile, config_files, token, source_config_path)) => Ok(Self {
                runtime_directory,
                environment,
                profile,
                config_files,
                repository: repository.clone(),
                token,
                source_config_path,
            }),
            Err(error) => {
                let erase = erase_private_config_paths_if_present(&[directory.join("hosts.yml")]);
                let close = runtime_directory.close();
                match (erase, close) {
                    (Ok(()), Ok(())) => Err(error),
                    (erase, close) => Err(anyhow::anyhow!(
                        "{error:#}; gh setup cleanup failed: erase={:?}, close={:?}",
                        erase.err().map(|error| format!("{error:#}")),
                        close.err().map(|error| format!("{error:#}")),
                    )),
                }
            }
        }
    }

    fn run(
        mut self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        let execution = (|| {
            if classify_gh_operation(&args, &stdin, &self.repository)?
                == GhOperationClass::HumanMutation
            {
                bail!("human-authored gh mutations require the approved GitHub actor guard");
            }
            self.run_inner(label, args, stdin)
        })();
        self.finish(execution)
    }

    fn run_human_mutation(
        mut self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        let execution = (|| {
            if classify_gh_operation(&args, &stdin, &self.repository)?
                != GhOperationClass::HumanMutation
            {
                bail!("approved GitHub actor guard accepts only human-authored gh mutations");
            }
            let binding = capture_approved_github_actor_binding(&self.source_config_path);
            execute_with_approved_github_actor(
                binding,
                || self.authenticated_github_actor(),
                || self.run_inner(label, args, stdin),
            )
        })();
        self.finish(execution)
    }

    fn authenticated_github_actor(&self) -> Result<String> {
        let output = self.run_inner(
            "gh authenticated actor",
            ["api", "user", "--jq", ".login"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            StdinMode::Null,
        )?;
        github_actor_login_from_output(output)
    }

    fn finish(
        &mut self,
        execution: Result<merge::RequiredCommandOutput>,
    ) -> Result<merge::RequiredCommandOutput> {
        let cleanup = self.close();
        match (execution, cleanup) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => {
                Err(cleanup
                    .context("gh command completed but private token runtime cleanup failed"))
            }
            (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
                "{error:#}; gh private token runtime cleanup also failed: {cleanup:#}"
            )),
        }
    }

    fn run_inner(
        &self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        self.runtime_directory
            .verify_identity()
            .context("private gh runtime changed before command execution")?;
        verify_private_config_files(&self.config_files)?;
        validate_gh_environment(&self.environment, self.runtime_directory.path())?;
        validate_gh_operation(&args, &stdin, &self.repository)?;
        let output = merge::run_required_network_direct(
            label,
            merge::resolve_trusted_executable("gh")?,
            args,
            self.runtime_directory.path(),
            self.environment.clone(),
            stdin,
            merge::NETWORK_PROCESS_TIMEOUT,
            GH_CAPTURE_LIMIT_BYTES,
            GH_STDIN_LIMIT_BYTES,
            self.profile.clone(),
        )
        .map_err(|error| {
            let mut message = format!("{error:#}");
            for private in [self.token.as_str(), self.token.basic_str()]
                .into_iter()
                .flatten()
            {
                message = message.replace(private, "<redacted:network-token>");
            }
            anyhow::anyhow!(message)
        })?;
        self.runtime_directory
            .verify_identity()
            .context("private gh runtime changed during command execution")?;
        verify_private_config_files(&self.config_files)?;
        let mut output = output;
        redact_private_bytes(&mut output.stdout, &self.token.bytes);
        redact_private_bytes(&mut output.stderr, &self.token.bytes);
        redact_private_bytes(&mut output.stdout, &self.token.basic);
        redact_private_bytes(&mut output.stderr, &self.token.basic);
        Ok(output)
    }

    fn close(&mut self) -> Result<()> {
        let erase = erase_private_config_files(&mut self.config_files);
        self.environment.clear();
        self.token.zeroize();
        let close = self.runtime_directory.close();
        match (erase, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(erase), Err(close)) => Err(anyhow::anyhow!(
                "gh private config erasure failed: {erase:#}; private runtime close failed: {close:#}"
            )),
        }
    }
}

fn validate_gh_environment(
    environment: &BTreeMap<String, String>,
    config_directory: &Path,
) -> Result<()> {
    let expected_directory = config_directory
        .to_str()
        .context("private gh config directory was not UTF-8")?;
    if environment.get("GH_CONFIG_DIR").map(String::as_str) != Some(expected_directory)
        || environment.get("GH_PROMPT_DISABLED").map(String::as_str) != Some("1")
    {
        bail!("gh environment omitted its exact private config and prompt bindings");
    }
    if environment.keys().any(|key| {
        key.starts_with("GIT_")
            || matches!(
                key.as_str(),
                "GH_TOKEN" | "GITHUB_TOKEN" | "GH_ENTERPRISE_TOKEN" | "GITHUB_ENTERPRISE_TOKEN"
            )
    }) {
        bail!("gh environment contains ambient Git or token inputs");
    }
    Ok(())
}

fn validate_gh_operation(
    args: &[OsString],
    stdin: &StdinMode,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    classify_gh_operation(args, stdin, repository).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GhOperationClass {
    ActorLookup,
    Observation,
    HumanMutation,
}

fn classify_gh_operation(
    args: &[OsString],
    stdin: &StdinMode,
    repository: &GithubRepositoryIdentity,
) -> Result<GhOperationClass> {
    let args = args
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .context("gh command argument was not strict UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let selector = repository.selector();
    let receipt_fields = GITHUB_PR_RECEIPT_FIELDS;
    match args.as_slice() {
        ["api", "user", "--jq", ".login"] if matches!(stdin, StdinMode::Null) => {
            Ok(GhOperationClass::ActorLookup)
        }
        ["issue", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_ISSUE_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "issue source number")?;
            Ok(GhOperationClass::Observation)
        }
        ["issue", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_ISSUE_EFFECT_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "issue effect number")?;
            Ok(GhOperationClass::Observation)
        }
        ["issue", "list", "--repo", bound, "--state", "open", "--json", fields, "--limit", limit, labels @ ..]
            if *bound == selector
                && *fields == GITHUB_ISSUE_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_github_source_list_tail(limit, labels)?;
            Ok(GhOperationClass::Observation)
        }
        ["issue", "list", "--repo", bound, "--state", "all", "--search", marker, "--limit", limit, "--json", fields]
            if *bound == selector
                && *limit == GITHUB_ISSUE_EFFECT_LOOKUP_LIMIT
                && *fields == GITHUB_ISSUE_EFFECT_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_external_effect_marker_argument(marker)?;
            Ok(GhOperationClass::Observation)
        }
        ["pr", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_PR_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "pull-request source number")?;
            Ok(GhOperationClass::Observation)
        }
        ["pr", "list", "--repo", bound, "--state", "open", "--json", fields, "--limit", limit, labels @ ..]
            if *bound == selector
                && *fields == GITHUB_PR_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_github_source_list_tail(limit, labels)?;
            Ok(GhOperationClass::Observation)
        }
        ["pr", "list", "--repo", bound, "--head", branch, "--state", "all", "--limit", limit, "--json", fields]
            if *bound == selector
                && *limit == GITHUB_PR_EFFECT_LOOKUP_LIMIT
                && *fields == receipt_fields
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_argument_value(branch, "PR branch")?;
            Ok(GhOperationClass::Observation)
        }
        ["pr", "view", view, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == receipt_fields
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_argument_value(view, "PR selector")?;
            Ok(GhOperationClass::Observation)
        }
        ["pr", "create", "--repo", bound, "--base", base, "--head", branch, "--title", title, "--body-file", "-"]
        | ["pr", "create", "--repo", bound, "--base", base, "--head", branch, "--title", title, "--body-file", "-", "--draft"]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            validate_gh_argument_value(base, "PR base")?;
            validate_gh_argument_value(branch, "PR branch")?;
            validate_gh_argument_value(title, "PR title")?;
            Ok(GhOperationClass::HumanMutation)
        }
        ["issue", "create", "--repo", bound, "--title", title, "--body-file", "-", labels @ ..]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            validate_gh_argument_value(title, "issue title")?;
            if labels.len() % 2 != 0 {
                bail!("gh issue label arguments were not paired");
            }
            for pair in labels.chunks_exact(2) {
                if pair[0] != "--label" {
                    bail!("gh issue command contains an unapproved option");
                }
                validate_gh_argument_value(pair[1], "issue label")?;
            }
            Ok(GhOperationClass::HumanMutation)
        }
        [subcommand @ ("issue" | "pr"), "comment", number, "--repo", bound, "--body-file", "-"]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            let _ = subcommand;
            validate_gh_positive_number(number, "comment source number")?;
            Ok(GhOperationClass::HumanMutation)
        }
        ["api", "--method", "GET", endpoint] if matches!(stdin, StdinMode::Null) => {
            validate_github_comment_api_endpoint(endpoint, repository)?;
            Ok(GhOperationClass::Observation)
        }
        ["api", "--method", "GET", "--paginate", "--slurp", endpoint]
            if matches!(stdin, StdinMode::Null) =>
        {
            validate_github_comment_list_api_endpoint(endpoint, repository)?;
            Ok(GhOperationClass::Observation)
        }
        _ => bail!("gh command is outside the fixed PR/issue allowlist"),
    }
}

fn capture_approved_github_actor_binding(
    source_config_path: &Path,
) -> Result<ApprovedGithubActorBinding> {
    let source_config = capture_bound_config_file(source_config_path, false).with_context(|| {
        format!(
            "failed to bind repository-local {APPROVED_GITHUB_LOGIN_CONFIG_KEY} configuration"
        )
    })?;
    let config = git2::Config::open(source_config_path).with_context(|| {
        format!(
            "failed to read repository-local {APPROVED_GITHUB_LOGIN_CONFIG_KEY} configuration"
        )
    })?;
    let mut values = Vec::new();
    match config.multivar(APPROVED_GITHUB_LOGIN_CONFIG_KEY, None) {
        Ok(mut entries) => {
            while let Some(entry) = entries.next() {
                let entry = entry.context("failed to iterate approved GitHub login pins")?;
                if entry.include_depth() != 0 {
                    continue;
                }
                let value = std::str::from_utf8(entry.value_bytes())
                    .context("repository-local approved GitHub login was not UTF-8")?;
                values.push(value.to_string());
            }
        }
        Err(error) if error.code() == git2::ErrorCode::NotFound => {}
        Err(error) => {
            return Err(error).context("failed to enumerate approved GitHub login pins")
        }
    }
    if values.len() != 1 || values[0].is_empty() {
        bail!(
            "repository-local {APPROVED_GITHUB_LOGIN_CONFIG_KEY} must contain exactly one non-empty value"
        );
    }
    validate_github_slug(&values[0], "repository-local approved GitHub login")?;
    verify_private_config_files(std::slice::from_ref(&source_config))
        .context("repository-local approved GitHub login configuration changed while binding")?;
    Ok(ApprovedGithubActorBinding {
        login: values.remove(0),
        source_config,
    })
}

fn execute_with_approved_github_actor<T>(
    binding: Result<ApprovedGithubActorBinding>,
    actor_lookup: impl FnOnce() -> Result<String>,
    mutation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let binding = binding?;
    let actual = actor_lookup()?;
    if actual != binding.login {
        bail!("authenticated GitHub actor does not exactly match the approved repository login");
    }
    verify_private_config_files(std::slice::from_ref(&binding.source_config))
        .context("repository-local approved GitHub login changed after actor verification")?;
    mutation()
}

fn github_actor_login_from_output(output: merge::RequiredCommandOutput) -> Result<String> {
    let stdout = required_command_stdout(output, "gh authenticated actor")?;
    let login = stdout.strip_suffix('\n').unwrap_or(&stdout);
    if login.is_empty() || login.contains(['\r', '\n']) {
        bail!("authenticated GitHub actor response was empty or malformed");
    }
    validate_github_slug(login, "authenticated GitHub actor")?;
    Ok(login.to_string())
}

fn validate_github_source_list_tail(limit: &str, labels: &[&str]) -> Result<()> {
    let parsed_limit = limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=MAX_GITHUB_SOURCE_LIST_ITEMS).contains(limit))
        .context("GitHub source list limit was not canonical and bounded")?;
    if parsed_limit.to_string() != limit {
        bail!("GitHub source list limit was not canonical");
    }
    if !labels.len().is_multiple_of(2) || labels.len() / 2 > MAX_GITHUB_SOURCE_LIST_LABELS {
        bail!("GitHub source list labels were malformed or excessive");
    }
    for pair in labels.chunks_exact(2) {
        if pair[0] != "--label" {
            bail!("GitHub source list contains an unapproved option");
        }
        validate_gh_argument_value(pair[1], "GitHub source list label")?;
        if pair[1].len() > MAX_GITHUB_SLUG_BYTES {
            bail!("GitHub source list label exceeded its bound");
        }
    }
    Ok(())
}

fn validate_gh_positive_number(value: &str, label: &str) -> Result<()> {
    if value.len() > 20 || value.parse::<u64>().is_err() || value == "0" {
        bail!("{label} is not a canonical positive integer");
    }
    Ok(())
}

fn validate_gh_argument_value(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.len() > 64 * 1024
        || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        bail!("{label} is empty, malformed, or oversized");
    }
    Ok(())
}

fn validate_external_effect_marker_argument(value: &str) -> Result<()> {
    let effect_id = value
        .strip_prefix(&format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:"))
        .and_then(|value| value.strip_suffix(" -->"))
        .context("GitHub effect lookup marker was malformed")?;
    validate_external_digest(effect_id, "GitHub effect lookup marker id")
}

fn validate_github_comment_api_endpoint(
    endpoint: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    let prefix = format!(
        "repos/{}/{}/issues/comments/",
        repository.owner, repository.name
    );
    let id = endpoint
        .strip_prefix(&prefix)
        .context("GitHub comment API endpoint did not match the bound repository")?;
    validate_gh_positive_number(id, "comment API id")?;
    if endpoint != format!("{prefix}{id}") {
        bail!("GitHub comment API endpoint was not canonical");
    }
    Ok(())
}

fn validate_github_comment_list_api_endpoint(
    endpoint: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    let prefix = format!("repos/{}/{}/issues/", repository.owner, repository.name);
    let number = endpoint
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix("/comments?per_page=100"))
        .context("GitHub comment list API endpoint did not match the bound repository")?;
    validate_gh_positive_number(number, "comment list source number")?;
    if endpoint != format!("{prefix}{number}/comments?per_page=100") {
        bail!("GitHub comment list API endpoint was not canonical");
    }
    Ok(())
}

impl Drop for GhCommandContext {
    fn drop(&mut self) {
        self.environment.clear();
    }
}

fn cli_github_source_view(
    worktree_path: &Path,
    number: u64,
    kind: ExternalSourceObjectKind,
    repository: &GithubRepositoryIdentity,
) -> Result<serde_json::Value> {
    if number == 0 {
        bail!("GitHub source number must be positive");
    }
    let (subcommand, fields) = match kind {
        ExternalSourceObjectKind::Issue => ("issue", GITHUB_ISSUE_SOURCE_FIELDS),
        ExternalSourceObjectKind::PullRequest => ("pr", GITHUB_PR_SOURCE_FIELDS),
    };
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh exact source view",
        [
            subcommand,
            "view",
            &number.to_string(),
            "--repo",
            &repository.selector(),
            "--json",
            fields,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh exact source view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh exact source view did not return valid JSON")?;
    if serde_json::to_vec(&value)?.len() > MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES {
        bail!("gh exact source view exceeded its JSON byte limit");
    }
    Ok(value)
}

pub(crate) fn view_github_source_item(
    repo: &Path,
    repository_selector: &str,
    number: u64,
    kind: ExternalSourceObjectKind,
) -> Result<serde_json::Value> {
    let repository = github_repository_identity_from_selector(repository_selector)?;
    cli_github_source_view(repo, number, kind, &repository)
}

fn github_source_list_args(
    repository: &GithubRepositoryIdentity,
    kind: ExternalSourceObjectKind,
    max_items: usize,
    labels: &[String],
) -> Result<Vec<OsString>> {
    if !(1..=MAX_GITHUB_SOURCE_LIST_ITEMS).contains(&max_items)
        || labels.len() > MAX_GITHUB_SOURCE_LIST_LABELS
    {
        bail!("GitHub source list request exceeded its item or label bound");
    }
    let (subcommand, fields) = match kind {
        ExternalSourceObjectKind::Issue => ("issue", GITHUB_ISSUE_SOURCE_FIELDS),
        ExternalSourceObjectKind::PullRequest => ("pr", GITHUB_PR_SOURCE_FIELDS),
    };
    let selector = repository.selector();
    let limit = max_items.to_string();
    let mut args = [
        subcommand, "list", "--repo", &selector, "--state", "open", "--json", fields, "--limit",
        &limit,
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    for label in labels {
        validate_gh_argument_value(label, "GitHub source list label")?;
        if label.len() > MAX_GITHUB_SLUG_BYTES {
            bail!("GitHub source list label exceeded its bound");
        }
        args.push(OsString::from("--label"));
        args.push(OsString::from(label));
    }
    validate_gh_operation(&args, &StdinMode::Null, repository)?;
    Ok(args)
}

pub(crate) fn list_github_source_items(
    repo: &Path,
    repository_selector: &str,
    kind: ExternalSourceObjectKind,
    max_items: usize,
    labels: &[String],
) -> Result<serde_json::Value> {
    let repository = github_repository_identity_from_selector(repository_selector)?;
    let args = github_source_list_args(&repository, kind, max_items, labels)?;
    let context = GhCommandContext::create(repo, &repository)?;
    let output = context.run("gh exact source list", args, StdinMode::Null)?;
    let stdout = required_command_stdout(output, "gh exact source list")?;
    if stdout.len() > MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES {
        bail!("gh exact source list exceeded its JSON byte limit");
    }
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh exact source list did not return valid JSON")?;
    let values = value
        .as_array()
        .context("gh exact source list did not return a JSON array")?;
    if values.len() > max_items {
        bail!("gh exact source list returned more items than requested");
    }
    Ok(value)
}

fn cli_github_pr_list(
    worktree_path: &Path,
    branch: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubPrResult>> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh pr list",
        [
            "pr",
            "list",
            "--repo",
            &repository.selector(),
            "--head",
            branch,
            "--state",
            "all",
            "--limit",
            GITHUB_PR_EFFECT_LOOKUP_LIMIT,
            "--json",
            GITHUB_PR_RECEIPT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr list")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr list did not return valid JSON")?;
    github_pr_list_from_json(&value)
}

fn github_pr_list_from_json(value: &serde_json::Value) -> Result<Vec<GithubPrResult>> {
    let receipts = value
        .as_array()
        .context("gh pr list JSON was not an array")?;
    if receipts.len() > MAX_GITHUB_PR_LIST_RECEIPTS {
        bail!("gh pr list returned too many receipts");
    }
    receipts.iter().map(github_pr_receipt_from_json).collect()
}

fn cli_github_pr_view(
    worktree_path: &Path,
    selector: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubPrResult> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh pr view",
        [
            "pr",
            "view",
            selector,
            "--repo",
            &repository.selector(),
            "--json",
            GITHUB_PR_RECEIPT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr view did not return valid JSON")?;
    github_pr_receipt_from_json(&value)
}

fn github_pr_receipt_from_json(value: &serde_json::Value) -> Result<GithubPrResult> {
    let url = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted url")?;
    validate_github_receipt_url_text(url)?;
    let head_oid = value
        .get("headRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRefOid")?;
    let parsed_head =
        Oid::from_str(head_oid).context("GitHub PR receipt headRefOid was invalid")?;
    if parsed_head.to_string() != head_oid {
        bail!("GitHub PR receipt headRefOid was not canonical lowercase hexadecimal");
    }
    let head_oid = parsed_head.to_string();
    let base_oid = value
        .get("baseRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefOid")?;
    let parsed_base =
        Oid::from_str(base_oid).context("GitHub PR receipt baseRefOid was invalid")?;
    if parsed_base.to_string() != base_oid {
        bail!("GitHub PR receipt baseRefOid was not canonical lowercase hexadecimal");
    }
    let base_oid = parsed_base.to_string();
    let number = value
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .context("GitHub PR receipt omitted number")?;
    if number == 0 {
        bail!("GitHub PR receipt number was zero");
    }
    let base_ref_name = value
        .get("baseRefName")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefName")?;
    let state = value
        .get("state")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted state")?;
    for (label, text) in [("baseRefName", base_ref_name), ("state", state)] {
        if text.is_empty()
            || text.len() > MAX_GITHUB_RECEIPT_STRING_BYTES
            || text.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            bail!("GitHub PR receipt {label} was empty, malformed, or oversized");
        }
    }
    let is_draft = value
        .get("isDraft")
        .and_then(serde_json::Value::as_bool)
        .context("GitHub PR receipt omitted isDraft")?;
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted title")?;
    let body = value
        .get("body")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted body")?;
    let head_ref_name = value
        .get("headRefName")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRefName")?;
    for (label, text, limit) in [
        ("title", title, MAX_GITHUB_RECEIPT_STRING_BYTES),
        ("body", body, MAX_GITHUB_RECEIPT_BODY_BYTES),
        ("headRefName", head_ref_name, MAX_PUBLICATION_REF_BYTES),
    ] {
        if text.is_empty() || text.len() > limit || text.as_bytes().contains(&0) {
            bail!("GitHub PR receipt {label} was empty, malformed, or oversized");
        }
    }
    let head_repository = value
        .get("headRepository")
        .and_then(serde_json::Value::as_object)
        .context("GitHub PR receipt omitted headRepository")?;
    let head_repository_name = head_repository
        .get("name")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRepository.name")?;
    let head_repository_owner = value
        .get("headRepositoryOwner")
        .and_then(serde_json::Value::as_object)
        .and_then(|owner| owner.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRepositoryOwner.login")?;
    validate_github_slug(head_repository_owner, "receipt head owner")?;
    validate_github_slug(head_repository_name, "receipt head repository")?;
    if let Some(name_with_owner) = head_repository
        .get("nameWithOwner")
        .and_then(serde_json::Value::as_str)
    {
        let expected = format!("{head_repository_owner}/{head_repository_name}");
        if !name_with_owner.eq_ignore_ascii_case(&expected) {
            bail!("GitHub PR receipt headRepository.nameWithOwner was inconsistent");
        }
    }
    let is_cross_repository = value
        .get("isCrossRepository")
        .and_then(serde_json::Value::as_bool)
        .context("GitHub PR receipt omitted isCrossRepository")?;
    let author = value
        .get("author")
        .and_then(serde_json::Value::as_object)
        .and_then(|author| author.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted author.login")?;
    let author =
        canonical_github_author_login(author).context("GitHub PR receipt author was malformed")?;
    Ok(GithubPrResult {
        url: url.to_string(),
        head_oid,
        base_oid,
        number,
        base_ref_name: base_ref_name.to_string(),
        state: state.to_string(),
        is_draft,
        title: title.to_string(),
        body: body.to_string(),
        head_ref_name: head_ref_name.to_string(),
        head_repository_owner: head_repository_owner.to_ascii_lowercase(),
        head_repository_name: head_repository_name.to_ascii_lowercase(),
        is_cross_repository,
        author,
        created: false,
    })
}

fn cli_github_pr_create(
    worktree_path: &Path,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
    draft: bool,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubCreateOutput> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let mut args = [
        "pr",
        "create",
        "--repo",
        &repository.selector(),
        "--base",
        base,
        "--head",
        branch,
        "--title",
        title,
        "--body-file",
        "-",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if draft {
        args.push(OsString::from("--draft"));
    }
    let output = context.run_human_mutation(
        "gh pr create",
        args,
        StdinMode::Bytes(body.as_bytes().to_vec()),
    )?;
    Ok(GithubCreateOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubIssueEffectObserved {
    number: u64,
    url: String,
    title: String,
    body: String,
    labels: Vec<String>,
    author: String,
    state: String,
}

struct GithubIssueExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    repository: &'a GithubRepositoryIdentity,
    title: &'a str,
    marked_body: String,
    labels: &'a [String],
    expected_author: &'a str,
}

impl GithubIssueExternalEffectProvider<'_> {
    fn exact_candidates(
        &self,
        request: &ExternalEffectRequest,
    ) -> Result<Vec<GithubIssueEffectObserved>> {
        let candidates =
            cli_github_issue_effect_list(self.worktree_path, &request.marker, self.repository)?;
        let mut exact = Vec::new();
        for candidate in candidates {
            let viewed = cli_github_issue_effect_view(
                self.worktree_path,
                candidate.number,
                self.repository,
            )?;
            if self.matches_contract(&viewed)? {
                exact.push(viewed);
            }
        }
        exact.sort_by_key(|candidate| candidate.number);
        exact.dedup_by_key(|candidate| candidate.number);
        Ok(exact)
    }

    fn matches_contract(&self, observed: &GithubIssueEffectObserved) -> Result<bool> {
        validate_github_issue_receipt_url(&observed.url, self.repository, observed.number)?;
        Ok(observed.title == self.title
            && observed.body == self.marked_body
            && observed.labels == self.labels
            && observed.author == self.expected_author
            && observed.state == "OPEN")
    }

    fn receipt(
        &self,
        request: &ExternalEffectRequest,
        observed: &GithubIssueEffectObserved,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: observed.number.to_string(),
            url: observed.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GithubIssueExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        Ok(())
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_candidates(request)?
            .iter()
            .map(|observed| self.receipt(request, observed))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        let context = GhCommandContext::create(self.worktree_path, self.repository)?;
        let mut args = [
            "issue",
            "create",
            "--repo",
            &self.repository.selector(),
            "--title",
            self.title,
            "--body-file",
            "-",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        for label in self.labels {
            args.push(OsString::from("--label"));
            args.push(OsString::from(label));
        }
        context.run_human_mutation(
            "gh issue create",
            args,
            StdinMode::Bytes(self.marked_body.as_bytes().to_vec()),
        )?;
        let matches = self.exact_candidates(request)?;
        if matches.len() != 1 {
            bail!("GitHub issue creation response could not be reconciled exactly");
        }
        Ok(self.receipt(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let number = receipt
            .provider_id
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .context("GitHub issue effect receipt number was malformed")?;
        let viewed = cli_github_issue_effect_view(self.worktree_path, number, self.repository)?;
        if !self.matches_contract(&viewed)? || viewed.url != receipt.url {
            bail!("GitHub issue effect receipt changed from its exact remote object");
        }
        Ok(self.receipt(request, &viewed))
    }
}

fn cli_github_issue_effect_list(
    worktree_path: &Path,
    marker: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubIssueEffectObserved>> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh issue effect list",
        [
            "issue",
            "list",
            "--repo",
            &repository.selector(),
            "--state",
            "all",
            "--search",
            marker,
            "--limit",
            GITHUB_ISSUE_EFFECT_LOOKUP_LIMIT,
            "--json",
            GITHUB_ISSUE_EFFECT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh issue effect list")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh issue effect list did not return valid JSON")?;
    github_issue_effect_list_from_json(&value)
}

fn github_issue_effect_list_from_json(
    value: &serde_json::Value,
) -> Result<Vec<GithubIssueEffectObserved>> {
    let values = value
        .as_array()
        .context("gh issue effect list JSON was not an array")?;
    if values.len() > MAX_GITHUB_EFFECT_CANDIDATES {
        bail!("gh issue effect list returned too many candidates");
    }
    values.iter().map(github_issue_effect_from_json).collect()
}

fn cli_github_issue_effect_view(
    worktree_path: &Path,
    number: u64,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubIssueEffectObserved> {
    if number == 0 {
        bail!("GitHub issue effect number must be positive");
    }
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh issue effect view",
        [
            "issue",
            "view",
            &number.to_string(),
            "--repo",
            &repository.selector(),
            "--json",
            GITHUB_ISSUE_EFFECT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh issue effect view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh issue effect view did not return valid JSON")?;
    github_issue_effect_from_json(&value)
}

fn github_issue_effect_from_json(value: &serde_json::Value) -> Result<GithubIssueEffectObserved> {
    let object = value
        .as_object()
        .context("GitHub issue effect receipt was not an object")?;
    let number = object
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .filter(|number| *number > 0)
        .context("GitHub issue effect receipt omitted a positive number")?;
    let text = |field: &str, limit: usize| -> Result<String> {
        let value = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("GitHub issue effect receipt omitted {field}"))?;
        if value.len() > limit || value.as_bytes().contains(&0) {
            bail!("GitHub issue effect receipt {field} was malformed or oversized");
        }
        Ok(value.to_string())
    };
    let url = text("url", MAX_GITHUB_RECEIPT_URL_BYTES)?;
    let title = text("title", MAX_GITHUB_RECEIPT_STRING_BYTES)?;
    let body = text("body", MAX_GITHUB_RECEIPT_BODY_BYTES)?;
    let state = text("state", MAX_GITHUB_RECEIPT_STRING_BYTES)?;
    let author = object
        .get("author")
        .and_then(serde_json::Value::as_object)
        .and_then(|author| author.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub issue effect receipt omitted author.login")?;
    let author = canonical_github_author_login(author)?;
    let label_values = object
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .context("GitHub issue effect receipt omitted labels")?;
    if label_values.len() > MAX_EXTERNAL_SOURCE_LABELS {
        bail!("GitHub issue effect receipt returned too many labels");
    }
    let mut labels = label_values
        .iter()
        .map(|label| {
            let name = label
                .as_object()
                .and_then(|label| label.get("name"))
                .and_then(serde_json::Value::as_str)
                .context("GitHub issue effect label omitted name")?;
            validate_gh_argument_value(name, "GitHub issue effect label")?;
            Ok(name.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    labels.sort();
    labels.dedup();
    Ok(GithubIssueEffectObserved {
        number,
        url,
        title,
        body,
        labels,
        author,
        state,
    })
}

fn external_effect_marked_body(body: &str, marker: &str) -> Result<String> {
    validate_external_effect_marker_argument(marker)?;
    if body.contains(EXTERNAL_EFFECT_MARKER_PREFIX) {
        bail!("external effect body already contains a reserved maco marker");
    }
    let marked = if body.is_empty() {
        marker.to_string()
    } else {
        format!("{body}\n\n{marker}")
    };
    if marked.len() > GH_STDIN_LIMIT_BYTES || marked.as_bytes().contains(&0) {
        bail!("external effect body was malformed or oversized");
    }
    Ok(marked)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubCommentEffectObserved {
    id: u64,
    url: String,
    body: String,
    author: String,
}

struct GithubCommentExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    repository: &'a GithubRepositoryIdentity,
    source: &'a ExternalSourceGuard,
    marked_body: String,
    expected_author: &'a str,
}

impl GithubCommentExternalEffectProvider<'_> {
    fn revalidate_full(&self) -> Result<()> {
        revalidate_external_source(self.worktree_path, self.source)
    }

    fn revalidate_action_revision(&self) -> Result<()> {
        revalidate_external_source_action_revision(self.worktree_path, self.source)
    }

    fn exact_candidates(
        &self,
        request: &ExternalEffectRequest,
    ) -> Result<Vec<GithubCommentEffectObserved>> {
        self.revalidate_action_revision()?;
        let candidates =
            cli_github_comment_candidates(self.worktree_path, self.source, self.repository)?;
        let mut exact = Vec::new();
        for candidate in candidates
            .into_iter()
            .filter(|candidate| candidate.body.contains(&request.marker))
        {
            let viewed =
                cli_github_comment_exact_view(self.worktree_path, candidate.id, self.repository)?;
            validate_github_comment_contract(
                &viewed,
                self.repository,
                self.source,
                &self.marked_body,
                self.expected_author,
            )?;
            exact.push(viewed);
        }
        exact.sort_by_key(|comment| comment.id);
        exact.dedup_by_key(|comment| comment.id);
        Ok(exact)
    }

    fn receipt(
        &self,
        request: &ExternalEffectRequest,
        comment: &GithubCommentEffectObserved,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: comment.id.to_string(),
            url: comment.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GithubCommentExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_full()
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_candidates(request)?
            .iter()
            .map(|comment| self.receipt(request, comment))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_full()?;
        let subcommand = match self.source.object_kind {
            ExternalSourceObjectKind::Issue => "issue",
            ExternalSourceObjectKind::PullRequest => "pr",
        };
        let context = GhCommandContext::create(self.worktree_path, self.repository)?;
        context.run_human_mutation(
            "gh source comment",
            [
                subcommand,
                "comment",
                &self.source.number.to_string(),
                "--repo",
                &self.repository.selector(),
                "--body-file",
                "-",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            StdinMode::Bytes(self.marked_body.as_bytes().to_vec()),
        )?;
        let matches = self.exact_candidates(request)?;
        if matches.len() != 1 {
            bail!("GitHub comment creation response could not be reconciled exactly");
        }
        Ok(self.receipt(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        self.revalidate_action_revision()?;
        let id = receipt
            .provider_id
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .context("GitHub comment effect receipt id was malformed")?;
        let viewed = cli_github_comment_exact_view(self.worktree_path, id, self.repository)?;
        validate_github_comment_contract(
            &viewed,
            self.repository,
            self.source,
            &self.marked_body,
            self.expected_author,
        )?;
        if viewed.url != receipt.url {
            bail!("GitHub comment receipt URL changed from its exact remote object");
        }
        Ok(self.receipt(request, &viewed))
    }
}

pub(crate) fn publish_github_source_comment(
    repo: &Path,
    source: ExternalSourceGuard,
    body: &str,
) -> Result<String> {
    source.validate()?;
    let repository = crate::git_repository::discover(repo)
        .context("failed to discover GitHub comment source repository")?;
    let remote_url = remote_url(&repository, "origin")
        .context("GitHub comment publication requires an origin remote")?;
    let github_repository = github_repository_identity(&remote_url)?;
    refuse_legacy_publication_journals(&repository)?;
    let auth = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind authenticated GitHub comment effect ledger")?;
    let repository_identity = auth.binding().repository_id.clone();
    drop(auth);
    let expected_author = select_github_expected_author_with(|key| env::var(key).ok())?;
    let operation = match source.object_kind {
        ExternalSourceObjectKind::Issue => ExternalEffectOperation::GithubIssueComment,
        ExternalSourceObjectKind::PullRequest => ExternalEffectOperation::GithubPullRequestComment,
    };
    let request = ExternalEffectRequest::new(
        "github",
        &github_repository.selector(),
        &repository_identity,
        Some(source.clone()),
        operation,
        serde_json::json!({
            "version": 1,
            "repository": github_repository.selector(),
            "source_kind": source.object_kind,
            "source_number": source.number,
        }),
        serde_json::json!({
            "version": 1,
            "body": body,
            "expected_author": expected_author,
        }),
    )?;
    let marked_body = external_effect_marked_body(body, &request.marker)?;
    let mut provider = GithubCommentExternalEffectProvider {
        worktree_path: repo,
        repository: &github_repository,
        source: &source,
        marked_body,
        expected_author: &expected_author,
    };
    let receipt = execute_external_effect_exactly_once(repo, request, &mut provider)?;
    Ok(receipt.url)
}

fn cli_github_comment_candidates(
    worktree_path: &Path,
    source: &ExternalSourceGuard,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubCommentEffectObserved>> {
    let endpoint = format!(
        "repos/{}/{}/issues/{}/comments?per_page=100",
        repository.owner, repository.name, source.number
    );
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh source comment candidates",
        ["api", "--method", "GET", "--paginate", "--slurp", &endpoint]
            .into_iter()
            .map(OsString::from)
            .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh source comment candidates")?;
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .context("gh source comment candidates did not return valid JSON")?;
    github_comment_candidates_from_slurped_json(&value, repository, source)
}

fn github_comment_candidates_from_slurped_json(
    value: &serde_json::Value,
    repository: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
) -> Result<Vec<GithubCommentEffectObserved>> {
    let pages = value
        .as_array()
        .context("GitHub paginated comment result was not an array of pages")?;
    if pages.len() > MAX_GITHUB_COMMENT_PAGES {
        bail!("GitHub comment lookup exceeded its page limit");
    }
    let mut comments = Vec::new();
    for page in pages {
        let page = page
            .as_array()
            .context("GitHub paginated comment page was not an array")?;
        if page.len() > 100 {
            bail!("GitHub comment lookup page exceeded its fixed page size");
        }
        if comments.len().saturating_add(page.len()) > MAX_GITHUB_COMMENT_CANDIDATES {
            bail!("GitHub comment lookup exceeded its total candidate limit");
        }
        for value in page {
            let comment = github_comment_from_rest_json(value)?;
            if github_comment_id_from_url(&comment.url, repository, source)? != comment.id {
                bail!("GitHub comment REST id did not match its canonical HTML URL fragment");
            }
            comments.push(comment);
        }
    }
    Ok(comments)
}

fn github_comment_from_rest_json(value: &serde_json::Value) -> Result<GithubCommentEffectObserved> {
    let object = value
        .as_object()
        .context("GitHub comment candidate was not an object")?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .filter(|id| *id > 0)
        .context("GitHub comment candidate omitted id")?;
    let url = object
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted html_url")?;
    let body = object
        .get("body")
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted body")?;
    if body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES || body.as_bytes().contains(&0) {
        bail!("GitHub comment candidate body was malformed or oversized");
    }
    let author = object
        .get("user")
        .and_then(serde_json::Value::as_object)
        .and_then(|user| user.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted user.login")?;
    Ok(GithubCommentEffectObserved {
        id,
        url: url.to_string(),
        body: body.to_string(),
        author: canonical_github_author_login(author)?,
    })
}

fn cli_github_comment_exact_view(
    worktree_path: &Path,
    id: u64,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubCommentEffectObserved> {
    if id == 0 {
        bail!("GitHub comment exact view id must be positive");
    }
    let endpoint = format!(
        "repos/{}/{}/issues/comments/{id}",
        repository.owner, repository.name
    );
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh comment exact view",
        ["api", "--method", "GET", &endpoint]
            .into_iter()
            .map(OsString::from)
            .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh comment exact view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh comment exact view did not return valid JSON")?;
    let observed = github_comment_from_rest_json(&value)?;
    if observed.id != id {
        bail!("gh comment exact view returned a different id");
    }
    Ok(observed)
}

fn validate_github_comment_contract(
    observed: &GithubCommentEffectObserved,
    repository: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
    marked_body: &str,
    expected_author: &str,
) -> Result<()> {
    if github_comment_id_from_url(&observed.url, repository, source)? != observed.id
        || observed.body != marked_body
        || observed.author != expected_author
    {
        bail!("GitHub comment did not match its exact repository, source, body, marker, and author contract");
    }
    Ok(())
}

fn github_comment_id_from_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
) -> Result<u64> {
    if url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '%', '\\', '@'])
    {
        bail!("GitHub comment URL was malformed or oversized");
    }
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub comment URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub comment URL was not HTTPS");
    }
    let (path, fragment) = remainder
        .split_once('#')
        .context("GitHub comment URL omitted its exact comment fragment")?;
    let slash = path
        .find('/')
        .context("GitHub comment URL omitted repository path")?;
    let authority = &path[..slash];
    if normalize_github_host(authority)? != authority || authority != expected.host {
        bail!("GitHub comment URL host did not match the repository");
    }
    let components = path[slash + 1..].split('/').collect::<Vec<_>>();
    let expected_kind = match source.object_kind {
        ExternalSourceObjectKind::Issue => "issues",
        ExternalSourceObjectKind::PullRequest => "pull",
    };
    if components.len() != 4
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
        || components[2] != expected_kind
        || components[3] != source.number.to_string()
    {
        bail!("GitHub comment URL did not match its exact repository and source object");
    }
    let id = fragment
        .strip_prefix("issuecomment-")
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .context("GitHub comment URL fragment did not contain a canonical comment id")?;
    if fragment != format!("issuecomment-{id}") {
        bail!("GitHub comment URL comment id was not canonical");
    }
    Ok(id)
}

fn create_github_issue(repo: &Path, title: &str, body: &str, labels: &[String]) -> Result<String> {
    let repository = crate::git_repository::discover(repo).with_context(|| {
        format!(
            "failed to discover issue repository from {}",
            repo.display()
        )
    })?;
    let remote_url = remote_url(&repository, "origin")
        .context("GitHub issue creation requires an 'origin' remote")?;
    let github_repository = github_repository_identity(&remote_url)?;
    refuse_legacy_publication_journals(&repository)?;
    let auth = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind authenticated GitHub issue effect ledger")?;
    let repository_identity = auth.binding().repository_id.clone();
    drop(auth);
    let expected_author = select_github_expected_author_with(|key| env::var(key).ok())?;
    let request = ExternalEffectRequest::new(
        "github",
        &github_repository.selector(),
        &repository_identity,
        None,
        ExternalEffectOperation::GithubIssue,
        serde_json::json!({
            "version": 1,
            "repository": github_repository.selector(),
            "title": title,
            "labels": labels,
            "expected_author": expected_author,
        }),
        serde_json::json!({
            "version": 1,
            "body": body,
        }),
    )?;
    let marked_body = external_effect_marked_body(body, &request.marker)?;
    let mut provider = GithubIssueExternalEffectProvider {
        worktree_path: repo,
        repository: &github_repository,
        title,
        marked_body,
        labels,
        expected_author: &expected_author,
    };
    let receipt = execute_external_effect_exactly_once(repo, request, &mut provider)?;
    let number = receipt
        .provider_id
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .context("GitHub issue receipt provider id was malformed")?;
    validate_github_issue_receipt_url(&receipt.url, &github_repository, number)
}

fn required_command_stdout(output: merge::RequiredCommandOutput, label: &str) -> Result<String> {
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("{label} failed: {}", stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_non_empty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn redacted_body(body: &str) -> (String, RedactionSummary) {
    let redacted = Redactor::new().redact(body);
    (redacted.text, redacted.summary)
}

fn normalize_title(title: &str) -> Result<String> {
    let title = title.trim();
    if title.is_empty() {
        bail!("issue title cannot be empty");
    }
    Ok(title.to_string())
}

fn normalized_labels(labels: Vec<String>) -> Vec<String> {
    labels
        .into_iter()
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fake_pr_url(agent_id: &str, branch: &str, changed_paths: &[PathBuf]) -> String {
    #[cfg(all(test, target_os = "linux"))]
    FAKE_PR_URL_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let mut input = Vec::new();
    input.extend_from_slice(agent_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(branch.as_bytes());
    for path in changed_paths {
        input.push(b'\n');
        input.extend_from_slice(&merge::raw_path_bytes(path));
    }
    format!(
        "fake://pr/{}-{:016x}",
        sanitize_url_segment(agent_id),
        stable_hash(&input)
    )
}

fn fake_issue_url(title: &str, body: &str, labels: &[String]) -> String {
    let mut input = String::new();
    input.push_str(title);
    input.push('\n');
    input.push_str(body);
    for label in labels {
        input.push('\n');
        input.push_str(label);
    }
    format!(
        "fake://issue/{}-{:016x}",
        sanitize_url_segment(title),
        stable_hash(input.as_bytes())
    )
}

fn sanitize_url_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if segment.is_empty() {
        "item".to_string()
    } else {
        segment
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| merge::path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

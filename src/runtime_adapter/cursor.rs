//! Runtime-advertised Cursor model catalog discovery.
//!
//! Catalog membership comes only from one bounded `cursor-agent models`
//! observation. Policy code may classify the returned slugs, but this adapter
//! does not embed a live model list or infer authority from a model name.

use super::AdapterId;
use crate::{
    artifacts::state_auth::sha256_hex,
    process_runner::{
        ProcessTreeEvidence, SideEffectConfinementEvidence, SideEffectConfinementProfileKind,
    },
};
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
    str,
    time::Duration,
};

const CURSOR_CATALOG_MAX_BYTES: usize = 256 * 1024;
const CURSOR_CATALOG_MAX_MODELS: usize = 512;
const CURSOR_MODEL_SLUG_MAX_BYTES: usize = 256;
const CURSOR_MODEL_DISPLAY_NAME_MAX_BYTES: usize = 768;
const CURSOR_CATALOG_TIP_MAX_BYTES: usize = 4 * 1024;
const CURSOR_CATALOG_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact bounded command request for Cursor's account-visible catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorCatalogCommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: PathBuf,
    environment: BTreeMap<String, String>,
    capture_limit_bytes: usize,
    timeout: Duration,
}

impl CursorCatalogCommandSpec {
    /// Construct the stable catalog request `cursor-agent models`.
    pub fn new(current_dir: impl Into<PathBuf>) -> Self {
        Self {
            program: PathBuf::from("cursor-agent"),
            args: vec![OsString::from("models")],
            current_dir: current_dir.into(),
            environment: BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ]),
            capture_limit_bytes: CURSOR_CATALOG_MAX_BYTES,
            timeout: CURSOR_CATALOG_TIMEOUT,
        }
    }

    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    /// Add host values named by the operator's `MACO_CURSOR_ENV` list.
    ///
    /// This uses the same two screens as the live runtime adapter: denied
    /// names are dropped from the operator list, then every retained name is
    /// checked again before its value is collected. Names that are absent from
    /// the host or have non-Unicode values are omitted.
    pub fn with_screened_env_passthrough(mut self, raw_names: &str) -> Result<Self> {
        let names = super::env_passthrough_names_from_operator_list(raw_names);
        self.environment
            .extend(super::collect_screened_passthrough_env(&names)?);
        Ok(self)
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn current_dir(&self) -> &Path {
        &self.current_dir
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub const fn capture_limit_bytes(&self) -> usize {
        self.capture_limit_bytes
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Bounded command evidence returned by a production or hermetic runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorCatalogCommandOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub process_tree: ProcessTreeEvidence,
    pub side_effects: SideEffectConfinementEvidence,
}

/// Injectable command boundary.
///
/// This module intentionally supplies no process implementation. A future
/// screened runtime layer must resolve and bind the executable, screen the
/// environment, apply an honest side-effect profile, capture bounded output,
/// and return verified process evidence. Unit tests inject hermetic evidence
/// without resolving or starting `cursor-agent`.
pub trait CursorCatalogCommandRunner {
    fn run(&self, spec: &CursorCatalogCommandSpec) -> Result<CursorCatalogCommandOutput>;
}

/// One runtime-advertised model and its human-facing label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorModelCatalogEntry {
    slug: String,
    display_name: String,
}

impl CursorModelCatalogEntry {
    pub fn slug(&self) -> &str {
        &self.slug
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Immutable snapshot of one successful Cursor catalog observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorModelCatalog {
    models: Vec<CursorModelCatalogEntry>,
}

impl CursorModelCatalog {
    pub fn models(&self) -> &[CursorModelCatalogEntry] {
        &self.models
    }

    pub fn slugs(&self) -> impl Iterator<Item = &str> {
        self.models.iter().map(CursorModelCatalogEntry::slug)
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.models.iter().any(|model| model.slug == slug)
    }
}

/// One content-bound runtime-advertised catalog observation.
///
/// Runtime identity is fixed to this adapter's typed identity. Observation
/// time is supplied by the screened caller. Neither field confers capability
/// or authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorAdvertisedCatalogObservation {
    catalog: CursorModelCatalog,
    runtime: AdapterId,
    observed_at_unix_millis: u64,
    source_sha256: String,
}

impl CursorAdvertisedCatalogObservation {
    pub fn catalog(&self) -> &CursorModelCatalog {
        &self.catalog
    }

    pub const fn runtime(&self) -> AdapterId {
        self.runtime
    }

    pub const fn observed_at_unix_millis(&self) -> u64 {
        self.observed_at_unix_millis
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

/// Run the supplied command seam and accept only complete successful evidence.
pub fn discover_cursor_model_catalog(
    runner: &dyn CursorCatalogCommandRunner,
    spec: &CursorCatalogCommandSpec,
    observed_at_unix_millis: Option<u64>,
) -> Result<CursorAdvertisedCatalogObservation> {
    let observed_at_unix_millis = observed_at_unix_millis
        .filter(|observed_at| *observed_at != 0)
        .context("Cursor runtime model catalog observation time is missing or zero")?;
    let output = runner.run(spec)?;
    if output.timed_out {
        bail!("Cursor runtime model catalog command timed out");
    }
    if output.stdout_truncated || output.stderr_truncated {
        bail!(
            "Cursor runtime model catalog command output exceeded the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.stdout.len() > spec.capture_limit_bytes()
        || output.stderr.len() > spec.capture_limit_bytes()
    {
        bail!(
            "Cursor runtime model catalog command returned output larger than the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.status != Some(0) {
        bail!(
            "Cursor runtime model catalog command failed with exit status {:?}",
            output.status
        );
    }
    if !output.process_tree.is_verified_empty() {
        bail!("Cursor runtime model catalog process ownership was not verified empty");
    }
    if !matches!(
        output.side_effects,
        SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace
                | SideEffectConfinementProfileKind::TrustedFixedNetwork
        )
    ) {
        bail!(
            "Cursor runtime model catalog side-effect confinement was not verified with a Cursor-compatible profile"
        );
    }
    if !output.stderr.is_empty() {
        bail!("Cursor runtime model catalog command emitted unexpected stderr");
    }
    let catalog = parse_cursor_model_catalog(&output.stdout)?;
    Ok(CursorAdvertisedCatalogObservation {
        catalog,
        runtime: AdapterId::Cursor,
        observed_at_unix_millis,
        source_sha256: sha256_hex(&output.stdout),
    })
}

/// Parse the strict plain-text grammar emitted by `cursor-agent models`.
pub fn parse_cursor_model_catalog(bytes: &[u8]) -> Result<CursorModelCatalog> {
    if bytes.is_empty() {
        bail!("Cursor runtime model catalog output was empty");
    }
    if bytes.len() > CURSOR_CATALOG_MAX_BYTES {
        bail!(
            "Cursor runtime model catalog output exceeds the {} byte limit",
            CURSOR_CATALOG_MAX_BYTES
        );
    }
    let text = str::from_utf8(bytes).context("Cursor runtime model catalog is not valid UTF-8")?;
    if !text.ends_with('\n') {
        bail!("Cursor runtime model catalog lacks its terminal newline and may be truncated");
    }
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        bail!("Cursor runtime model catalog contains a bare carriage return");
    }
    let lines = normalized
        .strip_suffix('\n')
        .unwrap_or(&normalized)
        .split('\n')
        .collect::<Vec<_>>();
    if lines.first().copied() != Some("Available models") || lines.get(1).copied() != Some("") {
        bail!("Cursor runtime model catalog has an invalid header");
    }

    let footer_separator = lines
        .iter()
        .enumerate()
        .skip(2)
        .find_map(|(index, line)| line.is_empty().then_some(index))
        .context("Cursor runtime model catalog is missing its footer separator")?;
    let model_lines = &lines[2..footer_separator];
    if model_lines.is_empty() {
        bail!("Cursor runtime model catalog contains no models");
    }
    if model_lines.len() > CURSOR_CATALOG_MAX_MODELS {
        bail!(
            "Cursor runtime model catalog contains {} models, exceeding the {} model limit",
            model_lines.len(),
            CURSOR_CATALOG_MAX_MODELS
        );
    }
    if lines.len() != footer_separator.saturating_add(2) {
        bail!("Cursor runtime model catalog has an invalid footer shape");
    }
    let tip = lines
        .get(footer_separator.saturating_add(1))
        .copied()
        .context("Cursor runtime model catalog is missing its tip footer")?;
    let tip_body = tip
        .strip_prefix("Tip: ")
        .context("Cursor runtime model catalog has an invalid tip footer")?;
    if tip_body.is_empty()
        || tip.len() > CURSOR_CATALOG_TIP_MAX_BYTES
        || tip_body.trim() != tip_body
        || tip_body.chars().any(char::is_control)
    {
        bail!("Cursor runtime model catalog has an invalid tip footer");
    }

    let mut seen = BTreeSet::new();
    let mut models = Vec::with_capacity(model_lines.len());
    for (index, line) in model_lines.iter().enumerate() {
        let (slug, display_name) = line
            .split_once(" - ")
            .with_context(|| format!("Cursor runtime model catalog entry {index} is malformed"))?;
        validate_cursor_model_slug(slug)
            .with_context(|| format!("Cursor runtime model catalog entry {index}"))?;
        validate_cursor_model_display_name(display_name)
            .with_context(|| format!("Cursor runtime model catalog entry {index}"))?;
        if !seen.insert(slug) {
            bail!("Cursor runtime model catalog contains duplicate slug '{slug}'");
        }
        models.push(CursorModelCatalogEntry {
            slug: slug.to_string(),
            display_name: display_name.to_string(),
        });
    }
    Ok(CursorModelCatalog { models })
}

fn validate_cursor_model_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("contains an empty model slug");
    }
    if slug.len() > CURSOR_MODEL_SLUG_MAX_BYTES {
        bail!(
            "model slug exceeds the {} byte limit",
            CURSOR_MODEL_SLUG_MAX_BYTES
        );
    }
    let mut bytes = slug.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        bail!(
            "model slug must start with an ASCII alphanumeric character and contain only ASCII alphanumerics or - _ . / :"
        );
    }
    Ok(())
}

fn validate_cursor_model_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty()
        || display_name.len() > CURSOR_MODEL_DISPLAY_NAME_MAX_BYTES
        || display_name.trim() != display_name
        || display_name.chars().any(char::is_control)
    {
        bail!("contains an invalid model display name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_runner::ContainmentBackend;
    use std::{cell::RefCell, env};

    const CAPTURED_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.txt"
    ));
    const HAND_AUTHORED_DUPLICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-duplicate.txt"
    ));
    const HAND_AUTHORED_MALFORMED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-malformed.txt"
    ));
    const HAND_AUTHORED_TRUNCATED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-truncated.txt"
    ));
    const HAND_AUTHORED_ADDED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-added.txt"
    ));
    const HAND_AUTHORED_WITHDRAWN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-withdrawn.txt"
    ));
    const CAPTURED_PROVENANCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.provenance.json"
    ));
    const CAPTURED_AT_UNIX_MILLIS: u64 = 1_787_240_463_000;

    #[derive(Debug)]
    struct FakeRunner {
        output: CursorCatalogCommandOutput,
        observed_specs: RefCell<Vec<CursorCatalogCommandSpec>>,
    }

    impl FakeRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: CursorCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: ProcessTreeEvidence::VerifiedEmpty(
                        ContainmentBackend::DirectChild,
                    ),
                    side_effects: SideEffectConfinementEvidence::Verified(
                        SideEffectConfinementProfileKind::TrustedFixedNetwork,
                    ),
                },
                observed_specs: RefCell::new(Vec::new()),
            }
        }
    }

    impl CursorCatalogCommandRunner for FakeRunner {
        fn run(&self, spec: &CursorCatalogCommandSpec) -> Result<CursorCatalogCommandOutput> {
            self.observed_specs.borrow_mut().push(spec.clone());
            Ok(self.output.clone())
        }
    }

    #[test]
    fn command_spec_is_exact_and_discovery_uses_only_the_injected_runner() -> Result<()> {
        let spec = CursorCatalogCommandSpec::new("/workspace");
        assert_eq!(spec.program(), Path::new("cursor-agent"));
        assert_eq!(spec.args(), [OsString::from("models")]);
        assert_eq!(
            spec.environment(),
            &BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ])
        );
        assert_eq!(spec.current_dir(), Path::new("/workspace"));
        assert_eq!(spec.capture_limit_bytes(), CURSOR_CATALOG_MAX_BYTES);
        assert_eq!(spec.timeout(), CURSOR_CATALOG_TIMEOUT);

        let runner = FakeRunner::successful(CAPTURED_CATALOG);
        let observation =
            discover_cursor_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))?;
        assert_eq!(runner.observed_specs.into_inner(), [spec]);
        let catalog = observation.catalog();
        assert_eq!(catalog.models().len(), 9);
        assert!(catalog.contains("composer-2.5"));
        assert!(catalog.contains("composer-2.5-fast"));
        assert_eq!(observation.runtime(), AdapterId::Cursor);
        assert_eq!(
            observation.observed_at_unix_millis(),
            CAPTURED_AT_UNIX_MILLIS
        );
        assert_eq!(
            observation.source_sha256(),
            "af088f298dd5b96cd0703887635cab1ea198047f5558f5ff128d02195ece83c1"
        );
        Ok(())
    }

    #[test]
    fn command_spec_adds_only_present_screened_operator_passthrough() -> Result<()> {
        let expected_path =
            env::var("PATH").context("cargo test PATH is missing or non-Unicode")?;
        let spec = CursorCatalogCommandSpec::new("/workspace").with_screened_env_passthrough(
            " PATH,MACO_DEFINITELY_MISSING_CURSOR_CATALOG_ENV, PATH ",
        )?;

        assert_eq!(spec.environment().get("PATH"), Some(&expected_path));
        assert!(!spec
            .environment()
            .contains_key("MACO_DEFINITELY_MISSING_CURSOR_CATALOG_ENV"));
        assert_eq!(spec.environment().len(), 3);
        Ok(())
    }

    #[test]
    fn command_spec_drops_denied_operator_passthrough_names() -> Result<()> {
        let expected_path =
            env::var("PATH").context("cargo test PATH is missing or non-Unicode")?;
        let spec = CursorCatalogCommandSpec::new("/workspace")
            .with_screened_env_passthrough("PATH,BASH_ENV,LD_PRELOAD,OPENAI_API_KEY,BAD=NAME")?;

        assert_eq!(spec.environment().get("PATH"), Some(&expected_path));
        for denied in ["BASH_ENV", "LD_PRELOAD", "OPENAI_API_KEY", "BAD=NAME"] {
            assert!(!spec.environment().contains_key(denied), "{denied}");
        }
        assert_eq!(spec.environment().len(), 3);
        Ok(())
    }

    #[test]
    fn command_spec_reuses_the_runtime_adapter_operator_env_contract() -> Result<()> {
        let raw_names = concat!(
            " PATH,PATH,",
            "BASH_ENV,",
            "LD_PRELOAD,",
            "MALLOC_CONF,",
            "PYTHONPATH,",
            "OPENAI_API_KEY,",
            "BAD=NAME,",
            "MACO_DEFINITELY_MISSING_CURSOR_CATALOG_ENV "
        );
        let screened_names = super::super::env_passthrough_names_from_operator_list(raw_names);
        let mut expected_environment = BTreeMap::from([
            ("NO_COLOR".to_string(), "1".to_string()),
            ("TERM".to_string(), "dumb".to_string()),
        ]);
        expected_environment.extend(super::super::collect_screened_passthrough_env(
            &screened_names,
        )?);

        let spec =
            CursorCatalogCommandSpec::new("/workspace").with_screened_env_passthrough(raw_names)?;

        assert_eq!(
            screened_names,
            vec![
                "PATH".to_string(),
                "PATH".to_string(),
                "MACO_DEFINITELY_MISSING_CURSOR_CATALOG_ENV".to_string(),
            ]
        );
        assert_eq!(spec.environment(), &expected_environment);
        Ok(())
    }

    #[test]
    fn captured_catalog_preserves_runtime_order_and_display_names() -> Result<()> {
        let catalog = parse_cursor_model_catalog(CAPTURED_CATALOG)?;
        assert_eq!(
            catalog.models().first().map(CursorModelCatalogEntry::slug),
            Some("auto")
        );
        assert_eq!(
            catalog
                .models()
                .last()
                .map(CursorModelCatalogEntry::display_name),
            Some("Claude Opus 5 1M Low")
        );
        Ok(())
    }

    #[test]
    fn captured_fixture_provenance_is_adjacent_exact_and_content_bound() -> Result<()> {
        let provenance: serde_json::Value = serde_json::from_str(CAPTURED_PROVENANCE)?;
        assert_eq!(provenance["schema_version"], 1);
        assert_eq!(provenance["fixture"], "captured-minimal-20260820.txt");
        assert_eq!(provenance["classification"], "capture-derived-minimal");
        assert_eq!(provenance["captured_at_utc"], "2026-08-20T15:41:03Z");
        assert_eq!(provenance["cli"], "cursor-agent");
        assert_eq!(provenance["cli_version"], "2026.06.26-7079533");
        assert_eq!(
            provenance["argv"],
            serde_json::json!(["cursor-agent", "models"])
        );
        assert_eq!(provenance["environment"]["NO_COLOR"], "1");
        assert_eq!(provenance["environment"]["TERM"], "dumb");
        assert_eq!(provenance["exit_status"], 0);
        assert_eq!(provenance["redactions"], "none");
        assert_eq!(provenance["fixture_sha256"], sha256_hex(CAPTURED_CATALOG));
        assert_eq!(
            provenance["scope_note"],
            "This capture-derived minimal fixture is not a full unabridged archive."
        );
        Ok(())
    }

    #[test]
    fn catalog_addition_and_withdrawal_require_no_parser_change() -> Result<()> {
        let added = parse_cursor_model_catalog(HAND_AUTHORED_ADDED)?;
        let withdrawn = parse_cursor_model_catalog(HAND_AUTHORED_WITHDRAWN)?;
        assert!(added.contains("worker-new"));
        assert!(!withdrawn.contains("worker-new"));
        assert_eq!(withdrawn.slugs().collect::<Vec<_>>(), ["worker-stable"]);
        Ok(())
    }

    #[test]
    fn malformed_duplicate_empty_and_structurally_truncated_catalogs_fail_closed() {
        for (label, bytes, expected) in [
            ("malformed", HAND_AUTHORED_MALFORMED, "malformed"),
            ("duplicate", HAND_AUTHORED_DUPLICATE, "duplicate slug"),
            ("empty", b"".as_slice(), "output was empty"),
            (
                "truncated",
                HAND_AUTHORED_TRUNCATED,
                "missing its footer separator",
            ),
        ] {
            let error = parse_cursor_model_catalog(bytes)
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn parser_limits_and_structural_edges_fail_closed_table() {
        fn fixture(model_lines: &[String], tip: &str) -> Vec<u8> {
            format!(
                "Available models\n\n{}\n\nTip: {tip}\n",
                model_lines.join("\n")
            )
            .into_bytes()
        }

        let too_many_models = (0..=CURSOR_CATALOG_MAX_MODELS)
            .map(|index| format!("worker-{index} - Worker {index}"))
            .collect::<Vec<_>>();
        let cases = vec![
            (
                "over catalog byte limit",
                vec![b'x'; CURSOR_CATALOG_MAX_BYTES.saturating_add(1)],
                "exceeds the 262144 byte limit",
            ),
            (
                "over model count limit",
                fixture(&too_many_models, "hand-authored test case"),
                "513 models",
            ),
            (
                "overlong slug",
                fixture(
                    &[format!(
                        "{} - Worker",
                        "a".repeat(CURSOR_MODEL_SLUG_MAX_BYTES.saturating_add(1))
                    )],
                    "hand-authored test case",
                ),
                "model slug exceeds",
            ),
            (
                "overlong display name",
                fixture(
                    &[format!(
                        "worker - {}",
                        "D".repeat(CURSOR_MODEL_DISPLAY_NAME_MAX_BYTES.saturating_add(1))
                    )],
                    "hand-authored test case",
                ),
                "invalid model display name",
            ),
            (
                "overlong tip",
                fixture(
                    &["worker - Worker".to_string()],
                    &"t".repeat(CURSOR_CATALOG_TIP_MAX_BYTES),
                ),
                "invalid tip footer",
            ),
            (
                "invalid utf8",
                [b"Available models\n\nworker - ".as_slice(), &[0xff], b"\n"].concat(),
                "not valid UTF-8",
            ),
            (
                "bare carriage return",
                b"Available models\n\nworker - Worker\rName\n\nTip: test\n".to_vec(),
                "bare carriage return",
            ),
            (
                "trailing footer content",
                b"Available models\n\nworker - Worker\n\nTip: test\ntrailing\n".to_vec(),
                "invalid footer shape",
            ),
        ];

        for (label, bytes, expected) in cases {
            let error = parse_cursor_model_catalog(&bytes).expect_err(label);
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn nonzero_timeout_and_truncation_command_evidence_fail_closed() {
        let spec = CursorCatalogCommandSpec::new("/workspace");
        type EvidenceMutation = fn(&mut CursorCatalogCommandOutput);
        let cases: [(&str, EvidenceMutation, &str); 5] = [
            (
                "nonzero",
                |output: &mut CursorCatalogCommandOutput| output.status = Some(7),
                "exit status Some(7)",
            ),
            (
                "timeout",
                |output: &mut CursorCatalogCommandOutput| output.timed_out = true,
                "timed out",
            ),
            (
                "stdout truncated",
                |output: &mut CursorCatalogCommandOutput| output.stdout_truncated = true,
                "exceeded",
            ),
            (
                "stderr truncated",
                |output: &mut CursorCatalogCommandOutput| output.stderr_truncated = true,
                "exceeded",
            ),
            (
                "successful command emitted stderr",
                |output: &mut CursorCatalogCommandOutput| {
                    output.stderr = b"unexpected warning".to_vec()
                },
                "unexpected stderr",
            ),
        ];
        for (label, mutate, expected) in cases {
            let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
            mutate(&mut runner.output);
            let error =
                discover_cursor_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                    .expect_err(label)
                    .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn unverified_process_and_side_effect_evidence_fail_closed_table() {
        let spec = CursorCatalogCommandSpec::new("/workspace");
        let cases = [
            (
                "best-effort process ownership",
                ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "process ownership was not verified empty",
            ),
            (
                "unverified process ownership",
                ProcessTreeEvidence::Unverified(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "process ownership was not verified empty",
            ),
            (
                "best-effort side effects",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::TrustedBestEffort(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "unverified side effects",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "compatibility profile cannot be promoted by a runner",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::TrustedCompatibility,
                ),
                "side-effect confinement was not verified",
            ),
            (
                "Codex-specific profile is not Cursor evidence",
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                "side-effect confinement was not verified",
            ),
        ];

        for (label, process_tree, side_effects, expected) in cases {
            let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
            runner.output.process_tree = process_tree;
            runner.output.side_effects = side_effects;
            let error =
                discover_cursor_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                    .expect_err(label)
                    .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn missing_or_zero_observation_time_fails_before_runner_dispatch() {
        let spec = CursorCatalogCommandSpec::new("/workspace");
        for observed_at in [None, Some(0)] {
            let runner = FakeRunner::successful(CAPTURED_CATALOG);
            let error = discover_cursor_model_catalog(&runner, &spec, observed_at)
                .expect_err("missing observation time must fail closed")
                .to_string();
            assert!(error.contains("missing or zero"), "{error}");
            assert!(runner.observed_specs.into_inner().is_empty());
        }
    }

    #[test]
    fn runner_cannot_clear_the_truncation_flag_on_oversized_evidence() {
        let spec = CursorCatalogCommandSpec::new("/workspace");
        let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
        runner.output.stderr = vec![b'x'; spec.capture_limit_bytes().saturating_add(1)];

        let error = discover_cursor_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
            .expect_err("oversized runner evidence must fail closed")
            .to_string();
        assert!(error.contains("larger than"), "{error}");
    }

    #[test]
    fn slug_and_display_name_validation_fail_closed() {
        for invalid_line in [
            "-leading - Invalid Slug",
            "bad slug - Invalid Slug",
            "valid-slug -  leading display",
        ] {
            let fixture = format!("Available models\n\n{invalid_line}\n\nTip: test fixture\n");
            assert!(parse_cursor_model_catalog(fixture.as_bytes()).is_err());
        }
    }
}

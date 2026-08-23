//! Runtime-advertised Grok model catalog discovery.
//!
//! Catalog membership comes only from one bounded `grok models` observation
//! or from the typed constructed-entry injection seam. Policy code may
//! classify the returned slugs, but this adapter does not embed a live model
//! list or infer authority from a model name.

use super::AdapterId;
use crate::{
    artifacts::state_auth::sha256_hex,
    process_runner::{
        run_process, EnvironmentMode, ProcessSpec, ProcessTreeEvidence,
        SideEffectConfinementEvidence, SideEffectConfinementProfile,
        SideEffectConfinementProfileKind, StdinMode, TrustedFixedNetworkProfile,
    },
};
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    str,
    time::Duration,
};

const GROK_CATALOG_MAX_BYTES: usize = 256 * 1024;
const GROK_CATALOG_MAX_MODELS: usize = 512;
const GROK_MODEL_SLUG_MAX_BYTES: usize = 256;
const GROK_MODEL_DISPLAY_NAME_MAX_BYTES: usize = 768;
const GROK_LOGIN_PROVIDER_MAX_BYTES: usize = 253;
const GROK_CATALOG_TIMEOUT: Duration = Duration::from_secs(30);
const GROK_DIGEST_FRAMING_VERSION: &[u8] = b"maco.grok.advertised-catalog.v1\n";

/// Exact bounded command request for Grok's account-visible catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokCatalogCommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: PathBuf,
    environment: BTreeMap<String, String>,
    capture_limit_bytes: usize,
    timeout: Duration,
}

impl GrokCatalogCommandSpec {
    /// Construct the stable catalog request `grok models`.
    pub fn new(current_dir: impl Into<PathBuf>) -> Self {
        Self {
            program: PathBuf::from("grok"),
            args: vec![OsString::from("models")],
            current_dir: current_dir.into(),
            environment: BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ]),
            capture_limit_bytes: GROK_CATALOG_MAX_BYTES,
            timeout: GROK_CATALOG_TIMEOUT,
        }
    }

    /// Bind an already-resolved executable.
    ///
    /// Production callers resolve `grok` first. Tests bind a scripted stand-in
    /// so `cargo test` never starts a live `grok` process.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
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
pub struct GrokCatalogCommandOutput {
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
/// Unit tests inject hermetic evidence without resolving or starting `grok`.
/// Production uses [`ScreenedGrokCatalogCommandRunner`].
pub trait GrokCatalogCommandRunner {
    fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput>;
}

/// Screened production runner for one bounded `grok models` observation.
///
/// The runner resolves the executable, screens the environment, requests
/// verified process-tree cleanup and a Grok-compatible side-effect profile,
/// and returns honest confinement evidence. It does not invent Verified
/// evidence after a failed or incomplete run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScreenedGrokCatalogCommandRunner;

impl GrokCatalogCommandRunner for ScreenedGrokCatalogCommandRunner {
    fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput> {
        run_screened_grok_catalog_command(spec)
    }
}

/// One constructed or observed Grok model and its human-facing label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokModelCatalogEntry {
    slug: String,
    display_name: String,
}

impl GrokModelCatalogEntry {
    pub fn new(slug: impl Into<String>, display_name: impl Into<String>) -> Result<Self> {
        let slug = slug.into();
        let display_name = display_name.into();
        validate_grok_model_slug(&slug).context("Grok constructed catalog entry")?;
        validate_grok_model_display_name(&display_name)
            .context("Grok constructed catalog entry")?;
        Ok(Self { slug, display_name })
    }

    pub fn slug(&self) -> &str {
        &self.slug
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Immutable snapshot of one Grok catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokModelCatalog {
    models: Vec<GrokModelCatalogEntry>,
}

impl GrokModelCatalog {
    pub fn from_injected_entries(
        entries: impl IntoIterator<Item = GrokModelCatalogEntry>,
    ) -> Result<Self> {
        let models = entries.into_iter().collect::<Vec<_>>();
        if models.is_empty() {
            bail!("Grok constructed catalog contains no models");
        }
        if models.len() > GROK_CATALOG_MAX_MODELS {
            bail!(
                "Grok constructed catalog contains {} models, exceeding the {} model limit",
                models.len(),
                GROK_CATALOG_MAX_MODELS
            );
        }
        let mut seen = BTreeSet::new();
        for entry in &models {
            if !seen.insert(entry.slug.as_str()) {
                bail!(
                    "Grok constructed catalog contains duplicate slug '{}'",
                    entry.slug
                );
            }
        }
        Ok(Self { models })
    }

    pub fn models(&self) -> &[GrokModelCatalogEntry] {
        &self.models
    }

    pub fn slugs(&self) -> impl Iterator<Item = &str> {
        self.models.iter().map(GrokModelCatalogEntry::slug)
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.models.iter().any(|model| model.slug == slug)
    }
}

/// One content-bound Grok catalog observation.
///
/// Runtime identity is fixed to this adapter's typed identity. Observation
/// time is supplied by the screened caller. Neither field confers capability
/// or authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokAdvertisedCatalogObservation {
    catalog: GrokModelCatalog,
    runtime: AdapterId,
    observed_at_unix_millis: u64,
    source_sha256: String,
}

impl GrokAdvertisedCatalogObservation {
    pub fn catalog(&self) -> &GrokModelCatalog {
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

/// Accept a constructed Grok catalog as an advertised observation.
///
/// The digest binds a canonical framing of runtime identity, constructed
/// entries, and the caller-supplied source bytes. It is not a listing-only
/// hash of `source_bytes`.
pub fn inject_grok_advertised_catalog(
    catalog: GrokModelCatalog,
    observed_at_unix_millis: Option<u64>,
    source_bytes: &[u8],
) -> Result<GrokAdvertisedCatalogObservation> {
    let observed_at_unix_millis = observed_at_unix_millis
        .filter(|observed_at| *observed_at != 0)
        .context("Grok runtime model catalog observation time is missing or zero")?;
    if source_bytes.is_empty() {
        bail!("Grok constructed catalog source bytes were empty");
    }
    Ok(GrokAdvertisedCatalogObservation {
        source_sha256: grok_catalog_source_digest(&catalog, source_bytes),
        catalog,
        runtime: AdapterId::Grok,
        observed_at_unix_millis,
    })
}

/// Run the supplied command seam and accept only complete successful evidence.
///
/// A successful observation is converted through
/// [`inject_grok_advertised_catalog`] so selector join keeps one typed seam.
pub fn discover_grok_model_catalog(
    runner: &dyn GrokCatalogCommandRunner,
    spec: &GrokCatalogCommandSpec,
    observed_at_unix_millis: Option<u64>,
) -> Result<GrokAdvertisedCatalogObservation> {
    let observed_at_unix_millis = observed_at_unix_millis
        .filter(|observed_at| *observed_at != 0)
        .context("Grok runtime model catalog observation time is missing or zero")?;
    let output = runner.run(spec)?;
    if output.timed_out {
        bail!("Grok runtime model catalog command timed out");
    }
    if output.stdout_truncated || output.stderr_truncated {
        bail!(
            "Grok runtime model catalog command output exceeded the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.stdout.len() > spec.capture_limit_bytes()
        || output.stderr.len() > spec.capture_limit_bytes()
    {
        bail!(
            "Grok runtime model catalog command returned output larger than the {} byte stream limit",
            spec.capture_limit_bytes()
        );
    }
    if output.status != Some(0) {
        bail!(
            "Grok runtime model catalog command failed with exit status {:?}",
            output.status
        );
    }
    if !output.process_tree.is_verified_empty() {
        bail!("Grok runtime model catalog process ownership was not verified empty");
    }
    if !matches!(
        output.side_effects,
        SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace
                | SideEffectConfinementProfileKind::TrustedFixedNetwork
        )
    ) {
        bail!(
            "Grok runtime model catalog side-effect confinement was not verified with a Grok-compatible profile"
        );
    }
    if !output.stderr.is_empty() {
        bail!("Grok runtime model catalog command emitted unexpected stderr");
    }
    let catalog = parse_grok_model_catalog(&output.stdout)?;
    inject_grok_advertised_catalog(catalog, Some(observed_at_unix_millis), &output.stdout)
}

/// Parse the strict plain-text grammar emitted by `grok models`.
pub fn parse_grok_model_catalog(bytes: &[u8]) -> Result<GrokModelCatalog> {
    if bytes.is_empty() {
        bail!("Grok runtime model catalog output was empty");
    }
    if bytes.len() > GROK_CATALOG_MAX_BYTES {
        bail!(
            "Grok runtime model catalog output exceeds the {} byte limit",
            GROK_CATALOG_MAX_BYTES
        );
    }
    let text = str::from_utf8(bytes).context("Grok runtime model catalog is not valid UTF-8")?;
    if !text.ends_with('\n') {
        bail!("Grok runtime model catalog lacks its terminal newline and may be truncated");
    }
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        bail!("Grok runtime model catalog contains a bare carriage return");
    }
    let lines = normalized
        .strip_suffix('\n')
        .unwrap_or(&normalized)
        .split('\n')
        .collect::<Vec<_>>();
    if lines.len() < 6 {
        bail!("Grok runtime model catalog has an invalid header");
    }
    validate_grok_login_line(lines[0])?;
    if !lines[1].is_empty() {
        bail!("Grok runtime model catalog has an invalid header");
    }
    let default_slug = lines[2]
        .strip_prefix("Default model: ")
        .context("Grok runtime model catalog has an invalid header")?;
    validate_grok_model_slug(default_slug).context("Grok runtime model catalog default model")?;
    if !lines[3].is_empty() || lines[4] != "Available models:" {
        bail!("Grok runtime model catalog has an invalid header");
    }

    let model_lines = &lines[5..];
    if model_lines.is_empty() {
        bail!("Grok runtime model catalog contains no models");
    }
    if model_lines.len() > GROK_CATALOG_MAX_MODELS {
        bail!(
            "Grok runtime model catalog contains {} models, exceeding the {} model limit",
            model_lines.len(),
            GROK_CATALOG_MAX_MODELS
        );
    }

    let mut seen = BTreeSet::new();
    let mut models = Vec::with_capacity(model_lines.len());
    let mut marked_default = None;
    for (index, line) in model_lines.iter().enumerate() {
        let (slug, is_default) = parse_grok_model_line(line)
            .with_context(|| format!("Grok runtime model catalog entry {index} is malformed"))?;
        validate_grok_model_slug(slug)
            .with_context(|| format!("Grok runtime model catalog entry {index}"))?;
        if !seen.insert(slug) {
            bail!("Grok runtime model catalog contains duplicate slug '{slug}'");
        }
        if is_default {
            if marked_default.is_some() {
                bail!("Grok runtime model catalog contains more than one default marker");
            }
            marked_default = Some(slug);
        }
        models.push(GrokModelCatalogEntry {
            slug: slug.to_string(),
            display_name: slug.to_string(),
        });
    }
    let marked_default =
        marked_default.context("Grok runtime model catalog is missing its default marker")?;
    if marked_default != default_slug {
        bail!(
            "Grok runtime model catalog default marker '{marked_default}' does not match header '{default_slug}'"
        );
    }
    Ok(GrokModelCatalog { models })
}

fn parse_grok_model_line(line: &str) -> Result<(&str, bool)> {
    if let Some(rest) = line.strip_prefix("  * ") {
        let slug = rest
            .strip_suffix(" (default)")
            .context("default marker must use '* <slug> (default)'")?;
        if slug.is_empty() || slug.contains(char::is_whitespace) {
            bail!("default marker is malformed");
        }
        return Ok((slug, true));
    }
    if let Some(slug) = line.strip_prefix("  - ") {
        if slug.is_empty() || slug.contains(char::is_whitespace) || slug.ends_with(" (default)") {
            bail!("non-default marker is malformed");
        }
        return Ok((slug, false));
    }
    bail!("line does not match a Grok model marker");
}

fn validate_grok_login_line(line: &str) -> Result<()> {
    let provider = line
        .strip_prefix("You are logged in with ")
        .and_then(|rest| rest.strip_suffix('.'))
        .context("Grok runtime model catalog has an invalid header")?;
    if provider.is_empty() || provider.len() > GROK_LOGIN_PROVIDER_MAX_BYTES {
        bail!("Grok runtime model catalog has an invalid login provider");
    }
    let mut bytes = provider.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        bail!("Grok runtime model catalog has an invalid login provider");
    }
    Ok(())
}

fn grok_catalog_source_digest(catalog: &GrokModelCatalog, source_bytes: &[u8]) -> String {
    let mut framed = Vec::new();
    framed.extend_from_slice(GROK_DIGEST_FRAMING_VERSION);
    framed.extend_from_slice(b"runtime=");
    framed.extend_from_slice(AdapterId::Grok.as_str().as_bytes());
    framed.push(b'\n');
    for entry in catalog.models() {
        framed.extend_from_slice(b"entry\t");
        framed.extend_from_slice(entry.slug().as_bytes());
        framed.push(b'\t');
        framed.extend_from_slice(entry.display_name().as_bytes());
        framed.push(b'\n');
    }
    framed.extend_from_slice(b"source\n");
    framed.extend_from_slice(source_bytes);
    sha256_hex(&framed)
}

fn validate_grok_model_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("contains an empty model slug");
    }
    if slug.len() > GROK_MODEL_SLUG_MAX_BYTES {
        bail!(
            "model slug exceeds the {} byte limit",
            GROK_MODEL_SLUG_MAX_BYTES
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

fn validate_grok_model_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty()
        || display_name.len() > GROK_MODEL_DISPLAY_NAME_MAX_BYTES
        || display_name.trim() != display_name
        || display_name.chars().any(char::is_control)
    {
        bail!("contains an invalid model display name");
    }
    Ok(())
}

fn run_screened_grok_catalog_command(
    spec: &GrokCatalogCommandSpec,
) -> Result<GrokCatalogCommandOutput> {
    let process_spec = screened_grok_catalog_process_spec(spec)?;
    let output = run_process(process_spec).context(
        "Grok runtime model catalog command failed before a verified result was available",
    )?;
    if output.process_error.is_some() || output.stdin_error.is_some() {
        bail!("Grok runtime model catalog process ownership cleanup was incomplete");
    }
    Ok(GrokCatalogCommandOutput {
        status: output.status.and_then(|status| status.code()),
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
        stdout_truncated: output.stdout.is_truncated(),
        stderr_truncated: output.stderr.is_truncated(),
        timed_out: output.timed_out,
        process_tree: output.process_tree,
        side_effects: output.side_effects,
    })
}

fn screened_grok_catalog_process_spec(spec: &GrokCatalogCommandSpec) -> Result<ProcessSpec> {
    let program = resolve_catalog_program(spec.program())?;
    let mut environment = spec.environment().clone();
    if let Ok(home) = env::var("HOME") {
        environment.insert("HOME".to_string(), home);
    }
    if let Ok(grok_home) = env::var("GROK_HOME") {
        environment.insert("GROK_HOME".to_string(), grok_home);
    }
    Ok(ProcessSpec::direct(
        "Grok runtime model catalog",
        program,
        spec.args().iter().cloned(),
        spec.current_dir(),
        spec.capture_limit_bytes(),
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(spec.timeout()))
    .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(
        TrustedFixedNetworkProfile::read_write(spec.current_dir()),
    )))
}

fn resolve_catalog_program(program: &Path) -> Result<PathBuf> {
    if program.components().count() > 1 {
        if program.is_file() {
            return Ok(program.to_path_buf());
        }
        bail!("Grok catalog executable '{}' is missing", program.display());
    }
    env::var_os("PATH")
        .as_deref()
        .into_iter()
        .flat_map(env::split_paths)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("Grok catalog executable '{}' is missing", program.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_runner::{ContainmentBackend, ProcessCommand};
    use std::{cell::RefCell, fs};

    const CAPTURED_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260821.txt"
    ));
    const HAND_AUTHORED_DUPLICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-duplicate.txt"
    ));
    const HAND_AUTHORED_MALFORMED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-malformed.txt"
    ));
    const HAND_AUTHORED_TRUNCATED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-truncated.txt"
    ));
    const HAND_AUTHORED_ADDED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-added.txt"
    ));
    const HAND_AUTHORED_WITHDRAWN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/hand-authored-withdrawn.txt"
    ));
    const CAPTURED_PROVENANCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260821.provenance.json"
    ));
    const CAPTURED_AT_UNIX_MILLIS: u64 = 1_787_303_960_000;

    fn worker_entry() -> Result<GrokModelCatalogEntry> {
        GrokModelCatalogEntry::new("worker-stable", "Worker Stable")
    }

    #[derive(Debug)]
    struct FakeRunner {
        output: GrokCatalogCommandOutput,
        observed_specs: RefCell<Vec<GrokCatalogCommandSpec>>,
    }

    impl FakeRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: GrokCatalogCommandOutput {
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

    impl GrokCatalogCommandRunner for FakeRunner {
        fn run(&self, spec: &GrokCatalogCommandSpec) -> Result<GrokCatalogCommandOutput> {
            self.observed_specs.borrow_mut().push(spec.clone());
            Ok(self.output.clone())
        }
    }

    fn listing(default: &str, model_lines: &[String]) -> Vec<u8> {
        let mut text = format!(
            "You are logged in with grok.com.\n\nDefault model: {default}\n\nAvailable models:\n"
        );
        if !model_lines.is_empty() {
            text.push_str(&model_lines.join("\n"));
            text.push('\n');
        }
        text.into_bytes()
    }

    #[test]
    fn constructed_catalog_rejects_empty_duplicate_and_overlong_membership() -> Result<()> {
        let error = GrokModelCatalog::from_injected_entries(Vec::new())
            .expect_err("empty catalog must fail closed")
            .to_string();
        assert!(error.contains("contains no models"), "{error}");

        let duplicate = GrokModelCatalog::from_injected_entries([
            worker_entry()?,
            GrokModelCatalogEntry::new("worker-stable", "Worker Stable Duplicate")?,
        ])
        .expect_err("duplicate catalog must fail closed")
        .to_string();
        assert!(duplicate.contains("duplicate slug"), "{duplicate}");

        let too_many = (0..=GROK_CATALOG_MAX_MODELS)
            .map(|index| {
                GrokModelCatalogEntry::new(format!("worker-{index}"), format!("Worker {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let overflow = GrokModelCatalog::from_injected_entries(too_many)
            .expect_err("overlong catalog must fail closed")
            .to_string();
        assert!(overflow.contains("513 models"), "{overflow}");
        Ok(())
    }

    #[test]
    fn entry_construction_validates_slug_and_display_name() {
        assert!(GrokModelCatalogEntry::new("", "Worker").is_err());
        assert!(GrokModelCatalogEntry::new("-leading", "Worker").is_err());
        assert!(GrokModelCatalogEntry::new("worker-stable", " leading").is_err());
        assert!(GrokModelCatalogEntry::new("worker-stable", "Worker Stable").is_ok());
    }

    #[test]
    fn missing_time_and_empty_source_fail_closed() -> Result<()> {
        let catalog = GrokModelCatalog::from_injected_entries([worker_entry()?])?;
        for observed_at in [None, Some(0)] {
            let error = inject_grok_advertised_catalog(catalog.clone(), observed_at, b"source")
                .expect_err("missing observation time must fail closed")
                .to_string();
            assert!(error.contains("missing or zero"), "{error}");
        }
        let error = inject_grok_advertised_catalog(catalog, Some(1), b"")
            .expect_err("empty source must fail closed")
            .to_string();
        assert!(error.contains("source bytes were empty"), "{error}");
        Ok(())
    }

    #[test]
    fn digest_binds_runtime_entries_and_source_bytes() -> Result<()> {
        let catalog = GrokModelCatalog::from_injected_entries([worker_entry()?])?;
        let observation =
            inject_grok_advertised_catalog(catalog.clone(), Some(1_787_240_463_000), b"alpha")?;
        assert_eq!(observation.runtime(), AdapterId::Grok);
        assert!(catalog.contains("worker-stable"));
        assert_ne!(observation.source_sha256(), sha256_hex(b"alpha"));

        let retargeted = inject_grok_advertised_catalog(catalog, Some(1_787_240_463_000), b"beta")?;
        assert_ne!(observation.source_sha256(), retargeted.source_sha256());

        let other = GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
            "worker-other",
            "Worker Other",
        )?])?;
        let other_observation =
            inject_grok_advertised_catalog(other, Some(1_787_240_463_000), b"alpha")?;
        assert_ne!(
            observation.source_sha256(),
            other_observation.source_sha256()
        );
        Ok(())
    }

    #[test]
    fn command_spec_is_exact_and_discovery_uses_only_the_injected_runner() -> Result<()> {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        assert_eq!(spec.program(), Path::new("grok"));
        assert_eq!(spec.args(), [OsString::from("models")]);
        assert_eq!(
            spec.environment(),
            &BTreeMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("TERM".to_string(), "dumb".to_string()),
            ])
        );
        assert_eq!(spec.current_dir(), Path::new("/workspace"));
        assert_eq!(spec.capture_limit_bytes(), GROK_CATALOG_MAX_BYTES);
        assert_eq!(spec.timeout(), GROK_CATALOG_TIMEOUT);

        let runner = FakeRunner::successful(CAPTURED_CATALOG);
        let observation =
            discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))?;
        assert_eq!(runner.observed_specs.into_inner(), [spec]);
        let catalog = observation.catalog();
        let parsed = parse_grok_model_catalog(CAPTURED_CATALOG)?;
        let injected = inject_grok_advertised_catalog(
            parsed,
            Some(CAPTURED_AT_UNIX_MILLIS),
            CAPTURED_CATALOG,
        )?;
        assert_eq!(observation, injected);
        assert_eq!(catalog.models().len(), 2);
        assert!(catalog.contains("grok-4.6"));
        assert!(catalog.contains("grok-4.5"));
        assert_eq!(observation.runtime(), AdapterId::Grok);
        assert_eq!(
            observation.observed_at_unix_millis(),
            CAPTURED_AT_UNIX_MILLIS
        );
        assert_ne!(observation.source_sha256(), sha256_hex(CAPTURED_CATALOG));
        Ok(())
    }

    #[test]
    fn captured_catalog_preserves_runtime_order_and_uses_slug_labels() -> Result<()> {
        let catalog = parse_grok_model_catalog(CAPTURED_CATALOG)?;
        assert_eq!(
            catalog
                .models()
                .iter()
                .map(|entry| (entry.slug(), entry.display_name()))
                .collect::<Vec<_>>(),
            [("grok-4.6", "grok-4.6"), ("grok-4.5", "grok-4.5")]
        );
        Ok(())
    }

    #[test]
    fn captured_fixture_provenance_is_adjacent_exact_and_content_bound() -> Result<()> {
        let provenance: serde_json::Value = serde_json::from_str(CAPTURED_PROVENANCE)?;
        assert_eq!(provenance["schema_version"], 1);
        assert_eq!(provenance["fixture"], "captured-minimal-20260821.txt");
        assert_eq!(provenance["classification"], "capture-derived-minimal");
        assert_eq!(provenance["captured_at_utc"], "2026-08-21T09:19:20Z");
        assert_eq!(provenance["cli"], "grok");
        assert_eq!(provenance["cli_version"], "0.2.93 (f00f96316d)");
        assert_eq!(provenance["argv"], serde_json::json!(["grok", "models"]));
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
        let added = parse_grok_model_catalog(HAND_AUTHORED_ADDED)?;
        let withdrawn = parse_grok_model_catalog(HAND_AUTHORED_WITHDRAWN)?;
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
                "lacks its terminal newline",
            ),
        ] {
            let error = parse_grok_model_catalog(bytes)
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn parser_limits_and_structural_edges_fail_closed_table() {
        let too_many_models = std::iter::once("  * worker-0 (default)".to_string())
            .chain((1..=GROK_CATALOG_MAX_MODELS).map(|index| format!("  - worker-{index}")))
            .collect::<Vec<_>>();
        let invalid_utf8 = [
            b"You are logged in with grok.com.\n\nDefault model: ".as_slice(),
            &[0xff],
            b"\n",
        ]
        .concat();
        let cases = vec![
            (
                "over catalog byte limit",
                vec![b'x'; GROK_CATALOG_MAX_BYTES.saturating_add(1)],
                "exceeds the 262144 byte limit",
            ),
            (
                "over model count limit",
                listing("worker-0", &too_many_models),
                "513 models",
            ),
            (
                "overlong slug",
                listing(
                    "worker",
                    &[format!(
                        "  * {} (default)",
                        "a".repeat(GROK_MODEL_SLUG_MAX_BYTES.saturating_add(1))
                    )],
                ),
                "model slug exceeds",
            ),
            ("invalid utf8", invalid_utf8, "not valid UTF-8"),
            (
                "bare carriage return",
                b"You are logged in with grok.com.\n\nDefault model: worker\rstable\n\nAvailable models:\n  * worker (default)\n".to_vec(),
                "bare carriage return",
            ),
            (
                "trailing footer content",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-stable (default)".to_string(),
                        String::new(),
                        "Tip: unexpected".to_string(),
                    ],
                ),
                "malformed",
            ),
            (
                "missing default marker",
                listing("worker-stable", &["  - worker-stable".to_string()]),
                "missing its default marker",
            ),
            (
                "default marker mismatch",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-other (default)".to_string(),
                        "  - worker-stable".to_string(),
                    ],
                ),
                "does not match header",
            ),
            (
                "two default markers",
                listing(
                    "worker-stable",
                    &[
                        "  * worker-stable (default)".to_string(),
                        "  * worker-new (default)".to_string(),
                    ],
                ),
                "more than one default marker",
            ),
            (
                "invalid login provider",
                b"You are logged in with not a host.\n\nDefault model: worker-stable\n\nAvailable models:\n  * worker-stable (default)\n".to_vec(),
                "invalid login provider",
            ),
        ];

        for (label, bytes, expected) in cases {
            let error = parse_grok_model_catalog(&bytes).expect_err(label);
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn nonzero_timeout_and_truncation_command_evidence_fail_closed() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        type EvidenceMutation = fn(&mut GrokCatalogCommandOutput);
        let cases: [(&str, EvidenceMutation, &str); 5] = [
            (
                "nonzero",
                |output: &mut GrokCatalogCommandOutput| output.status = Some(7),
                "exit status Some(7)",
            ),
            (
                "timeout",
                |output: &mut GrokCatalogCommandOutput| output.timed_out = true,
                "timed out",
            ),
            (
                "stdout truncated",
                |output: &mut GrokCatalogCommandOutput| output.stdout_truncated = true,
                "exceeded",
            ),
            (
                "stderr truncated",
                |output: &mut GrokCatalogCommandOutput| output.stderr_truncated = true,
                "exceeded",
            ),
            (
                "successful command emitted stderr",
                |output: &mut GrokCatalogCommandOutput| {
                    output.stderr = b"unexpected warning".to_vec()
                },
                "unexpected stderr",
            ),
        ];
        for (label, mutate, expected) in cases {
            let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
            mutate(&mut runner.output);
            let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn unverified_process_and_side_effect_evidence_fail_closed_table() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
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
                "Codex-specific profile is not Grok evidence",
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
            let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn missing_or_zero_observation_time_fails_before_runner_dispatch() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        for observed_at in [None, Some(0)] {
            let runner = FakeRunner::successful(CAPTURED_CATALOG);
            let error = discover_grok_model_catalog(&runner, &spec, observed_at)
                .expect_err("missing observation time must fail closed")
                .to_string();
            assert!(error.contains("missing or zero"), "{error}");
            assert!(runner.observed_specs.into_inner().is_empty());
        }
    }

    #[test]
    fn runner_cannot_clear_the_truncation_flag_on_oversized_evidence() {
        let spec = GrokCatalogCommandSpec::new("/workspace");
        let mut runner = FakeRunner::successful(CAPTURED_CATALOG);
        runner.output.stderr = vec![b'x'; spec.capture_limit_bytes().saturating_add(1)];

        let error = discover_grok_model_catalog(&runner, &spec, Some(CAPTURED_AT_UNIX_MILLIS))
            .expect_err("oversized runner evidence must fail closed")
            .to_string();
        assert!(error.contains("larger than"), "{error}");
    }

    #[test]
    fn slug_and_marker_validation_fail_closed() {
        for invalid_line in [
            "  * -leading (default)",
            "  - bad slug",
            "  * worker-stable",
            "  - worker-stable (default)",
        ] {
            let fixture = listing("worker-stable", &[invalid_line.to_string()]);
            assert!(
                parse_grok_model_catalog(&fixture).is_err(),
                "{invalid_line}"
            );
        }
    }

    #[test]
    fn screened_process_spec_is_bounded_cleared_and_confined() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join("catalog-standin");
        fs::write(&program, "")?;
        let spec = GrokCatalogCommandSpec::new(dir.path()).with_program(&program);
        let process = screened_grok_catalog_process_spec(&spec)?;
        match &process.command {
            ProcessCommand::Direct {
                program: observed_program,
                args,
            } => {
                assert_eq!(observed_program, &program);
                assert_eq!(args, &spec.args());
            }
            other => panic!("expected a direct catalog command, got {other:?}"),
        }
        let EnvironmentMode::ClearAndSet(environment) = &process.environment else {
            panic!("screened catalog environment must be ClearAndSet");
        };
        assert_eq!(environment.get("NO_COLOR").map(String::as_str), Some("1"));
        assert_eq!(environment.get("TERM").map(String::as_str), Some("dumb"));
        assert!(!environment.contains_key("PATH"));
        assert_eq!(process.stdin, StdinMode::Null);
        assert_eq!(process.timeout, Some(GROK_CATALOG_TIMEOUT));
        assert_eq!(process.stdout.max_bytes, GROK_CATALOG_MAX_BYTES);
        assert_eq!(process.stderr.max_bytes, GROK_CATALOG_MAX_BYTES);
        assert_eq!(
            process.side_effects.kind(),
            SideEffectConfinementProfileKind::TrustedFixedNetwork
        );
        Ok(())
    }

    #[test]
    fn screened_runner_fails_closed_on_a_missing_program_without_starting_grok() {
        let spec = GrokCatalogCommandSpec::new("/workspace")
            .with_program("/maco-definitely-missing-grok-catalog");
        let error = ScreenedGrokCatalogCommandRunner
            .run(&spec)
            .expect_err("missing catalog executable must fail closed")
            .to_string();
        assert!(
            error.contains("maco-definitely-missing-grok-catalog"),
            "{error}"
        );
        assert!(error.contains("missing"), "{error}");
    }
}

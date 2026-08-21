//! Typed Grok advertised-catalog observation construction.
//!
//! Callers supply constructed catalog entries. This module does not parse
//! `grok models` output; live listing grammar is tracking issue #244.

use super::AdapterId;
use crate::artifacts::state_auth::sha256_hex;
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;

const GROK_CATALOG_MAX_MODELS: usize = 512;
const GROK_MODEL_SLUG_MAX_BYTES: usize = 256;
const GROK_MODEL_DISPLAY_NAME_MAX_BYTES: usize = 768;
const GROK_DIGEST_FRAMING_VERSION: &[u8] = b"maco.grok.advertised-catalog.v1\n";

/// One constructed Grok model and its human-facing label.
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

/// Immutable snapshot of one constructed Grok catalog.
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

/// One content-bound constructed Grok catalog observation.
///
/// Runtime identity is fixed to this adapter's typed identity. Observation
/// time is supplied by the caller. Neither field confers capability or
/// authority.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn worker_entry() -> Result<GrokModelCatalogEntry> {
        GrokModelCatalogEntry::new("worker-stable", "Worker Stable")
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
}

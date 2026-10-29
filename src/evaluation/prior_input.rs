//! Frozen selection evidence for explicitly opted-in held-out execution.

use crate::{
    artifacts::ArtifactRunWriter,
    selection::OperatorPriorDataProvenance,
    supervise::{FrozenOperatorPriorData, OperatorPriorDataGuard},
};
use anyhow::Result;
use std::path::Path;

/// Validated operator input resolved against the evaluated source repository.
/// This supplies selection evidence, never token prices or provider authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldOutPriorDataInput {
    snapshot: FrozenOperatorPriorData,
}

impl HeldOutPriorDataInput {
    /// Read once through the same bounded Unix repository confinement as supervise.
    pub fn freeze(source_repo: &Path, relative_path: &Path) -> Result<Self> {
        Ok(Self {
            snapshot: FrozenOperatorPriorData::read(source_repo, relative_path)?,
        })
    }

    pub fn provenance(&self) -> &OperatorPriorDataProvenance {
        self.snapshot.provenance()
    }

    pub(super) fn verify_source(&self, source_repo: &Path) -> Result<()> {
        self.snapshot.verify_source(source_repo)
    }

    pub(super) fn bind_for_repo(
        input: Option<&Self>,
        repo: &Path,
    ) -> Result<OperatorPriorDataGuard> {
        FrozenOperatorPriorData::bind_for_repo(input.map(|input| &input.snapshot), repo)
    }

    pub(super) fn archive(&self, writer: &mut ArtifactRunWriter, prefix: &Path) -> Result<()> {
        self.snapshot.archive(writer, prefix)
    }
}

//! Source binding for the version-pinned Cursor managed ACP bridge.
//!
//! This module does not enable Cursor dispatch. It binds the only vendor
//! sources that the sibling CommonJS bootstrap may import and exposes the
//! bootstrap bytes to the later screened process boundary.

use crate::artifacts::state_auth::sha256_hex;
use anyhow::{bail, Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const CURSOR_CLI_VERSION: &str = "2026.04.08-a41fba1";
pub const CURSOR_INDEX_SHA256: &str =
    "13acf826c5205ffd8ee7ceb32e0366f150f792891ab5f48ca5554b9934ce1457";
pub const CURSOR_ACP_CHUNK_SHA256: &str =
    "338f9c221055bdc46f70844de78ea6e83e27e45718a207b66d2becbeb017a064";
pub const CURSOR_EXEC_CHUNK_SHA256: &str =
    "4e932032048be5846917173a1351b8b5a99a22b5e5b47b6117c908311644eaa5";
pub const CURSOR_NATIVE_HOST_CHUNK_361_SHA256: &str =
    "f75f351cf81ea0852a07df9376357b62b103fb4535591b728c6ffbdafcceb3d9";
pub const CURSOR_NATIVE_HOST_CHUNK_156_SHA256: &str =
    "b3c48d6d171a8fc25437a7049e979a1e3234d726408bcb9b6ff14b7b6c67e6f1";
pub const CURSOR_INDEX_FILE: &str = "index.js";
pub const CURSOR_ACP_CHUNK_FILE: &str = "414.index.js";
/// Zero-based byte offset of the synchronous `this.client.run(...)` assignment
/// in the pinned entry. Its result is consumed as an async iterable before the
/// lossy ACP projection. The nearby synchronous disposal anchor belongs to the
/// handshake span, so it is not evidence that the native RPC iterable is disposed.
pub const CURSOR_LOWER_RPC_CALL_BYTE_OFFSET: usize = 3_702_334;
pub const MANAGED_BRIDGE_SOURCE: &str = include_str!("managed_bridge.cjs");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorManagedBridgeBinding {
    root: PathBuf,
    index: PathBuf,
    acp_chunk: PathBuf,
    guarded_chunks: Vec<PathBuf>,
}

impl CursorManagedBridgeBinding {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn index(&self) -> &Path {
        &self.index
    }

    pub fn acp_chunk(&self) -> &Path {
        &self.acp_chunk
    }

    pub fn guarded_chunks(&self) -> &[PathBuf] {
        &self.guarded_chunks
    }
}

/// Bind the two immutable vendor files before a bridge process is constructed.
///
/// The CommonJS bootstrap repeats these checks with no-follow descriptors and
/// compiles the exact verified bytes. This Rust-side check lets the future
/// process boundary refuse source drift before launching Node at all.
pub fn bind_managed_bridge_sources(root: impl AsRef<Path>) -> Result<CursorManagedBridgeBinding> {
    let root = root.as_ref();
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("Cursor package root is unavailable: {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Cursor package root is not a non-symbolic directory");
    }

    let index = root.join(CURSOR_INDEX_FILE);
    let acp_chunk = root.join(CURSOR_ACP_CHUNK_FILE);
    let guarded_chunks = vec![
        root.join("357.index.js"),
        root.join("361.index.js"),
        root.join("156.index.js"),
    ];
    bind_regular_file(&index, CURSOR_INDEX_SHA256, "Cursor entry")?;
    bind_regular_file(&acp_chunk, CURSOR_ACP_CHUNK_SHA256, "Cursor ACP chunk")?;
    bind_regular_file(
        &guarded_chunks[0],
        CURSOR_EXEC_CHUNK_SHA256,
        "Cursor execution chunk",
    )?;
    bind_regular_file(
        &guarded_chunks[1],
        CURSOR_NATIVE_HOST_CHUNK_361_SHA256,
        "Cursor native-host chunk 361",
    )?;
    bind_regular_file(
        &guarded_chunks[2],
        CURSOR_NATIVE_HOST_CHUNK_156_SHA256,
        "Cursor native-host chunk 156",
    )?;

    Ok(CursorManagedBridgeBinding {
        root: root.to_path_buf(),
        index,
        acp_chunk,
        guarded_chunks,
    })
}

fn bind_regular_file(path: &Path, expected_sha256: &str, label: &str) -> Result<()> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("{label} is unavailable: {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        bail!("{label} is not a non-symbolic regular file");
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {label}"))?;
    let after = fs::symlink_metadata(path).with_context(|| format!("failed to restat {label}"))?;
    if after.file_type().is_symlink() || !after.is_file() || before.len() != after.len() {
        bail!("{label} changed while it was being bound");
    }
    let observed_sha256 = sha256_hex(&bytes);
    if observed_sha256 != expected_sha256 {
        bail!("{label} digest mismatch: expected {expected_sha256}, observed {observed_sha256}");
    }
    Ok(())
}

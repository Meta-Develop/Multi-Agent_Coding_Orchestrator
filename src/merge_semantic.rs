use crate::{
    merge::{serialize_path, serialize_paths},
    repo_semantic::{SemanticDependencyImpact, SemanticSymbolKind},
};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictClassification {
    pub advisory: bool,
    pub status: SemanticConflictClassificationStatus,
    pub risk: SemanticConflictRisk,
    pub confidence: SemanticConflictConfidence,
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub conflict_paths: Vec<PathBuf>,
    pub overlaps: Vec<SemanticConflictOverlap>,
}

impl SemanticConflictClassification {
    pub(crate) fn no_conflict() -> Self {
        Self {
            advisory: true,
            status: SemanticConflictClassificationStatus::NoConflict,
            risk: SemanticConflictRisk::None,
            confidence: SemanticConflictConfidence::High,
            degraded: false,
            notes: Vec::new(),
            conflict_paths: Vec::new(),
            overlaps: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictClassificationStatus {
    NoConflict,
    Classified,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictRisk {
    None,
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictConfidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictOverlap {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub kind: SemanticConflictOverlapKind,
    pub risk: SemanticConflictRisk,
    pub confidence: SemanticConflictConfidence,
    pub primary: SemanticConflictSide,
    pub candidate: SemanticConflictSide,
    pub common_symbols: Vec<SemanticConflictSymbol>,
    pub common_impls: Vec<SemanticConflictSymbol>,
    pub common_modules: Vec<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub impacted_files: Vec<PathBuf>,
    pub dependency_impacts: Vec<SemanticConflictDependencyImpact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictOverlapKind {
    ImportOnly,
    FormattingOnly,
    SignatureLevel,
    SymbolLevel,
    ImplLevel,
    ModuleLevel,
    FileLevel,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictSide {
    pub touched_symbols: Vec<SemanticConflictSymbol>,
    pub touched_impls: Vec<SemanticConflictSymbol>,
    pub touched_modules: Vec<String>,
    pub touched_imports: Vec<SemanticConflictImport>,
    pub formatting_only: bool,
    pub import_only: bool,
    pub signature_level: bool,
    pub current_line_ranges: Vec<SemanticConflictLineRange>,
    pub base_line_ranges: Vec<SemanticConflictLineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictSymbol {
    pub name: String,
    pub qualified_path: Vec<String>,
    pub kind: SemanticSymbolKind,
    pub visibility: String,
    pub impl_target: Option<String>,
    pub impl_trait: Option<String>,
    #[serde(serialize_with = "serialize_path")]
    pub file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictImport {
    pub path: String,
    pub alias: Option<String>,
    pub glob: bool,
    pub visibility: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictLineRange {
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictDependencyImpact {
    pub side: SemanticConflictDependencySide,
    pub impact: SemanticDependencyImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictDependencySide {
    Primary,
    Candidate,
}

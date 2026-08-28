use std::path::{Path, PathBuf};

use super::{
    python::PythonAdapter, rust::RustAdapter, SemanticDependency, SemanticImport, SemanticReExport,
    SemanticScanError, SemanticSymbol,
};

/// Language adapters emit into the same typed semantic map as the Rust parser.
pub(super) trait LanguageAdapter: Send + Sync {
    fn language_id(&self) -> &'static str;
    fn matches(&self, path: &Path) -> bool;
    fn module_path(&self, file: &Path) -> Vec<String>;
    fn parse(
        &self,
        file: &Path,
        source: &str,
        repository_files: &[PathBuf],
        output: AdapterOutput<'_>,
    );
}

pub(super) struct AdapterOutput<'a> {
    pub symbols: &'a mut Vec<SemanticSymbol>,
    pub imports: &'a mut Vec<SemanticImport>,
    pub re_exports: &'a mut Vec<SemanticReExport>,
    pub dependencies: &'a mut Vec<SemanticDependency>,
    pub parse_error: &'a mut Option<SemanticScanError>,
}

const UNADAPTED_SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "cjs", "cs", "go", "h", "hpp", "hxx", "java", "js", "jsx", "kt",
    "mjs", "php", "rb", "scala", "swift", "ts", "tsx",
];

pub(super) fn builtin_adapters() -> &'static [&'static dyn LanguageAdapter] {
    static ADAPTERS: [&dyn LanguageAdapter; 2] = [&RustAdapter, &PythonAdapter];
    &ADAPTERS
}

pub(super) fn adapter_for(path: &Path) -> Option<&'static dyn LanguageAdapter> {
    builtin_adapters()
        .iter()
        .copied()
        .find(|adapter| adapter.matches(path))
}

pub(super) fn is_semantic_candidate(path: &Path) -> bool {
    adapter_for(path).is_some() || has_unadapted_source_extension(path)
}

pub(super) fn has_unadapted_source_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| UNADAPTED_SOURCE_EXTENSIONS.contains(&extension))
}

pub(super) fn unsupported_language_label(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!(".{extension}"))
        .unwrap_or_else(|| "unrecognized source".to_string())
}

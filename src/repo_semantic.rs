use crate::safe_state::BoundedRegularReader;
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use proc_macro2::{LineColumn, Span};
use quote::ToTokens;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::unix::{
    ffi::OsStrExt,
    fs::OpenOptionsExt,
    io::{AsRawFd, FromRawFd},
};
use syn::{
    spanned::Spanned, Attribute, Expr, ImplItem, Item, Lit, Meta, TraitItem, UseTree, Visibility,
};

const MAX_SEMANTIC_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SEMANTIC_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SEMANTIC_SCAN_ENTRIES: usize = 100_000;
const MAX_SEMANTIC_DIRECTORY_DEPTH: usize = 128;
const MAX_SEMANTIC_PATH_BYTES: usize = 16 * 1024;
const MAX_SEMANTIC_PATH_COMPONENTS: usize = 129;
const MAX_SEMANTIC_RETAINED_PATH_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct SemanticScanLimits {
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_entries: usize,
    max_depth: usize,
    max_path_bytes: usize,
    max_path_components: usize,
    max_retained_path_bytes: usize,
}

const DEFAULT_SEMANTIC_SCAN_LIMITS: SemanticScanLimits = SemanticScanLimits {
    max_file_bytes: MAX_SEMANTIC_FILE_BYTES,
    max_total_bytes: MAX_SEMANTIC_TOTAL_BYTES,
    max_entries: MAX_SEMANTIC_SCAN_ENTRIES,
    max_depth: MAX_SEMANTIC_DIRECTORY_DEPTH,
    max_path_bytes: MAX_SEMANTIC_PATH_BYTES,
    max_path_components: MAX_SEMANTIC_PATH_COMPONENTS,
    max_retained_path_bytes: MAX_SEMANTIC_RETAINED_PATH_BYTES,
};

#[derive(Clone, Copy)]
struct SemanticScanExclusions<'a> {
    allowed_files: Option<&'a BTreeSet<PathBuf>>,
    nested_repository_boundaries: &'a [PathBuf],
}

impl SemanticScanExclusions<'static> {
    const fn none() -> Self {
        const EMPTY: &[PathBuf] = &[];
        Self {
            allowed_files: None,
            nested_repository_boundaries: EMPTY,
        }
    }
}

impl SemanticScanExclusions<'_> {
    fn skips_directory(self, relative: &Path) -> bool {
        if self.is_nested_boundary(relative) {
            return true;
        }
        match self.allowed_files {
            Some(allowed) if !relative.as_os_str().is_empty() => {
                !allowed.iter().any(|file| file.starts_with(relative))
            }
            _ => false,
        }
    }

    fn skips_file(self, relative: &Path) -> bool {
        if self
            .nested_repository_boundaries
            .iter()
            .any(|boundary| relative == boundary.as_path() || relative.starts_with(boundary))
        {
            return true;
        }
        self.allowed_files
            .is_some_and(|allowed| !allowed.contains(relative))
    }

    fn is_nested_boundary(self, relative: &Path) -> bool {
        self.nested_repository_boundaries
            .iter()
            .any(|boundary| relative == boundary.as_path() || relative.starts_with(boundary))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticRepoMap {
    pub root: PathBuf,
    pub files: Vec<SemanticFile>,
    pub symbols: Vec<SemanticSymbol>,
    pub imports: Vec<SemanticImport>,
    pub re_exports: Vec<SemanticReExport>,
    pub dependencies: Vec<SemanticDependency>,
    pub errors: Vec<SemanticScanError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticFile {
    pub path: PathBuf,
    pub module_path: Vec<String>,
    pub byte_len: usize,
    pub line_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSymbolKind {
    Module,
    Function,
    Struct,
    Enum,
    Trait,
    Impl,
    Method,
    Const,
    TypeAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticSymbol {
    pub id: String,
    pub file: PathBuf,
    pub name: String,
    pub qualified_path: Vec<String>,
    pub kind: SemanticSymbolKind,
    pub visibility: String,
    pub parent_symbol: Option<String>,
    pub impl_target: Option<String>,
    pub impl_trait: Option<String>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticImport {
    pub file: PathBuf,
    pub module_path: Vec<String>,
    pub path: String,
    pub alias: Option<String>,
    pub glob: bool,
    pub visibility: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticReExport {
    pub file: PathBuf,
    pub module_path: Vec<String>,
    pub path: String,
    pub alias: Option<String>,
    pub glob: bool,
    pub visibility: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDependencyKind {
    Import,
    ModuleDeclaration,
    InlineModule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticDependency {
    pub from_file: PathBuf,
    pub from_module: Vec<String>,
    pub to: String,
    pub to_file: Option<PathBuf>,
    pub kind: SemanticDependencyKind,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScanErrorKind {
    Read,
    Parse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticScanError {
    pub file: PathBuf,
    pub kind: SemanticScanErrorKind,
    pub message: String,
    pub span: Option<SourceSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDependencyDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticDependencyImpact {
    pub direction: SemanticDependencyDirection,
    pub changed_path: PathBuf,
    pub related_file: Option<PathBuf>,
    pub dependency: SemanticDependency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticRiskReport {
    pub changed_paths: Vec<PathBuf>,
    pub touched_files: Vec<SemanticFile>,
    pub touched_symbols: Vec<SemanticSymbol>,
    pub dependency_impacts: Vec<SemanticDependencyImpact>,
    pub impacted_files: Vec<PathBuf>,
    pub errors: Vec<SemanticScanError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SourceSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
    /// Last line of the declaration signature (through `{` or `;`), not the body.
    pub signature_end_line: usize,
}

pub fn scan_repository(repo_path: impl AsRef<Path>) -> Result<SemanticRepoMap> {
    scan_repository_with_limits(repo_path.as_ref(), DEFAULT_SEMANTIC_SCAN_LIMITS)
}

/// Scan only outer-inventory files and skip nested-repository trees before
/// spending entry, depth, byte, or parse budgets inside them.
pub fn scan_repository_with_exclusions(
    repo_path: impl AsRef<Path>,
    allowed_files: Option<&BTreeSet<PathBuf>>,
    nested_repository_boundaries: &[PathBuf],
) -> Result<SemanticRepoMap> {
    scan_repository_with_limits_and_exclusions(
        repo_path.as_ref(),
        DEFAULT_SEMANTIC_SCAN_LIMITS,
        SemanticScanExclusions {
            allowed_files,
            nested_repository_boundaries,
        },
    )
}

fn scan_repository_with_limits(
    repo_path: &Path,
    limits: SemanticScanLimits,
) -> Result<SemanticRepoMap> {
    scan_repository_with_limits_and_exclusions(repo_path, limits, SemanticScanExclusions::none())
}

fn scan_repository_with_limits_and_exclusions(
    repo_path: &Path,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<SemanticRepoMap> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    let root = repo
        .workdir()
        .context("semantic repository map requires a non-bare repository")?
        .to_path_buf();

    let mut map = SemanticRepoMap {
        root: root.clone(),
        files: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        re_exports: Vec::new(),
        dependencies: Vec::new(),
        errors: Vec::new(),
    };

    let mut rust_files = Vec::new();
    collect_rust_files(&root, &mut rust_files, limits, exclusions)?;
    rust_files.sort();

    let mut total_source_bytes = 0u64;
    for file in &rust_files {
        scan_rust_file(
            &root,
            file,
            &rust_files,
            &mut map,
            &mut total_source_bytes,
            limits,
        )?;
    }

    sort_map(&mut map);
    Ok(map)
}

pub fn risk_report_for_paths<I, P>(map: &SemanticRepoMap, paths: I) -> SemanticRiskReport
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut changed_paths = paths
        .into_iter()
        .map(|path| normalize_query_path(&map.root, path.as_ref()))
        .collect::<Vec<_>>();
    changed_paths.sort();
    changed_paths.dedup();
    let changed_set = changed_paths.iter().cloned().collect::<BTreeSet<_>>();

    let touched_files = map
        .files
        .iter()
        .filter(|file| changed_set.contains(&file.path))
        .cloned()
        .collect::<Vec<_>>();
    let touched_symbols = map
        .symbols
        .iter()
        .filter(|symbol| changed_set.contains(&symbol.file))
        .cloned()
        .collect::<Vec<_>>();
    let errors = map
        .errors
        .iter()
        .filter(|error| changed_set.contains(&error.file))
        .cloned()
        .collect::<Vec<_>>();

    let mut impacted_files = BTreeSet::new();
    let mut dependency_impacts = Vec::new();
    for changed_path in &changed_paths {
        for dependency in &map.dependencies {
            if dependency.from_file == *changed_path {
                if let Some(related_file) = &dependency.to_file {
                    if related_file != changed_path {
                        impacted_files.insert(related_file.clone());
                    }
                }
                dependency_impacts.push(SemanticDependencyImpact {
                    direction: SemanticDependencyDirection::Outgoing,
                    changed_path: changed_path.clone(),
                    related_file: dependency.to_file.clone(),
                    dependency: dependency.clone(),
                });
            }

            if dependency.to_file.as_deref() == Some(changed_path.as_path())
                && dependency.from_file != *changed_path
            {
                impacted_files.insert(dependency.from_file.clone());
                dependency_impacts.push(SemanticDependencyImpact {
                    direction: SemanticDependencyDirection::Incoming,
                    changed_path: changed_path.clone(),
                    related_file: Some(dependency.from_file.clone()),
                    dependency: dependency.clone(),
                });
            }
        }
    }

    dependency_impacts.sort_by(|left, right| {
        left.changed_path
            .cmp(&right.changed_path)
            .then_with(|| left.direction.cmp(&right.direction))
            .then_with(|| left.related_file.cmp(&right.related_file))
            .then_with(|| left.dependency.from_file.cmp(&right.dependency.from_file))
            .then_with(|| left.dependency.kind.cmp(&right.dependency.kind))
            .then_with(|| left.dependency.to.cmp(&right.dependency.to))
    });

    SemanticRiskReport {
        changed_paths,
        touched_files,
        touched_symbols,
        dependency_impacts,
        impacted_files: impacted_files.into_iter().collect(),
        errors,
    }
}

fn collect_rust_files(
    root: &Path,
    files: &mut Vec<PathBuf>,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<()> {
    if limits.max_file_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_entries == 0
        || limits.max_depth == 0
        || limits.max_path_bytes == 0
        || limits.max_path_components == 0
        || limits.max_retained_path_bytes == 0
    {
        bail!("semantic repository scan limits must be positive");
    }
    let mut entries = 0usize;
    let mut retained_path_bytes = 0usize;
    collect_rust_files_bounded(
        root,
        files,
        &mut entries,
        &mut retained_path_bytes,
        limits,
        exclusions,
    )
}

#[cfg(target_os = "linux")]
fn collect_rust_files_bounded(
    root: &Path,
    files: &mut Vec<PathBuf>,
    entries: &mut usize,
    retained_path_bytes: &mut usize,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<()> {
    let directory = open_semantic_directory(root)?;
    collect_rust_files_from_directory(
        &directory,
        Path::new(""),
        0,
        files,
        entries,
        retained_path_bytes,
        limits,
        exclusions,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn collect_rust_files_from_directory(
    directory: &File,
    relative_directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    entries: &mut usize,
    retained_path_bytes: &mut usize,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<()> {
    if depth > limits.max_depth {
        bail!("semantic repository scan exceeded its directory depth limit");
    }
    let mut names = Vec::new();
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let children = fs::read_dir(&descriptor_path)
        .context("failed to enumerate semantic repository directory")?;
    for child in children {
        let child = child.context("failed to enumerate semantic repository entry")?;
        *entries = entries
            .checked_add(1)
            .context("semantic repository entry count overflow")?;
        if *entries > limits.max_entries {
            bail!("semantic repository scan exceeded its entry limit");
        }
        names.push(child.file_name());
    }
    names.sort();

    for name in names {
        let relative = bounded_semantic_child_path(relative_directory, Path::new(&name), limits)?;
        if is_ignored_path(&relative) {
            continue;
        }
        let name_c = std::ffi::CString::new(name.as_bytes())
            .context("semantic repository entry name contains a NUL byte")?;
        let stat = semantic_fstatat_no_follow(directory.as_raw_fd(), &name_c)?;
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                if exclusions.skips_directory(&relative) {
                    continue;
                }
                if depth >= limits.max_depth {
                    bail!("semantic repository scan exceeded its directory depth limit");
                }
                let child = open_semantic_child_directory(directory, &name_c, &stat)?;
                if nested_semantic_repository_marker_exists(&child)? {
                    continue;
                }
                collect_rust_files_from_directory(
                    &child,
                    &relative,
                    depth + 1,
                    files,
                    entries,
                    retained_path_bytes,
                    limits,
                    exclusions,
                )?;
            }
            libc::S_IFREG if has_rust_extension(&relative) => {
                if exclusions.skips_file(&relative) {
                    continue;
                }
                retain_semantic_path(files, relative, retained_path_bytes, limits)?;
            }
            libc::S_IFREG | libc::S_IFLNK => {}
            _ => {}
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_semantic_directory(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options
        .open(path)
        .context("failed to open semantic repository root without following links")
}

#[cfg(target_os = "linux")]
fn open_semantic_child_directory(
    parent: &File,
    name: &std::ffi::CStr,
    expected: &libc::stat,
) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open semantic repository directory safely");
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    let opened = directory
        .metadata()
        .context("failed to verify semantic repository directory")?;
    use std::os::unix::fs::MetadataExt;
    if opened.dev() != expected.st_dev
        || opened.ino() != expected.st_ino
        || opened.file_type().is_symlink()
        || !opened.is_dir()
    {
        bail!("semantic repository directory identity changed during traversal");
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn nested_semantic_repository_marker_exists(directory: &File) -> Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c".git".as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error).context("failed to probe nested semantic repository marker")
    }
}

fn semantic_fstatat_no_follow(fd: i32, name: &std::ffi::CStr) -> Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect semantic repository entry safely");
    }
    Ok(unsafe { stat.assume_init() })
}

#[cfg(not(target_os = "linux"))]
fn collect_rust_files_bounded(
    root: &Path,
    files: &mut Vec<PathBuf>,
    entries: &mut usize,
    retained_path_bytes: &mut usize,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<()> {
    collect_rust_files_portable(
        root,
        root,
        0,
        files,
        entries,
        retained_path_bytes,
        limits,
        exclusions,
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn collect_rust_files_portable(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    entries: &mut usize,
    retained_path_bytes: &mut usize,
    limits: SemanticScanLimits,
    exclusions: SemanticScanExclusions<'_>,
) -> Result<()> {
    if depth > limits.max_depth {
        bail!("semantic repository scan exceeded its directory depth limit");
    }
    let metadata = fs::symlink_metadata(directory)
        .context("failed to inspect semantic repository directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("semantic repository traversal encountered an unsafe directory");
    }
    let mut children = Vec::new();
    for child in fs::read_dir(directory).context("failed to read semantic repository directory")? {
        let child = child.context("failed to read semantic repository entry")?;
        *entries = entries
            .checked_add(1)
            .context("semantic repository entry count overflow")?;
        if *entries > limits.max_entries {
            bail!("semantic repository scan exceeded its entry limit");
        }
        children.push(child);
    }
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let child_name = child.file_name();
        let relative_directory = directory
            .strip_prefix(root)
            .context("failed to relativize semantic repository directory")?;
        let relative =
            bounded_semantic_child_path(relative_directory, Path::new(&child_name), limits)?;
        let path = root.join(&relative);
        if is_ignored_path(&relative) {
            continue;
        }
        let metadata =
            fs::symlink_metadata(&path).context("failed to inspect semantic repository entry")?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if exclusions.skips_directory(&relative) {
                continue;
            }
            if depth > 0 || !relative.as_os_str().is_empty() {
                match fs::symlink_metadata(path.join(".git")) {
                    Ok(_) => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error)
                            .context("failed to probe nested semantic repository marker");
                    }
                }
            }
            collect_rust_files_portable(
                root,
                &path,
                depth + 1,
                files,
                entries,
                retained_path_bytes,
                limits,
                exclusions,
            )?;
        } else if metadata.is_file() && has_rust_extension(&relative) {
            if exclusions.skips_file(&relative) {
                continue;
            }
            retain_semantic_path(files, relative, retained_path_bytes, limits)?;
        }
    }
    Ok(())
}

fn scan_rust_file(
    root: &Path,
    file: &Path,
    repository_files: &[PathBuf],
    map: &mut SemanticRepoMap,
    total_source_bytes: &mut u64,
    limits: SemanticScanLimits,
) -> Result<()> {
    let source = match read_semantic_source(root, file, limits.max_file_bytes) {
        Ok(source) => source,
        Err(_) => {
            map.errors.push(SemanticScanError {
                file: file.to_path_buf(),
                kind: SemanticScanErrorKind::Read,
                message: "source file was refused by bounded no-follow UTF-8 scan limits"
                    .to_string(),
                span: None,
            });
            return Ok(());
        }
    };
    let source_bytes = u64::try_from(source.len()).unwrap_or(u64::MAX);
    let new_total = total_source_bytes
        .checked_add(source_bytes)
        .context("semantic repository source aggregate byte count overflowed")?;
    if new_total > limits.max_total_bytes {
        bail!("semantic repository source aggregate byte limit was exceeded");
    }
    *total_source_bytes = new_total;

    let module_path = module_path_for_file(file);
    map.files.push(SemanticFile {
        path: file.to_path_buf(),
        module_path: module_path.clone(),
        byte_len: source.len(),
        line_count: line_count(&source),
    });

    let source_index = SourceIndex::new(&source);
    let syntax = match syn::parse_file(&source) {
        Ok(syntax) => syntax,
        Err(error) => {
            map.errors.push(SemanticScanError {
                file: file.to_path_buf(),
                kind: SemanticScanErrorKind::Parse,
                message: error.to_string(),
                span: Some(source_index.span(error.span())),
            });
            return Ok(());
        }
    };

    let mut scanner = FileScanner {
        file,
        repository_files,
        source_index,
        symbols: &mut map.symbols,
        imports: &mut map.imports,
        re_exports: &mut map.re_exports,
        dependencies: &mut map.dependencies,
    };
    scanner.scan_items(&syntax.items, &module_path, None);
    Ok(())
}

fn read_semantic_source(root: &Path, file: &Path, max_bytes: u64) -> Result<String> {
    BoundedRegularReader::read_relative_utf8(root, file, max_bytes)
}

fn bounded_semantic_child_path(
    parent: &Path,
    child: &Path,
    limits: SemanticScanLimits,
) -> Result<PathBuf> {
    let separator_bytes = usize::from(!parent.as_os_str().is_empty());
    let path_bytes = parent
        .as_os_str()
        .len()
        .checked_add(separator_bytes)
        .and_then(|bytes| bytes.checked_add(child.as_os_str().len()))
        .context("semantic repository path byte count overflow")?;
    if path_bytes > limits.max_path_bytes {
        bail!("semantic repository scan exceeded its relative path byte limit");
    }
    let path_components = parent
        .components()
        .count()
        .checked_add(child.components().count())
        .context("semantic repository path component count overflow")?;
    if path_components > limits.max_path_components {
        bail!("semantic repository scan exceeded its relative path component limit");
    }
    Ok(parent.join(child))
}

fn retain_semantic_path(
    files: &mut Vec<PathBuf>,
    path: PathBuf,
    retained_path_bytes: &mut usize,
    limits: SemanticScanLimits,
) -> Result<()> {
    let new_total = retained_path_bytes
        .checked_add(path.as_os_str().len())
        .context("semantic repository retained path byte count overflow")?;
    if new_total > limits.max_retained_path_bytes {
        bail!("semantic repository scan exceeded its retained path byte limit");
    }
    *retained_path_bytes = new_total;
    files.push(path);
    Ok(())
}

struct FileScanner<'a> {
    file: &'a Path,
    repository_files: &'a [PathBuf],
    source_index: SourceIndex,
    symbols: &'a mut Vec<SemanticSymbol>,
    imports: &'a mut Vec<SemanticImport>,
    re_exports: &'a mut Vec<SemanticReExport>,
    dependencies: &'a mut Vec<SemanticDependency>,
}

impl FileScanner<'_> {
    fn scan_items(&mut self, items: &[Item], module_path: &[String], parent_symbol: Option<&str>) {
        for item in items {
            self.scan_item(item, module_path, parent_symbol);
        }
    }

    fn scan_item(&mut self, item: &Item, module_path: &[String], parent_symbol: Option<&str>) {
        match item {
            Item::Mod(item_mod) => {
                let name = item_mod.ident.to_string();
                let qualified_path = child_path(module_path, &name);
                let span = self.source_index.span(item_mod.span());
                let symbol_id = self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: qualified_path.clone(),
                    kind: SemanticSymbolKind::Module,
                    visibility: visibility_text(&item_mod.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span,
                });

                let dependency_kind = if item_mod.content.is_some() {
                    SemanticDependencyKind::InlineModule
                } else {
                    SemanticDependencyKind::ModuleDeclaration
                };
                self.dependencies.push(SemanticDependency {
                    from_file: self.file.to_path_buf(),
                    from_module: module_path.to_vec(),
                    to: qualified_path.join("::"),
                    to_file: if item_mod.content.is_some() {
                        None
                    } else {
                        resolve_module_file(
                            self.repository_files,
                            self.file,
                            &name,
                            module_path_attribute(&item_mod.attrs),
                        )
                    },
                    kind: dependency_kind,
                    span,
                });

                if let Some((_, items)) = &item_mod.content {
                    self.scan_items(items, &qualified_path, Some(&symbol_id));
                }
            }
            Item::Fn(item_fn) => {
                let name = item_fn.sig.ident.to_string();
                self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: child_path(module_path, &name),
                    kind: SemanticSymbolKind::Function,
                    visibility: visibility_text(&item_fn.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_fn.span()),
                });
            }
            Item::Struct(item_struct) => {
                let name = item_struct.ident.to_string();
                self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: child_path(module_path, &name),
                    kind: SemanticSymbolKind::Struct,
                    visibility: visibility_text(&item_struct.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_struct.span()),
                });
            }
            Item::Enum(item_enum) => {
                let name = item_enum.ident.to_string();
                self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: child_path(module_path, &name),
                    kind: SemanticSymbolKind::Enum,
                    visibility: visibility_text(&item_enum.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_enum.span()),
                });
            }
            Item::Trait(item_trait) => {
                let name = item_trait.ident.to_string();
                let qualified_path = child_path(module_path, &name);
                let symbol_id = self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: qualified_path.clone(),
                    kind: SemanticSymbolKind::Trait,
                    visibility: visibility_text(&item_trait.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_trait.span()),
                });
                self.scan_trait_items(&item_trait.items, &qualified_path, &symbol_id);
            }
            Item::Impl(item_impl) => {
                let impl_target = type_to_string(&item_impl.self_ty);
                let impl_trait = item_impl
                    .trait_
                    .as_ref()
                    .map(|(_, path, _)| path_to_string(path));
                let name = match &impl_trait {
                    Some(trait_name) => format!("impl {trait_name} for {impl_target}"),
                    None => format!("impl {impl_target}"),
                };
                let qualified_path = child_path(module_path, &name);
                let span = self.source_index.span(item_impl.span());
                let symbol_id = self.push_symbol(SymbolInput {
                    name,
                    qualified_path: qualified_path.clone(),
                    kind: SemanticSymbolKind::Impl,
                    visibility: "inherent".to_string(),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: Some(impl_target.clone()),
                    impl_trait: impl_trait.clone(),
                    span,
                });
                self.scan_impl_items(
                    &item_impl.items,
                    &qualified_path,
                    &symbol_id,
                    &impl_target,
                    impl_trait,
                );
            }
            Item::Const(item_const) => {
                let name = item_const.ident.to_string();
                self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: child_path(module_path, &name),
                    kind: SemanticSymbolKind::Const,
                    visibility: visibility_text(&item_const.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_const.span()),
                });
            }
            Item::Type(item_type) => {
                let name = item_type.ident.to_string();
                self.push_symbol(SymbolInput {
                    name: name.clone(),
                    qualified_path: child_path(module_path, &name),
                    kind: SemanticSymbolKind::TypeAlias,
                    visibility: visibility_text(&item_type.vis),
                    parent_symbol: parent_symbol.map(str::to_string),
                    impl_target: None,
                    impl_trait: None,
                    span: self.source_index.span(item_type.span()),
                });
            }
            Item::Use(item_use) => {
                self.scan_use_tree(&item_use.tree, &item_use.vis, module_path, item_use.span());
            }
            _ => {}
        }
    }

    fn scan_trait_items(&mut self, items: &[TraitItem], trait_path: &[String], trait_symbol: &str) {
        for item in items {
            match item {
                TraitItem::Fn(item_fn) => {
                    let name = item_fn.sig.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(trait_path, &name),
                        kind: SemanticSymbolKind::Method,
                        visibility: "trait".to_string(),
                        parent_symbol: Some(trait_symbol.to_string()),
                        impl_target: None,
                        impl_trait: Some(trait_path.join("::")),
                        span: self.source_index.span(item_fn.span()),
                    });
                }
                TraitItem::Const(item_const) => {
                    let name = item_const.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(trait_path, &name),
                        kind: SemanticSymbolKind::Const,
                        visibility: "trait".to_string(),
                        parent_symbol: Some(trait_symbol.to_string()),
                        impl_target: None,
                        impl_trait: Some(trait_path.join("::")),
                        span: self.source_index.span(item_const.span()),
                    });
                }
                TraitItem::Type(item_type) => {
                    let name = item_type.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(trait_path, &name),
                        kind: SemanticSymbolKind::TypeAlias,
                        visibility: "trait".to_string(),
                        parent_symbol: Some(trait_symbol.to_string()),
                        impl_target: None,
                        impl_trait: Some(trait_path.join("::")),
                        span: self.source_index.span(item_type.span()),
                    });
                }
                _ => {}
            }
        }
    }

    fn scan_impl_items(
        &mut self,
        items: &[ImplItem],
        impl_path: &[String],
        impl_symbol: &str,
        impl_target: &str,
        impl_trait: Option<String>,
    ) {
        for item in items {
            match item {
                ImplItem::Fn(item_fn) => {
                    let name = item_fn.sig.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(impl_path, &name),
                        kind: SemanticSymbolKind::Method,
                        visibility: visibility_text(&item_fn.vis),
                        parent_symbol: Some(impl_symbol.to_string()),
                        impl_target: Some(impl_target.to_string()),
                        impl_trait: impl_trait.clone(),
                        span: self.source_index.span(item_fn.span()),
                    });
                }
                ImplItem::Const(item_const) => {
                    let name = item_const.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(impl_path, &name),
                        kind: SemanticSymbolKind::Const,
                        visibility: visibility_text(&item_const.vis),
                        parent_symbol: Some(impl_symbol.to_string()),
                        impl_target: Some(impl_target.to_string()),
                        impl_trait: impl_trait.clone(),
                        span: self.source_index.span(item_const.span()),
                    });
                }
                ImplItem::Type(item_type) => {
                    let name = item_type.ident.to_string();
                    self.push_symbol(SymbolInput {
                        name: name.clone(),
                        qualified_path: child_path(impl_path, &name),
                        kind: SemanticSymbolKind::TypeAlias,
                        visibility: "inherited".to_string(),
                        parent_symbol: Some(impl_symbol.to_string()),
                        impl_target: Some(impl_target.to_string()),
                        impl_trait: impl_trait.clone(),
                        span: self.source_index.span(item_type.span()),
                    });
                }
                _ => {}
            }
        }
    }

    fn scan_use_tree(
        &mut self,
        tree: &UseTree,
        visibility: &Visibility,
        module_path: &[String],
        span: Span,
    ) {
        let span = self.source_index.span(span);
        let visibility_text = visibility_text(visibility);
        let imports = flatten_use_tree(tree);
        for import in imports {
            let to_file = resolve_import_file(self.repository_files, module_path, &import.path);
            self.imports.push(SemanticImport {
                file: self.file.to_path_buf(),
                module_path: module_path.to_vec(),
                path: import.path.clone(),
                alias: import.alias.clone(),
                glob: import.glob,
                visibility: visibility_text.clone(),
                span,
            });
            if !matches!(visibility, Visibility::Inherited) {
                self.re_exports.push(SemanticReExport {
                    file: self.file.to_path_buf(),
                    module_path: module_path.to_vec(),
                    path: import.path.clone(),
                    alias: import.alias.clone(),
                    glob: import.glob,
                    visibility: visibility_text.clone(),
                    span,
                });
            }
            self.dependencies.push(SemanticDependency {
                from_file: self.file.to_path_buf(),
                from_module: module_path.to_vec(),
                to: import.path,
                to_file,
                kind: SemanticDependencyKind::Import,
                span,
            });
        }
    }

    fn push_symbol(&mut self, input: SymbolInput) -> String {
        let id = symbol_id(self.file, input.kind, &input.qualified_path, input.span);
        self.symbols.push(SemanticSymbol {
            id: id.clone(),
            file: self.file.to_path_buf(),
            name: input.name,
            qualified_path: input.qualified_path,
            kind: input.kind,
            visibility: input.visibility,
            parent_symbol: input.parent_symbol,
            impl_target: input.impl_target,
            impl_trait: input.impl_trait,
            span: input.span,
        });
        id
    }
}

struct SymbolInput {
    name: String,
    qualified_path: Vec<String>,
    kind: SemanticSymbolKind,
    visibility: String,
    parent_symbol: Option<String>,
    impl_target: Option<String>,
    impl_trait: Option<String>,
    span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UseImport {
    path: String,
    alias: Option<String>,
    glob: bool,
}

#[derive(Debug, Clone)]
struct SourceIndex {
    source: String,
    line_starts: Vec<usize>,
}

impl SourceIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (index, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(index + 1);
            }
        }

        Self {
            source: source.to_string(),
            line_starts,
        }
    }

    fn span(&self, span: Span) -> SourceSpan {
        let start = span.start();
        let end = span.end();
        let start_byte = self.offset(start);
        let end_byte = self.offset(end).max(start_byte);
        let start_line = start.line;
        let end_line = end.line.max(start.line);
        SourceSpan {
            start_byte,
            end_byte,
            start_line,
            end_line,
            signature_end_line: self.signature_end_line(start_byte, end_byte, start_line),
        }
    }

    fn signature_end_line(&self, start_byte: usize, end_byte: usize, start_line: usize) -> usize {
        let snippet = self.source.get(start_byte..end_byte).unwrap_or_default();
        for (offset, line) in snippet.split_inclusive('\n').enumerate() {
            if line.contains('{') || line.contains(';') {
                return start_line.saturating_add(offset);
            }
        }
        start_line
    }

    fn offset(&self, location: LineColumn) -> usize {
        if location.line == 0 {
            return 0;
        }

        let line_index = location.line.saturating_sub(1);
        let line_start = self
            .line_starts
            .get(line_index)
            .copied()
            .unwrap_or(self.source.len());
        let line_end = self
            .line_starts
            .get(line_index + 1)
            .copied()
            .unwrap_or(self.source.len());
        let line = self.source.get(line_start..line_end).unwrap_or_default();
        // proc-macro2 LineColumn::column counts UTF-8 characters, not bytes.
        let byte_in_line = line
            .char_indices()
            .nth(location.column)
            .map(|(index, _)| index)
            .unwrap_or(line.len());
        line_start
            .saturating_add(byte_in_line)
            .min(self.source.len())
    }
}

fn flatten_use_tree(tree: &UseTree) -> Vec<UseImport> {
    let mut imports = Vec::new();
    collect_use_tree(tree, Vec::new(), &mut imports);
    imports.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.alias.cmp(&right.alias))
            .then_with(|| left.glob.cmp(&right.glob))
    });
    imports
}

fn collect_use_tree(tree: &UseTree, prefix: Vec<String>, imports: &mut Vec<UseImport>) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            collect_use_tree(&path.tree, next, imports);
        }
        UseTree::Name(name) => {
            imports.push(UseImport {
                path: use_path_with_ident(&prefix, &name.ident.to_string()),
                alias: None,
                glob: false,
            });
        }
        UseTree::Rename(rename) => {
            imports.push(UseImport {
                path: use_path_with_ident(&prefix, &rename.ident.to_string()),
                alias: Some(rename.rename.to_string()),
                glob: false,
            });
        }
        UseTree::Glob(_) => {
            imports.push(UseImport {
                path: prefix.join("::"),
                alias: None,
                glob: true,
            });
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix.clone(), imports);
            }
        }
    }
}

fn use_path_with_ident(prefix: &[String], ident: &str) -> String {
    if ident == "self" {
        if prefix.is_empty() {
            ident.to_string()
        } else {
            prefix.join("::")
        }
    } else {
        let mut path = prefix.to_vec();
        path.push(ident.to_string());
        path.join("::")
    }
}

fn resolve_module_file(
    repository_files: &[PathBuf],
    file: &Path,
    module_name: &str,
    path_attribute: Option<String>,
) -> Option<PathBuf> {
    if let Some(path_attribute) = path_attribute {
        return resolve_path_attribute_file(repository_files, file, &path_attribute);
    }

    let base = module_base_path(file);
    let flat = base.join(format!("{module_name}.rs"));
    if repository_files.binary_search(&flat).is_ok() {
        return Some(flat);
    }

    let nested = base.join(module_name).join("mod.rs");
    if repository_files.binary_search(&nested).is_ok() {
        return Some(nested);
    }

    None
}

fn module_path_attribute(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }

        match &attr.meta {
            Meta::NameValue(meta) => match &meta.value {
                Expr::Lit(expr_lit) => match &expr_lit.lit {
                    Lit::Str(value) => Some(value.value()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    })
}

fn resolve_path_attribute_file(
    repository_files: &[PathBuf],
    file: &Path,
    path_attribute: &str,
) -> Option<PathBuf> {
    let base = file.parent().unwrap_or_else(|| Path::new(""));
    let candidate = normalize_relative_path(&base.join(path_attribute));
    if repository_files.binary_search(&candidate).is_ok() {
        Some(candidate)
    } else {
        None
    }
}

fn resolve_import_file(
    repository_files: &[PathBuf],
    module_path: &[String],
    import_path: &str,
) -> Option<PathBuf> {
    let absolute_path = absolute_import_path(module_path, import_path)?;
    resolve_module_segments(repository_files, &absolute_path)
}

fn absolute_import_path(module_path: &[String], import_path: &str) -> Option<Vec<String>> {
    let mut segments = import_path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let first = segments.first()?.as_str();

    match first {
        "crate" => Some(segments),
        "self" => {
            segments.remove(0);
            let mut absolute = module_path.to_vec();
            absolute.extend(segments);
            Some(absolute)
        }
        "super" => {
            let mut absolute = module_path.to_vec();
            while segments.first().is_some_and(|segment| segment == "super") {
                if absolute.len() > 1 {
                    absolute.pop();
                }
                segments.remove(0);
            }
            absolute.extend(segments);
            Some(absolute)
        }
        _ => None,
    }
}

fn resolve_module_segments(
    repository_files: &[PathBuf],
    absolute_path: &[String],
) -> Option<PathBuf> {
    if absolute_path.first().map(String::as_str) != Some("crate") {
        return None;
    }

    for end in (1..=absolute_path.len()).rev() {
        if let Some(file) = module_segments_to_file(repository_files, &absolute_path[..end]) {
            return Some(file);
        }
    }

    None
}

fn module_segments_to_file(repository_files: &[PathBuf], segments: &[String]) -> Option<PathBuf> {
    if segments.first().map(String::as_str) != Some("crate") {
        return None;
    }

    if segments.len() == 1 {
        for candidate in [PathBuf::from("src/lib.rs"), PathBuf::from("src/main.rs")] {
            if repository_files.binary_search(&candidate).is_ok() {
                return Some(candidate);
            }
        }
        return None;
    }

    let module_segments = &segments[1..];
    let mut flat = PathBuf::from("src");
    for segment in module_segments {
        flat.push(segment);
    }
    flat.set_extension("rs");
    if repository_files.binary_search(&flat).is_ok() {
        return Some(flat);
    }

    let mut nested = PathBuf::from("src");
    for segment in module_segments {
        nested.push(segment);
    }
    nested.push("mod.rs");
    if repository_files.binary_search(&nested).is_ok() {
        return Some(nested);
    }

    None
}

fn module_base_path(file: &Path) -> PathBuf {
    match file.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => {
            file.parent().unwrap_or_else(|| Path::new("")).to_path_buf()
        }
        _ => file.with_extension(""),
    }
}

fn module_path_for_file(file: &Path) -> Vec<String> {
    let mut parts = Vec::new();
    let mut components = file
        .components()
        .filter_map(|component| component.as_os_str().to_str().map(str::to_string))
        .collect::<Vec<_>>();

    let under_src = components
        .first()
        .is_some_and(|component| component == "src");
    if under_src {
        parts.push("crate".to_string());
        components.remove(0);
    }

    if let Some(last) = components.last_mut() {
        if let Some(stripped) = last.strip_suffix(".rs") {
            *last = stripped.to_string();
        }
    }

    let last_index = components.len().saturating_sub(1);
    for (index, component) in components.into_iter().enumerate() {
        // Only the file-stem component is a crate root alias. Directories named
        // lib/main/mod are real modules and must stay in the path.
        if index == last_index && matches!(component.as_str(), "lib" | "main" | "mod") {
            continue;
        }
        parts.push(component);
    }

    if parts.is_empty() {
        parts.push("crate".to_string());
    }

    parts
}

fn symbol_id(
    file: &Path,
    kind: SemanticSymbolKind,
    qualified_path: &[String],
    span: SourceSpan,
) -> String {
    format!(
        "{}:{}:{}:{}",
        path_key(file),
        span.start_byte,
        kind.as_str(),
        qualified_path.join("::")
    )
}

impl SemanticSymbolKind {
    fn as_str(self) -> &'static str {
        match self {
            SemanticSymbolKind::Module => "module",
            SemanticSymbolKind::Function => "function",
            SemanticSymbolKind::Struct => "struct",
            SemanticSymbolKind::Enum => "enum",
            SemanticSymbolKind::Trait => "trait",
            SemanticSymbolKind::Impl => "impl",
            SemanticSymbolKind::Method => "method",
            SemanticSymbolKind::Const => "const",
            SemanticSymbolKind::TypeAlias => "type_alias",
        }
    }
}

fn child_path(parent: &[String], child: &str) -> Vec<String> {
    let mut path = parent.to_vec();
    path.push(child.to_string());
    path
}

fn path_to_string(path: &syn::Path) -> String {
    let mut value = String::new();
    if path.leading_colon.is_some() {
        value.push_str("::");
    }
    value.push_str(
        &path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
    );
    value
}

fn type_to_string(ty: &syn::Type) -> String {
    ty.to_token_stream().to_string()
}

fn visibility_text(visibility: &Visibility) -> String {
    match visibility {
        Visibility::Public(_) => "public".to_string(),
        Visibility::Restricted(restricted) => {
            let path = restricted.path.to_token_stream().to_string();
            if path == "crate" {
                "crate".to_string()
            } else {
                format!("restricted({path})")
            }
        }
        Visibility::Inherited => "private".to_string(),
    }
}

fn has_rust_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "rs")
}

fn is_ignored_path(path: &Path) -> bool {
    crate::repo_map::is_ignored_scan_path(path)
}

fn normalize_query_path(root: &Path, path: &Path) -> PathBuf {
    let repo_relative = if path.is_absolute() {
        path.strip_prefix(root).unwrap_or(path)
    } else {
        path
    };
    normalize_relative_path(repo_relative)
}

fn normalize_relative_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn line_count(source: &str) -> usize {
    if source.is_empty() {
        0
    } else {
        source.bytes().filter(|byte| *byte == b'\n').count() + 1
    }
}

fn sort_map(map: &mut SemanticRepoMap) {
    map.files.sort_by(|left, right| left.path.cmp(&right.path));
    map.symbols.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.qualified_path.cmp(&right.qualified_path))
            .then_with(|| left.name.cmp(&right.name))
    });
    map.imports.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.alias.cmp(&right.alias))
            .then_with(|| left.glob.cmp(&right.glob))
    });
    map.re_exports.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.alias.cmp(&right.alias))
            .then_with(|| left.glob.cmp(&right.glob))
    });
    map.dependencies.sort_by(|left, right| {
        left.from_file
            .cmp(&right.from_file)
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.to.cmp(&right.to))
            .then_with(|| left.to_file.cmp(&right.to_file))
    });
    map.errors.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.span.cmp(&right.span))
            .then_with(|| left.message.cmp(&right.message))
    });
}

fn path_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir_all(&repo_path).expect("create repo dir");
        Repository::init(&repo_path).expect("init repo");
        (temp, repo_path)
    }

    fn write_file(repo: &Path, path: &str, contents: &str) {
        let full_path = repo.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(full_path, contents).expect("write file");
    }

    fn symbols_of_kind(map: &SemanticRepoMap, kind: SemanticSymbolKind) -> Vec<&SemanticSymbol> {
        map.symbols
            .iter()
            .filter(|symbol| symbol.kind == kind)
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn semantic_scan_skips_links_fifo_and_external_escape_without_reading_contents() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let (temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn local() {}\n");
        let external = temp.path().join("external");
        fs::create_dir(&external).expect("create external directory");
        fs::write(
            external.join("secret.rs"),
            "pub fn ultra_secret_external_contents() {}\n",
        )
        .expect("write external secret");
        symlink(&external, repo.join("src/escape")).expect("create directory escape");
        symlink(
            external.join("secret.rs"),
            repo.join("src/external-link.rs"),
        )
        .expect("create file escape");
        let fifo = repo.join("src/nonregular.rs");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let map = scan_repository(&repo).expect("bounded semantic scan");

        assert_eq!(
            map.files
                .iter()
                .map(|file| file.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("src/lib.rs")]
        );
        assert!(map
            .symbols
            .iter()
            .all(|symbol| symbol.name != "ultra_secret_external_contents"));
        assert!(map
            .errors
            .iter()
            .all(|error| !error.message.contains("ultra_secret_external_contents")));
    }

    #[test]
    fn semantic_scan_bounds_huge_invalid_utf8_aggregate_entries_and_depth() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/a.rs", "pub fn a() {}\n");
        write_file(&repo, "src/b.rs", "pub fn b() {}\n");
        let huge = repo.join("src/huge.rs");
        File::create(&huge)
            .expect("create sparse huge source")
            .set_len(MAX_SEMANTIC_FILE_BYTES + 1)
            .expect("size sparse huge source");
        fs::write(repo.join("src/invalid.rs"), [0xff, 0xfe]).expect("write invalid UTF-8");

        let default_map = scan_repository(&repo).expect("default bounded scan");
        for refused in ["src/huge.rs", "src/invalid.rs"] {
            assert!(default_map.errors.iter().any(|error| {
                error.file == Path::new(refused) && error.kind == SemanticScanErrorKind::Read
            }));
        }
        assert!(default_map.errors.iter().all(|error| {
            !error.message.contains(repo.to_string_lossy().as_ref())
                && !error.message.contains("pub fn")
        }));

        let aggregate = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_file_bytes: 64,
                max_total_bytes: 16,
                max_entries: 100,
                max_depth: 16,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("aggregate source budget must fail closed");
        assert!(aggregate.to_string().contains("aggregate byte limit"));

        let entries = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_file_bytes: 64,
                max_total_bytes: 1024,
                max_entries: 2,
                max_depth: 16,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("entry budget must fail closed");
        assert!(entries.to_string().contains("entry limit"));

        let nested = repo.join("deep/a/b");
        fs::create_dir_all(&nested).expect("create deep tree");
        fs::write(nested.join("deep.rs"), "pub fn deep() {}\n").expect("write deep source");
        let depth = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_file_bytes: 64,
                max_total_bytes: 1024,
                max_entries: 100,
                max_depth: 1,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("depth budget must fail closed");
        assert!(depth.to_string().contains("depth limit"));
    }

    #[test]
    fn nested_repository_trees_do_not_spend_entry_depth_byte_or_parse_budgets() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn outer() {}\n");

        let nested = repo.join("vendor/sdk");
        fs::create_dir_all(nested.join("src")).expect("nested tree");
        Repository::init(&nested).expect("init nested repository");
        write_file(
            &repo,
            "vendor/sdk/src/excluded.rs",
            "pub fn nested_only() {}\n",
        );
        let huge = repo.join("vendor/sdk/src/huge.rs");
        File::create(&huge)
            .expect("create nested huge source")
            .set_len(MAX_SEMANTIC_FILE_BYTES + 1)
            .expect("size nested huge source");

        let probed = scan_repository(&repo).expect("nested git trees must be skipped before parse");
        assert_eq!(
            probed
                .files
                .iter()
                .map(|file| file.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("src/lib.rs")]
        );
        assert!(probed
            .symbols
            .iter()
            .all(|symbol| symbol.name != "nested_only"));
        assert!(probed
            .errors
            .iter()
            .all(|error| !error.file.starts_with("vendor/sdk")));

        for index in 0..32 {
            write_file(
                &repo,
                &format!("bulk/src/file_{index}.rs"),
                &format!("pub fn bulk_{index}() {{}}\n"),
            );
        }
        let tight = SemanticScanLimits {
            max_file_bytes: 64,
            max_total_bytes: 256,
            max_entries: 12,
            max_depth: 3,
            max_path_bytes: 64,
            max_path_components: 8,
            max_retained_path_bytes: 256,
        };
        scan_repository_with_limits(&repo, tight)
            .expect_err("unexcluded sibling trees must still spend the entry budget");

        let allowed = BTreeSet::from([PathBuf::from("src/lib.rs")]);
        let allowed_map = scan_repository_with_limits_and_exclusions(
            &repo,
            tight,
            SemanticScanExclusions {
                allowed_files: Some(&allowed),
                nested_repository_boundaries: &[],
            },
        )
        .expect("allowed-file exclusions must skip unlisted trees before budget spend");
        assert_eq!(
            allowed_map
                .files
                .iter()
                .map(|file| file.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("src/lib.rs")]
        );

        let boundary_map = scan_repository_with_limits_and_exclusions(
            &repo,
            tight,
            SemanticScanExclusions {
                allowed_files: None,
                nested_repository_boundaries: &[PathBuf::from("bulk")],
            },
        )
        .expect("named nested-boundary exclusions must skip the tree before budget spend");
        assert!(boundary_map
            .files
            .iter()
            .all(|file| !file.path.starts_with("bulk")));
    }

    #[test]
    fn semantic_scan_bounds_relative_and_retained_path_memory() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/a.rs", "pub fn a() {}\n");
        write_file(&repo, "src/b.rs", "pub fn b() {}\n");

        let path_bytes = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_path_bytes: 7,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("relative path byte budget must fail closed");
        assert!(path_bytes.to_string().contains("relative path byte limit"));

        let components = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_path_components: 1,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("relative path component budget must fail closed");
        assert!(components
            .to_string()
            .contains("relative path component limit"));

        let retained = scan_repository_with_limits(
            &repo,
            SemanticScanLimits {
                max_retained_path_bytes: 10,
                ..DEFAULT_SEMANTIC_SCAN_LIMITS
            },
        )
        .expect_err("retained path byte budget must fail closed");
        assert!(retained.to_string().contains("retained path byte limit"));
    }

    #[test]
    fn captures_modules_and_module_dependencies() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub mod api;
mod inline {
    pub fn nested() {}
}
"#,
        );
        write_file(&repo, "src/api.rs", "pub fn endpoint() {}\n");

        let map = scan_repository(&repo).expect("scan");
        let modules = symbols_of_kind(&map, SemanticSymbolKind::Module);

        assert_eq!(
            modules
                .iter()
                .map(|symbol| symbol.qualified_path.join("::"))
                .collect::<Vec<_>>(),
            vec!["crate::api", "crate::inline"]
        );
        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::ModuleDeclaration
                && dependency.to == "crate::api"
                && dependency.to_file == Some(PathBuf::from("src/api.rs"))
        }));
        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::InlineModule
                && dependency.to == "crate::inline"
        }));
        assert!(map.symbols.iter().any(|symbol| {
            symbol.kind == SemanticSymbolKind::Function
                && symbol.qualified_path == vec!["crate", "inline", "nested"]
                && symbol.parent_symbol.as_deref() == Some(&modules[1].id)
        }));
    }

    #[test]
    fn resolves_path_attributed_module_declarations() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
#[path = "generated/api_surface.rs"]
pub mod api;
"#,
        );
        write_file(
            &repo,
            "src/generated/api_surface.rs",
            "pub fn endpoint() {}\n",
        );

        let map = scan_repository(&repo).expect("scan");

        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::ModuleDeclaration
                && dependency.to == "crate::api"
                && dependency.to_file == Some(PathBuf::from("src/generated/api_surface.rs"))
        }));
    }

    #[test]
    fn captures_traits_impls_and_methods() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub trait Service {
    type Error;
    const VERSION: usize;
    fn run(&self);
}

pub struct Worker;

impl Service for Worker {
    type Error = ();
    const VERSION: usize = 1;
    fn run(&self) {}
}

impl Worker {
    pub fn new() -> Self { Worker }
    fn hidden(&self) {}
}
"#,
        );

        let map = scan_repository(&repo).expect("scan");
        let impls = symbols_of_kind(&map, SemanticSymbolKind::Impl);
        let methods = symbols_of_kind(&map, SemanticSymbolKind::Method);

        assert!(map.symbols.iter().any(|symbol| {
            symbol.kind == SemanticSymbolKind::Trait
                && symbol.name == "Service"
                && symbol.visibility == "public"
        }));
        assert!(impls.iter().any(|symbol| {
            symbol.impl_target.as_deref() == Some("Worker")
                && symbol.impl_trait.as_deref() == Some("Service")
        }));
        assert!(impls
            .iter()
            .any(|symbol| symbol.impl_target.as_deref() == Some("Worker")
                && symbol.impl_trait.is_none()));
        assert!(methods.iter().any(|symbol| {
            symbol.name == "new"
                && symbol.visibility == "public"
                && symbol.impl_target.as_deref() == Some("Worker")
                && symbol.parent_symbol.is_some()
        }));
        assert!(methods
            .iter()
            .any(|symbol| symbol.name == "run" && symbol.impl_trait.as_deref() == Some("Service")));
    }

    #[test]
    fn captures_imports_re_exports_and_import_dependencies() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub mod api;
use std::{collections::BTreeMap as Map, fmt::Display};
pub use crate::api::{self as api_mod, endpoint};
pub(crate) use crate::api as api_mod;
"#,
        );
        write_file(
            &repo,
            "src/api.rs",
            r#"
pub mod inner;
pub use self::inner::Helper;
pub fn endpoint() {}
"#,
        );
        write_file(&repo, "src/api/inner.rs", "pub struct Helper;\n");

        let map = scan_repository(&repo).expect("scan");

        assert!(map.imports.iter().any(|import| {
            import.path == "crate::api"
                && import.alias.as_deref() == Some("api_mod")
                && import.visibility == "public"
        }));
        assert!(map.imports.iter().any(|import| {
            import.path == "crate::api::endpoint"
                && import.alias.is_none()
                && import.visibility == "public"
        }));
        assert!(map.imports.iter().any(|import| {
            import.path == "self::inner::Helper"
                && import.alias.is_none()
                && import.visibility == "public"
        }));
        assert!(map.re_exports.iter().any(|export| {
            export.path == "crate::api" && export.alias.as_deref() == Some("api_mod")
        }));
        assert!(map
            .re_exports
            .iter()
            .any(|export| { export.path == "crate::api::endpoint" && export.alias.is_none() }));
        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::Import
                && dependency.to == "std::collections::BTreeMap"
                && dependency.to_file.is_none()
        }));
        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::Import
                && dependency.to == "crate::api::endpoint"
                && dependency.to_file == Some(PathBuf::from("src/api.rs"))
        }));
        assert!(map.dependencies.iter().any(|dependency| {
            dependency.kind == SemanticDependencyKind::Import
                && dependency.to == "self::inner::Helper"
                && dependency.to_file == Some(PathBuf::from("src/api/inner.rs"))
        }));
    }

    #[test]
    fn risk_report_lists_touched_symbols_and_dependency_impact() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub mod api;
pub use crate::api::endpoint;
"#,
        );
        write_file(
            &repo,
            "src/api.rs",
            r#"
pub struct Api;
pub fn endpoint() {}
"#,
        );

        let map = scan_repository(&repo).expect("scan");
        let report = risk_report_for_paths(&map, [PathBuf::from("src/api.rs")]);

        assert_eq!(report.changed_paths, vec![PathBuf::from("src/api.rs")]);
        assert_eq!(
            report
                .touched_symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Api", "endpoint"]
        );
        assert_eq!(report.impacted_files, vec![PathBuf::from("src/lib.rs")]);
        assert!(report.dependency_impacts.iter().any(|impact| {
            impact.direction == SemanticDependencyDirection::Incoming
                && impact.changed_path == Path::new("src/api.rs")
                && impact.related_file.as_deref() == Some(Path::new("src/lib.rs"))
                && impact.dependency.kind == SemanticDependencyKind::ModuleDeclaration
        }));
        assert!(report.dependency_impacts.iter().any(|impact| {
            impact.direction == SemanticDependencyDirection::Incoming
                && impact.dependency.kind == SemanticDependencyKind::Import
                && impact.dependency.to == "crate::api::endpoint"
        }));
    }

    #[test]
    fn scans_rust_files_in_deterministic_order_and_ignores_local_state() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/z.rs", "pub fn zed() {}\n");
        write_file(&repo, "src/a.rs", "pub fn alpha() {}\n");
        write_file(&repo, "target/generated.rs", "pub fn generated() {}\n");
        write_file(&repo, ".maco/state/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".maco-cache/generated.rs", "pub fn cached() {}\n");
        write_file(&repo, ".codex/session.rs", "pub fn session() {}\n");
        write_file(&repo, ".agent/temp/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agent/storage/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agents/temp/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agents/storage/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agents/live/claims/worker.rs", "pub fn live() {}\n");
        write_file(&repo, ".agents/docs/context.rs", "pub fn context() {}\n");

        let map = scan_repository(&repo).expect("scan");

        assert_eq!(
            map.files
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>(),
            vec![
                PathBuf::from(".agents/docs/context.rs"),
                PathBuf::from("src/a.rs"),
                PathBuf::from("src/z.rs")
            ]
        );
        assert_eq!(
            map.symbols
                .iter()
                .filter(|symbol| symbol.kind == SemanticSymbolKind::Function)
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            vec!["context", "alpha", "zed"]
        );
        assert!(map
            .symbols
            .iter()
            .all(|symbol| !matches!(symbol.name.as_str(), "cached" | "session" | "live")));
    }

    #[test]
    fn records_parse_errors_and_continues_scanning_other_files() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/bad.rs", "pub fn broken( {\n");
        write_file(&repo, "src/good.rs", "pub const OK: usize = 1;\n");

        let map = scan_repository(&repo).expect("scan");

        assert_eq!(map.errors.len(), 1);
        assert_eq!(map.errors[0].file, PathBuf::from("src/bad.rs"));
        assert_eq!(map.errors[0].kind, SemanticScanErrorKind::Parse);
        assert!(map.errors[0].span.is_some());
        assert!(map.symbols.iter().any(|symbol| {
            symbol.kind == SemanticSymbolKind::Const
                && symbol.name == "OK"
                && symbol.file == Path::new("src/good.rs")
        }));
    }

    #[test]
    fn source_spans_use_byte_offsets_on_non_ascii_lines() {
        let source = "/* héllo */ fn f() {}\nuse crate::api; /* café */\n";
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", source);

        let map = scan_repository(&repo).expect("scan");
        let function = map
            .symbols
            .iter()
            .find(|symbol| symbol.name == "f")
            .expect("function symbol");
        let import = map
            .imports
            .iter()
            .find(|import| import.path == "crate::api")
            .expect("import");

        let expected_fn = source.find("fn f() {}").expect("function text");
        let expected_use = source.find("use crate::api;").expect("import text");
        assert_eq!(function.span.start_byte, expected_fn);
        assert_eq!(
            &source[function.span.start_byte..function.span.end_byte],
            "fn f() {}"
        );
        assert_eq!(import.span.start_byte, expected_use);
        assert_eq!(
            &source[import.span.start_byte..import.span.end_byte],
            "use crate::api;"
        );
        assert!(source.is_char_boundary(function.span.start_byte));
        assert!(source.is_char_boundary(function.span.end_byte));
        assert!(source.is_char_boundary(import.span.start_byte));
        assert!(source.is_char_boundary(import.span.end_byte));
    }

    #[test]
    fn source_index_converts_char_columns_to_byte_offsets() {
        let source = "/* héllo */ fn f() {}\n";
        let index = SourceIndex::new(source);
        let start = source.find("fn").expect("fn");
        let location = LineColumn {
            line: 1,
            column: source[..start].chars().count(),
        };
        assert_eq!(index.offset(location), start);
        assert_eq!(
            index.offset(LineColumn {
                line: 1,
                column: source.chars().count() - 1
            }),
            source.len() - 1
        );
    }

    #[test]
    fn module_path_strips_lib_main_mod_only_from_the_file_stem() {
        assert_eq!(
            module_path_for_file(Path::new("src/lib.rs")),
            vec!["crate".to_string()]
        );
        assert_eq!(
            module_path_for_file(Path::new("src/main.rs")),
            vec!["crate".to_string()]
        );
        assert_eq!(
            module_path_for_file(Path::new("src/main/config.rs")),
            vec![
                "crate".to_string(),
                "main".to_string(),
                "config".to_string()
            ]
        );
        assert_eq!(
            module_path_for_file(Path::new("src/lib/helpers.rs")),
            vec![
                "crate".to_string(),
                "lib".to_string(),
                "helpers".to_string()
            ]
        );
        assert_eq!(
            module_path_for_file(Path::new("src/main/mod.rs")),
            vec!["crate".to_string(), "main".to_string()]
        );
        assert_eq!(
            module_path_for_file(Path::new("tests/main.rs")),
            vec!["tests".to_string()]
        );
        assert_eq!(
            module_path_for_file(Path::new("src/mod/inner.rs")),
            vec!["crate".to_string(), "mod".to_string(), "inner".to_string()]
        );
    }

    #[test]
    fn semantic_scan_keeps_directory_components_named_main_lib_or_mod() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        write_file(&repo, "src/main/config.rs", "pub fn cfg() {}\n");
        write_file(&repo, "src/lib/helpers.rs", "pub fn help() {}\n");
        write_file(&repo, "tests/main.rs", "fn harness() {}\n");

        let map = scan_repository(&repo).expect("scan");
        let module_path = |path: &str| {
            map.files
                .iter()
                .find(|file| file.path == Path::new(path))
                .map(|file| file.module_path.clone())
                .expect(path)
        };

        assert_eq!(module_path("src/lib.rs"), vec!["crate".to_string()]);
        assert_eq!(
            module_path("src/main/config.rs"),
            vec![
                "crate".to_string(),
                "main".to_string(),
                "config".to_string()
            ]
        );
        assert_eq!(
            module_path("src/lib/helpers.rs"),
            vec![
                "crate".to_string(),
                "lib".to_string(),
                "helpers".to_string()
            ]
        );
        assert_eq!(module_path("tests/main.rs"), vec!["tests".to_string()]);
        assert!(map.symbols.iter().any(|symbol| {
            symbol.name == "cfg" && symbol.qualified_path == vec!["crate", "main", "config", "cfg"]
        }));
    }

    #[test]
    fn signature_end_line_stops_at_the_declaration_brace() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            "pub fn foo(\n    x: i32,\n    y: i32,\n) -> i32 {\n    x + y\n}\n",
        );

        let map = scan_repository(&repo).expect("scan");
        let function = map
            .symbols
            .iter()
            .find(|symbol| symbol.name == "foo")
            .expect("function");
        assert_eq!(function.span.start_line, 1);
        assert_eq!(function.span.signature_end_line, 4);
        assert!(function.span.end_line > function.span.signature_end_line);
    }
}

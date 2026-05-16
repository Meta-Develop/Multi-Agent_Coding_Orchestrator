use anyhow::{Context, Result};
use git2::Repository;
use proc_macro2::{LineColumn, Span};
use quote::ToTokens;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};
use syn::{
    spanned::Spanned, Attribute, Expr, ImplItem, Item, Lit, Meta, TraitItem, UseTree, Visibility,
};

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
}

pub fn scan_repository(repo_path: impl AsRef<Path>) -> Result<SemanticRepoMap> {
    let repo = Repository::discover(repo_path.as_ref()).with_context(|| {
        format!(
            "failed to discover repository from {}",
            repo_path.as_ref().display()
        )
    })?;
    let root = repo
        .workdir()
        .context("semantic repository map requires a non-bare repository")?
        .to_path_buf();

    let mut rust_files = Vec::new();
    collect_rust_files(&root, &root, &mut rust_files)?;
    rust_files.sort();

    let mut map = SemanticRepoMap {
        root: root.clone(),
        files: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        re_exports: Vec::new(),
        dependencies: Vec::new(),
        errors: Vec::new(),
    };

    for file in rust_files {
        scan_rust_file(&root, &file, &mut map);
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

fn collect_rust_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut children = fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read directory entry in {}", directory.display()))?;

    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("failed to relativize {}", path.display()))?
            .to_path_buf();

        if is_ignored_path(&relative) {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.is_dir() {
            collect_rust_files(root, &path, files)?;
        } else if metadata.is_file() && has_rust_extension(&path) {
            files.push(relative);
        }
    }

    Ok(())
}

fn scan_rust_file(root: &Path, file: &Path, map: &mut SemanticRepoMap) {
    let full_path = root.join(file);
    let source = match fs::read_to_string(&full_path) {
        Ok(source) => source,
        Err(error) => {
            map.errors.push(SemanticScanError {
                file: file.to_path_buf(),
                kind: SemanticScanErrorKind::Read,
                message: format!("failed to read {}: {error}", file.display()),
                span: None,
            });
            return;
        }
    };

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
            return;
        }
    };

    let mut scanner = FileScanner {
        root,
        file,
        source_index,
        symbols: &mut map.symbols,
        imports: &mut map.imports,
        re_exports: &mut map.re_exports,
        dependencies: &mut map.dependencies,
    };
    scanner.scan_items(&syntax.items, &module_path, None);
}

struct FileScanner<'a> {
    root: &'a Path,
    file: &'a Path,
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
                            self.root,
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
            let to_file = resolve_import_file(self.root, module_path, &import.path);
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
    line_starts: Vec<usize>,
    source_len: usize,
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
            line_starts,
            source_len: source.len(),
        }
    }

    fn span(&self, span: Span) -> SourceSpan {
        let start = span.start();
        let end = span.end();
        let start_byte = self.offset(start);
        let end_byte = self.offset(end);
        SourceSpan {
            start_byte,
            end_byte: end_byte.max(start_byte),
            start_line: start.line,
            end_line: end.line.max(start.line),
        }
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
            .unwrap_or(self.source_len);
        line_start
            .saturating_add(location.column)
            .min(self.source_len)
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
    root: &Path,
    file: &Path,
    module_name: &str,
    path_attribute: Option<String>,
) -> Option<PathBuf> {
    if let Some(path_attribute) = path_attribute {
        return resolve_path_attribute_file(root, file, &path_attribute);
    }

    let base = module_base_path(file);
    let flat = base.join(format!("{module_name}.rs"));
    if root.join(&flat).is_file() {
        return Some(flat);
    }

    let nested = base.join(module_name).join("mod.rs");
    if root.join(&nested).is_file() {
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

fn resolve_path_attribute_file(root: &Path, file: &Path, path_attribute: &str) -> Option<PathBuf> {
    let base = file.parent().unwrap_or_else(|| Path::new(""));
    let candidate = normalize_relative_path(&base.join(path_attribute));
    if root.join(&candidate).is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn resolve_import_file(root: &Path, module_path: &[String], import_path: &str) -> Option<PathBuf> {
    let absolute_path = absolute_import_path(module_path, import_path)?;
    resolve_module_segments(root, &absolute_path)
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

fn resolve_module_segments(root: &Path, absolute_path: &[String]) -> Option<PathBuf> {
    if absolute_path.first().map(String::as_str) != Some("crate") {
        return None;
    }

    for end in (1..=absolute_path.len()).rev() {
        if let Some(file) = module_segments_to_file(root, &absolute_path[..end]) {
            return Some(file);
        }
    }

    None
}

fn module_segments_to_file(root: &Path, segments: &[String]) -> Option<PathBuf> {
    if segments.first().map(String::as_str) != Some("crate") {
        return None;
    }

    if segments.len() == 1 {
        for candidate in [PathBuf::from("src/lib.rs"), PathBuf::from("src/main.rs")] {
            if root.join(&candidate).is_file() {
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
    if root.join(&flat).is_file() {
        return Some(flat);
    }

    let mut nested = PathBuf::from("src");
    for segment in module_segments {
        nested.push(segment);
    }
    nested.push("mod.rs");
    if root.join(&nested).is_file() {
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

    for component in components {
        if component == "lib" || component == "main" || component == "mod" {
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
    path == Path::new(".git")
        || path.starts_with(".git")
        || path == Path::new(".maco")
        || path.starts_with(".maco")
        || path == Path::new("target")
        || path.starts_with("target")
        || path == Path::new(".agent/temp")
        || path.starts_with(".agent/temp")
        || path == Path::new(".agent/storage")
        || path.starts_with(".agent/storage")
        || path == Path::new(".agents/temp")
        || path.starts_with(".agents/temp")
        || path == Path::new(".agents/storage")
        || path.starts_with(".agents/storage")
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
        write_file(&repo, ".agent/temp/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agent/storage/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agents/temp/skipped.rs", "pub fn skipped() {}\n");
        write_file(&repo, ".agents/storage/skipped.rs", "pub fn skipped() {}\n");
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
}

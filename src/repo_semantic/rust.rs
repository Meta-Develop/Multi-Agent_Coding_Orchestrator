use proc_macro2::Span;
use quote::ToTokens;
use std::path::{Path, PathBuf};
use syn::{
    spanned::Spanned, Attribute, Expr, ImplItem, Item, Lit, Meta, TraitItem, UseTree, Visibility,
};

use super::{
    child_path, normalize_relative_path, symbol_id, AdapterOutput, LanguageAdapter,
    SemanticDependency, SemanticDependencyKind, SemanticImport, SemanticReExport,
    SemanticScanError, SemanticScanErrorKind, SemanticSymbol, SemanticSymbolKind, SourceIndex,
    SourceSpan,
};

pub(super) struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language_id(&self) -> &'static str {
        "rust"
    }

    fn matches(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "rs")
    }

    fn module_path(&self, file: &Path) -> Vec<String> {
        module_path_for_file(file)
    }

    fn parse(
        &self,
        file: &Path,
        source: &str,
        repository_files: &[PathBuf],
        output: AdapterOutput<'_>,
    ) {
        let source_index = SourceIndex::new(source);
        let syntax = match syn::parse_file(source) {
            Ok(syntax) => syntax,
            Err(error) => {
                *output.parse_error = Some(SemanticScanError {
                    file: file.to_path_buf(),
                    kind: SemanticScanErrorKind::Parse,
                    message: error.to_string(),
                    span: Some(source_index.span(error.span())),
                });
                return;
            }
        };

        let mut scanner = FileScanner {
            file,
            repository_files,
            source_index,
            symbols: output.symbols,
            imports: output.imports,
            re_exports: output.re_exports,
            dependencies: output.dependencies,
        };
        scanner.scan_items(&syntax.items, &module_path_for_file(file), None);
    }
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
                    .map(|(path, _)| path_to_string(path));
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

pub(super) fn module_path_for_file(file: &Path) -> Vec<String> {
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

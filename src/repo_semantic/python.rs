use std::path::{Path, PathBuf};

use super::{
    child_path, symbol_id, AdapterOutput, LanguageAdapter, SemanticDependency,
    SemanticDependencyKind, SemanticImport, SemanticSymbol, SemanticSymbolKind, SourceIndex,
};

/// Parser-backed Python adapter.
///
/// Coverage is the declaration surface needed for mixed-language risk impact:
/// module and class `class` / `def` / `async def` symbols plus `import` and
/// `from ... import` edges, including relative imports. Nested functions inside
/// function bodies are ignored. Classes are recorded as `SemanticSymbolKind::Struct`
/// because the published symbol-kind enum is shared with the Rust adapter.
/// This is not a full CPython grammar; comments, string literals (including
/// triple quotes), parentheses, and explicit line continuations are skipped so
/// declarations inside them are not collected.
pub(super) struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language_id(&self) -> &'static str {
        "python"
    }

    fn matches(&self, path: &Path) -> bool {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("py" | "pyi")
        )
    }

    fn module_path(&self, file: &Path) -> Vec<String> {
        python_module_path(file)
    }

    fn parse(
        &self,
        file: &Path,
        source: &str,
        repository_files: &[PathBuf],
        output: AdapterOutput<'_>,
    ) {
        parse_python(file, source, repository_files, output);
    }
}

fn python_module_path(file: &Path) -> Vec<String> {
    let mut parts = file
        .components()
        .filter_map(|component| component.as_os_str().to_str().map(str::to_string))
        .collect::<Vec<_>>();
    if let Some(last) = parts.last() {
        if last == "__init__.py" || last == "__init__.pyi" {
            parts.pop();
        } else if let Some(stripped) = last
            .strip_suffix(".py")
            .or_else(|| last.strip_suffix(".pyi"))
        {
            let stripped = stripped.to_string();
            if let Some(last) = parts.last_mut() {
                *last = stripped;
            }
        }
    }
    if parts.is_empty() {
        parts.push("module".to_string());
    }
    parts
}

fn parse_python(
    file: &Path,
    source: &str,
    repository_files: &[PathBuf],
    output: AdapterOutput<'_>,
) {
    let source_index = SourceIndex::new(source);
    let lines = logical_lines(source);
    let module_path = python_module_path(file);
    let mut class_stack: Vec<OpenScope> = Vec::new();
    let mut function_indent: Option<usize> = None;
    let mut last_content_end = 0usize;

    for line in &lines {
        while class_stack
            .last()
            .is_some_and(|scope| line.indent <= scope.indent)
        {
            if let Some(scope) = class_stack.pop() {
                patch_span_end(
                    output.symbols,
                    scope.symbol_index,
                    last_content_end,
                    &source_index,
                );
            }
        }
        if function_indent.is_some_and(|indent| line.indent <= indent) {
            function_indent = None;
        }

        let trimmed = line.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('@') {
            if !trimmed.is_empty() {
                last_content_end = line.end_byte;
            }
            continue;
        }

        last_content_end = line.end_byte;

        if let Some(import) = parse_import(trimmed) {
            push_import(
                file,
                &module_path,
                repository_files,
                &source_index,
                line,
                import,
                output.imports,
                output.dependencies,
            );
            continue;
        }

        if function_indent.is_some_and(|indent| line.indent > indent) {
            continue;
        }

        if let Some(class) = parse_class(trimmed) {
            let parent = class_stack.last();
            let qualified_path = child_path(
                parent
                    .map(|scope| scope.qualified_path.as_slice())
                    .unwrap_or(module_path.as_slice()),
                &class.name,
            );
            let span = source_index.span_bytes(line.start_byte, line.end_byte);
            let id = symbol_id(file, SemanticSymbolKind::Struct, &qualified_path, span);
            let index = output.symbols.len();
            let visibility = python_visibility(&class.name);
            output.symbols.push(SemanticSymbol {
                id: id.clone(),
                file: file.to_path_buf(),
                name: class.name,
                qualified_path: qualified_path.clone(),
                kind: SemanticSymbolKind::Struct,
                visibility,
                parent_symbol: parent.map(|scope| scope.symbol_id.clone()),
                impl_target: None,
                impl_trait: None,
                span,
            });
            class_stack.push(OpenScope {
                indent: line.indent,
                symbol_id: id,
                qualified_path,
                symbol_index: index,
            });
            function_indent = None;
            continue;
        }

        if let Some(function) = parse_function(trimmed) {
            let parent = class_stack.last();
            let in_class = parent.is_some_and(|scope| line.indent > scope.indent);
            let qualified_base = if in_class {
                parent
                    .map(|scope| scope.qualified_path.as_slice())
                    .unwrap_or(module_path.as_slice())
            } else {
                module_path.as_slice()
            };
            let qualified_path = child_path(qualified_base, &function.name);
            let kind = if in_class {
                SemanticSymbolKind::Method
            } else {
                SemanticSymbolKind::Function
            };
            let span = source_index.span_bytes(line.start_byte, line.end_byte);
            let id = symbol_id(file, kind, &qualified_path, span);
            let visibility = python_visibility(&function.name);
            output.symbols.push(SemanticSymbol {
                id,
                file: file.to_path_buf(),
                name: function.name,
                qualified_path,
                kind,
                visibility,
                parent_symbol: if in_class {
                    parent.map(|scope| scope.symbol_id.clone())
                } else {
                    None
                },
                impl_target: None,
                impl_trait: None,
                span,
            });
            function_indent = Some(line.indent);
        }
    }

    while let Some(scope) = class_stack.pop() {
        patch_span_end(
            output.symbols,
            scope.symbol_index,
            last_content_end,
            &source_index,
        );
    }
}

fn python_visibility(name: &str) -> String {
    if name.starts_with("__") && name.ends_with("__") {
        "public".to_string()
    } else if name.starts_with('_') {
        "private".to_string()
    } else {
        "public".to_string()
    }
}

fn patch_span_end(
    symbols: &mut [SemanticSymbol],
    index: usize,
    end_byte: usize,
    source_index: &SourceIndex,
) {
    if let Some(symbol) = symbols.get_mut(index) {
        if end_byte > symbol.span.end_byte {
            symbol.span.end_byte = end_byte;
            symbol.span.end_line =
                source_index.line_of(end_byte.saturating_sub(1).max(symbol.span.start_byte));
        }
    }
}

struct OpenScope {
    indent: usize,
    symbol_id: String,
    qualified_path: Vec<String>,
    symbol_index: usize,
}

struct LogicalLine {
    indent: usize,
    start_byte: usize,
    end_byte: usize,
    text: String,
}

struct ParsedName {
    name: String,
}

struct ParsedImport {
    path: String,
    alias: Option<String>,
    glob: bool,
}

fn parse_class(text: &str) -> Option<ParsedName> {
    let rest = text.strip_prefix("class ")?;
    parse_identifier(rest).map(|name| ParsedName { name })
}

fn parse_function(text: &str) -> Option<ParsedName> {
    let rest = text
        .strip_prefix("async def ")
        .or_else(|| text.strip_prefix("def "))?;
    parse_identifier(rest).map(|name| ParsedName { name })
}

fn parse_identifier(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let mut name = String::from(first);
    for ch in chars {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    Some(name)
}

fn parse_import(text: &str) -> Option<Vec<ParsedImport>> {
    if let Some(rest) = text.strip_prefix("import ") {
        return Some(parse_import_names(rest, None));
    }
    let rest = text.strip_prefix("from ")?;
    let (module, names) = split_from_import(rest)?;
    if names.trim() == "*" {
        return Some(vec![ParsedImport {
            path: module,
            alias: None,
            glob: true,
        }]);
    }
    Some(parse_import_names(&names, Some(module)))
}

fn split_from_import(text: &str) -> Option<(String, String)> {
    let import_at = text.find(" import ")?;
    let module = text[..import_at].trim().to_string();
    let names = text[import_at + " import ".len()..].trim().to_string();
    if module.is_empty() || names.is_empty() {
        None
    } else {
        Some((module, names))
    }
}

fn parse_import_names(text: &str, from_module: Option<String>) -> Vec<ParsedImport> {
    let mut imports = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (path_text, alias) = match part.split_once(" as ") {
            Some((path, alias)) => (path.trim(), Some(alias.trim().to_string())),
            None => (part, None),
        };
        let path = match &from_module {
            Some(module) if path_text == module => module.clone(),
            Some(module) if module == "." || module.chars().all(|ch| ch == '.') => {
                format!("{module}{path_text}")
            }
            Some(module) => format!("{module}.{path_text}"),
            None => path_text.to_string(),
        };
        imports.push(ParsedImport {
            path,
            alias,
            glob: false,
        });
    }
    imports
}

#[allow(clippy::too_many_arguments)]
fn push_import(
    file: &Path,
    module_path: &[String],
    repository_files: &[PathBuf],
    source_index: &SourceIndex,
    line: &LogicalLine,
    imports: Vec<ParsedImport>,
    collected: &mut Vec<SemanticImport>,
    dependencies: &mut Vec<SemanticDependency>,
) {
    let span = source_index.span_bytes(line.start_byte, line.end_byte);
    for import in imports {
        let to_file = resolve_python_import(repository_files, file, module_path, &import.path);
        collected.push(SemanticImport {
            file: file.to_path_buf(),
            module_path: module_path.to_vec(),
            path: import.path.clone(),
            alias: import.alias.clone(),
            glob: import.glob,
            visibility: "public".to_string(),
            span,
        });
        dependencies.push(SemanticDependency {
            from_file: file.to_path_buf(),
            from_module: module_path.to_vec(),
            to: import.path,
            to_file,
            kind: SemanticDependencyKind::Import,
            span,
        });
    }
}

fn resolve_python_import(
    repository_files: &[PathBuf],
    file: &Path,
    module_path: &[String],
    import_path: &str,
) -> Option<PathBuf> {
    let (dots, remainder) = split_relative(import_path);
    let mut segments = if dots == 0 {
        remainder
            .split('.')
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        let mut package = module_path.to_vec();
        let climb = dots.saturating_sub(1);
        for _ in 0..climb {
            package.pop();
        }
        if !remainder.is_empty() {
            package.extend(
                remainder
                    .split('.')
                    .filter(|segment| !segment.is_empty())
                    .map(str::to_string),
            );
        }
        package
    };
    if segments.is_empty() {
        if let Some(parent) = file.parent() {
            let init = parent.join("__init__.py");
            if repository_files.binary_search(&init).is_ok() {
                return Some(init);
            }
        }
        return None;
    }

    while !segments.is_empty() {
        if let Some(resolved) = python_segments_to_file(repository_files, &segments) {
            return Some(resolved);
        }
        segments.pop();
    }
    None
}

fn split_relative(import_path: &str) -> (usize, &str) {
    let dots = import_path.chars().take_while(|ch| *ch == '.').count();
    (dots, &import_path[dots..])
}

fn python_segments_to_file(repository_files: &[PathBuf], segments: &[String]) -> Option<PathBuf> {
    let mut file = PathBuf::new();
    for segment in segments {
        file.push(segment);
    }
    let mut module = file.clone();
    module.set_extension("py");
    if repository_files.binary_search(&module).is_ok() {
        return Some(module);
    }
    let mut stub = file.clone();
    stub.set_extension("pyi");
    if repository_files.binary_search(&stub).is_ok() {
        return Some(stub);
    }
    file.push("__init__.py");
    if repository_files.binary_search(&file).is_ok() {
        return Some(file);
    }
    None
}

fn logical_lines(source: &str) -> Vec<LogicalLine> {
    let mut lines = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let line_start = index;
        let indent = leading_indent(source, &mut index);
        if index >= bytes.len() {
            break;
        }
        if bytes.get(index) == Some(&b'#') || bytes.get(index) == Some(&b'\n') {
            skip_physical_line(bytes, &mut index);
            continue;
        }
        let text_start = index;
        let mut text = String::new();
        let mut paren_depth = 0i32;
        let mut end_byte = index;
        loop {
            if index >= bytes.len() {
                break;
            }
            let ch = bytes[index];
            if ch == b'\\' && bytes.get(index + 1) == Some(&b'\n') {
                index += 2;
                continue;
            }
            match ch {
                b'\'' | b'"' => {
                    if let Some((literal, next)) = take_string(source, index) {
                        text.push_str(literal);
                        end_byte = next;
                        index = next;
                        continue;
                    }
                }
                b'#' if paren_depth == 0 => {
                    skip_physical_line(bytes, &mut index);
                    break;
                }
                b'(' | b'[' | b'{' => paren_depth += 1,
                b')' | b']' | b'}' => paren_depth = paren_depth.saturating_sub(1),
                b'\n' if paren_depth == 0 => {
                    index += 1;
                    break;
                }
                _ => {}
            }
            if let Some(c) = source[index..].chars().next() {
                text.push(c);
                index += c.len_utf8();
                end_byte = index;
            } else {
                index += 1;
                end_byte = index;
            }
        }
        let text = text.trim_end().to_string();
        if !text.is_empty() {
            lines.push(LogicalLine {
                indent,
                start_byte: if indent == 0 { text_start } else { line_start },
                end_byte: end_byte.max(text_start),
                text,
            });
        }
    }
    lines
}

fn leading_indent(source: &str, index: &mut usize) -> usize {
    let bytes = source.as_bytes();
    let mut indent = 0usize;
    while *index < bytes.len() {
        match bytes[*index] {
            b' ' => {
                indent += 1;
                *index += 1;
            }
            b'\t' => {
                indent += 8;
                *index += 1;
            }
            _ => break,
        }
    }
    indent
}

fn skip_physical_line(bytes: &[u8], index: &mut usize) {
    while *index < bytes.len() {
        let ch = bytes[*index];
        *index += 1;
        if ch == b'\n' {
            break;
        }
    }
}

fn take_string(source: &str, start: usize) -> Option<(&str, usize)> {
    let rest = &source[start..];
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let triple = rest.starts_with("'''") || rest.starts_with("\"\"\"");
    let delimiter_len = if triple { 3 } else { 1 };
    let mut index = start + delimiter_len;
    let delimiter = &source[start..start + delimiter_len];
    while index < source.len() {
        if source[index..].starts_with(delimiter) {
            index += delimiter_len;
            return Some((&source[start..index], index));
        }
        if !triple && source.as_bytes().get(index) == Some(&b'\\') {
            index += source[index..]
                .chars()
                .next()
                .map(|ch| ch.len_utf8())
                .unwrap_or(1);
            if index < source.len() {
                index += source[index..]
                    .chars()
                    .next()
                    .map(|ch| ch.len_utf8())
                    .unwrap_or(1);
            }
            continue;
        }
        index += source[index..]
            .chars()
            .next()
            .map(|ch| ch.len_utf8())
            .unwrap_or(1);
    }
    Some((&source[start..], source.len()))
}

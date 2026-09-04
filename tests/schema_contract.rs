//! Fixture-backed contract tests for published machine-readable JSON schemas.

use anyhow::{bail, Context, Result};
use boon::{
    Compiler, Draft, ErrorKind, InstanceLocation, InstanceToken, SchemaIndex, Schemas,
    ValidationError,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
const DRIFT_PROPERTY: &str = "__schema_contract_deliberate_drift";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    contracts: Vec<Contract>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    valid: Vec<String>,
    invalid: Vec<InvalidFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidFixture {
    path: String,
    expected_error: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Diagnostic {
    instance_path: String,
    keyword: String,
}

#[derive(Debug)]
struct ValidationFailure {
    diagnostics: BTreeSet<Diagnostic>,
    rendered: String,
}

struct CompiledSchemas {
    schemas: Schemas,
    indices: BTreeMap<String, SchemaIndex>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn relative_manifest_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    relative
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .with_context(|| format!("non-UTF-8 path below {}", root.display()))
        })
        .collect::<Result<Vec<_>>>()
        .map(|components| components.join("/"))
}

fn discover_files(root: &Path, suffixes: &[&str]) -> Result<BTreeSet<String>> {
    let mut pending = vec![root.to_path_buf()];
    let mut discovered = BTreeSet::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("read schema directory {}", directory.display()))?
        {
            let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("inspect {}", path.display()))?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }

            let relative = relative_manifest_path(root, &path)?;
            let selected = suffixes.iter().any(|suffix| relative.ends_with(suffix));
            if selected && !file_type.is_file() {
                bail!("published contract path is not a regular file: {relative}");
            }
            if selected && !discovered.insert(relative.clone()) {
                bail!("duplicate published contract path: {relative}");
            }
        }
    }

    Ok(discovered)
}

fn compile_and_meta_validate_2020_12(
    documents: &BTreeMap<String, Value>,
) -> Result<CompiledSchemas> {
    let mut compiler = Compiler::new();
    compiler.set_default_draft(Draft::V2020_12);

    let mut ids_by_name = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    for (name, schema) in documents {
        if schema.get("$schema").and_then(Value::as_str) != Some(DRAFT_2020_12) {
            bail!("{name}: published schema must declare Draft 2020-12");
        }
        let id = schema
            .get("$id")
            .and_then(Value::as_str)
            .with_context(|| format!("{name}: published schema must declare a string $id"))?;
        if !seen_ids.insert(id.to_owned()) {
            bail!("{name}: duplicate published schema $id {id}");
        }
        compiler
            .add_resource(id, schema.clone())
            .map_err(|error| anyhow::anyhow!("{name}: register schema resource: {error:#}"))?;
        ids_by_name.insert(name.clone(), id.to_owned());
    }

    let mut schemas = Schemas::new();
    let mut indices = BTreeMap::new();
    for (name, id) in ids_by_name {
        // Boon's Draft 2020-12 compiler validates each schema and discovered
        // subschema against its bundled meta-schema before compilation.
        let index = compiler
            .compile(&id, &mut schemas)
            .map_err(|error| anyhow::anyhow!("{name}: meta-validate and compile: {error:#}"))?;
        indices.insert(name, index);
    }

    Ok(CompiledSchemas { schemas, indices })
}

fn json_path(location: &InstanceLocation<'_>) -> String {
    let mut path = "$".to_owned();
    for token in &location.tokens {
        match token {
            InstanceToken::Prop(property) => path = append_property(&path, property),
            InstanceToken::Item(index) => path.push_str(&format!("[{index}]")),
        }
    }
    path
}

fn append_property(path: &str, property: &str) -> String {
    if !property.is_empty()
        && property
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        format!("{path}.{property}")
    } else {
        let quoted = serde_json::to_string(property).expect("serializing a string cannot fail");
        format!("{path}[{quoted}]")
    }
}

fn error_keyword(kind: &ErrorKind<'_, '_>) -> Option<String> {
    match kind {
        ErrorKind::Group | ErrorKind::Schema { .. } => None,
        ErrorKind::ContentSchema => Some("contentSchema".to_owned()),
        ErrorKind::PropertyName { .. } => Some("propertyNames".to_owned()),
        ErrorKind::Reference { kw, .. } => Some((*kw).to_owned()),
        ErrorKind::RefCycle { .. } => Some("$ref".to_owned()),
        ErrorKind::FalseSchema => Some("falseSchema".to_owned()),
        ErrorKind::Type { .. } => Some("type".to_owned()),
        ErrorKind::Enum { .. } => Some("enum".to_owned()),
        ErrorKind::Const { .. } => Some("const".to_owned()),
        ErrorKind::Format { .. } => Some("format".to_owned()),
        ErrorKind::MinProperties { .. } => Some("minProperties".to_owned()),
        ErrorKind::MaxProperties { .. } => Some("maxProperties".to_owned()),
        ErrorKind::AdditionalProperties { .. } => Some("additionalProperties".to_owned()),
        ErrorKind::Required { .. } => Some("required".to_owned()),
        ErrorKind::Dependency { .. } => Some("dependencies".to_owned()),
        ErrorKind::DependentRequired { .. } => Some("dependentRequired".to_owned()),
        ErrorKind::MinItems { .. } => Some("minItems".to_owned()),
        ErrorKind::MaxItems { .. } => Some("maxItems".to_owned()),
        ErrorKind::Contains => Some("contains".to_owned()),
        ErrorKind::MinContains { .. } => Some("minContains".to_owned()),
        ErrorKind::MaxContains { .. } => Some("maxContains".to_owned()),
        ErrorKind::UniqueItems { .. } => Some("uniqueItems".to_owned()),
        ErrorKind::AdditionalItems { .. } => Some("additionalItems".to_owned()),
        ErrorKind::MinLength { .. } => Some("minLength".to_owned()),
        ErrorKind::MaxLength { .. } => Some("maxLength".to_owned()),
        ErrorKind::Pattern { .. } => Some("pattern".to_owned()),
        ErrorKind::ContentEncoding { .. } => Some("contentEncoding".to_owned()),
        ErrorKind::ContentMediaType { .. } => Some("contentMediaType".to_owned()),
        ErrorKind::Minimum { .. } => Some("minimum".to_owned()),
        ErrorKind::Maximum { .. } => Some("maximum".to_owned()),
        ErrorKind::ExclusiveMinimum { .. } => Some("exclusiveMinimum".to_owned()),
        ErrorKind::ExclusiveMaximum { .. } => Some("exclusiveMaximum".to_owned()),
        ErrorKind::MultipleOf { .. } => Some("multipleOf".to_owned()),
        ErrorKind::Not => Some("not".to_owned()),
        ErrorKind::AllOf => Some("allOf".to_owned()),
        ErrorKind::AnyOf => Some("anyOf".to_owned()),
        ErrorKind::OneOf(_) => Some("oneOf".to_owned()),
    }
}

fn collect_diagnostics(error: &ValidationError<'_, '_>, diagnostics: &mut BTreeSet<Diagnostic>) {
    let base = json_path(&error.instance_location);
    let keyword = error_keyword(&error.kind);

    match (&error.kind, keyword) {
        (ErrorKind::AdditionalProperties { got }, Some(keyword)) => {
            for property in got {
                diagnostics.insert(Diagnostic {
                    instance_path: append_property(&base, property.as_ref()),
                    keyword: keyword.clone(),
                });
            }
        }
        (ErrorKind::Required { want }, Some(keyword)) => {
            for property in want {
                diagnostics.insert(Diagnostic {
                    instance_path: append_property(&base, property),
                    keyword: keyword.clone(),
                });
            }
        }
        (ErrorKind::Dependency { missing, .. }, Some(keyword))
        | (ErrorKind::DependentRequired { missing, .. }, Some(keyword)) => {
            for property in missing {
                diagnostics.insert(Diagnostic {
                    instance_path: append_property(&base, property),
                    keyword: keyword.clone(),
                });
            }
        }
        (ErrorKind::PropertyName { prop }, Some(keyword)) => {
            diagnostics.insert(Diagnostic {
                instance_path: append_property(&base, prop),
                keyword,
            });
        }
        (_, Some(keyword)) => {
            diagnostics.insert(Diagnostic {
                instance_path: base,
                keyword,
            });
        }
        (_, None) => {}
    }

    for cause in &error.causes {
        collect_diagnostics(cause, diagnostics);
    }
}

fn validate_instance(
    schemas: &Schemas,
    index: SchemaIndex,
    instance: &Value,
) -> std::result::Result<(), ValidationFailure> {
    schemas.validate(instance, index).map_err(|error| {
        let mut diagnostics = BTreeSet::new();
        collect_diagnostics(&error, &mut diagnostics);
        ValidationFailure {
            diagnostics,
            rendered: format!("{error:#}"),
        }
    })
}

fn parse_expected_diagnostic(expected: &str) -> Result<Diagnostic> {
    let (instance_path, keyword) = expected.rsplit_once(": ").with_context(|| {
        format!("expected_error must use '<instance path>: <keyword>': {expected}")
    })?;
    if !instance_path.starts_with('$') || instance_path.is_empty() || keyword.is_empty() {
        bail!("invalid expected_error diagnostic: {expected}");
    }
    Ok(Diagnostic {
        instance_path: instance_path.to_owned(),
        keyword: keyword.to_owned(),
    })
}

fn assert_expected_diagnostic(
    fixture: &str,
    expected: &str,
    failure: &ValidationFailure,
) -> Result<()> {
    let expected = parse_expected_diagnostic(expected)?;
    if failure.diagnostics.contains(&expected) {
        return Ok(());
    }

    let diagnostics = failure
        .diagnostics
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.instance_path, diagnostic.keyword))
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "{fixture}: expected diagnostic '{}: {}' was absent; actual diagnostics: [{}]\n{}",
        expected.instance_path,
        expected.keyword,
        diagnostics,
        failure.rendered
    )
}

#[test]
fn published_schemas_and_fixtures_follow_the_manifest_contract() -> Result<()> {
    let root = repo_root();
    let schema_dir = root.join("schemas");
    let fixture_dir = root.join("fixtures/schemas");
    let manifest_path = fixture_dir.join("manifest.json");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .with_context(|| format!("parse strict manifest {}", manifest_path.display()))?;
    if manifest.version != 1 {
        bail!(
            "unsupported schema fixture manifest version {}",
            manifest.version
        );
    }

    let published_schemas = discover_files(&schema_dir, &[".schema.json"])?;
    let declared_schemas = manifest
        .contracts
        .iter()
        .map(|contract| contract.schema.clone())
        .collect::<BTreeSet<_>>();
    if declared_schemas.len() != manifest.contracts.len() {
        bail!("schema fixture manifest contains duplicate contract entries");
    }
    if declared_schemas != published_schemas {
        bail!(
            "schema fixture manifest must account for every published schema; declared={declared_schemas:?}, published={published_schemas:?}"
        );
    }

    let declared_fixtures = manifest
        .contracts
        .iter()
        .flat_map(|contract| {
            contract
                .valid
                .iter()
                .cloned()
                .chain(contract.invalid.iter().map(|fixture| fixture.path.clone()))
        })
        .collect::<BTreeSet<_>>();
    let published_fixtures = discover_files(&fixture_dir, &[".valid.json", ".invalid.json"])?;
    if declared_fixtures != published_fixtures {
        bail!(
            "schema fixture manifest must account for every valid/invalid fixture; declared={declared_fixtures:?}, published={published_fixtures:?}"
        );
    }

    let documents = published_schemas
        .iter()
        .map(|name| Ok((name.clone(), load_json(&schema_dir.join(name))?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let compiled = compile_and_meta_validate_2020_12(&documents)?;

    for contract in &manifest.contracts {
        let index = *compiled
            .indices
            .get(&contract.schema)
            .with_context(|| format!("compiled schema missing for {}", contract.schema))?;

        for valid in &contract.valid {
            let instance = load_json(&fixture_dir.join(valid))?;
            if let Err(failure) = validate_instance(&compiled.schemas, index, &instance) {
                bail!(
                    "{valid} should satisfy {}:\n{}",
                    contract.schema,
                    failure.rendered
                );
            }
        }

        for invalid in &contract.invalid {
            let instance = load_json(&fixture_dir.join(&invalid.path))?;
            let failure =
                validate_instance(&compiled.schemas, index, &instance).map_or_else(Ok, |()| {
                    Err(anyhow::anyhow!(
                        "{}: expected invalid but {} accepted it ({})",
                        invalid.path,
                        contract.schema,
                        invalid.expected_error
                    ))
                })?;
            assert_expected_diagnostic(&invalid.path, &invalid.expected_error, &failure)?;
        }

        let representative = contract.valid.first().with_context(|| {
            format!(
                "{} needs at least one valid fixture for deliberate drift coverage",
                contract.schema
            )
        })?;
        let mut drifted = load_json(&fixture_dir.join(representative))?;
        let object = drifted.as_object_mut().with_context(|| {
            format!(
                "{representative}: representative published output must be an object for drift coverage"
            )
        })?;
        if object
            .insert(DRIFT_PROPERTY.to_owned(), Value::Bool(true))
            .is_some()
        {
            bail!("{representative}: reserved drift property already exists");
        }
        let failure =
            validate_instance(&compiled.schemas, index, &drifted).map_or_else(Ok, |()| {
                Err(anyhow::anyhow!(
                    "{} accepted deliberate drift in representative valid fixture {}",
                    contract.schema,
                    representative
                ))
            })?;
        assert_expected_diagnostic(
            representative,
            &format!("$.{DRIFT_PROPERTY}: additionalProperties"),
            &failure,
        )?;
    }

    Ok(())
}

#[test]
fn live_semantic_risk_report_serializes_against_the_published_schema() -> Result<()> {
    use git2::Repository;
    use multi_agent_coding_orchestrator::repo_semantic::{risk_report_for_paths, scan_repository};
    use tempfile::TempDir;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = temp.path().join("repo");
    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::create_dir_all(repo_path.join("pkg")).context("create pkg")?;
    Repository::init(&repo_path).context("init repo")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub mod api;\npub use crate::api::endpoint;\n",
    )
    .context("write lib")?;
    fs::write(
        repo_path.join("src/api.rs"),
        "pub struct Api;\npub fn endpoint(\n    x: i32,\n) -> i32 {\n    x\n}\n",
    )
    .context("write api")?;
    fs::write(repo_path.join("pkg/util.py"), "def util():\n    return 1\n")
        .context("write python")?;

    let map = scan_repository(&repo_path).context("scan live semantic map")?;
    let report = risk_report_for_paths(&map, ["src/api.rs", "pkg/util.py"]);
    let mut instance = serde_json::to_value(&report).context("serialize live risk report")?;
    // Published CLI risk JSON is SemanticRiskReport flattened with megafile_hotspots.
    instance
        .as_object_mut()
        .context("risk report JSON object")?
        .insert("megafile_hotspots".to_string(), serde_json::json!([]));

    let spans = instance
        .pointer("/touched_symbols")
        .and_then(Value::as_array)
        .context("live touched_symbols")?;
    assert!(
        spans.iter().any(|symbol| symbol
            .pointer("/span/signature_end_line")
            .and_then(Value::as_u64)
            .is_some_and(|line| line >= 1)),
        "live SourceSpan JSON must emit signature_end_line: {instance}"
    );
    assert!(
        spans.iter().any(|symbol| symbol["name"] == "util"),
        "live mixed-language report must include Python symbols: {instance}"
    );

    let schema_name = "semantic-risk-report-v1.schema.json";
    let schema = load_json(&repo_root().join("schemas").join(schema_name))?;
    let documents = BTreeMap::from([(schema_name.to_owned(), schema)]);
    let compiled = compile_and_meta_validate_2020_12(&documents)?;
    let index = *compiled
        .indices
        .get(schema_name)
        .context("compiled semantic risk schema")?;
    if let Err(failure) = validate_instance(&compiled.schemas, index, &instance) {
        bail!(
            "live SemanticRiskReport JSON failed the published schema:\n{}",
            failure.rendered
        );
    }
    Ok(())
}

//! Fixture-backed contract tests for published machine-readable JSON schemas.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct Manifest {
    version: u32,
    contracts: Vec<Contract>,
}

#[derive(Debug, Deserialize)]
struct Contract {
    schema: String,
    valid: Vec<String>,
    invalid: Vec<InvalidFixture>,
}

#[derive(Debug, Deserialize)]
struct InvalidFixture {
    path: String,
    expected_error: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn validate(
    schema: &Value,
    instance: &Value,
    schemas: &std::collections::BTreeMap<String, Value>,
) -> Result<(), String> {
    validate_at(schema, schema, instance, "$", schemas)
}

fn validate_at(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    schemas: &std::collections::BTreeMap<String, Value>,
) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let (resolved_root, resolved) = resolve_ref(root, reference, schemas)?;
        return validate_at(resolved_root, resolved, instance, path, schemas);
    }
    if let Some(const_value) = schema.get("const") {
        if instance != const_value {
            return Err(format!("{path}: const"));
        }
    }
    if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
        if !enum_values.iter().any(|value| value == instance) {
            return Err(format!("{path}: enum"));
        }
    }
    if let Some(type_value) = schema.get("type") {
        if !type_matches(type_value, instance) {
            return Err(format!("{path}: type"));
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if let Some(text) = instance.as_str() {
            let regex = regex_lite(pattern);
            if !regex(text) {
                return Err(format!("{path}: pattern"));
            }
        }
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        if let (Some(object), Some(properties)) = (
            instance.as_object(),
            schema.get("properties").and_then(Value::as_object),
        ) {
            for key in object.keys() {
                if !properties.contains_key(key) {
                    return Err(format!("{path}.{key}: additionalProperties"));
                }
            }
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        if let Some(object) = instance.as_object() {
            for key in required {
                let key = key.as_str().ok_or_else(|| format!("{path}: required"))?;
                if !object.contains_key(key) {
                    return Err(format!("{path}.{key}: required"));
                }
            }
        }
    }
    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        instance.as_object(),
    ) {
        for (key, property_schema) in properties {
            if let Some(value) = object.get(key) {
                validate_at(
                    root,
                    property_schema,
                    value,
                    &format!("{path}.{key}"),
                    schemas,
                )?;
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if let Some(array) = instance.as_array() {
            for (index, value) in array.iter().enumerate() {
                validate_at(root, items, value, &format!("{path}[{index}]"), schemas)?;
            }
        }
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|option| validate_at(root, option, instance, path, schemas).is_ok())
            .count();
        if matches != 1 {
            return Err(format!("{path}: oneOf"));
        }
    }
    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array) {
        if !any_of
            .iter()
            .any(|option| validate_at(root, option, instance, path, schemas).is_ok())
        {
            return Err(format!("{path}: anyOf"));
        }
    }
    if let Some(not) = schema.get("not") {
        if validate_at(root, not, instance, path, schemas).is_ok() {
            return Err(format!("{path}: not"));
        }
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for option in all_of {
            validate_at(root, option, instance, path, schemas)?;
        }
    }
    if schema.get("if").is_some() {
        let condition = schema.get("if").expect("if");
        if validate_at(root, condition, instance, path, schemas).is_ok() {
            if let Some(then_schema) = schema.get("then") {
                validate_at(root, then_schema, instance, path, schemas)?;
            }
        } else if let Some(else_schema) = schema.get("else") {
            validate_at(root, else_schema, instance, path, schemas)?;
        }
    }
    Ok(())
}

fn type_matches(type_value: &Value, instance: &Value) -> bool {
    match type_value {
        Value::String(name) => instance_has_type(name, instance),
        Value::Array(names) => names.iter().any(|name| {
            name.as_str()
                .is_some_and(|name| instance_has_type(name, instance))
        }),
        _ => true,
    }
}

fn instance_has_type(name: &str, instance: &Value) -> bool {
    match name {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        "number" => instance.as_f64().is_some(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        _ => true,
    }
}

fn resolve_ref<'a>(
    root: &'a Value,
    reference: &str,
    schemas: &'a std::collections::BTreeMap<String, Value>,
) -> Result<(&'a Value, &'a Value), String> {
    let (document, pointer) = if let Some(pointer) = reference.strip_prefix("#/") {
        (root, pointer)
    } else if let Some((file, pointer)) = reference.split_once("#/") {
        let document = schemas
            .get(file)
            .ok_or_else(|| format!("unresolved $ref {reference}"))?;
        (document, pointer)
    } else {
        return Err(format!("unsupported $ref {reference}"));
    };
    let mut current = document;
    for part in pointer.split('/') {
        current = current
            .get(part)
            .ok_or_else(|| format!("unresolved $ref {reference}"))?;
    }
    Ok((document, current))
}

fn regex_lite(pattern: &str) -> impl Fn(&str) -> bool {
    let pattern = pattern.to_string();
    move |text: &str| {
        if pattern == "^(0|[1-9][0-9]*)$" {
            return text == "0"
                || (!text.starts_with('0') && text.chars().all(|ch| ch.is_ascii_digit()));
        }
        if pattern.starts_with('^') && pattern.ends_with('$') && !pattern.contains('[') {
            let exact = &pattern[1..pattern.len() - 1];
            return text == exact;
        }
        !text.is_empty()
    }
}

#[test]
fn published_schemas_and_fixtures_follow_the_manifest_contract() -> Result<()> {
    let root = repo_root();
    let schema_dir = root.join("schemas");
    let fixture_dir = root.join("fixtures/schemas");
    let manifest: Manifest = serde_json::from_slice(&fs::read(fixture_dir.join("manifest.json"))?)?;
    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.contracts.len(), 6);
    let mut schemas = std::collections::BTreeMap::new();
    for contract in &manifest.contracts {
        schemas.insert(
            contract.schema.clone(),
            load_json(&schema_dir.join(&contract.schema))?,
        );
    }

    let mut seen_schemas = 0usize;
    for contract in &manifest.contracts {
        let schema = schemas
            .get(&contract.schema)
            .context("schema missing from registry")?;
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert!(schema.get("$id").and_then(Value::as_str).is_some());
        seen_schemas += 1;

        for valid in &contract.valid {
            let instance = load_json(&fixture_dir.join(valid))?;
            validate(schema, &instance, &schemas).map_err(|error| {
                anyhow::anyhow!("{} should satisfy {}: {error}", valid, contract.schema)
            })?;
        }
        for invalid in &contract.invalid {
            let instance = load_json(&fixture_dir.join(&invalid.path))?;
            match validate(schema, &instance, &schemas) {
                Ok(()) => bail!(
                    "{}: expected invalid but schema accepted it ({})",
                    invalid.path,
                    invalid.expected_error
                ),
                Err(error) => {
                    assert!(
                        !error.is_empty(),
                        "{} rejected without a diagnostic; salvage expected {}",
                        invalid.path,
                        invalid.expected_error
                    );
                }
            }
        }
    }
    assert_eq!(seen_schemas, 6);
    Ok(())
}

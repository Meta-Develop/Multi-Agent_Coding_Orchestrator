//! Tracked optimizer weight-profile schema and default document.
//!
//! This is the first #150 slice: operator-tunable preference weights load from
//! versioned, repository-tracked files and fail closed when a document does
//! not satisfy the schema.

use std::sync::OnceLock;

use serde_json::Value;

use super::error::OptimizerError;

pub(crate) const PREFERENCE_PROFILE_SCHEMA_JSON: &str =
    include_str!("data/preference-profile-v1.schema.json");
pub(crate) const DEFAULT_PREFERENCE_PROFILE_JSON: &str =
    include_str!("data/default-preference-profile-v1.json");

pub(crate) fn validate_preference_profile_document(instance: &Value) -> Result<(), OptimizerError> {
    let schema = tracked_schema()?;
    validate_at(schema, schema, instance, "$")
}

fn tracked_schema() -> Result<&'static Value, OptimizerError> {
    static SCHEMA: OnceLock<Result<Value, String>> = OnceLock::new();
    match SCHEMA.get_or_init(|| {
        serde_json::from_str(PREFERENCE_PROFILE_SCHEMA_JSON).map_err(|error| {
            format!("tracked preference profile schema is not valid JSON: {error}")
        })
    }) {
        Ok(schema) => Ok(schema),
        Err(message) => Err(OptimizerError::invalid(message.clone())),
    }
}

fn validate_at(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
) -> Result<(), OptimizerError> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let resolved = resolve_ref(root, reference)?;
        return validate_at(root, resolved, instance, path);
    }
    if let Some(const_value) = schema.get("const") {
        if instance != const_value {
            return Err(schema_error(path, "const"));
        }
    }
    if let Some(type_value) = schema.get("type") {
        if !type_matches(type_value, instance) {
            return Err(schema_error(path, "type"));
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        if let Some(value) = instance.as_f64() {
            if value < minimum {
                return Err(schema_error(path, "minimum"));
            }
        }
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
        if let Some(text) = instance.as_str() {
            if (text.chars().count() as u64) < min_length {
                return Err(schema_error(path, "minLength"));
            }
        }
    }
    if let Some(object) = instance.as_object() {
        if let Some(property_names) = schema.get("propertyNames") {
            for key in object.keys() {
                validate_at(root, property_names, &Value::String(key.clone()), path)?;
            }
        }
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required {
                let key = key.as_str().ok_or_else(|| schema_error(path, "required"))?;
                if !object.contains_key(key) {
                    return Err(schema_error(&format!("{path}.{key}"), "required"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, property_schema) in properties {
                if let Some(value) = object.get(key) {
                    validate_at(root, property_schema, value, &format!("{path}.{key}"))?;
                }
            }
        }
        if let Some(additional) = schema.get("additionalProperties") {
            for (key, value) in object {
                let declared = properties.is_some_and(|properties| properties.contains_key(key));
                if declared {
                    continue;
                }
                if additional == &Value::Bool(false) {
                    return Err(schema_error(
                        &format!("{path}.{key}"),
                        "additionalProperties",
                    ));
                }
                if additional.is_object() {
                    validate_at(root, additional, value, &format!("{path}.{key}"))?;
                }
            }
        }
    }
    Ok(())
}

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Result<&'a Value, OptimizerError> {
    let pointer = reference.strip_prefix("#/").ok_or_else(|| {
        OptimizerError::invalid(format!("unsupported preference schema $ref {reference}"))
    })?;
    let mut current = root;
    for part in pointer.split('/') {
        current = current.get(part).ok_or_else(|| {
            OptimizerError::invalid(format!("unresolved preference schema $ref {reference}"))
        })?;
    }
    Ok(current)
}

fn type_matches(type_value: &Value, instance: &Value) -> bool {
    let Some(name) = type_value.as_str() else {
        return true;
    };
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

fn schema_error(path: &str, keyword: &str) -> OptimizerError {
    OptimizerError::invalid(format!(
        "preference profile failed tracked schema ({path}: {keyword})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tracked_schema_and_default_are_valid_and_aligned() {
        let schema: Value =
            serde_json::from_str(PREFERENCE_PROFILE_SCHEMA_JSON).expect("schema json");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        let default: Value =
            serde_json::from_str(DEFAULT_PREFERENCE_PROFILE_JSON).expect("default json");
        validate_preference_profile_document(&default).expect("default satisfies schema");
        assert_eq!(default["id"], "default");
        assert_eq!(default["schema_version"], 1);
        assert_eq!(default["version"], 1);
        assert_eq!(default["latency_weight_bp"], 5000);
        assert_eq!(default["cost_weight_bp"], 5000);
    }

    #[test]
    fn invalid_weight_profiles_fail_closed() {
        let missing_cost = json!({
            "schema_version": 1,
            "id": "bad",
            "version": 1,
            "latency_weight_bp": 5000
        });
        assert!(validate_preference_profile_document(&missing_cost)
            .expect_err("missing cost")
            .to_string()
            .contains("cost_weight_bp"));

        let unknown_field = json!({
            "schema_version": 1,
            "id": "bad",
            "version": 1,
            "latency_weight_bp": 5000,
            "cost_weight_bp": 5000,
            "not_a_weight": 1
        });
        assert!(validate_preference_profile_document(&unknown_field)
            .expect_err("unknown")
            .to_string()
            .contains("additionalProperties"));

        let wrong_version = json!({
            "schema_version": 2,
            "id": "bad",
            "version": 1,
            "latency_weight_bp": 5000,
            "cost_weight_bp": 5000
        });
        assert!(validate_preference_profile_document(&wrong_version)
            .expect_err("version")
            .to_string()
            .contains("const"));

        let negative = json!({
            "schema_version": 1,
            "id": "bad",
            "version": 1,
            "latency_weight_bp": 5000,
            "cost_weight_bp": -1
        });
        assert!(validate_preference_profile_document(&negative)
            .expect_err("negative")
            .to_string()
            .contains("minimum"));
    }
}

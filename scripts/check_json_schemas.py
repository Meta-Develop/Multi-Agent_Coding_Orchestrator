#!/usr/bin/env python3
"""Validate MACO's published JSON schemas and their contract fixtures.

This is deliberately a small, dependency-free Draft 2020-12 subset.  The
schema preflight rejects every keyword outside that subset so a misspelled or
unsupported assertion can never degrade into an annotation that is ignored.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_PREFIX = (
    "https://raw.githubusercontent.com/Meta-Develop/"
    "Multi-Agent_Coding_Orchestrator/main/schemas/"
)

# Every accepted keyword is either implemented below or is an explicitly
# non-assertive annotation/identifier used by the published schemas.
SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "description",
        "else",
        "enum",
        "examples",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "if",
        "items",
        "maxContains",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minContains",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    }
)
SCHEMA_MAP_KEYWORDS = frozenset({"$defs", "properties"})
SCHEMA_VALUE_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "contains",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
    }
)
SCHEMA_ARRAY_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf"})
KNOWN_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
VERSIONED_SCHEMA_FILENAME = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*\.schema\.json$"
)


class SchemaCheckError(Exception):
    """A deterministic schema, manifest, or fixture contract failure."""


@dataclass(frozen=True)
class ValidationError:
    instance_path: str
    keyword: str
    message: str

    def render(self) -> str:
        return f"{self.instance_path}: {self.keyword}: {self.message}"


def _reject_constant(value: str) -> None:
    raise SchemaCheckError(f"non-standard JSON numeric constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaCheckError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SchemaCheckError(f"failed to load JSON {path}: {error}") from error


def _schema_path(path: str, key: str) -> str:
    escaped = key.replace("~", "~0").replace("/", "~1")
    return f"{path}/{escaped}"


def _require_schema(value: Any, path: str) -> None:
    if not isinstance(value, (bool, dict)):
        raise SchemaCheckError(f"{path}: schema must be an object or boolean")


def audit_schema(
    schema: Any,
    *,
    source: Path | None = None,
    allowed_relative_refs: set[str] | None = None,
    schema_registry: dict[str, Any] | None = None,
) -> None:
    """Reject malformed schemas and every unsupported keyword recursively."""

    registry = schema_registry or {}
    allowed_refs = set(registry) | (allowed_relative_refs or set())
    _audit_schema_node(schema, "#", allowed_refs)
    if not isinstance(schema, dict):
        raise SchemaCheckError("#: published root schema must be an object")
    if schema.get("$schema") != DRAFT_2020_12:
        raise SchemaCheckError(f"#: $schema must be {DRAFT_2020_12}")
    schema_id = schema.get("$id")
    if not isinstance(schema_id, str) or not schema_id.startswith(SCHEMA_ID_PREFIX):
        raise SchemaCheckError(f"#: $id must start with {SCHEMA_ID_PREFIX}")
    if source is not None and schema_id != f"{SCHEMA_ID_PREFIX}{source.name}":
        raise SchemaCheckError(
            f"#: $id {schema_id!r} does not match published filename {source.name!r}"
        )
    if source is not None and VERSIONED_SCHEMA_FILENAME.fullmatch(source.name) is None:
        raise SchemaCheckError(
            f"#: published schema filename must carry a stable positive version: {source.name!r}"
        )
    for examples in _iter_schema_examples(schema):
        _reject_host_local_strings(
            examples,
            source or Path("<schema examples>"),
            source.parent.parent if source is not None else None,
            subject="schema examples",
        )
    for ref in _iter_schema_refs(schema):
        _resolve_ref(schema, ref, registry)


def _iter_schema_refs(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            yield ref
        for child in value.values():
            yield from _iter_schema_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_schema_refs(child)


def _iter_schema_examples(schema: Any) -> Iterable[Any]:
    """Yield examples annotations without interpreting example objects as schemas."""

    if not isinstance(schema, dict):
        return
    if "examples" in schema:
        yield schema["examples"]
    for keyword in SCHEMA_MAP_KEYWORDS:
        mapping = schema.get(keyword)
        if isinstance(mapping, dict):
            for subschema in mapping.values():
                yield from _iter_schema_examples(subschema)
    for keyword in SCHEMA_VALUE_KEYWORDS:
        if keyword in schema:
            yield from _iter_schema_examples(schema[keyword])
    for keyword in SCHEMA_ARRAY_KEYWORDS:
        branches = schema.get(keyword)
        if isinstance(branches, list):
            for subschema in branches:
                yield from _iter_schema_examples(subschema)


def _audit_schema_node(schema: Any, path: str, allowed_relative_refs: set[str]) -> None:
    _require_schema(schema, path)
    if isinstance(schema, bool):
        return

    unknown = sorted(set(schema) - SUPPORTED_KEYWORDS)
    if unknown:
        raise SchemaCheckError(
            f"{path}: unsupported JSON Schema keyword(s): {', '.join(unknown)}"
        )
    nested_identifiers = sorted(key for key in ("$id", "$schema") if key in schema)
    if path != "#" and nested_identifiers:
        raise SchemaCheckError(
            f"{path}: nested schema identifiers/dialects are unsupported: "
            f"{', '.join(nested_identifiers)}"
        )

    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str):
            raise SchemaCheckError(f"{path}/$ref: must be a string")
        if ref.startswith("#/"):
            _audit_pointer_fragment(ref[1:], f"{path}/$ref")
        else:
            filename, separator, fragment = ref.partition("#")
            if (
                Path(filename).name != filename
                or filename not in allowed_relative_refs
                or (separator and fragment and not fragment.startswith("/"))
            ):
                raise SchemaCheckError(
                    f"{path}/$ref: only local pointers or declared sibling schema refs are supported"
                )
            if separator and fragment:
                _audit_pointer_fragment(fragment, f"{path}/$ref")

    if "type" in schema:
        declared = schema["type"]
        values = declared if isinstance(declared, list) else [declared]
        if (
            not values
            or not all(isinstance(value, str) and value in KNOWN_TYPES for value in values)
            or len(set(values)) != len(values)
        ):
            raise SchemaCheckError(f"{path}/type: invalid or duplicate JSON type")

    for keyword in SCHEMA_MAP_KEYWORDS:
        if keyword not in schema:
            continue
        mapping = schema[keyword]
        if not isinstance(mapping, dict):
            raise SchemaCheckError(f"{path}/{keyword}: must be an object")
        for key, subschema in mapping.items():
            _audit_schema_node(
                subschema,
                _schema_path(f"{path}/{keyword}", key),
                allowed_relative_refs,
            )

    for keyword in SCHEMA_VALUE_KEYWORDS:
        if keyword not in schema:
            continue
        subschema = schema[keyword]
        _audit_schema_node(subschema, f"{path}/{keyword}", allowed_relative_refs)

    for keyword in SCHEMA_ARRAY_KEYWORDS:
        if keyword not in schema:
            continue
        branches = schema[keyword]
        if not isinstance(branches, list) or not branches:
            raise SchemaCheckError(f"{path}/{keyword}: must be a non-empty array")
        for index, subschema in enumerate(branches):
            _audit_schema_node(
                subschema, f"{path}/{keyword}/{index}", allowed_relative_refs
            )

    _audit_keyword_shapes(schema, path)


def _audit_keyword_shapes(schema: dict[str, Any], path: str) -> None:
    if "required" in schema and (
        not isinstance(schema["required"], list)
        or not all(isinstance(item, str) for item in schema["required"])
        or len(set(schema["required"])) != len(schema["required"])
    ):
        raise SchemaCheckError(f"{path}/required: must contain unique strings")
    for keyword in ("minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "minContains", "maxContains"):
        if keyword in schema and (
            not _is_integer(schema[keyword]) or schema[keyword] < 0
        ):
            raise SchemaCheckError(f"{path}/{keyword}: must be a nonnegative integer")
    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        if keyword in schema and not _is_number(schema[keyword]):
            raise SchemaCheckError(f"{path}/{keyword}: must be a finite number")
    for keyword in ("uniqueItems",):
        if keyword in schema and not isinstance(schema[keyword], bool):
            raise SchemaCheckError(f"{path}/{keyword}: must be boolean")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise SchemaCheckError(f"{path}/pattern: must be a string")
        try:
            re.compile(schema["pattern"])
        except re.error as error:
            raise SchemaCheckError(f"{path}/pattern: invalid regex: {error}") from error
    for keyword in ("title", "description", "$id", "$schema"):
        if keyword in schema and not isinstance(schema[keyword], str):
            raise SchemaCheckError(f"{path}/{keyword}: must be a string")
    if "examples" in schema and not isinstance(schema["examples"], list):
        raise SchemaCheckError(f"{path}/examples: must be an array")
    if "enum" in schema and (
        not isinstance(schema["enum"], list) or not schema["enum"]
    ):
        raise SchemaCheckError(f"{path}/enum: must be a non-empty array")
    if "additionalProperties" in schema and not isinstance(
        schema["additionalProperties"], (bool, dict)
    ):
        raise SchemaCheckError(
            f"{path}/additionalProperties: must be a schema or boolean"
        )
    if "contains" not in schema and (
        "minContains" in schema or "maxContains" in schema
    ):
        raise SchemaCheckError(
            f"{path}: minContains/maxContains require a contains schema"
        )
    if "if" not in schema and ("then" in schema or "else" in schema):
        raise SchemaCheckError(f"{path}: then/else require an if schema")


def _audit_pointer_fragment(pointer: str, path: str) -> None:
    if not pointer.startswith("/"):
        raise SchemaCheckError(f"{path}: schema ref fragment must be a JSON Pointer")
    if re.search(r"~(?:[^01]|$)", pointer):
        raise SchemaCheckError(
            f"{path}: malformed JSON Pointer escape; only ~0 and ~1 are valid"
        )


def _is_integer(value: Any) -> bool:
    return (
        (isinstance(value, int) and not isinstance(value, bool))
        or (
            isinstance(value, float)
            and math.isfinite(value)
            and value.is_integer()
        )
    )


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _instance_type_matches(instance: Any, declared: str) -> bool:
    return {
        "null": instance is None,
        "boolean": isinstance(instance, bool),
        "integer": _is_integer(instance),
        "number": _is_number(instance),
        "string": isinstance(instance, str),
        "array": isinstance(instance, list),
        "object": isinstance(instance, dict),
    }[declared]


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right))
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and set(left) == set(right)
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    return False


def _resolve_pointer(document: Any, pointer: str, ref: str) -> Any:
    current = document
    if not pointer:
        return current
    if not pointer.startswith("/"):
        raise SchemaCheckError(f"invalid JSON Pointer fragment in schema ref: {ref}")
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise SchemaCheckError(f"unresolved local schema ref: {ref}")
    _require_schema(current, ref)
    return current


def _resolve_ref(
    root_schema: Any, ref: str, registry: dict[str, Any]
) -> tuple[Any, Any]:
    if ref.startswith("#/"):
        return _resolve_pointer(root_schema, ref[1:], ref), root_schema
    filename, _, fragment = ref.partition("#")
    target_root = registry.get(filename)
    if target_root is None:
        raise SchemaCheckError(f"unresolved sibling schema ref: {ref}")
    return _resolve_pointer(target_root, fragment, ref), target_root


def validate(
    instance: Any, schema: Any, *, registry: dict[str, Any] | None = None
) -> list[ValidationError]:
    return _validate(instance, schema, schema, "$", registry or {})


def _validate(
    instance: Any,
    schema: Any,
    root_schema: Any,
    instance_path: str,
    registry: dict[str, Any],
) -> list[ValidationError]:
    if schema is True:
        return []
    if schema is False:
        return [ValidationError(instance_path, "false schema", "value is forbidden")]

    errors: list[ValidationError] = []
    if "$ref" in schema:
        target, target_root = _resolve_ref(root_schema, schema["$ref"], registry)
        errors.extend(
            _validate(instance, target, target_root, instance_path, registry)
        )

    declared = schema.get("type")
    if declared is not None:
        types = declared if isinstance(declared, list) else [declared]
        if not any(_instance_type_matches(instance, value) for value in types):
            return errors + [
                ValidationError(
                    instance_path,
                    "type",
                    f"expected {' or '.join(types)}, got {_json_type_name(instance)}",
                )
            ]

    if "const" in schema and not _json_equal(instance, schema["const"]):
        errors.append(
            ValidationError(instance_path, "const", f"expected {schema['const']!r}")
        )
    if "enum" in schema and not any(
        _json_equal(instance, candidate) for candidate in schema["enum"]
    ):
        errors.append(ValidationError(instance_path, "enum", "value is not allowed"))

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword not in schema:
            continue
        branch_errors = [
            _validate(instance, branch, root_schema, instance_path, registry)
            for branch in schema[keyword]
        ]
        valid_count = sum(not branch for branch in branch_errors)
        if keyword == "allOf":
            for branch in branch_errors:
                errors.extend(branch)
        elif keyword == "anyOf" and valid_count == 0:
            errors.append(
                ValidationError(instance_path, "anyOf", "no branch matched")
            )
        elif keyword == "oneOf" and valid_count != 1:
            errors.append(
                ValidationError(
                    instance_path,
                    "oneOf",
                    f"expected exactly one matching branch, got {valid_count}",
                )
            )

    if "not" in schema and not _validate(
        instance, schema["not"], root_schema, instance_path, registry
    ):
        errors.append(ValidationError(instance_path, "not", "forbidden schema matched"))
    if "if" in schema:
        condition_matches = not _validate(
            instance, schema["if"], root_schema, instance_path, registry
        )
        selected = "then" if condition_matches else "else"
        if selected in schema:
            errors.extend(
                _validate(
                    instance, schema[selected], root_schema, instance_path, registry
                )
            )

    if isinstance(instance, dict):
        errors.extend(
            _validate_object(instance, schema, root_schema, instance_path, registry)
        )
    if isinstance(instance, list):
        errors.extend(
            _validate_array(instance, schema, root_schema, instance_path, registry)
        )
    if isinstance(instance, str):
        errors.extend(_validate_string(instance, schema, instance_path))
    if _is_number(instance):
        errors.extend(_validate_number(instance, schema, instance_path))
    return errors


def _json_type_name(value: Any) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _instance_type_matches(value, name):
            return name
    return type(value).__name__


def _child_path(parent: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=True)}]"


def _validate_object(
    instance: dict[str, Any],
    schema: dict[str, Any],
    root_schema: Any,
    path: str,
    registry: dict[str, Any],
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    required = schema.get("required", [])
    for key in required:
        if key not in instance:
            errors.append(
                ValidationError(path, "required", f"missing property {key!r}")
            )
    properties = schema.get("properties", {})
    additional = schema.get("additionalProperties", True)
    for key, value in instance.items():
        child = _child_path(path, key)
        if key in properties:
            errors.extend(
                _validate(value, properties[key], root_schema, child, registry)
            )
        elif additional is False:
            errors.append(
                ValidationError(child, "additionalProperties", "property is not allowed")
            )
        elif additional is not True:
            errors.extend(_validate(value, additional, root_schema, child, registry))
    if "propertyNames" in schema:
        for key in instance:
            errors.extend(
                _validate(
                    key,
                    schema["propertyNames"],
                    root_schema,
                    _child_path(path, key),
                    registry,
                )
            )
    size = len(instance)
    if "minProperties" in schema and size < schema["minProperties"]:
        errors.append(ValidationError(path, "minProperties", f"got {size}"))
    if "maxProperties" in schema and size > schema["maxProperties"]:
        errors.append(ValidationError(path, "maxProperties", f"got {size}"))
    return errors


def _validate_array(
    instance: list[Any],
    schema: dict[str, Any],
    root_schema: Any,
    path: str,
    registry: dict[str, Any],
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    size = len(instance)
    if "minItems" in schema and size < schema["minItems"]:
        errors.append(ValidationError(path, "minItems", f"got {size}"))
    if "maxItems" in schema and size > schema["maxItems"]:
        errors.append(ValidationError(path, "maxItems", f"got {size}"))
    if schema.get("uniqueItems"):
        for index, value in enumerate(instance):
            if any(_json_equal(value, prior) for prior in instance[:index]):
                errors.append(
                    ValidationError(
                        _child_path(path, index), "uniqueItems", "duplicate array item"
                    )
                )
    if "items" in schema:
        for index, value in enumerate(instance):
            errors.extend(
                _validate(
                    value,
                    schema["items"],
                    root_schema,
                    _child_path(path, index),
                    registry,
                )
            )
    if "contains" in schema:
        matches = sum(
            not _validate(
                value,
                schema["contains"],
                root_schema,
                _child_path(path, index),
                registry,
            )
            for index, value in enumerate(instance)
        )
        minimum = schema.get("minContains", 1)
        maximum = schema.get("maxContains")
        if matches < minimum:
            errors.append(
                ValidationError(path, "minContains", f"got {matches}, expected {minimum}")
            )
        if maximum is not None and matches > maximum:
            errors.append(
                ValidationError(path, "maxContains", f"got {matches}, expected <= {maximum}")
            )
    return errors


def _validate_string(
    instance: str, schema: dict[str, Any], path: str
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    if "minLength" in schema and len(instance) < schema["minLength"]:
        errors.append(ValidationError(path, "minLength", f"got {len(instance)}"))
    if "maxLength" in schema and len(instance) > schema["maxLength"]:
        errors.append(ValidationError(path, "maxLength", f"got {len(instance)}"))
    if "pattern" in schema and re.search(schema["pattern"], instance) is None:
        errors.append(
            ValidationError(path, "pattern", f"does not match {schema['pattern']!r}")
        )
    return errors


def _validate_number(
    instance: int | float, schema: dict[str, Any], path: str
) -> list[ValidationError]:
    errors: list[ValidationError] = []
    comparisons = (
        ("minimum", lambda value, bound: value >= bound, ">="),
        ("maximum", lambda value, bound: value <= bound, "<="),
        ("exclusiveMinimum", lambda value, bound: value > bound, ">"),
        ("exclusiveMaximum", lambda value, bound: value < bound, "<"),
    )
    for keyword, predicate, operator in comparisons:
        if keyword in schema and not predicate(instance, schema[keyword]):
            errors.append(
                ValidationError(
                    path, keyword, f"expected {operator} {schema[keyword]}, got {instance}"
                )
            )
    return errors


def _manifest_child(directory: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).name != raw:
        raise SchemaCheckError(f"manifest {label} must be a direct-child filename")
    return directory / raw


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)


def _reject_host_local_strings(
    value: Any,
    path: Path,
    repo_root: Path | None,
    *,
    subject: str,
) -> None:
    repo_text = str(repo_root.resolve()) if repo_root is not None else None
    patterns = (
        re.compile(r"/(?:home|Users)/[^/]+/"),
        re.compile(r"/mnt/[A-Za-z]/home/"),
        re.compile(r"/(?:root|tmp|var/tmp)/"),
        re.compile(r"[A-Za-z]:[\\/]", re.IGNORECASE),
        re.compile(r"^[\\]{2}[^\\]+[\\]"),
    )
    for text in _walk_strings(value):
        if (repo_text is not None and repo_text in text) or any(
            pattern.search(text) for pattern in patterns
        ):
            raise SchemaCheckError(f"{path}: {subject} contains a host-local path")


def _reject_fixture_host_leaks(value: Any, path: Path, repo_root: Path) -> None:
    _reject_host_local_strings(value, path, repo_root, subject="fixture")


def _direct_contract_files(directory: Path, pattern: str, label: str) -> set[str]:
    paths = sorted(directory.rglob(pattern))
    nested = [str(path.relative_to(directory)) for path in paths if path.parent != directory]
    if nested:
        raise SchemaCheckError(
            f"nested {label} files are unsupported and would be orphan contracts: {nested}"
        )
    return {path.name for path in paths}


def check_contracts(schema_dir: Path, fixture_dir: Path) -> list[str]:
    manifest_path = fixture_dir / "manifest.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != {"version", "contracts"}:
        raise SchemaCheckError("fixture manifest must contain only version and contracts")
    if manifest["version"] != 1 or not isinstance(manifest["contracts"], list):
        raise SchemaCheckError("fixture manifest version must be 1 with a contracts array")

    actual_schemas = _direct_contract_files(
        schema_dir, "*.schema.json", "published schema"
    )
    actual_valid = _direct_contract_files(fixture_dir, "*.valid.json", "valid fixture")
    actual_invalid = _direct_contract_files(
        fixture_dir, "*.invalid.json", "invalid fixture"
    )
    referenced_schemas: set[str] = set()
    referenced_valid: set[str] = set()
    referenced_invalid: set[str] = set()
    output: list[str] = []
    repo_root = schema_dir.parent
    schema_registry = {
        name: load_json(schema_dir / name) for name in sorted(actual_schemas)
    }
    for name, schema in schema_registry.items():
        audit_schema(
            schema,
            source=schema_dir / name,
            schema_registry=schema_registry,
        )

    for index, contract in enumerate(manifest["contracts"]):
        label = f"contracts[{index}]"
        if not isinstance(contract, dict) or set(contract) != {"schema", "valid", "invalid"}:
            raise SchemaCheckError(
                f"manifest {label} must contain only schema, valid, and invalid"
            )
        schema_path = _manifest_child(schema_dir, contract["schema"], f"{label}.schema")
        if schema_path.name in referenced_schemas:
            raise SchemaCheckError(f"manifest repeats schema {schema_path.name}")
        referenced_schemas.add(schema_path.name)
        if schema_path.name not in schema_registry:
            raise SchemaCheckError(f"manifest references missing schema {schema_path.name}")
        schema = schema_registry[schema_path.name]

        valid_names = contract["valid"]
        invalid_entries = contract["invalid"]
        if not isinstance(valid_names, list) or not valid_names:
            raise SchemaCheckError(f"manifest {label}.valid must be a non-empty array")
        if not isinstance(invalid_entries, list) or not invalid_entries:
            raise SchemaCheckError(f"manifest {label}.invalid must be a non-empty array")

        for raw_name in valid_names:
            fixture_path = _manifest_child(fixture_dir, raw_name, f"{label}.valid")
            if fixture_path.name in referenced_valid:
                raise SchemaCheckError(f"manifest repeats valid fixture {fixture_path.name}")
            referenced_valid.add(fixture_path.name)
            instance = load_json(fixture_path)
            _reject_fixture_host_leaks(instance, fixture_path, repo_root)
            errors = validate(instance, schema, registry=schema_registry)
            if errors:
                rendered = "; ".join(error.render() for error in errors[:8])
                raise SchemaCheckError(
                    f"{fixture_path.name}: expected valid but failed: {rendered}"
                )
            output.append(f"PASS valid   {schema_path.name} <- {fixture_path.name}")

        for invalid in invalid_entries:
            if not isinstance(invalid, dict) or set(invalid) != {"path", "expected_error"}:
                raise SchemaCheckError(
                    f"manifest {label}.invalid entry needs path and expected_error"
                )
            fixture_path = _manifest_child(
                fixture_dir, invalid["path"], f"{label}.invalid.path"
            )
            expected = invalid["expected_error"]
            if not isinstance(expected, str) or not expected:
                raise SchemaCheckError(
                    f"manifest {label}.invalid expected_error must be non-empty"
                )
            expected_match = re.fullmatch(
                r"(?P<path>\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:[0-9]+|\"(?:[^\"\\]|\\.)*\")\])*)"
                r": (?P<keyword>[A-Za-z][A-Za-z0-9]*)",
                expected,
            )
            if expected_match is None:
                raise SchemaCheckError(
                    f"manifest {label}.invalid expected_error must be '$path: keyword'"
                )
            if fixture_path.name in referenced_invalid:
                raise SchemaCheckError(f"manifest repeats invalid fixture {fixture_path.name}")
            referenced_invalid.add(fixture_path.name)
            instance = load_json(fixture_path)
            _reject_fixture_host_leaks(instance, fixture_path, repo_root)
            errors = validate(instance, schema, registry=schema_registry)
            rendered = "; ".join(error.render() for error in errors)
            if not errors:
                raise SchemaCheckError(
                    f"{fixture_path.name}: expected invalid but schema accepted it"
                )
            if not any(
                error.instance_path == expected_match.group("path")
                and error.keyword == expected_match.group("keyword")
                for error in errors
            ):
                raise SchemaCheckError(
                    f"{fixture_path.name}: intended reason {expected!r} not found in: {rendered}"
                )
            output.append(
                f"PASS invalid {schema_path.name} <- {fixture_path.name} ({expected})"
            )

    if actual_schemas != referenced_schemas:
        raise SchemaCheckError(
            "schema manifest coverage mismatch: "
            f"unreferenced={sorted(actual_schemas - referenced_schemas)}, "
            f"missing={sorted(referenced_schemas - actual_schemas)}"
        )
    if actual_valid != referenced_valid:
        raise SchemaCheckError(
            "valid fixture coverage mismatch: "
            f"unreferenced={sorted(actual_valid - referenced_valid)}, "
            f"missing={sorted(referenced_valid - actual_valid)}"
        )
    if actual_invalid != referenced_invalid:
        raise SchemaCheckError(
            "invalid fixture coverage mismatch: "
            f"unreferenced={sorted(actual_invalid - referenced_invalid)}, "
            f"missing={sorted(referenced_invalid - actual_invalid)}"
        )
    return output


def parse_args(argv: list[str]) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Validate published JSON schemas and paired fixtures"
    )
    parser.add_argument("--schema-dir", type=Path, default=repo_root / "schemas")
    parser.add_argument("--fixture-dir", type=Path, default=repo_root / "fixtures" / "schemas")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        output = check_contracts(args.schema_dir, args.fixture_dir)
    except SchemaCheckError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    for line in output:
        print(line)
    print(
        f"Validated {len(output)} schema fixture expectations with the strict stdlib subset."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

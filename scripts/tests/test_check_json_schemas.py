from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import check_json_schemas


class JsonSchemaSubsetTests(unittest.TestCase):
    def test_published_contract_fixtures_pass(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        output = check_json_schemas.check_contracts(
            repo_root / "schemas", repo_root / "fixtures" / "schemas"
        )

        self.assertGreaterEqual(len(output), 10)
        self.assertTrue(any(line.startswith("PASS valid") for line in output))
        self.assertTrue(any(line.startswith("PASS invalid") for line in output))

    def test_unknown_keyword_is_rejected_at_any_depth(self) -> None:
        schema = self.schema(
            {
                "type": "object",
                "properties": {
                    "nested": {
                        "type": "string",
                        "unevaluatedProperties": False,
                    }
                },
            }
        )

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError,
            r"unsupported JSON Schema keyword.*unevaluatedProperties",
        ):
            check_json_schemas.audit_schema(schema)

    def test_external_ref_is_rejected_in_preflight(self) -> None:
        schema = self.schema({"$ref": "https://example.invalid/remote.json"})

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError, "only local pointers or declared sibling"
        ):
            check_json_schemas.audit_schema(schema)

    def test_malformed_json_pointer_escape_is_rejected_in_preflight(self) -> None:
        schema = self.schema(
            {
                "$ref": "#/$defs/value~2name",
                "$defs": {"value~2name": {"type": "integer"}},
            }
        )

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError,
            "malformed JSON Pointer escape",
        ):
            check_json_schemas.audit_schema(schema)

    def test_unused_unresolved_ref_is_rejected_in_preflight(self) -> None:
        schema = self.schema(
            {
                "type": "integer",
                "$defs": {
                    "unused": {
                        "$ref": "#/$defs/missing",
                    }
                },
            }
        )

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError, "unresolved local schema ref"
        ):
            check_json_schemas.audit_schema(schema)

    def test_nested_schema_identity_is_rejected_when_scope_is_not_implemented(self) -> None:
        schema = self.schema(
            {
                "type": "object",
                "properties": {
                    "nested": {
                        "$id": "nested-resource.json",
                        "type": "string",
                    }
                },
            }
        )

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError,
            "nested schema identifiers/dialects are unsupported",
        ):
            check_json_schemas.audit_schema(schema)

    def test_loader_rejects_duplicate_keys_and_nonstandard_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"field": 1, "field": 2}\n', encoding="utf-8")
            nonstandard = root / "nonstandard.json"
            nonstandard.write_text('{"field": NaN}\n', encoding="utf-8")

            with self.assertRaisesRegex(
                check_json_schemas.SchemaCheckError, "duplicate JSON object key"
            ):
                check_json_schemas.load_json(duplicate)
            with self.assertRaisesRegex(
                check_json_schemas.SchemaCheckError,
                "non-standard JSON numeric constant",
            ):
                check_json_schemas.load_json(nonstandard)

    def test_fixture_host_path_detection_rejects_user_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for host_path in (
                "/home/example/private/repository",
                "/root/private/repository",
                "/tmp/private/repository",
                "D:\\private\\repository",
            ):
                with self.subTest(host_path=host_path), self.assertRaisesRegex(
                    check_json_schemas.SchemaCheckError,
                    "fixture contains a host-local path",
                ):
                    check_json_schemas._reject_fixture_host_leaks(
                        {"path": host_path},
                        root / "fixture.json",
                        root,
                    )

    def test_schema_examples_reject_host_local_paths(self) -> None:
        schema = self.schema(
            {
                "type": "string",
                "examples": ["/home/example/private/repository"],
            }
        )

        with self.assertRaisesRegex(
            check_json_schemas.SchemaCheckError, "contains a host-local path"
        ):
            check_json_schemas.audit_schema(schema)

    def test_nested_contract_files_are_rejected_as_orphans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema_dir = root / "schemas"
            fixture_dir = root / "fixtures" / "schemas"
            schema_dir.mkdir(parents=True)
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "manifest.json").write_text(
                '{"version": 1, "contracts": []}\n', encoding="utf-8"
            )

            nested = schema_dir / "nested"
            nested.mkdir()
            (nested / "orphan-v1.schema.json").write_text(
                json.dumps(self.schema({"type": "integer"})), encoding="utf-8"
            )

            with self.assertRaisesRegex(
                check_json_schemas.SchemaCheckError,
                "would be orphan contracts",
            ):
                check_json_schemas.check_contracts(schema_dir, fixture_dir)

    def test_published_schema_filename_must_be_versioned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "sample.schema.json"
            schema = {
                "$schema": check_json_schemas.DRAFT_2020_12,
                "$id": f"{check_json_schemas.SCHEMA_ID_PREFIX}{source.name}",
                "type": "integer",
            }

            with self.assertRaisesRegex(
                check_json_schemas.SchemaCheckError,
                "must carry a stable positive version",
            ):
                check_json_schemas.audit_schema(schema, source=source)

    def test_integer_does_not_accept_boolean(self) -> None:
        errors = check_json_schemas.validate(True, {"type": "integer"})

        self.assertEqual(errors[0].keyword, "type")
        self.assertEqual(
            check_json_schemas.validate(1.0, {"type": "integer"}),
            [],
            "Draft integer includes zero-fraction JSON numbers",
        )

    def test_published_relative_path_definitions_reject_roots_and_traversal(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        for name, definition in (
            ("repository-map-v1.schema.json", "repositoryRelativePath"),
            ("semantic-risk-report-v1.schema.json", "repositoryRelativePath"),
            ("merge-preview-report-v1.schema.json", "repositoryRelativePath"),
            ("supervisor-final-report-v1.schema.json", "safePublishedPath"),
        ):
            schema = check_json_schemas.load_json(repo_root / "schemas" / name)
            path_schema = schema["$defs"][definition]
            for invalid in (
                "/private/file",
                "../private",
                "C:\\private\\file",
                "C:drive-relative",
            ):
                with self.subTest(schema=name, invalid=invalid):
                    self.assertTrue(check_json_schemas.validate(invalid, path_schema))
            self.assertEqual(
                check_json_schemas.validate("src\\lib.rs", path_schema),
                [],
                "relative native separator must remain portable",
            )

    def test_merge_samples_bind_the_published_full_patch(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        fixture_root = repo_root / "fixtures" / "schemas"
        for name, candidate_path in (
            ("merge-preview-report-v1.valid.json", ("candidate",)),
            ("merge-apply-report-v1.valid.json", ("preview", "candidate")),
        ):
            sample = check_json_schemas.load_json(fixture_root / name)
            candidate = sample
            for key in candidate_path:
                candidate = candidate[key]
            patch = candidate["diff"]["full"]
            patch_bytes = patch.encode("utf-8")
            expected_oid = hashlib.sha1(
                f"blob {len(patch_bytes)}\0".encode("ascii") + patch_bytes
            ).hexdigest()

            with self.subTest(fixture=name):
                self.assertEqual(candidate["diff"]["summary"]["text"], patch)
                self.assertFalse(candidate["diff"]["summary"]["truncated"])
                self.assertEqual(candidate["validation_binding"]["diff_oid"], expected_oid)
                self.assertEqual(
                    [change["path"] for change in candidate["changes"]],
                    candidate["changed_paths"],
                )
                if "freshness_watermark" in sample:
                    self.assertEqual(
                        sample["freshness_watermark"]["candidate"]["diff_oid"],
                        expected_oid,
                    )

    def test_claimed_paths_are_uncapped_and_admission_config_uses_omission(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        schema_root = repo_root / "schemas"

        merge_schema = check_json_schemas.load_json(
            schema_root / "merge-preview-report-v1.schema.json"
        )
        candidate_properties = merge_schema["$defs"]["candidate"]["properties"]
        self.assertNotIn("maxItems", candidate_properties["claimed_paths"])
        for bounded in ("changed_paths", "changes", "unclaimed_changed_paths"):
            self.assertEqual(candidate_properties[bounded]["maxItems"], 8192)

        supervisor_schema = check_json_schemas.load_json(
            schema_root / "supervisor-final-report-v1.schema.json"
        )
        admission = supervisor_schema["$defs"]["admissionConfig"]
        fields = (
            "max_concurrent_children",
            "provider_inflight_limit",
            "host_memory_available_mib",
            "host_memory_per_child_mib",
            "host_fd_available",
            "host_fds_per_child",
            "host_disk_available_mib",
            "host_disk_per_child_mib",
            "host_fallback_children",
        )
        self.assertEqual(check_json_schemas.validate({}, admission), [])
        self.assertEqual(
            check_json_schemas.validate({field: 1 for field in fields}, admission),
            [],
        )
        for field in fields:
            with self.subTest(field=field):
                null_errors = check_json_schemas.validate({field: None}, admission)
                self.assertEqual(null_errors[0].instance_path, f"$.{field}")
                self.assertEqual(null_errors[0].keyword, "type")
                minimum_errors = check_json_schemas.validate({field: 0}, admission)
                self.assertEqual(minimum_errors[0].instance_path, f"$.{field}")
                self.assertEqual(minimum_errors[0].keyword, "minimum")

    def test_unique_items_uses_json_numeric_equality_but_not_boolean_equality(self) -> None:
        schema = {"type": "array", "uniqueItems": True}

        self.assertEqual(
            check_json_schemas.validate([True, 1], schema), [], "bool and number differ"
        )
        errors = check_json_schemas.validate([1, 1.0], schema)
        self.assertEqual(errors[0].keyword, "uniqueItems")

    def test_one_of_and_conditionals_are_assertive(self) -> None:
        schema = {
            "type": "object",
            "required": ["kind", "enabled"],
            "properties": {
                "kind": {"oneOf": [{"const": "one"}, {"const": "two"}]},
                "enabled": {"type": "boolean"},
            },
            "if": {"properties": {"kind": {"const": "one"}}},
            "then": {"properties": {"enabled": {"const": True}}},
        }

        self.assertEqual(
            check_json_schemas.validate({"kind": "one", "enabled": True}, schema),
            [],
        )
        rendered = "; ".join(
            error.render()
            for error in check_json_schemas.validate(
                {"kind": "one", "enabled": False}, schema
            )
        )
        self.assertIn("$.enabled: const", rendered)

    def test_manifest_requires_intended_invalid_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema_dir = root / "schemas"
            fixture_dir = root / "fixtures" / "schemas"
            schema_dir.mkdir(parents=True)
            fixture_dir.mkdir(parents=True)
            schema_name = "sample-v1.schema.json"
            (schema_dir / schema_name).write_text(
                json.dumps(
                    {
                        "$schema": check_json_schemas.DRAFT_2020_12,
                        "$id": f"{check_json_schemas.SCHEMA_ID_PREFIX}{schema_name}",
                        "type": "integer",
                        "minimum": 1,
                    }
                ),
                encoding="utf-8",
            )
            (fixture_dir / "sample-v1.valid.json").write_text("1\n", encoding="utf-8")
            (fixture_dir / "sample-v1.invalid.json").write_text("0\n", encoding="utf-8")
            (fixture_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "contracts": [
                            {
                                "schema": schema_name,
                                "valid": ["sample-v1.valid.json"],
                                "invalid": [
                                    {
                                        "path": "sample-v1.invalid.json",
                                        "expected_error": "$: enum",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                check_json_schemas.SchemaCheckError,
                r"intended reason '\$: enum' not found",
            ):
                check_json_schemas.check_contracts(schema_dir, fixture_dir)

    @staticmethod
    def schema(body: dict[str, object]) -> dict[str, object]:
        return {
            "$schema": check_json_schemas.DRAFT_2020_12,
            "$id": f"{check_json_schemas.SCHEMA_ID_PREFIX}test.schema.json",
            **body,
        }


if __name__ == "__main__":
    unittest.main()

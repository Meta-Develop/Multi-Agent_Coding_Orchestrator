from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from scripts import check_megafile_baseline as megafile


def thresholds(
    max_lines: int = megafile.DEFAULT_MAX_LINES,
    max_bytes: int = megafile.DEFAULT_MAX_BYTES,
) -> megafile.Thresholds:
    return megafile.Thresholds(max_lines=max_lines, max_bytes=max_bytes)


def measurement(path: str, lines: int, size: int) -> megafile.FileMeasurement:
    return megafile.FileMeasurement(path=path, lines=lines, bytes=size)


def entry(lines: int, size: int) -> megafile.BaselineEntry:
    return megafile.BaselineEntry(lines=lines, bytes=size)


def codes(findings: tuple[megafile.Finding, ...]) -> list[str]:
    return [finding.code for finding in findings]


class EvaluationTests(unittest.TestCase):
    def test_new_over_threshold_file_not_in_baseline_fails(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/foo.rs", 4120, 100)],
            {},
            thresholds(),
        )

        self.assertEqual(codes(evaluation.violations), ["new-megafile"])
        self.assertEqual(evaluation.violations[0].path, "src/foo.rs")
        self.assertEqual(evaluation.violations[0].measured_lines, 4120)
        self.assertEqual(evaluation.violations[0].threshold_lines, 4000)
        self.assertEqual(evaluation.notices, ())

    def test_file_exactly_at_threshold_is_a_new_megafile(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/foo.rs", 4000, 10)],
            {},
            thresholds(),
        )

        self.assertEqual(codes(evaluation.violations), ["new-megafile"])

    def test_baseline_file_that_grew_fails(self) -> None:
        evaluation = megafile.evaluate(
            [
                measurement("src/bytes.rs", 10, 21),
                measurement("src/lines.rs", 101, 10),
            ],
            {
                "src/bytes.rs": entry(10, 20),
                "src/lines.rs": entry(100, 10),
            },
            thresholds(max_lines=50, max_bytes=15),
        )

        self.assertEqual(codes(evaluation.violations), ["growth-bytes", "growth-lines"])
        self.assertEqual(evaluation.violations[0].path, "src/bytes.rs")
        self.assertEqual(evaluation.violations[0].measured_bytes, 21)
        self.assertEqual(evaluation.violations[0].baseline_bytes, 20)
        self.assertEqual(evaluation.violations[1].path, "src/lines.rs")
        self.assertEqual(evaluation.violations[1].measured_lines, 101)
        self.assertEqual(evaluation.violations[1].baseline_lines, 100)

    def test_growth_fails_even_when_a_threshold_override_is_under(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/worktree.rs", 19100, 600_000)],
            {"src/worktree.rs": entry(19039, 524_289)},
            thresholds(max_lines=20_000, max_bytes=700_000),
        )

        self.assertEqual(codes(evaluation.violations), ["growth-bytes", "growth-lines"])
        self.assertEqual(codes(evaluation.notices), ["dropped-under-threshold"])

    def test_baseline_file_that_shrank_passes_with_rebaseline_notice(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/baz.rs", 4100, 1_000)],
            {"src/baz.rs": entry(4200, 2_000)},
            thresholds(),
        )

        self.assertEqual(evaluation.violations, ())
        self.assertEqual(codes(evaluation.notices), ["shrink-bytes", "shrink-lines"])
        rendered = "\n".join(
            megafile.render_notice(notice) for notice in evaluation.notices
        )
        self.assertIn("--update-baseline", rendered)
        self.assertIn(megafile.quote_path("src/baz.rs"), rendered)

    def test_under_threshold_file_absent_from_baseline_passes(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/small.rs", 10, 10)],
            {},
            thresholds(),
        )

        self.assertEqual(evaluation.violations, ())
        self.assertEqual(evaluation.notices, ())

    def test_dropped_under_threshold_is_a_notice_not_a_failure(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/baz.rs", 3900, 100)],
            {"src/baz.rs": entry(4100, 200)},
            thresholds(),
        )

        self.assertEqual(evaluation.violations, ())
        self.assertEqual(
            codes(evaluation.notices),
            ["dropped-under-threshold", "shrink-bytes", "shrink-lines"],
        )

    def test_missing_baseline_path_is_a_notice_not_a_failure(self) -> None:
        evaluation = megafile.evaluate(
            [measurement("src/keep.rs", 4100, 100)],
            {
                "src/keep.rs": entry(4100, 100),
                "src/gone.rs": entry(5000, 200),
            },
            thresholds(),
        )

        self.assertEqual(evaluation.violations, ())
        self.assertEqual(codes(evaluation.notices), ["missing-from-tree"])
        self.assertEqual(evaluation.notices[0].path, "src/gone.rs")

    def test_findings_are_sorted_by_path_then_code(self) -> None:
        reversed_order = megafile.evaluate(
            [
                measurement("z.rs", 5000, 10),
                measurement("a.rs", 4100, 10),
            ],
            {},
            thresholds(),
        )
        forward_order = megafile.evaluate(
            [
                measurement("a.rs", 4100, 10),
                measurement("z.rs", 5000, 10),
            ],
            {},
            thresholds(),
        )

        self.assertEqual(reversed_order, forward_order)
        self.assertEqual(
            [finding.path for finding in forward_order.violations],
            ["a.rs", "z.rs"],
        )


class MeasurementTests(unittest.TestCase):
    def test_physical_line_count_uses_newline_bytes_only(self) -> None:
        self.assertEqual(megafile.physical_line_count(b""), 0)
        self.assertEqual(megafile.physical_line_count(b"abc"), 1)
        self.assertEqual(megafile.physical_line_count(b"abc\n"), 1)
        self.assertEqual(megafile.physical_line_count(b"a\nb"), 2)
        self.assertEqual(megafile.physical_line_count(b"a\nb\n"), 2)
        self.assertEqual(megafile.physical_line_count(b"a\rb"), 1)

    def test_measure_file_reads_on_disk_size_and_physical_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            relative_path = "sample.rs"
            (repository / relative_path).write_bytes(b"one\ntwo")

            observed = megafile.measure_file(repository, relative_path)

        self.assertEqual(observed.path, relative_path)
        self.assertEqual(observed.lines, 2)
        self.assertEqual(observed.bytes, 7)


class BaselineDocumentTests(unittest.TestCase):
    def test_serialize_baseline_is_sorted_lines_then_bytes_with_trailing_newline(
        self,
    ) -> None:
        text = megafile.serialize_baseline(
            [
                measurement("z.rs", 4100, 100),
                measurement("a.rs", 5000, 200),
            ]
        )

        self.assertEqual(
            text,
            """{
  "a.rs": {
    "lines": 5000,
    "bytes": 200
  },
  "z.rs": {
    "lines": 4100,
    "bytes": 100
  }
}
""",
        )
        parsed = json.loads(text)
        self.assertEqual(list(parsed), ["a.rs", "z.rs"])
        self.assertEqual(list(parsed["a.rs"]), ["lines", "bytes"])

    def test_missing_baseline_file_loads_as_empty_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "missing.json"
            self.assertEqual(megafile.load_baseline(path), {})

    def test_invalid_baseline_types_and_unknown_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            megafile.parse_baseline(["not", "an", "object"])
        with self.assertRaises(ValueError):
            megafile.parse_baseline({"src/foo.rs": {"lines": 1, "bytes": 1, "extra": 0}})
        with self.assertRaises(ValueError):
            megafile.parse_baseline({"src/foo.rs": {"lines": True, "bytes": 1}})
        with self.assertRaises(ValueError):
            megafile.parse_baseline({"src/foo.rs": {"lines": -1, "bytes": 1}})


class GitEnumerationTests(unittest.TestCase):
    @mock.patch("scripts.check_megafile_baseline.subprocess.run")
    def test_git_paths_are_requested_with_nul_delimiters_and_rust_pathspec(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["git", "ls-files", "-z", "--", "*.rs"],
            0,
            stdout=b"one.rs\0src/two.rs\0",
        )

        paths = megafile.git_tracked_rust_files(Path("repository"))

        self.assertEqual(paths, [b"one.rs", b"src/two.rs"])
        run.assert_called_once_with(
            ["git", "ls-files", "-z", "--", "*.rs"],
            cwd=Path("repository"),
            check=True,
            stdout=subprocess.PIPE,
        )


class CliTests(unittest.TestCase):
    def test_update_baseline_writes_only_over_threshold_files_deterministically(
        self,
    ) -> None:
        measurements = {
            "z.rs": measurement("z.rs", 4100, 100),
            "a.rs": measurement("a.rs", 10, 600_000),
            "mid.rs": measurement("mid.rs", 10, 10),
            "b.rs": measurement("b.rs", 4000, 50),
        }

        def fake_measure(
            repository: Path, relative_path: str
        ) -> megafile.FileMeasurement:
            del repository
            return measurements[relative_path]

        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            baseline = repository / "megafile_baseline.json"
            with mock.patch.object(
                megafile,
                "git_tracked_rust_files",
                return_value=[b"z.rs", b"a.rs", b"mid.rs", b"b.rs"],
            ), mock.patch.object(megafile, "measure_file", side_effect=fake_measure):
                stdout = StringIO()
                stderr = StringIO()
                with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                    status = megafile.main(
                        [str(repository), "--update-baseline", "--baseline", str(baseline)]
                    )

            self.assertEqual(status, 0)
            text = baseline.read_text(encoding="utf-8")

        self.assertTrue(stdout.getvalue().startswith("updated megafile baseline with 3 "))
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            text,
            """{
  "a.rs": {
    "lines": 10,
    "bytes": 600000
  },
  "b.rs": {
    "lines": 4000,
    "bytes": 50
  },
  "z.rs": {
    "lines": 4100,
    "bytes": 100
  }
}
""",
        )
        parsed = json.loads(text)
        self.assertEqual(list(parsed), ["a.rs", "b.rs", "z.rs"])
        self.assertNotIn("mid.rs", parsed)
        self.assertEqual(list(parsed["a.rs"]), ["lines", "bytes"])

    def test_json_mode_includes_violation_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            with mock.patch.object(
                megafile,
                "git_tracked_rust_files",
                return_value=[b"src/foo.rs"],
            ), mock.patch.object(
                megafile,
                "measure_file",
                return_value=measurement("src/foo.rs", 4120, 100),
            ):
                stdout = StringIO()
                stderr = StringIO()
                with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                    status = megafile.main([str(repository), "--json"])

        self.assertEqual(status, 1)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["tracked_rust_files"], 1)
        self.assertEqual(payload["over_threshold"], 1)
        self.assertFalse(payload["updated_baseline"])
        self.assertEqual(payload["violations"][0]["code"], "new-megafile")
        self.assertEqual(payload["violations"][0]["path"], "src/foo.rs")
        self.assertIn("new-megafile", stderr.getvalue())
        self.assertEqual(payload["thresholds"]["max_lines"], 4000)
        self.assertEqual(payload["thresholds"]["max_bytes"], 524288)

    def test_invalid_utf8_tracked_path_is_operational_error(self) -> None:
        with mock.patch.object(
            megafile,
            "git_tracked_rust_files",
            return_value=[b"src/bad-\xff.rs"],
        ):
            stderr = StringIO()
            with mock.patch("sys.stderr", stderr):
                status = megafile.main(["/tmp/unused-repo"])

        self.assertEqual(status, 2)
        self.assertIn("not valid UTF-8", stderr.getvalue())
        self.assertIn(r"b'src/bad-\xff.rs'", stderr.getvalue())

    def test_unreadable_baseline_is_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            baseline = repository / "baseline.json"
            baseline.write_text("{", encoding="utf-8")
            with mock.patch.object(
                megafile, "git_tracked_rust_files", return_value=[]
            ), mock.patch.object(megafile, "measure_file") as measure:
                stderr = StringIO()
                with mock.patch("sys.stderr", stderr):
                    status = megafile.main(
                        [str(repository), "--baseline", str(baseline)]
                    )

        self.assertEqual(status, 2)
        self.assertIn("unable to read baseline", stderr.getvalue())
        measure.assert_not_called()


if __name__ == "__main__":
    unittest.main()

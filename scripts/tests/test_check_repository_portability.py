from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_repository_portability as portability


def codes(paths: list[bytes]) -> list[str]:
    return [violation.code for violation in portability.collect_violations(paths)]


class PathLengthTests(unittest.TestCase):
    def test_utf16_boundary(self) -> None:
        self.assertNotIn("path-length", codes([b"a" * 180]))
        self.assertIn("path-length", codes([b"a" * 181]))

    def test_astral_characters_use_two_utf16_units(self) -> None:
        at_boundary = ("a" * 178 + "\U0001f600").encode()
        over_boundary = ("a" * 179 + "\U0001f600").encode()

        self.assertEqual(portability.windows_utf16_units(at_boundary.decode()), 180)
        self.assertNotIn("path-length", codes([at_boundary]))
        self.assertIn("path-length", codes([over_boundary]))


class Win32NameTests(unittest.TestCase):
    def test_every_invalid_punctuation_character_and_controls(self) -> None:
        for character in '<>:"\\|?*':
            with self.subTest(character=character):
                self.assertIn(
                    "invalid-character", codes([f"bad{character}name".encode()])
                )
        for codepoint in range(32):
            with self.subTest(codepoint=codepoint):
                self.assertIn(
                    "invalid-character", codes([b"bad" + bytes([codepoint]) + b"name"])
                )

    def test_trailing_dots_and_spaces_in_any_component(self) -> None:
        violations = portability.collect_violations(
            [b"trailing./file", b"directory/trailing "]
        )

        self.assertEqual(
            [
                violation.code
                for violation in violations
                if violation.code == "trailing-dot-or-space"
            ],
            ["trailing-dot-or-space", "trailing-dot-or-space"],
        )

    def test_reserved_device_name_families_and_extensions(self) -> None:
        names = ["CON", "prn.log", "Aux.tar.gz", "NUL"]
        names += [f"COM{suffix}.txt" for suffix in "123456789¹²³"]
        names += [f"lpt{suffix}" for suffix in "123456789¹²³"]

        for name in names:
            with self.subTest(name=name):
                self.assertIn("reserved-device-name", codes([name.encode()]))

    def test_similar_names_and_valid_dotfiles_are_allowed(self) -> None:
        paths = [
            b".gitignore",
            b".env.local",
            b"directory/.CON",
            b"COM0",
            b"COM10.txt",
            b"LPT0",
            b"conifer.txt",
        ]

        self.assertEqual(portability.collect_violations(paths), [])


class PrefixCollisionTests(unittest.TestCase):
    def test_file_name_casefold_collision(self) -> None:
        violations = portability.collect_violations([b"README", b"readme"])

        self.assertEqual(codes([b"README", b"readme"]), ["casefold-collision"])
        self.assertEqual(violations[0].paths, (b"README", b"readme"))

    def test_directory_casing_collision(self) -> None:
        violations = portability.collect_violations(
            [b"Source/one.txt", b"source/two.txt"]
        )

        self.assertEqual([violation.code for violation in violations], ["casefold-collision"])
        self.assertEqual(
            violations[0].paths, (b"Source/one.txt", b"source/two.txt")
        )

    def test_file_directory_collision_is_casefolded(self) -> None:
        violations = portability.collect_violations([b"docs", b"DOCS/readme.md"])

        self.assertEqual(
            {violation.code for violation in violations},
            {"casefold-collision", "file-directory-collision"},
        )

    def test_multiple_collisions_are_complete_and_deterministic(self) -> None:
        paths = [b"z", b"Z/file", b"Alpha", b"alpha"]

        forward = portability.collect_violations(paths)
        reverse = portability.collect_violations(reversed(paths))

        self.assertEqual(forward, reverse)
        self.assertEqual(len(forward), 3)
        rendered = portability.render_violations(forward)
        for path in paths:
            self.assertIn(portability.quote_path(path), rendered)


class RawGitPathTests(unittest.TestCase):
    def test_invalid_utf8_is_reported_and_safely_quoted(self) -> None:
        raw_path = b"directory/bad-\xff-name"
        violations = portability.collect_violations([raw_path])

        self.assertEqual([violation.code for violation in violations], ["invalid-utf8"])
        rendered = portability.render_violations(violations)
        self.assertIn("b'directory/bad-\\xff-name'", rendered)
        self.assertNotIn("\ufffd", rendered)

    @mock.patch("scripts.check_repository_portability.subprocess.run")
    def test_git_paths_are_requested_with_nul_delimiters(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["git", "ls-files", "-z"], 0, stdout=b"one\0line\nbreak\0"
        )

        paths = portability.git_tracked_paths(Path("repository"))

        self.assertEqual(paths, [b"one", b"line\nbreak"])
        run.assert_called_once_with(
            ["git", "ls-files", "-z"],
            cwd=Path("repository"),
            check=True,
            stdout=subprocess.PIPE,
        )

    @mock.patch.object(portability.sys, "platform", "linux")
    @mock.patch("scripts.check_repository_portability.subprocess.run")
    def test_windows_worktree_pointer_is_translated_in_wsl(
        self, run: mock.Mock
    ) -> None:
        run.side_effect = [
            subprocess.CompletedProcess(
                ["wslpath", "-u", "D:/source/.git/worktrees/task"],
                0,
                stdout="/mnt/d/source/.git/worktrees/task\n",
            ),
            subprocess.CompletedProcess(
                [
                    "git",
                    "--git-dir",
                    "/mnt/d/source/.git/worktrees/task",
                    "--work-tree",
                    "unused",
                    "ls-files",
                    "-z",
                ],
                0,
                stdout=b"one\0two\0",
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / ".git").write_text(
                "gitdir: D:/source/.git/worktrees/task\n", encoding="utf-8"
            )

            paths = portability.git_tracked_paths(repository)

        self.assertEqual(paths, [b"one", b"two"])
        self.assertEqual(run.call_count, 2)
        run.assert_has_calls(
            [
                mock.call(
                    ["wslpath", "-u", "D:/source/.git/worktrees/task"],
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ),
                mock.call(
                    [
                        "git",
                        "--git-dir",
                        "/mnt/d/source/.git/worktrees/task",
                        "--work-tree",
                        str(repository.resolve()),
                        "ls-files",
                        "-z",
                    ],
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                ),
            ]
        )


if __name__ == "__main__":
    unittest.main()

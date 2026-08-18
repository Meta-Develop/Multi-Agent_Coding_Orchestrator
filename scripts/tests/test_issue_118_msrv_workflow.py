import pathlib
import re
import tomllib
import unittest
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "Cargo.toml"
WORKFLOW = ROOT / ".github" / "workflows" / "issue-118-msrv.yml"


class ContractError(AssertionError):
    pass


@dataclass(frozen=True)
class ActiveLine:
    number: int
    indent: int
    text: str


def active_lines(source: str) -> list[ActiveLine]:
    lines = []
    for number, raw_line in enumerate(source.splitlines(), start=1):
        if "\t" in raw_line:
            raise ContractError(f"line {number}: tabs are not valid indentation")
        text = raw_line.lstrip(" ")
        if not text or text.startswith("#"):
            continue
        lines.append(ActiveLine(number, len(raw_line) - len(text), text))
    return lines


def mapping_matches(
    lines: list[ActiveLine], key: str, indent: int
) -> list[tuple[int, re.Match[str]]]:
    pattern = re.compile(rf"^{re.escape(key)}:\s*(.*?)\s*(?:#.*)?$")
    matches = [
        (index, pattern.fullmatch(line.text))
        for index, line in enumerate(lines)
        if line.indent == indent
    ]
    return [(index, match) for index, match in matches if match is not None]


def mapping_entry(
    lines: list[ActiveLine], key: str, indent: int
) -> tuple[str, list[ActiveLine]]:
    matches = mapping_matches(lines, key, indent)
    if len(matches) != 1:
        raise ContractError(
            f"expected one active {key!r} mapping at indentation {indent}, "
            f"found {len(matches)}"
        )

    index, match = matches[0]
    end = index + 1
    while end < len(lines) and lines[end].indent > indent:
        end += 1
    return match.group(1), lines[index + 1 : end]


def reject_mapping_entry(
    lines: list[ActiveLine], key: str, indent: int, scope: str
) -> None:
    if mapping_matches(lines, key, indent):
        raise ContractError(f"{scope} must not have an active {key!r} field")


def step_blocks(lines: list[ActiveLine], indent: int) -> list[list[ActiveLine]]:
    starts = [
        index
        for index, line in enumerate(lines)
        if line.indent == indent and line.text.startswith("- ")
    ]
    if not starts:
        raise ContractError("the active msrv job must contain steps")

    blocks = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        first = lines[start]
        blocks.append(
            [
                ActiveLine(first.number, first.indent + 2, first.text[2:]),
                *lines[start + 1 : end],
            ]
        )
    return blocks


def scalar_body(step: list[ActiveLine], key: str = "run") -> list[ActiveLine]:
    value, scalar = mapping_entry(step, key, 8)
    if value not in {"|", "|-", "|+"}:
        raise ContractError(f"active {key} field must use a literal block")
    return [line for line in scalar if not line.text.startswith("#")]


def scalar_commands(step: list[ActiveLine], key: str = "run") -> list[str]:
    return [line.text for line in scalar_body(step, key)]


def require_command(commands: list[str], expected: str) -> None:
    if expected not in commands:
        raise ContractError(f"active run block is missing: {expected}")


def require_failing_if_branch(
    step: list[ActiveLine], condition: str
) -> None:
    body = scalar_body(step)
    starts = [
        index for index, line in enumerate(body) if line.text == condition
    ]
    if len(starts) != 1:
        raise ContractError("the rustc release mismatch branch must be active")

    start = starts[0]
    branch_indent = body[start].indent
    end = next(
        (
            index
            for index in range(start + 1, len(body))
            if body[index].indent == branch_indent and body[index].text == "fi"
        ),
        None,
    )
    if end is None:
        raise ContractError("the rustc release mismatch branch must close with fi")
    if not any(
        line.indent > branch_indent and line.text == "exit 1"
        for line in body[start + 1 : end]
    ):
        raise ContractError("the rustc release mismatch branch must run exit 1")


def validate_msrv_workflow(source: str, manifest_version: str) -> None:
    lines = active_lines(source)
    _, on_block = mapping_entry(lines, "on", 0)
    mapping_entry(on_block, "pull_request", 2)
    mapping_entry(on_block, "push", 2)

    _, jobs_block = mapping_entry(lines, "jobs", 0)
    _, msrv_job = mapping_entry(jobs_block, "msrv", 2)
    reject_mapping_entry(msrv_job, "if", 4, "jobs.msrv")
    reject_mapping_entry(msrv_job, "continue-on-error", 4, "jobs.msrv")
    timeout_minutes, _ = mapping_entry(msrv_job, "timeout-minutes", 4)
    if not timeout_minutes.isdecimal() or int(timeout_minutes) <= 0:
        raise ContractError("the active msrv job must have a positive whole-job timeout")
    _, steps = mapping_entry(msrv_job, "steps", 4)
    active_steps = step_blocks(steps, 6)

    checkout_steps = []
    for step in active_steps:
        try:
            uses, _ = mapping_entry(step, "uses", 8)
        except ContractError:
            continue
        checkout_steps.append((uses, step))
    if len(checkout_steps) != 1:
        raise ContractError("the active msrv job must contain one action step")
    checkout, checkout_step = checkout_steps[0]
    if not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout):
        raise ContractError("the checkout action must be pinned to an immutable SHA")
    _, checkout_with = mapping_entry(checkout_step, "with", 8)
    persist_credentials, _ = mapping_entry(
        checkout_with, "persist-credentials", 10
    )
    if persist_credentials != "false":
        raise ContractError("checkout credentials must not persist")

    resolver_steps = []
    for step in active_steps:
        try:
            step_id, _ = mapping_entry(step, "id", 8)
        except ContractError:
            continue
        if step_id == "msrv":
            resolver_steps.append(step)
    if len(resolver_steps) != 1:
        raise ContractError("the active msrv job must contain one id: msrv step")
    reject_mapping_entry(resolver_steps[0], "if", 8, "the resolver step")
    reject_mapping_entry(
        resolver_steps[0],
        "continue-on-error",
        8,
        "the resolver step",
    )
    resolver_commands = scalar_commands(resolver_steps[0])
    require_command(resolver_commands, 'msrv="$(python3 - <<\'PY\'')
    require_command(
        resolver_commands, 'value = manifest["package"].get("rust-version")'
    )
    require_command(resolver_commands, "print(value)")
    require_command(
        resolver_commands, 'echo "version=${msrv}" >> "${GITHUB_OUTPUT}"'
    )

    check_steps = []
    for step in active_steps:
        try:
            _, env_block = mapping_entry(step, "env", 8)
            msrv_env, _ = mapping_entry(env_block, "MSRV", 10)
        except ContractError:
            continue
        if msrv_env == "${{ steps.msrv.outputs.version }}":
            check_steps.append(step)
    if len(check_steps) != 1:
        raise ContractError(
            "the active msrv job must bind one check step to the resolver output"
        )
    reject_mapping_entry(check_steps[0], "if", 8, "the MSRV check step")
    reject_mapping_entry(
        check_steps[0],
        "continue-on-error",
        8,
        "the MSRV check step",
    )
    check_commands = scalar_commands(check_steps[0])
    require_command(
        check_commands, 'rustup toolchain install "${MSRV}" --profile minimal'
    )
    require_command(check_commands, 'actual_release="$(')
    require_command(
        check_commands, 'rustc +"${MSRV}" --version --verbose |'
    )
    require_command(
        check_commands, 'awk \'$1 == "release:" { print $2; exit }\''
    )
    require_command(check_commands, 'expected_release="${MSRV}"')
    require_command(
        check_commands, 'expected_release="${expected_release}.0"'
    )
    require_command(
        check_commands,
        'if [[ "${actual_release}" != "${expected_release}" ]]; then',
    )
    require_failing_if_branch(
        check_steps[0],
        'if [[ "${actual_release}" != "${expected_release}" ]]; then',
    )
    require_command(check_commands, 'rustc +"${MSRV}" --version --verbose')
    require_command(
        check_commands, 'cargo +"${MSRV}" check --locked --all-targets'
    )

    active_job_text = "\n".join(line.text for line in msrv_job)
    if re.search(
        rf"(?<![0-9]){re.escape(manifest_version)}(?![0-9])", active_job_text
    ):
        raise ContractError(
            "the active msrv job must derive the version instead of duplicating it"
        )


class MsrvWorkflowContractTests(unittest.TestCase):
    def test_workflow_enforces_manifest_rust_version(self) -> None:
        self.assertTrue(
            WORKFLOW.is_file(),
            "dedicated MSRV workflow is absent; no active gate can be validated",
        )
        with MANIFEST.open("rb") as manifest_file:
            manifest = tomllib.load(manifest_file)
        rust_version = manifest["package"].get("rust-version")
        self.assertIsInstance(rust_version, str)
        self.assertRegex(rust_version, r"^\d+\.\d+(?:\.\d+)?$")
        validate_msrv_workflow(
            WORKFLOW.read_text(encoding="utf-8"), rust_version
        )

    def test_commented_contract_fragments_are_rejected(self) -> None:
        commented = """
name: Pretend MSRV
# on:
#   pull_request:
#   push:
on:
  workflow_dispatch:
# jobs:
#   msrv:
#     steps:
#       - run: cargo +"${MSRV}" check --locked --all-targets
jobs:
  placeholder:
    runs-on: ubuntu-latest
"""
        with self.assertRaisesRegex(ContractError, "pull_request"):
            validate_msrv_workflow(commented, "1.89")

    def test_commands_in_a_different_job_are_rejected(self) -> None:
        wrong_job = """
on:
  pull_request:
  push:
jobs:
  not-msrv:
    steps:
      - id: msrv
        run: |
          value = manifest["package"].get("rust-version")
          echo "version=${msrv}" >> "${GITHUB_OUTPUT}"
      - env:
          MSRV: ${{ steps.msrv.outputs.version }}
        run: |
          rustup toolchain install "${MSRV}" --profile minimal
          cargo +"${MSRV}" check --locked --all-targets
"""
        with self.assertRaisesRegex(ContractError, "'msrv' mapping"):
            validate_msrv_workflow(wrong_job, "1.89")

    def test_disabled_msrv_job_is_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        disabled = source.replace(
            "  msrv:\n",
            "  msrv:\n    if: ${{ false }}\n",
            1,
        )
        self.assertNotEqual(disabled, source)
        with self.assertRaisesRegex(ContractError, "jobs.msrv.*'if'"):
            validate_msrv_workflow(disabled, "1.89")

    def test_masked_critical_steps_are_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        disabled_resolver = source.replace(
            "        id: msrv\n",
            "        id: msrv\n        if: ${{ false }}\n",
            1,
        )
        self.assertNotEqual(disabled_resolver, source)
        with self.assertRaisesRegex(ContractError, "resolver step.*'if'"):
            validate_msrv_workflow(disabled_resolver, "1.89")

        tolerated_failure = source.replace(
            "        env:\n          MSRV: ${{ steps.msrv.outputs.version }}\n",
            "        continue-on-error: true\n"
            "        env:\n"
            "          MSRV: ${{ steps.msrv.outputs.version }}\n",
            1,
        )
        self.assertNotEqual(tolerated_failure, source)
        with self.assertRaisesRegex(
            ContractError, "MSRV check step.*'continue-on-error'"
        ):
            validate_msrv_workflow(tolerated_failure, "1.89")

    def test_resolver_must_emit_the_parsed_manifest_value(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        hard_coded_output = source.replace(
            "          print(value)\n",
            '          print("1.90")\n',
            1,
        )
        self.assertNotEqual(hard_coded_output, source)
        with self.assertRaisesRegex(ContractError, r"missing: print\(value\)"):
            validate_msrv_workflow(hard_coded_output, "1.89")

    def test_rustc_mismatch_must_fail_the_step(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        fail_open = source.replace(
            "            exit 1\n",
            "            true\n",
            1,
        )
        self.assertNotEqual(fail_open, source)
        with self.assertRaisesRegex(ContractError, "must run exit 1"):
            validate_msrv_workflow(fail_open, "1.89")


if __name__ == "__main__":
    unittest.main()

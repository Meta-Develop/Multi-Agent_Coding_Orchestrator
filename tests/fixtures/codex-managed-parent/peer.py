"""Deterministic offline app-server peer, executed only by Rust contained tests."""
import datetime
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
import tempfile


def receive():
    line = sys.stdin.readline()
    assert line, "client EOF"
    return json.loads(line)


def send(value):
    print(json.dumps(value), flush=True)


def event(method, item):
    send({"method": method, "params": {
        "threadId": thread, "turnId": turn, "item": item}})


assert sys.argv[1:4] == ["app-server", "--stdio", "--strict-config"]
for feature in ("multi_agent", "goals"):
    assert any(sys.argv[i:i + 2] == ["--disable", feature]
               for i in range(len(sys.argv) - 1))
initialize = receive()
assert initialize["method"] == "initialize"
send({"id": initialize["id"], "result": {}})
assert receive()["method"] == "initialized"
start = receive()
assert start["method"] == "thread/start"
params = start["params"]
workspace = pathlib.Path(params["cwd"])
thread, turn = "fixture-thread-" + str(os.getpid()), "fixture-turn"
send({"id": start["id"], "result": {
    "thread": {"id": thread}, "cwd": str(workspace), "model": params["model"],
    "reasoningEffort": json.loads(next(arg.split("=", 1)[1] for arg in sys.argv
                                     if arg.startswith("model_reasoning_effort="))),
    "approvalPolicy": "on-request", "approvalsReviewer": "user",
    "activePermissionProfile": {"id": "maco_external_codex"}}})
request = receive()
assert request["method"] == "turn/start"
prompt = request["params"]["input"][0]["text"]
payload = json.loads(prompt.split("\nOFFLINE_FIXTURE=", 1)[1])
report = payload["report"]
if payload["mode"] in ("initial", "final", "review"):
    try:
        with open(workspace / "src/lib.rs", "a") as source:
            source.write("unauthorized parent edit\n")
    except OSError:
        pass
    else:
        raise AssertionError("managed coordination turn had writable source")
send({"id": request["id"], "result": {"turn": {"id": turn, "status": "inProgress"}}})
send({"method": "turn/started", "params": {
    "threadId": thread, "turn": {"id": turn, "status": "inProgress"}}})

if payload["mode"] == "initial":
    assert len(params["dynamicTools"]) == 1
    assert params["dynamicTools"][0]["name"] == "maco_worker_request"
    for ordinal, proposal in enumerate(report["requests"], 1):
        arguments = {"operation": "submit_worker_request", **proposal}
        if payload["case"] == "forged-identity":
            arguments["run_id"] = "forged"
        if payload["case"] == "widened-request":
            arguments["assigned_paths"] = ["outside"]
        repeats = 2 if ordinal == 1 and payload["case"] == "lost-response" else 1
        for retry in range(repeats):
            call_id = f"submit-{ordinal}-{retry}"
            item = {"id": call_id, "type": "dynamicToolCall", "status": "inProgress",
                    "tool": "maco_worker_request", "arguments": arguments}
            event("item/started", item)
            send({"id": call_id, "method": "item/tool/call", "params": {
                "threadId": thread, "turnId": turn, "callId": call_id,
                "tool": "maco_worker_request", "arguments": arguments}})
            response = receive()
            assert response["id"] == call_id
            if not response["result"]["success"]:
                sys.exit(0)
            text = response["result"]["contentItems"][0]["text"]
            receipt = json.loads(text)
            assert receipt["request_id"] == proposal["request_id"]
            assert receipt["worker_id"] == proposal["worker_id"]
            assert receipt["status"] == "queued"
            if retry:
                assert text == previous_receipt
            previous_receipt = text
            event("item/completed", {**item, "status": "completed",
                  "contentItems": [{"type": "inputText", "text": text}], "success": True})
elif payload["mode"] == "worker":
    assert params["dynamicTools"] == []
    path = report["assigned_paths"][0]
    code = ("from pathlib import Path; p=Path(" + repr(path) + "); "
            "p.write_text(" + ("" if payload.get("replace") else "p.read_text() + ")
            + repr(payload["edit"]) + ")")
    if payload.get("validate"):
        code += "; assert 'pub fn first() -> u32 { 40 }' in p.read_text(), 'first() must return 40'"
    if payload["case"] == "isolated-long-output":
        code += "; print('captured Worker output\\n' * 768, end='')"
    mixed_occurrence = report["id"] == "worker" and payload["case"] in (
        "outer-wrong-occurrence", "outer-wrong-validation-occurrence",
        "outer-ambiguous-validation-reference")
    if mixed_occurrence:
        # The same exact argv first succeeds, then fails on the changed input.
        code = ("from pathlib import Path; p=Path(" + repr(path) + "); "
                "previous=p.read_text(); p.write_text(" + repr(payload["edit"]) + "); "
                "assert 'pub fn selected() {}' in previous")
    argv = [sys.executable, "-c", code]
    if payload["case"].startswith(("outer-", "correction-")):
        assert payload.get("native_journal_helper"), "production-journal regression cannot handappend rows"
    if payload.get("native_journal_helper"):
        def wrapped(inner, label, observe=False, unknown=False):
            cli = payload["journal_prefix"] + ["--cwd", str(workspace), "--auto-timestamps"]
            if observe:
                cli += ["--observe-changes"]
            cli += ["--"] + inner
            actual = [cli[0], "--exact",
                      "supervise::assignment_execution::managed_parent_outer_tests::production_journal_cli_helper",
                      "--nocapture", "--ignored", "--skip", json.dumps(cli)]
            item = {"id": label, "type": "commandExecution", "command": shlex.join(actual),
                    "cwd": str(workspace), "status": "inProgress", "exitCode": None}
            event("item/started", item)
            begin = time.monotonic()
            result = subprocess.run(actual, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elapsed = int((time.monotonic() - begin) * 1000)
            event("item/completed", {**item, "status": "completed" if result.returncode == 0 else "failed",
                                    "exitCode": None if unknown else result.returncode})
            return result, elapsed, cli

        def explicit_reference(cli, entry):
            reference = list(cli)
            reference.remove("--auto-timestamps")
            separator = reference.index("--")
            flags = ["--start-timestamp", entry["start_timestamp"],
                     "--end-timestamp", entry["end_timestamp"]]
            for changed_path in entry["changed_paths"]:
                flags += ["--changed-path", changed_path]
            reference[separator:separator] = flags
            return reference

        opened, _, _ = wrapped(["true"], "opening-observation", observe=True)
        assert opened.returncode == 0, opened.stderr.decode()
        # Execute two identical successful inspections through the actual CLI
        # producer, then omit both from the normal report's permitted subset.
        inspection = [sys.executable, "-c",
                      "from pathlib import Path; Path(" + repr(path) + ").read_bytes()"]
        inspected, inspection_ms, _ = wrapped(inspection, "inspection-one")
        assert inspected.returncode == 0, inspected.stderr.decode()
        repeated_inspection, _, _ = wrapped(inspection, "inspection-two")
        assert repeated_inspection.returncode == 0, repeated_inspection.stderr.decode()
        negative = payload["case"] in ("outer-unknown", "outer-launch", "outer-signal")
        if payload["case"] == "outer-launch":
            argv = ["/nonexistent-maco-fixture-command"]
        elif payload["case"] == "outer-signal":
            argv = [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]
        result, elapsed, observed_argv = wrapped(argv, "edit", unknown=payload["case"] == "outer-unknown")
        validation_reference = []
        if payload["case"] == "outer-omitted-repeat-failure" and report["id"] == "worker":
            repeated, _, _ = wrapped(argv, "repeated-failed-validation")
            assert result.returncode == repeated.returncode == 1
            entries = [json.loads(line) for line in pathlib.Path(payload["journal"]).read_text().splitlines()]
            first = next(entry for entry in entries if entry["command"] == argv
                         and entry.get("observation", {}).get("phase") == "completed")
            # Accurately report the first failure so omission of the second
            # reaches the completeness guard rather than wrapper ambiguity.
            observed_argv = explicit_reference(observed_argv, first)
        if mixed_occurrence:
            assert result.returncode == 0
            result, elapsed, _ = wrapped(argv, "same-argv-failed-validation")
            assert result.returncode == 1
            # Read both actual production records; only the raw report varies.
            entries = [json.loads(line) for line in pathlib.Path(payload["journal"]).read_text().splitlines()]
            first = next(entry for entry in entries if entry["command"] == argv
                         and entry.get("observation", {}).get("phase") == "completed")
            first_reference = explicit_reference(observed_argv, first)
            failed_reference = explicit_reference(observed_argv, entries[-1])
            assert first["changed_paths"] == [path]
            assert entries[-1]["changed_paths"] == []
            if payload["case"] == "outer-wrong-occurrence":
                observed_argv = first_reference
            else:
                # commands_run correctly names the later attested failure.
                validation_reference = (first_reference
                    if payload["case"] == "outer-wrong-validation-occurrence"
                    else list(observed_argv))
                observed_argv = failed_reference
        status = "succeeded" if result.returncode == 0 else "failed"
        if result.returncode:
            assert payload.get("validate") or negative, result.stderr.decode()
            report.update(status="failed", accepted=False, rejected=True)
        claimed_exit = 1 if negative else result.returncode
        report["commands_run"] = [{"command": observed_argv, "cwd": str(workspace),
            "exit_code": claimed_exit, "status": status, "timeout_seconds": 10,
            "duration_ms": elapsed, "timed_out": False,
            "error": None if negative or claimed_exit == 0 else
                     f"Wrapped command exited with status {claimed_exit}; journal retained.",
            "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}]
        if report["id"] == "worker" and payload["case"] in ("outer-omitted-failure", "outer-reordered"):
            inspection_record = {"command": inspection, "cwd": str(workspace),
                "exit_code": inspected.returncode, "status": "succeeded", "timeout_seconds": 10,
                "duration_ms": inspection_ms, "timed_out": False, "error": None,
                "stdout": inspected.stdout.decode(), "stderr": inspected.stderr.decode()}
            if payload["case"] == "outer-omitted-failure":
                # The real failed validation is absent from the raw report.
                report["commands_run"] = [inspection_record]
            else:
                # These references are genuine, but the inspection preceded edit.
                report["commands_run"].append(inspection_record)
        report["files_changed"] = [] if payload["case"] in ("outer-launch", "outer-signal") else [path]
        report["validation_results"] = [{"name": "actual validation" if payload.get("validate") else "actual edit",
            "status": status, "command": validation_reference if result.returncode else observed_argv,
            "message": "completed by the contained process"}]
    else:
        item = {"id": "edit", "type": "commandExecution", "command": shlex.join(argv),
                "cwd": str(workspace), "status": "inProgress", "exitCode": None}
        event("item/started", item)
        before = datetime.datetime.now(datetime.timezone.utc).isoformat()
        observation = None
        journal_cwd = str(workspace)
        if "journal_head" in payload:
            identity = workspace.stat()
            observation = {"worktree": str(workspace),
                           "worktree_identity": {"device": identity.st_dev, "file": identity.st_ino},
                           "head_oid": payload["journal_head"], "phase": "started",
                           "before": {}, "after": {}, "declared_paths": [path]}
            if report["id"] == "worker":
                observation.update(payload.get("journal_binding", {}))
                journal_cwd = observation["worktree"]
                if payload["case"] == "isolated-journal-identity":
                    observation["worktree_identity"]["file"] += 1
                if payload["case"] == "isolated-journal-base":
                    observation["head_oid"] = "0" * 40
            with open(payload["journal"], "a") as journal:
                journal.write(json.dumps({"command": argv, "cwd": journal_cwd,
                              "start_timestamp": before, "end_timestamp": before,
                              "changed_paths": [], "observation": observation}) + "\n")
                journal.flush()
                os.fsync(journal.fileno())
        begin = time.monotonic()
        result = subprocess.run(argv, cwd=workspace, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if payload["case"] == "isolated-overlap":
            other = "src/other.rs" if path == "src/lib.rs" else "src/lib.rs"
            (workspace / other).write_text("overlapping candidate edit\n")
        if payload["case"] == "widened-worker":
            (workspace / "src/escape.rs").write_text("outside the Worker scope\n")
        elapsed = int((time.monotonic() - begin) * 1000)
        after = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = {"command": argv, "cwd": journal_cwd,
                 "start_timestamp": before, "end_timestamp": after, "changed_paths": [path]}
        if observation is not None:
            source = workspace / path
            material = (source.stat().st_mode & 0o111).to_bytes(4, "big") + source.read_bytes()
            entry["observation"] = {**observation, "phase": "completed",
                                    "after": {path: hashlib.sha256(material).hexdigest()}}
        with open(payload["journal"], "a") as journal:
            journal.write(json.dumps(entry) + "\n")
            journal.flush()
            os.fsync(journal.fileno())
        status = "succeeded" if result.returncode == 0 else "failed"
        if result.returncode:
            assert payload.get("validate"), result.stderr.decode()
            report.update(status="failed", accepted=False, rejected=True)
        report["commands_run"] = [{"command": argv, "cwd": journal_cwd,
            "exit_code": result.returncode, "status": status, "timeout_seconds": 10,
            "duration_ms": elapsed, "timed_out": False,
            "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}]
        report["files_changed"] = [path]
        report["validation_results"] = [{"name": "actual validation" if payload.get("validate") else "actual edit", "status": status,
            "command": argv, "message": "completed by the contained process"}]
        event("item/completed", {**item, "status": "completed", "exitCode": result.returncode})
    if payload["case"] == "cancel-active-worker" and report["id"] == "worker":
        descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        pathlib.Path(payload["signal"]).write_text(str(descendant.pid))
        interrupt = receive()
        assert interrupt["method"] == "turn/interrupt"
        send({"method": "turn/completed", "params": {
            "threadId": thread, "turn": {"id": turn, "status": "interrupted"}}})
        sys.exit(0)
elif payload["mode"] == "review":
    assert params["dynamicTools"] == []
    assert not (workspace / "src/lib.rs").exists()
    assert not (workspace / "src/other.rs").exists()
    request_text = prompt.split("REVIEW_LENS_REQUEST_JSON:\n", 1)[1]
    lens, _ = json.JSONDecoder().raw_decode(request_text)
    coverage_text = prompt.split("REQUIRED_COVERAGE_JSON:\n", 1)[1]
    coverage, _ = json.JSONDecoder().raw_decode(coverage_text)
    assert lens == payload["request"]
    info = lens["information"]
    scope = info["scope"]
    if scope == "bounded_full_child_transcript":
        assert set(info) == {"scope", "child_transcript", "bindings", "diff", "output_report"}
        assert info["bindings"]["validation_bindings"]["worker_execution_evidence"]
    elif scope == "diff_only":
        assert set(info) == {"scope", "diff"}
    else:
        assert scope == "output_report_only"
        assert set(info) == {"scope", "output_report"}
    if "diff" in info:
        assert "+pub fn first() -> u32 { 40 }" in info["diff"]
        assert ("+pub fn second() -> u32 { crate::first() + 2 }" in info["diff"]
                or "+pub fn second() -> u32 { 42 }" in info["diff"])
    if "output_report" in info:
        child = json.loads(info["output_report"])
        assert child["accepted"] and not child["rejected"]
        assert all(worker["status"] == "succeeded" for worker in child["worker_reports"])
    # A constant happens to pass the combined value check, but violates the
    # authored implementation requirement to call first() + 2.
    rejected = "+pub fn second() -> u32 { 42 }" in info.get("diff", "")
    report.update(reviewed_worker_ids=coverage["worker_ids"], reviewed_paths=coverage["paths"],
                  accepted=not rejected, rejected=rejected,
                  status="rejected" if rejected else "succeeded",
                  rejection_kind="implementation_defect" if rejected else None,
                  validation_results=[{"name": "scoped packet inspection", "status": "succeeded",
                                       "command": [], "message": lens["request_binding"]}])
    if rejected:
        report["findings"] = [{"severity": "error", "message": "second() must call crate::first() + 2 instead of returning a constant",
                               "paths": coverage["paths"]}]
else:
    assert payload["mode"] == "final"
    assert params["dynamicTools"] == []
    first = (workspace / "src/lib.rs").read_text()
    second = (workspace / "src/other.rs").read_text()
    assert "pub fn first() -> u32" in first, first
    assert ("pub fn second() -> u32 { crate::first() + 2 }" in second
            or (payload.get("allow_implementation_defect")
                and "pub fn second() -> u32 { 42 }" in second)), second
    if payload["case"] == "isolated-masked-rustup":
        # Reproduce the hosted runner's masked user-home compiler shim even
        # when the test host normally supplies rustc from the visible Nix store.
        try:
            subprocess.run([payload["masked_rustc"], "--version"], check=True)
        except (FileNotFoundError, PermissionError):
            pass
        else:
            raise AssertionError("unprojected compiler shim was visible")
    assert pathlib.Path(payload["rustc"]).is_absolute()
    # Compile and execute the actual functions together. The harness and binary
    # live in private temporary storage; candidate source stays read-only.
    with tempfile.TemporaryDirectory() as temporary:
        harness = pathlib.Path(temporary) / "combined.rs"
        binary = pathlib.Path(temporary) / "combined"
        harness.write_text(
            '#[path = ' + json.dumps(str(workspace / "src/lib.rs")) + '] mod candidate;\n'
            'pub use candidate::*;\n'
            '#[test] fn combined() { assert_eq!(first(), 40); '
            'assert_eq!(other::second(), 42); }\n')
        for name, argv in (("compile", [payload["rustc"], "--test", str(harness), "-o", str(binary)]),
                           ("combined", [str(binary)])):
            item = {"id": name, "type": "commandExecution", "command": shlex.join(argv),
                    "cwd": str(workspace), "status": "inProgress", "exitCode": None}
            event("item/started", item)
            result = subprocess.run(argv, cwd=workspace, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            if result.returncode:
                assert payload.get("allow_failed_validation") and name == "combined", result.stderr.decode()
                report["turn"]["report"].update(status="failed", accepted=False, rejected=True)
            report["turn"]["report"]["validation_results"].append({
                "name": "combined check" if name == "combined" else "compile check",
                "status": "succeeded" if result.returncode == 0 else "failed", "command": argv,
                "message": result.stdout.decode() + result.stderr.decode()})
            event("item/completed", {**item, "status": "completed", "exitCode": result.returncode})

usage = {"inputTokens": 10, "outputTokens": 4, "cachedInputTokens": 0,
         "reasoningOutputTokens": 0, "totalTokens": 14}
send({"method": "thread/tokenUsage/updated", "params": {
    "threadId": thread, "turnId": turn, "tokenUsage": {"last": usage, "total": usage}}})
event("item/started", {"id": "answer", "type": "agentMessage"})
event("item/completed", {"id": "answer", "type": "agentMessage", "text": json.dumps(report)})
send({"method": "turn/completed", "params": {
    "threadId": thread, "turn": {"id": turn, "status": "completed"}}})

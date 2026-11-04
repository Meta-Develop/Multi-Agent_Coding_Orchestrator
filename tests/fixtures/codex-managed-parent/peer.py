"""Deterministic offline app-server peer, executed only by Rust contained tests."""
import datetime
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
if payload["mode"] in ("initial", "final"):
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
            "p.write_text(p.read_text() + " + repr(payload["edit"]) + ")")
    argv = [sys.executable, "-c", code]
    item = {"id": "edit", "type": "commandExecution", "command": shlex.join(argv),
            "cwd": str(workspace), "status": "inProgress", "exitCode": None}
    event("item/started", item)
    before = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    result = subprocess.run(argv, cwd=workspace, check=True)
    if payload["case"] == "isolated-overlap":
        other = "src/other.rs" if path == "src/lib.rs" else "src/lib.rs"
        (workspace / other).write_text("overlapping candidate edit\n")
    if payload["case"] == "widened-worker":
        (workspace / "src/escape.rs").write_text("outside the Worker scope\n")
    elapsed = int((time.monotonic() - begin) * 1000)
    after = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(payload["journal"], "a") as journal:
        journal.write(json.dumps({"command": argv, "cwd": str(workspace),
                      "start_timestamp": before, "end_timestamp": after,
                      "changed_paths": [path]}) + "\n")
        journal.flush()
        os.fsync(journal.fileno())
    report["commands_run"] = [{"command": argv, "cwd": str(workspace),
        "exit_code": result.returncode, "status": "succeeded", "timeout_seconds": 10,
        "duration_ms": elapsed, "timed_out": False}]
    report["files_changed"] = [path]
    report["validation_results"] = [{"name": "actual edit", "status": "succeeded",
        "command": argv, "message": "completed by the contained process"}]
    event("item/completed", {**item, "status": "completed", "exitCode": 0})
    if payload["case"] == "cancel-active-worker" and report["id"] == "worker":
        descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        pathlib.Path(payload["signal"]).write_text(str(descendant.pid))
        interrupt = receive()
        assert interrupt["method"] == "turn/interrupt"
        send({"method": "turn/completed", "params": {
            "threadId": thread, "turn": {"id": turn, "status": "interrupted"}}})
        sys.exit(0)
else:
    assert payload["mode"] == "final"
    assert params["dynamicTools"] == []
    first = (workspace / "src/lib.rs").read_text()
    second = (workspace / "src/other.rs").read_text()
    assert "pub fn first() -> u32 { 40 }" in first, first
    assert "pub fn second() -> u32 { crate::first() + 2 }" in second, second
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
        for name, argv in (("compile", ["rustc", "--test", str(harness), "-o", str(binary)]),
                           ("combined", [str(binary)])):
            item = {"id": name, "type": "commandExecution", "command": shlex.join(argv),
                    "cwd": str(workspace), "status": "inProgress", "exitCode": None}
            event("item/started", item)
            result = subprocess.run(argv, cwd=workspace, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            report["turn"]["report"]["validation_results"].append({
                "name": "combined check" if name == "combined" else "compile check",
                "status": "succeeded", "command": argv,
                "message": result.stdout.decode()})
            event("item/completed", {**item, "status": "completed", "exitCode": result.returncode})

usage = {"inputTokens": 10, "outputTokens": 4, "cachedInputTokens": 0,
         "reasoningOutputTokens": 0, "totalTokens": 14}
send({"method": "thread/tokenUsage/updated", "params": {
    "threadId": thread, "turnId": turn, "tokenUsage": {"last": usage, "total": usage}}})
event("item/started", {"id": "answer", "type": "agentMessage"})
event("item/completed", {"id": "answer", "type": "agentMessage", "text": json.dumps(report)})
send({"method": "turn/completed", "params": {
    "threadId": thread, "turn": {"id": turn, "status": "completed"}}})

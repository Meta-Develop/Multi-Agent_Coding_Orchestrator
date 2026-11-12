import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  mergeInvocations,
  parseArtifact,
  parseExternalTranscript,
  renderSvg,
  roleCategory,
  scanRoot,
  sortInvocations,
  summarize,
} from "../scripts/collect-usage.mjs";

const script = fileURLToPath(new URL("../scripts/collect-usage.mjs", import.meta.url));

function tempDir(t) {
  const root = mkdtempSync(join(tmpdir(), "maco-collect-usage-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function writeArtifact(root, relPath, doc) {
  const target = join(root, relPath);
  mkdirSync(join(target, ".."), { recursive: true });
  writeFileSync(target, JSON.stringify(doc));
  return target;
}

function invocation(overrides = {}) {
  return {
    optimization_run_id: "run-1",
    invocation_id: "inv-1",
    started_at: "2026-02-01T00:00:00.000Z",
    finished_at: "2026-02-01T00:01:00.000Z",
    role: "worker",
    backend: "vibe",
    provider: "mistral",
    requested_model: "model-a",
    resolved_model: "model-a",
    input_tokens: 100,
    cached_input_tokens: 20,
    output_tokens: 50,
    ...overrides,
  };
}

test("scanRoot finds nested artifacts, skips .git and node_modules, ignores symlinks", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "a/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "a/b/c/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "a/.git/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "a/node_modules/pkg/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  const linkTarget = join(root, "linked");
  mkdirSync(join(linkTarget, "switch-cost"), { recursive: true });
  writeFileSync(join(linkTarget, "switch-cost", "live-evidence.json"), "{}");
  symlinkSync(linkTarget, join(root, "a", "linked-sym"), "dir");

  const { files, errors } = scanRoot(root);
  assert.deepEqual(errors, []);
  assert.equal(files.length, 3);
  assert(files.every((file) => !file.includes("linked-sym")));
  assert(files.every((file) => !file.includes(".git") && !file.includes("node_modules")));
  assert(files.includes(join(root, "a/switch-cost/live-evidence.json")));
  assert(files.includes(join(root, "a/b/c/switch-cost/live-evidence.json")));
  assert(files.includes(join(root, "linked/switch-cost/live-evidence.json")));
});

test("scanRoot does not collect paths where switch-cost is not a complete directory component", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "other-switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "switch-cost/live-evidence.json.bak", { schema_version: 1, invocations: [] });
  writeArtifact(root, "real/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  const { files, errors } = scanRoot(root);
  assert.deepEqual(errors, []);
  assert.deepEqual(files, [join(root, "real/switch-cost/live-evidence.json")]);
});

test("scanRoot does not follow a symlink ROOT and skips roots named .git or node_modules", (t) => {
  const root = tempDir(t);
  const target = join(root, "target");
  writeArtifact(target, "switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(target, ".git/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "nm/node_modules/pkg/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  const link = join(root, "root-link");
  symlinkSync(target, link, "dir");

  const viaLink = scanRoot(link);
  assert.deepEqual(viaLink.files, []);
  assert.deepEqual(viaLink.errors, []);

  const gitRoot = scanRoot(join(root, "target", ".git"));
  assert.deepEqual(gitRoot.files, []);
  assert.deepEqual(gitRoot.errors, []);

  const nmRoot = scanRoot(join(root, "nm", "node_modules"));
  assert.deepEqual(nmRoot.files, []);
  assert.deepEqual(nmRoot.errors, []);
});

test("parseArtifact rejects invalid schemas and accepts valid ones", () => {
  assert.equal(parseArtifact("p", "not json").invalid, true);
  const badVersion = parseArtifact("p", JSON.stringify({ schema_version: 2, invocations: [] }));
  assert.equal(badVersion.invalid, true);
  assert.match(badVersion.reason, /schema_version/);
  const badArray = parseArtifact("p", JSON.stringify({ schema_version: 1, invocations: {} }));
  assert.equal(badArray.invalid, true);
  const badEntry = parseArtifact(
    "p",
    JSON.stringify({ schema_version: 1, invocations: [{ optimization_run_id: "", invocation_id: "x" }] })
  );
  assert.equal(badEntry.invalid, true);
  const good = parseArtifact(
    "p",
    JSON.stringify({ schema_version: 1, invocations: [invocation()] })
  );
  assert.equal(good.invalid, false);
  assert.equal(good.invocations.length, 1);
});

test("mergeInvocations collapses identical duplicates and counts them", () => {
  const records = [
    { path: "a.json", invocations: [invocation()] },
    { path: "b.json", invocations: [invocation()] },
  ];
  const merged = mergeInvocations(records);
  assert.equal(merged.invocations.length, 1);
  assert.equal(merged.identicalDuplicates, 1);
  assert.deepEqual(merged.conflicts, []);
});

test("mergeInvocations compares field values deeply, not by reference", () => {
  const records = [
    { path: "a.json", invocations: [invocation({ resolved_model: { known: "m" } })] },
    { path: "b.json", invocations: [invocation({ resolved_model: { known: "m" } })] },
  ];
  const merged = mergeInvocations(records);
  assert.equal(merged.invocations.length, 1);
  assert.equal(merged.identicalDuplicates, 1);
  assert.deepEqual(merged.conflicts, []);
});

test("mergeInvocations flags deeply differing object field values as conflicts", () => {
  const records = [
    { path: "a.json", invocations: [invocation({ resolved_model: { known: "m" } })] },
    { path: "b.json", invocations: [invocation({ resolved_model: { known: "x" } })] },
  ];
  const merged = mergeInvocations(records);
  assert.deepEqual(merged.invocations, []);
  assert.equal(merged.conflicts.length, 1);
  assert.deepEqual(merged.conflicts[0].fields, ["resolved_model"]);
});

test("mergeInvocations keeps reused IDs with different started_at", () => {
  const records = [
    {
      path: "a.json",
      invocations: [invocation({ started_at: "2026-02-01T00:00:00.000Z" })],
    },
    {
      path: "b.json",
      invocations: [invocation({ started_at: "2026-02-02T00:00:00.000Z" })],
    },
  ];
  const merged = mergeInvocations(records);
  assert.equal(merged.invocations.length, 2);
  assert.equal(merged.identicalDuplicates, 0);
  const sorted = sortInvocations(merged.invocations);
  assert.equal(sorted[0].started_at, "2026-02-01T00:00:00.000Z");
  assert.equal(sorted[1].started_at, "2026-02-02T00:00:00.000Z");
});

test("mergeInvocations excludes conflicting versions and reports fields and paths", () => {
  const records = [
    { path: "a.json", invocations: [invocation({ output_tokens: 50 })] },
    { path: "b.json", invocations: [invocation({ output_tokens: 60 })] },
  ];
  const merged = mergeInvocations(records);
  assert.deepEqual(merged.invocations, []);
  assert.equal(merged.conflicts.length, 1);
  const conflict = merged.conflicts[0];
  assert.equal(conflict.optimization_run_id, "run-1");
  assert.equal(conflict.invocation_id, "inv-1");
  assert.deepEqual(conflict.fields, ["output_tokens"]);
  assert.deepEqual(conflict.paths, ["a.json", "b.json"]);
});

test("parseExternalTranscript emits turns, copies counters, nulls unsafe counters, counts malformed lines", () => {
  const manifestEntry = {
    path: "transcript.jsonl",
    label: "manager-outer",
    role: "manager",
    requested_model: "gpt-5",
    requested_effort: "high",
  };
  const text = [
    JSON.stringify({ type: "turn.started" }),
    "{ this line is not json",
    JSON.stringify({
      type: "turn.completed",
      usage: { input_tokens: 1000, cached_input_tokens: 400, output_tokens: 200, reasoning_output_tokens: 80 },
    }),
    JSON.stringify({
      type: "turn.completed",
      usage: { input_tokens: -5, cached_input_tokens: 2.5, output_tokens: 30 },
    }),
    "",
  ].join("\n");
  const result = parseExternalTranscript(manifestEntry, text);
  assert.equal(result.turns, 2);
  assert.equal(result.malformedLines, 1);
  assert.equal(result.invocations.length, 2);

  const first = result.invocations[0];
  assert.equal(first.optimization_run_id, "external:manager-outer");
  assert.equal(first.invocation_id, "manager-outer:turn-1");
  assert.equal(first.started_at, null);
  assert.equal(first.role, "manager");
  assert.equal(first.requested_model, "gpt-5");
  assert.equal(first.requested_effort, "high");
  assert.equal(first.resolved_model, null);
  assert.equal(first.backend, "codex_cli");
  assert.equal(first.provider, "openai");
  assert.equal(first.record_source, "codex_exec_jsonl");
  assert.equal(first.input_tokens, 1000);
  assert.equal(first.cached_input_tokens, 400);
  assert.equal(first.output_tokens, 200);

  const second = result.invocations[1];
  assert.equal(second.invocation_id, "manager-outer:turn-2");
  assert.equal(second.input_tokens, null);
  assert.equal(second.cached_input_tokens, null);
  assert.equal(second.output_tokens, 30);
});

test("parseExternalTranscript uses a manifest optimization_run_id and falls back to external label", () => {
  const text = JSON.stringify({
    type: "turn.completed",
    usage: { input_tokens: 100, cached_input_tokens: 10, output_tokens: 20 },
  });
  const withRun = parseExternalTranscript(
    { path: "transcript.jsonl", label: "manager-outer", role: "manager", optimization_run_id: "run-7" },
    text
  );
  assert.equal(withRun.invocations.length, 1);
  assert.equal(withRun.invocations[0].optimization_run_id, "run-7");
  assert.equal(withRun.invocations[0].invocation_id, "manager-outer:turn-1");

  const withoutRun = parseExternalTranscript({ path: "transcript.jsonl", label: "manager-outer" }, text);
  assert.equal(withoutRun.invocations.length, 1);
  assert.equal(withoutRun.invocations[0].optimization_run_id, "external:manager-outer");
  assert.equal(withoutRun.invocations[0].invocation_id, "manager-outer:turn-1");
});

test("roleCategory maps case-insensitively and defaults to Other", () => {
  assert.equal(roleCategory("Manager"), "Manager");
  assert.equal(roleCategory("SUPERVISOR"), "Manager");
  assert.equal(roleCategory("ChildOrchestrator"), "Manager");
  assert.equal(roleCategory("Reviewer"), "Review");
  assert.equal(roleCategory("auditor"), "Review");
  assert.equal(roleCategory("Worker"), "Worker");
  assert.equal(roleCategory("chef"), "Other");
  assert.equal(roleCategory(undefined), "Other");
});

test("summarize prints percentages and '-' for zero denominators", () => {
  const noTokens = summarize([
    invocation({ requested_model: "model-a", role: "worker", input_tokens: null, output_tokens: null }),
  ]);
  assert.match(noTokens, /Known measured input\+output tokens: 0/);
  assert.match(noTokens, /Coverage \(both counters known\): 0\/1 0\.0%/);
  assert.match(noTokens, /measured 0\/1/);
  assert.match(noTokens, /tokens\s+-\s+-/);

  const text = summarize([
    invocation({ requested_model: "model-a", role: "worker", input_tokens: 100, output_tokens: 100 }),
    invocation({ requested_model: "model-b", role: "manager", input_tokens: 300, output_tokens: 100 }),
    invocation({ requested_model: "model-b", role: "reviewer", input_tokens: null, output_tokens: 50 }),
  ]);
  assert.match(text, /Known measured input\+output tokens: 600/);
  assert.match(text, /Coverage \(both counters known\): 2\/3 66\.7%/);
  assert.match(text, /model-a\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+200\s+33\.3%/);
  assert.match(text, /model-b\s+count\s+2\s+66\.7%\s+measured\s+1\/2\s+tokens\s+400\s+66\.7%/);
  assert.match(text, /Manager\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+400\s+66\.7%/);
  assert.match(text, /Worker\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+200\s+33\.3%/);
  assert.match(text, /Review\s+count\s+1\s+33\.3%\s+measured\s+0\/1\s+tokens\s+-\s+-/);
});

test("summarize shows unavailable tokens for a Review group with no measured invocation", () => {
  const text = summarize([
    invocation({ requested_model: "model-a", role: "worker", input_tokens: 100, output_tokens: 50 }),
    invocation({ requested_model: "model-a", role: "auditor", input_tokens: null, output_tokens: null }),
  ]);
  assert.match(text, /Known measured input\+output tokens: 150/);
  assert.match(text, /Coverage \(both counters known\): 1\/2 50\.0%/);
  assert.match(text, /Worker\s+count\s+1\s+50\.0%\s+measured\s+1\/1\s+tokens\s+150\s+100\.0%/);
  assert.match(text, /Review\s+count\s+1\s+50\.0%\s+measured\s+0\/1\s+tokens\s+-\s+-/);
});

test("summarize prints a measured zero as 0", () => {
  const text = summarize([
    invocation({ requested_model: "model-a", role: "worker", input_tokens: 0, output_tokens: 0 }),
    invocation({ requested_model: "model-a", role: "manager", input_tokens: 100, output_tokens: 100 }),
  ]);
  assert.match(text, /Known measured input\+output tokens: 200/);
  assert.match(text, /Worker\s+count\s+1\s+50\.0%\s+measured\s+1\/1\s+tokens\s+0\s+0\.0%/);
});

test("summarize groups runs by Worker model with tokens across all roles", () => {
  const invocations = [
    invocation({ optimization_run_id: "run-1", role: "worker", requested_model: "model-w", input_tokens: 100, output_tokens: 50 }),
    invocation({ optimization_run_id: "run-1", role: "manager", requested_model: "model-m", input_tokens: 200, output_tokens: 100 }),
    invocation({ optimization_run_id: "run-1", role: "auditor", requested_model: "model-r", input_tokens: 30, output_tokens: 20 }),
    invocation({ optimization_run_id: "run-2", role: "worker", requested_model: "model-w", input_tokens: 400, output_tokens: 100 }),
    invocation({ optimization_run_id: "run-2", role: "manager", requested_model: "model-m", input_tokens: 500, output_tokens: 300 }),
    invocation({ optimization_run_id: "run-2", role: "auditor", requested_model: "model-r", input_tokens: 60, output_tokens: 40 }),
  ];
  const text = summarize(invocations, [
    { run_id: "run-1", accepted: true },
    { run_id: "run-2", accepted: false },
  ]);
  const lines = text.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.notEqual(heading, -1);
  assert.equal(lines[heading + 1], "model-w                  runs    2 accepted    1 not accepted    1 tokens       1900 per accepted run       1900 incomplete 0");
});

test("summarize marks a run with an unknown counter as incomplete", () => {
  const text = summarize(
    [
      invocation({ optimization_run_id: "run-1", role: "worker", requested_model: "model-w", input_tokens: 100, output_tokens: null }),
    ],
    [{ run_id: "run-1", accepted: true }]
  );
  const lines = text.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.equal(lines[heading + 1], "model-w                  runs    1 accepted    1 not accepted    0 tokens          - per accepted run          - incomplete 1");
});

test("summarize keys a run without Worker invocations as (no Worker)", () => {
  const text = summarize(
    [
      invocation({ optimization_run_id: "run-1", role: "manager", requested_model: "model-m", input_tokens: 100, output_tokens: 100 }),
    ],
    [{ run_id: "run-1", accepted: true }]
  );
  const lines = text.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.equal(lines[heading + 1], "(no Worker)              runs    1 accepted    1 not accepted    0 tokens        200 per accepted run        200 incomplete 0");
});

test("summarize ignores invocations whose run has no outcome", () => {
  const invocations = [
    invocation({ optimization_run_id: "run-1", role: "worker", requested_model: "model-w", input_tokens: 100, output_tokens: 50 }),
    invocation({ optimization_run_id: "run-9", role: "worker", requested_model: "model-x", input_tokens: 900, output_tokens: 900 }),
  ];
  const text = summarize(invocations, [{ run_id: "run-1", accepted: true }]);
  const lines = text.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.equal(lines[heading + 1], "model-w                  runs    1 accepted    1 not accepted    0 tokens        150 per accepted run        150 incomplete 0");
  assert.ok(!lines.slice(heading + 1).some((line) => line.startsWith("model-x")));
});

test("summarize prints (none) for the Worker model section without outcomes", () => {
  const text = summarize([invocation({ role: "worker", requested_model: "model-w" })], []);
  const lines = text.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.equal(lines[heading + 1], "(none)");
});
test("CLI end to end with --out, --summary, and an external manifest", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "run/switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations: [invocation()],
  });
  writeArtifact(root, "run/bad/switch-cost/live-evidence.json", { schema_version: 9 });
  const transcript = join(root, "outer.jsonl");
  writeFileSync(
    transcript,
    [
      JSON.stringify({ type: "turn.completed", usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 } }),
      "garbage line",
      "",
    ].join("\n")
  );
  const manifest = join(root, "manifest.json");
  writeFileSync(manifest, JSON.stringify([
    { path: transcript, label: "outer", role: "manager", requested_model: "gpt-5", requested_effort: "medium" },
  ]));
  const outFile = join(root, "usage.json");

  const result = spawnSync(
    process.execPath,
    [script, "--external-manifest", manifest, "--out", outFile, "--summary", root],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Invocations: 2/);
  assert.match(result.stderr, /By requested model:/);
  assert.match(result.stderr, /By role category:/);

  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.schema_version, 1);
  assert.equal(doc.invocations.length, 2);
  assert.equal(doc.collection.files_scanned, 2);
  assert.equal(doc.collection.artifacts_parsed, 1);
  assert.equal(doc.collection.invalid_artifacts.length, 1);
  assert.equal(doc.collection.identical_duplicates, 0);
  assert.deepEqual(doc.collection.roots, [root]);
  assert.equal(doc.collection.external_sources.length, 1);
  assert.equal(doc.collection.external_sources[0].label, "outer");
  assert.equal(doc.collection.external_sources[0].turns, 1);
  assert.equal(doc.collection.external_sources[0].malformed_lines, 1);
  assert.deepEqual(doc.collection.errors, []);
  assert.equal(doc.invocations[0].optimization_run_id, "external:outer");
  assert.equal(doc.invocations[1].optimization_run_id, "run-1");
});

test("CLI records an error for a manifest containing JSON null", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "run/switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations: [invocation()],
  });
  const manifest = join(root, "manifest.json");
  writeFileSync(manifest, "null");
  const outFile = join(root, "usage.json");

  const result = spawnSync(
    process.execPath,
    [script, "--external-manifest", manifest, "--out", outFile, root],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.deepEqual(doc.collection.external_sources, []);
  assert.equal(doc.collection.errors.length, 1);
  assert.equal(doc.collection.errors[0].reason, "manifest is not a JSON array");
});

test("CLI writes a large document to stdout without truncation", (t) => {
  const root = tempDir(t);
  const invocations = [];
  for (let i = 0; i < 1200; i++) {
    invocations.push(
      invocation({
        optimization_run_id: "run-" + i,
        invocation_id: "inv-" + i,
        input_tokens: 1000 + i,
        output_tokens: 500 + i,
      })
    );
  }
  writeArtifact(root, "big/switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations,
  });

  const result = spawnSync(process.execPath, [script, root], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.length > 500_000);
  const doc = JSON.parse(result.stdout);
  assert.equal(doc.schema_version, 1);
  assert.equal(doc.invocations.length, 1200);
  assert.equal(doc.invocations[0].optimization_run_id, "run-0");
  assert.equal(doc.invocations[1199].optimization_run_id, "run-999");
});

test("CLI exits 2 with usage on stderr for no ROOT or an unknown option", () => {
  const noRoot = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(noRoot.status, 2);
  assert.equal(noRoot.stdout, "");
  assert.match(noRoot.stderr, /^usage: /);

  const unknownLong = spawnSync(process.execPath, [script, "--bogus", "."], { encoding: "utf8" });
  assert.equal(unknownLong.status, 2);
  assert.match(unknownLong.stderr, /^usage: /);

  const unknownShort = spawnSync(process.execPath, [script, "-x", "."], { encoding: "utf8" });
  assert.equal(unknownShort.status, 2);
  assert.match(unknownShort.stderr, /^usage: /);

  const optionAsOperand = spawnSync(
    process.execPath,
    [script, "--out", "--bogus", "."],
    { encoding: "utf8" }
  );
  assert.equal(optionAsOperand.status, 2);
  assert.match(optionAsOperand.stderr, /^usage: /);

  const missingOperand = spawnSync(process.execPath, [script, "--out"], { encoding: "utf8" });
  assert.equal(missingOperand.status, 2);
  assert.match(missingOperand.stderr, /^usage: /);
});

test("scanRoot finds artifacts directly under relative roots '.' and 'switch-cost'", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(root, "nested/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  const previous = process.cwd();
  process.chdir(root);
  try {
    const dot = scanRoot(".");
    assert.deepEqual(dot.errors, []);
    assert.deepEqual(dot.files, [
      "nested/switch-cost/live-evidence.json",
      "switch-cost/live-evidence.json",
    ]);

    const nested = scanRoot("nested");
    assert.deepEqual(nested.errors, []);
    assert.deepEqual(nested.files, ["nested/switch-cost/live-evidence.json"]);

    const direct = scanRoot("switch-cost");
    assert.deepEqual(direct.errors, []);
    assert.deepEqual(direct.files, ["switch-cost/live-evidence.json"]);
  } finally {
    process.chdir(previous);
  }
});

test("scanRoot normalizes root spelling before symlink and exclusion checks", (t) => {
  const root = tempDir(t);
  const target = join(root, "target");
  writeArtifact(target, "switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(target, ".git/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  const link = join(root, "root-link");
  symlinkSync(target, link, "dir");

  const viaTrailingLink = scanRoot(link + "/");
  assert.deepEqual(viaTrailingLink.files, []);
  assert.deepEqual(viaTrailingLink.errors, []);

  const gitTrailing = scanRoot(join(root, "target", ".git") + "/");
  assert.deepEqual(gitTrailing.files, []);
  assert.deepEqual(gitTrailing.errors, []);

  const gitDot = scanRoot(join(root, "target", ".git") + "/.");
  assert.deepEqual(gitDot.files, []);
  assert.deepEqual(gitDot.errors, []);
});

test("CLI collects an artifact directly under a relative ROOT '.'", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations: [invocation()],
  });
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, "."], {
    encoding: "utf8",
    cwd: root,
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.deepEqual(doc.collection.roots, ["."]);
  assert.equal(doc.collection.files_scanned, 1);
  assert.equal(doc.collection.artifacts_parsed, 1);
});

test("scanRoot finds an artifact directly under ROOT '.' inside a switch-cost directory", (t) => {
  const root = tempDir(t);
  const sc = join(root, "switch-cost");
  mkdirSync(sc, { recursive: true });
  writeFileSync(join(sc, "live-evidence.json"), JSON.stringify({ schema_version: 1, invocations: [] }));
  const previous = process.cwd();
  process.chdir(sc);
  try {
    const dot = scanRoot(".");
    assert.deepEqual(dot.errors, []);
    assert.deepEqual(dot.files, ["live-evidence.json"]);
  } finally {
    process.chdir(previous);
  }
});

test("scanRoot rejects an empty ROOT without scanning", () => {
  const { files, errors } = scanRoot("");
  assert.deepEqual(files, []);
  assert.deepEqual(errors, [{ path: "", reason: "empty root" }]);
});

test("scanRoot ignores a ROOT whose path traverses an intermediate symlink", (t) => {
  const root = tempDir(t);
  const target = join(root, "target");
  writeArtifact(target, "archive/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  symlinkSync(target, join(root, "link"), "dir");
  const { files, errors } = scanRoot(join(root, "link", "archive"));
  assert.deepEqual(files, []);
  assert.deepEqual(errors, []);
});

test("scanRoot skips a ROOT spelled through '.git/child/..'", (t) => {
  const root = tempDir(t);
  const target = join(root, "target");
  writeArtifact(target, "switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  writeArtifact(target, ".git/switch-cost/live-evidence.json", { schema_version: 1, invocations: [] });
  mkdirSync(join(target, ".git", "child"), { recursive: true });
  const raw = root + "/target/.git/child/..";
  const { files, errors } = scanRoot(raw);
  assert.deepEqual(files, []);
  assert.deepEqual(errors, []);
});

test("parseArtifact keeps negative counters and summarize treats them as unknown", () => {
  const parsed = parseArtifact(
    "p",
    JSON.stringify({ schema_version: 1, invocations: [invocation({ input_tokens: -10, output_tokens: 0 })] })
  );
  assert.equal(parsed.invalid, false);
  assert.equal(parsed.invocations[0].input_tokens, -10);
  const text = summarize(parsed.invocations);
  assert.match(text, /Known measured input\+output tokens: 0/);
  assert.match(text, /Coverage \(both counters known\): 0\/1 0\.0%/);
  assert.match(text, /measured 0\/1/);
  assert.match(text, /tokens\s+-\s+-/);
});

test("CLI collects an artifact directly under ROOT '.' from inside switch-cost", (t) => {
  const root = tempDir(t);
  const sc = join(root, "switch-cost");
  writeArtifact(sc, "live-evidence.json", { schema_version: 1, invocations: [invocation()] });
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, "."], {
    encoding: "utf8",
    cwd: sc,
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.equal(doc.collection.files_scanned, 1);
  assert.deepEqual(doc.collection.roots, ["."]);
});

test("CLI records an error for an empty ROOT argument", (t) => {
  const root = tempDir(t);
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, ""], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.deepEqual(doc.invocations, []);
  assert.deepEqual(doc.collection.roots, [""]);
  assert.deepEqual(doc.collection.errors, [{ path: "", reason: "empty root" }]);
});

function writeRunTree(root, name, finalDoc, invocations) {
  writeArtifact(root, name + "/switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations,
  });
  if (finalDoc !== null) {
    writeArtifact(root, name + "/reports/supervisor-final.json", finalDoc);
  }
}

test("CLI links run outcomes, keeps invocations unchanged, and summarizes by outcome", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-a", { run_id: "run-a", success: true, accepted: true, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-a", invocation_id: "inv-a", input_tokens: 100, output_tokens: 50 }),
  ]);
  writeRunTree(root, "run-b", { run_id: "run-b", success: false, accepted: false, publishable: false, status: "rejected" }, [
    invocation({ optimization_run_id: "run-b", invocation_id: "inv-b", input_tokens: 200, output_tokens: 100 }),
  ]);
  writeRunTree(root, "run-c", null, [
    invocation({ optimization_run_id: "run-c", invocation_id: "inv-c", input_tokens: 10, output_tokens: 5 }),
  ]);
  const outFile = join(root, "usage.json");

  const result = spawnSync(process.execPath, [script, "--out", outFile, "--summary", root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /By run outcome:/);
  assert.match(result.stderr, /^accepted\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+150\s+32\.3%/m);
  assert.match(result.stderr, /^not accepted\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+300\s+64\.5%/m);
  assert.match(result.stderr, /^unknown\s+count\s+1\s+33\.3%\s+measured\s+1\/1\s+tokens\s+15\s+3\.2%/m);
  assert.match(result.stderr, /Runs with outcome: 1 accepted, 1 not accepted/);
  assert.match(result.stderr, /Known tokens per accepted run: 465/);

  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.deepEqual(doc.collection.run_outcomes, [
    {
      run_id: "run-a",
      success: true,
      accepted: true,
      publishable: true,
      status: "succeeded",
      path: join(root, "run-a/reports/supervisor-final.json"),
    },
    {
      run_id: "run-b",
      success: false,
      accepted: false,
      publishable: false,
      status: "rejected",
      path: join(root, "run-b/reports/supervisor-final.json"),
    },
  ]);
  assert.deepEqual(doc.collection.run_outcome_conflicts, []);
  assert.deepEqual(doc.collection.errors, []);
  assert.equal(doc.invocations.length, 3);
  assert.deepEqual(doc.invocations[0], invocation({ optimization_run_id: "run-a", invocation_id: "inv-a" }));
  assert.deepEqual(doc.invocations[1], invocation({ optimization_run_id: "run-b", invocation_id: "inv-b", input_tokens: 200, output_tokens: 100 }));
  assert.deepEqual(doc.invocations[2], invocation({ optimization_run_id: "run-c", invocation_id: "inv-c", input_tokens: 10, output_tokens: 5 }));
});

test("CLI attributes an external manager transcript to its MACO run", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-1", { run_id: "run-1", success: true, accepted: true, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-1", invocation_id: "inv-1", input_tokens: 100, output_tokens: 50 }),
  ]);
  const transcript = join(root, "manager-outer.jsonl");
  writeFileSync(
    transcript,
    JSON.stringify({ type: "turn.completed", usage: { input_tokens: 300, cached_input_tokens: 0, output_tokens: 100 } }) + "\n"
  );
  const manifest = join(root, "manifest.json");
  writeFileSync(manifest, JSON.stringify([
    {
      path: transcript,
      label: "manager-outer",
      role: "manager",
      requested_model: "gpt-5",
      requested_effort: "medium",
      optimization_run_id: "run-1",
    },
  ]));
  const outFile = join(root, "usage.json");

  const result = spawnSync(
    process.execPath,
    [script, "--external-manifest", manifest, "--out", outFile, "--summary", root],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  const lines = result.stderr.split("\n");
  const heading = lines.indexOf("By Worker model per run:");
  assert.notEqual(heading, -1);
  assert.equal(lines[heading + 1], "model-a                  runs    1 accepted    1 not accepted    0 tokens        550 per accepted run        550 incomplete 0");

  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 2);
  const manager = doc.invocations.find((invocation) => invocation.role === "manager");
  assert.equal(manager.optimization_run_id, "run-1");
  assert.equal(manager.invocation_id, "manager-outer:turn-1");
});

test("CLI skips a manifest entry with an invalid optimization_run_id and records the error", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-1", { run_id: "run-1", success: true, accepted: true, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-1", invocation_id: "inv-1" }),
  ]);
  const transcript = join(root, "outer.jsonl");
  writeFileSync(
    transcript,
    JSON.stringify({ type: "turn.completed", usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 } }) + "\n"
  );
  const manifest = join(root, "manifest.json");
  writeFileSync(manifest, JSON.stringify([
    { path: transcript, label: "outer", role: "manager", optimization_run_id: 5 },
  ]));
  const outFile = join(root, "usage.json");

  const result = spawnSync(
    process.execPath,
    [script, "--external-manifest", manifest, "--out", outFile, root],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.deepEqual(doc.collection.external_sources, []);
  assert.deepEqual(doc.collection.errors, [
    { path: manifest, reason: "manifest entry outer has an invalid optimization_run_id" },
  ]);
});

test("CLI reports conflicting outcomes as conflicts and treats the run as unknown", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-x1", { run_id: "run-x", success: true, accepted: true, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-x", invocation_id: "inv-x1", input_tokens: 100, output_tokens: 50 }),
  ]);
  writeRunTree(root, "run-x2", { run_id: "run-x", success: true, accepted: false, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-x", invocation_id: "inv-x2", input_tokens: 20, output_tokens: 10 }),
  ]);
  const outFile = join(root, "usage.json");

  const result = spawnSync(process.execPath, [script, "--out", outFile, "--summary", root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.deepEqual(doc.collection.run_outcomes, []);
  assert.deepEqual(doc.collection.run_outcome_conflicts, [
    {
      run_id: "run-x",
      fields: ["accepted"],
      paths: [
        join(root, "run-x1/reports/supervisor-final.json"),
        join(root, "run-x2/reports/supervisor-final.json"),
      ],
    },
  ]);
  assert.deepEqual(doc.collection.errors, []);
  assert.equal(doc.invocations.length, 2);
  assert.match(result.stderr, /^unknown\s+count\s+2\s+100\.0%\s+measured\s+2\/2\s+tokens\s+180\s+100\.0%/m);
  assert.match(result.stderr, /Runs with outcome: 0 accepted, 0 not accepted/);
  assert.match(result.stderr, /Known tokens per accepted run: -/);
  assert.doesNotMatch(result.stderr, /^accepted\s/m);
  assert.doesNotMatch(result.stderr, /^not accepted\s/m);
});

test("CLI records an error for an invalid supervisor-final.json without failing", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-d", { run_id: "run-d", accepted: true }, [
    invocation({ optimization_run_id: "run-d", invocation_id: "inv-d" }),
  ]);
  writeFileSync(join(root, "run-d/reports/supervisor-final.json"), "not json");
  const outFile = join(root, "usage.json");

  const result = spawnSync(process.execPath, [script, "--out", outFile, root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.deepEqual(doc.collection.run_outcomes, []);
  assert.equal(doc.invocations.length, 1);
  assert.equal(doc.collection.errors.length, 1);
  assert.equal(doc.collection.errors[0].path, join(root, "run-d/reports/supervisor-final.json"));
  assert.match(doc.collection.errors[0].reason, /invalid JSON/);
});

test("CLI links run outcomes when ROOT is '.' from inside a switch-cost directory", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-e", { run_id: "run-e", success: true, accepted: true, publishable: true, status: "succeeded" }, [
    invocation({ optimization_run_id: "run-e", invocation_id: "inv-e", input_tokens: 100, output_tokens: 50 }),
  ]);
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, "."], {
    encoding: "utf8",
    cwd: join(root, "run-e", "switch-cost"),
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.equal(doc.invocations[0].optimization_run_id, "run-e");
  assert.equal(doc.collection.run_outcomes.length, 1);
  assert.equal(doc.collection.run_outcomes[0].run_id, "run-e");
  assert.equal(doc.collection.run_outcomes[0].accepted, true);
  assert.equal(doc.collection.run_outcomes[0].path, join(root, "run-e/reports/supervisor-final.json"));
  assert.deepEqual(doc.collection.run_outcome_conflicts, []);
  assert.deepEqual(doc.collection.errors, []);
});

test("CLI records an error when supervisor-final.json cannot be inspected", (t) => {
  const root = tempDir(t);
  writeRunTree(root, "run-f", null, [
    invocation({ optimization_run_id: "run-f", invocation_id: "inv-f" }),
  ]);
  writeFileSync(join(root, "run-f", "reports"), "not a directory");
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
  assert.deepEqual(doc.collection.run_outcomes, []);
  assert.equal(doc.collection.errors.length, 1);
  assert.equal(doc.collection.errors[0].path, join(root, "run-f/reports/supervisor-final.json"));
  assert.match(doc.collection.errors[0].reason, /unreadable file: /);
});

test("renderSvg draws the four sections with role category shares", () => {
  const invocations = [
    invocation({ invocation_id: "inv-m", role: "manager", requested_model: "model-a", input_tokens: 100, output_tokens: 100 }),
    invocation({ invocation_id: "inv-w", role: "worker", requested_model: "model-b", input_tokens: 100, output_tokens: 100 }),
    invocation({ invocation_id: "inv-a", role: "auditor", requested_model: "model-a", input_tokens: 50, output_tokens: 50 }),
  ];
  const svg = renderSvg(invocations, []);
  assert.ok(svg.startsWith("<svg"));
  assert.ok(svg.trimEnd().endsWith("</svg>"));
  assert.match(svg, /<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /MACO token usage shares/);
  assert.match(svg, /By role category/);
  assert.match(svg, /By requested model/);
  assert.match(svg, /By run outcome/);
  assert.match(svg, /Role category x requested model/);
  assert.match(svg, /40\.0% \| 200 tokens \| 1 invocations/);
  assert.match(svg, /20\.0% \| 100 tokens \| 1 invocations/);
  assert.match(svg, /Invocations: 3 \| Known measured input\+output tokens: 500 \| Coverage \(both counters known\): 3\/3/);
  assert.equal(renderSvg(invocations, []), svg);
});

test("renderSvg escapes XML metacharacters in requested model names", () => {
  const svg = renderSvg([invocation({ requested_model: "<&>" })], []);
  assert.match(svg, /&lt;&amp;&gt;/);
  assert.ok(!svg.includes("<&>"));
});

test("renderSvg shows unavailable for a group without counters", () => {
  const svg = renderSvg(
    [invocation({ role: "reviewer", input_tokens: null, output_tokens: null })],
    []
  );
  assert.match(svg, /unavailable \| 1 invocations/);
  assert.match(svg, /Known measured input\+output tokens: 0/);
});

test("CLI writes both --svg and --out files", (t) => {
  const root = tempDir(t);
  writeArtifact(root, "run/switch-cost/live-evidence.json", {
    schema_version: 1,
    invocations: [invocation()],
  });
  const svgFile = join(root, "usage.svg");
  const outFile = join(root, "usage.json");
  const result = spawnSync(process.execPath, [script, "--svg", svgFile, "--out", outFile, root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const svg = readFileSync(svgFile, "utf8");
  assert.ok(svg.startsWith("<svg"));
  assert.ok(svg.trimEnd().endsWith("</svg>"));
  const doc = JSON.parse(readFileSync(outFile, "utf8"));
  assert.equal(doc.invocations.length, 1);
});

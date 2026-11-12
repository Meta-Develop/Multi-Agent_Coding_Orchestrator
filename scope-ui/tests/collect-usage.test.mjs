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

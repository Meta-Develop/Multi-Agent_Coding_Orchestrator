import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { buildReport, main, parseDecisionRecord, renderSummary, scanDecisionRecords, wilson } from "../scripts/collect-decisions.mjs";

const script = fileURLToPath(new URL("../scripts/collect-decisions.mjs", import.meta.url));

function tempDir(t) {
  const root = mkdtempSync(join(tmpdir(), "maco-collect-decisions-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function candidate(runtime, model, effort) {
  return { runtime, model, effort };
}

function decisionRecord(overrides = {}) {
  const deterministic = candidate("vibe", "model-a", "high");
  const proposed = candidate("vibe", "model-a", "high");
  return {
    version: 1,
    mode: "shadow",
    applied_to_binding: false,
    role: "worker",
    assignment_id: "initial",
    attempt: 0,
    endpoint: "http://127.0.0.1:8099/",
    question: {
      task_text: "task",
      task: {},
      deterministic_choice: deterministic,
      options: [
        { option_id: "option-1", candidate: deterministic, description: "deterministic" },
        { option_id: "option-2", candidate: proposed, description: "proposed" },
      ],
    },
    adoption: {
      decision_model: "model-x",
      decision_model_version: "1",
      threshold_basis_points: 9000,
      probabilities: [
        { option_id: "option-1", probability_basis_points: 4000 },
        { option_id: "option-2", probability_basis_points: 9500 },
      ],
      proposed_option_id: "option-2",
      confidence_basis_points: 9500,
      outcome: "adopted",
      adopted: true,
      reason: "above threshold",
      deterministic_choice: deterministic,
      final_choice: deterministic,
    },
    ...overrides,
  };
}

function writeRun(root, runRel, record, final) {
  const runDir = join(root, runRel);
  mkdirSync(join(runDir, "decision-proposals"), { recursive: true });
  mkdirSync(join(runDir, "reports"), { recursive: true });
  writeFileSync(join(runDir, "decision-proposals", "worker.initial.attempt-0.json"), JSON.stringify(record));
  writeFileSync(join(runDir, "reports", "supervisor-final.json"), JSON.stringify(final));
  return runDir;
}

function threeRunFixture(t) {
  const root = tempDir(t);
  const deterministic = candidate("vibe", "model-a", "high");
  writeRun(
    root,
    "runs/r1",
    decisionRecord({
      adoption: {
        decision_model: "model-x",
        decision_model_version: "1",
        threshold_basis_points: 9000,
        probabilities: [
          { option_id: "option-1", probability_basis_points: 4000 },
          { option_id: "option-2", probability_basis_points: 9500 },
        ],
        proposed_option_id: "option-2",
        confidence_basis_points: 9500,
        outcome: "adopted",
        adopted: true,
        reason: "above threshold",
        deterministic_choice: deterministic,
        final_choice: deterministic,
      },
    }),
    { run_id: "r1", success: true, accepted: true, publishable: true, status: "succeeded" }
  );
  writeRun(
    root,
    "runs/r2",
    decisionRecord({
      question: {
        task_text: "task",
        task: {},
        deterministic_choice: deterministic,
        options: [
          { option_id: "option-1", candidate: deterministic, description: "deterministic" },
          { option_id: "option-2", candidate: candidate("codex", "model-b", "medium"), description: "proposed" },
        ],
      },
      adoption: {
        decision_model: "model-x",
        decision_model_version: "1",
        threshold_basis_points: 9000,
        probabilities: [
          { option_id: "option-1", probability_basis_points: 4000 },
          { option_id: "option-2", probability_basis_points: 6000 },
        ],
        proposed_option_id: null,
        confidence_basis_points: 6000,
        outcome: "below_threshold",
        adopted: false,
        reason: "below threshold",
        deterministic_choice: deterministic,
        final_choice: deterministic,
      },
    }),
    { run_id: "r2", success: true, accepted: true, publishable: true, status: "succeeded" }
  );
  writeRun(
    root,
    "runs/r3",
    decisionRecord({
      question: {
        task_text: "task",
        task: {},
        deterministic_choice: null,
        options: [],
      },
      adoption: {
        decision_model: "model-x",
        decision_model_version: "1",
        threshold_basis_points: 9000,
        probabilities: [],
        proposed_option_id: null,
        confidence_basis_points: null,
        outcome: "not_consulted",
        adopted: false,
        reason: "not consulted",
        deterministic_choice: null,
        final_choice: null,
      },
    }),
    { run_id: "r3", success: false, accepted: false, publishable: false, status: "failed" }
  );
  return root;
}

test("wilson matches known intervals", () => {
  assert.deepStrictEqual(wilson(8, 10), { low: 0.4902, high: 0.9433 });
  assert.deepStrictEqual(wilson(0, 5), { low: 0, high: 0.4345 });
  assert.strictEqual(Object.is(wilson(0, 5).low, 0), true);
  assert.strictEqual(wilson(0, 0), null);
});

test("report joins records to run outcomes and counts adoption", async (t) => {
  const root = threeRunFixture(t);
  const outFile = join(root, "report.json");
  const code = await main(["--out", outFile, join(root, "runs")]);
  assert.strictEqual(code, 0);
  const report = JSON.parse(readFileSync(outFile, "utf8"));
  assert.strictEqual(report.schema_version, 1);
  assert.strictEqual(report.kind, "decision-calibration");
  assert.strictEqual(report.errors.length, 0);
  assert.strictEqual(report.totals.records, 3);
  assert.strictEqual(report.totals.consulted, 2);
  assert.strictEqual(report.totals.by_outcome.adopted, 1);
  assert.strictEqual(report.totals.by_outcome.below_threshold, 1);
  assert.strictEqual(report.totals.by_outcome.not_consulted, 1);
  assert.strictEqual(report.totals.adopted_at_recorded_threshold.adopted, 1);
  assert.strictEqual(report.totals.adopted_at_recorded_threshold.consulted, 2);
  assert.strictEqual(report.totals.adopted_at_recorded_threshold.rate, 0.5);
  const row6000 = report.grid.find((row) => row.threshold === 6000);
  assert.strictEqual(row6000.would_adopt, 2);
  assert.strictEqual(row6000.would_adopt_disagreeing, 1);
  const row9000 = report.grid.find((row) => row.threshold === 9000);
  assert.strictEqual(row9000.would_adopt, 1);
  assert.strictEqual(report.outcome_comparison.agree.accepted, 1);
  assert.strictEqual(report.outcome_comparison.agree.known, 1);
  assert.strictEqual(report.outcome_comparison.disagree.accepted, 1);
  assert.strictEqual(report.outcome_comparison.disagree.known, 1);
  assert.strictEqual(report.outcome_comparison.difference, 0);
  assert.strictEqual(report.calibration.status, "insufficient_evidence");
  assert.strictEqual(report.calibration.sample, 2);
  assert.strictEqual(
    report.calibration.message,
    "2 consulted decisions with a known run outcome; at least 30 are needed before the threshold changes"
  );
  const r1 = report.records.find((record) => record.run_dir.endsWith("r1"));
  assert.strictEqual(r1.run_accepted, true);
  assert.strictEqual(r1.agrees, true);
  const r2 = report.records.find((record) => record.run_dir.endsWith("r2"));
  assert.strictEqual(r2.run_accepted, true);
  assert.strictEqual(r2.agrees, false);
  const r3 = report.records.find((record) => record.run_dir.endsWith("r3"));
  assert.strictEqual(r3.run_accepted, false);
});

test("tied probabilities never propose", async (t) => {
  const root = tempDir(t);
  const deterministic = candidate("vibe", "model-a", "high");
  writeRun(
    root,
    "runs/t1",
    decisionRecord({
      adoption: {
        decision_model: "model-x",
        decision_model_version: "1",
        threshold_basis_points: 9000,
        probabilities: [
          { option_id: "option-1", probability_basis_points: 5000 },
          { option_id: "option-2", probability_basis_points: 5000 },
        ],
        proposed_option_id: null,
        confidence_basis_points: 9000,
        outcome: "below_threshold",
        adopted: false,
        reason: "tied",
        deterministic_choice: deterministic,
        final_choice: deterministic,
      },
    }),
    { run_id: "t1", success: true, accepted: true, publishable: true, status: "succeeded" }
  );
  const parsed = parseDecisionRecord(
    join(root, "runs/t1/decision-proposals/worker.initial.attempt-0.json"),
    readFileSync(join(root, "runs/t1/decision-proposals/worker.initial.attempt-0.json"), "utf8")
  );
  assert.ok(parsed.record);
  assert.strictEqual(parsed.record.tied, true);
  assert.strictEqual(parsed.record.proposed_candidate, null);
  assert.strictEqual(parsed.record.agrees, null);
  const outFile = join(root, "report.json");
  const code = await main(["--out", outFile, join(root, "runs")]);
  assert.strictEqual(code, 0);
  const report = JSON.parse(readFileSync(outFile, "utf8"));
  assert.strictEqual(report.totals.consulted, 1);
  for (const row of report.grid) {
    assert.strictEqual(row.would_adopt, 0);
    assert.strictEqual(row.would_adopt_disagreeing, 0);
  }
});

test("invalid records and bad arguments are reported", async (t) => {
  const root = tempDir(t);
  const runDir = join(root, "runs/bad");
  mkdirSync(join(runDir, "decision-proposals"), { recursive: true });
  writeFileSync(join(runDir, "decision-proposals", "worker.initial.attempt-0.json"), JSON.stringify({ version: 2 }));
  const outFile = join(root, "report.json");
  const code = await main(["--out", outFile, join(root, "runs")]);
  assert.strictEqual(code, 0);
  const report = JSON.parse(readFileSync(outFile, "utf8"));
  assert.strictEqual(report.records.length, 0);
  assert.strictEqual(report.errors.length, 1);
  assert.strictEqual(report.errors[0].path, join(runDir, "decision-proposals", "worker.initial.attempt-0.json"));

  const thresholdZero = spawnSync(process.execPath, [script, "--threshold", "0", root], { encoding: "utf8" });
  assert.strictEqual(thresholdZero.status, 2);
  const thresholdText = spawnSync(process.execPath, [script, "--threshold", "abc", root], { encoding: "utf8" });
  assert.strictEqual(thresholdText.status, 2);
  const noRoot = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.strictEqual(noRoot.status, 2);
});

test("summary prints the calibration lines", (t) => {
  const root = threeRunFixture(t);
  const result = spawnSync(process.execPath, [script, "--summary", join(root, "runs")], {
    encoding: "utf8",
  });
  assert.strictEqual(result.status, 0);
  const lines = result.stdout.split("\n");
  assert.ok(lines.includes("Decision records: 3 (consulted 2)"));
  const calibrationLine = lines.find((line) => line.startsWith("Calibration: insufficient_evidence - 2 consulted decisions"));
  assert.ok(calibrationLine !== undefined);
  assert.strictEqual(
    calibrationLine,
    "Calibration: insufficient_evidence - 2 consulted decisions with a known run outcome; at least 30 are needed before the threshold changes"
  );
});

test("relative ROOT still joins run outcomes", (t) => {
  const root = threeRunFixture(t);
  const outFile = join(root, "report.json");
  const result = spawnSync(process.execPath, [script, "--out", outFile, "runs"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.strictEqual(result.status, 0);
  const report = JSON.parse(readFileSync(outFile, "utf8"));
  assert.strictEqual(report.records.length, 3);
  for (const record of report.records) {
    assert.ok(record.path.startsWith("/"));
    assert.ok(record.run_dir.startsWith("/"));
  }
  assert.strictEqual(report.outcome_comparison.agree.known, 1);
});

test("scan skips excluded roots and refuses symlinked root paths", (t) => {
  const root = tempDir(t);

  for (const name of ["node_modules", ".git"]) {
    const runDir = join(root, name, "run-1");
    mkdirSync(join(runDir, "decision-proposals"), { recursive: true });
    writeFileSync(
      join(runDir, "decision-proposals", "worker.initial.attempt-0.json"),
      JSON.stringify(decisionRecord())
    );
    const scanned = scanDecisionRecords(join(root, name));
    assert.deepEqual(scanned.files, []);
    assert.deepEqual(scanned.errors, []);
  }

  const realRun = join(root, "real", "run-1");
  mkdirSync(join(realRun, "decision-proposals"), { recursive: true });
  writeFileSync(
    join(realRun, "decision-proposals", "worker.initial.attempt-0.json"),
    JSON.stringify(decisionRecord())
  );

  const link = join(root, "link");
  symlinkSync(join(root, "real"), link);

  const viaLink = scanDecisionRecords(link);
  assert.deepEqual(viaLink.files, []);
  assert.equal(viaLink.errors.length, 1);
  assert.match(viaLink.errors[0].reason, /symbolic link/);

  const viaLinkParent = scanDecisionRecords(join(link, "run-1"));
  assert.deepEqual(viaLinkParent.files, []);
  assert.equal(viaLinkParent.errors.length, 1);
  assert.match(viaLinkParent.errors[0].reason, /symbolic link/);

  const direct = scanDecisionRecords(join(root, "real"));
  assert.equal(direct.files.length, 1);
  assert.deepEqual(direct.errors, []);
});

test("missing or non-directory excluded-name roots still error", (t) => {
  const root = tempDir(t);

  for (const name of ["node_modules", ".git"]) {
    const missing = scanDecisionRecords(join(root, name, "missing"));
    assert.deepEqual(missing.files, []);
    assert.equal(missing.errors.length, 1);
    assert.equal(missing.errors[0].path, join(root, name, "missing"));

    const filePath = join(root, name, "file");
    mkdirSync(join(root, name), { recursive: true });
    writeFileSync(filePath, "not a directory");
    const scanned = scanDecisionRecords(filePath);
    assert.deepEqual(scanned.files, []);
    assert.equal(scanned.errors.length, 1);
    assert.equal(scanned.errors[0].path, filePath);
    assert.match(scanned.errors[0].reason, /not a directory/);
  }
});

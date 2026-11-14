import { lstatSync, readdirSync, readFileSync, writeFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { collectRunOutcomes } from "./collect-usage.mjs";

const USAGE =
  "usage: node scope-ui/scripts/collect-decisions.mjs [--threshold BP]... [--out FILE] [--summary] ROOT...";

const SKIP_DIRS = new Set([".git", "node_modules"]);

const OUTCOMES = [
  "adopted",
  "below_threshold",
  "malformed",
  "no_options",
  "provider_error",
  "not_consulted",
];

const DEFAULT_THRESHOLDS = [5000, 6000, 7000, 8000, 9000];

function round4(value) {
  return Math.round(value * 10000) / 10000;
}

export function scanDecisionRecords(rootInput) {
  const files = [];
  const errors = [];
  const root = resolve(rootInput);
  let stat;
  try {
    stat = lstatSync(root);
  } catch (err) {
    errors.push({ path: rootInput, reason: `missing or unreadable root: ${err.message}` });
    return { files, errors };
  }
  if (stat.isSymbolicLink()) {
    errors.push({ path: rootInput, reason: "root is a symbolic link" });
    return { files, errors };
  }
  if (!stat.isDirectory()) {
    errors.push({ path: rootInput, reason: "not a directory" });
    return { files, errors };
  }
  if (SKIP_DIRS.has(basename(root))) {
    return { files, errors };
  }
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      errors.push({ path: dir, reason: `unreadable directory: ${err.message}` });
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const child = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(child);
      } else if (
        entry.isFile() &&
        entry.name.endsWith(".json") &&
        basename(dir) === "decision-proposals"
      ) {
        files.push(child);
      }
    }
  }
  files.sort();
  return { files, errors };
}

export function parseDecisionRecord(path, text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    return { error: { path, reason: `invalid JSON: ${err.message}` } };
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return { error: { path, reason: "record is not a JSON object" } };
  }
  if (data.version !== 1) {
    return { error: { path, reason: "record version is not 1" } };
  }
  if (data.mode !== "shadow") {
    return { error: { path, reason: "record mode is not shadow" } };
  }
  const adoption = data.adoption;
  if (adoption === null || typeof adoption !== "object" || Array.isArray(adoption)) {
    return { error: { path, reason: "record has no adoption object" } };
  }
  if (!OUTCOMES.includes(adoption.outcome)) {
    return { error: { path, reason: "adoption outcome is not one of the known outcomes" } };
  }
  if (!Array.isArray(adoption.probabilities)) {
    return { error: { path, reason: "adoption probabilities is not an array" } };
  }
  const question = data.question;
  if (question === null || typeof question !== "object" || Array.isArray(question)) {
    return { error: { path, reason: "record has no question object" } };
  }
  if (!Array.isArray(question.options)) {
    return { error: { path, reason: "question options is not an array" } };
  }

  const probabilities = adoption.probabilities;
  let maxProbability = null;
  let maxCount = 0;
  let maxOptionId = null;
  for (const entry of probabilities) {
    const value = entry && typeof entry === "object" ? entry.probability_basis_points : undefined;
    if (typeof value !== "number") continue;
    if (maxProbability === null || value > maxProbability) {
      maxProbability = value;
      maxCount = 1;
      maxOptionId = entry.option_id;
    } else if (value === maxProbability) {
      maxCount += 1;
    }
  }
  const tied = maxCount > 1;
  let proposedCandidate = null;
  if (probabilities.length > 0 && !tied && maxOptionId !== null) {
    for (const option of question.options) {
      if (option && typeof option === "object" && option.option_id === maxOptionId) {
        proposedCandidate = option.candidate ?? null;
        break;
      }
    }
  }
  const deterministicChoice = question.deterministic_choice ?? null;
  let agrees = null;
  if (proposedCandidate !== null && deterministicChoice !== null) {
    agrees =
      proposedCandidate.runtime === deterministicChoice.runtime &&
      proposedCandidate.model === deterministicChoice.model &&
      proposedCandidate.effort === deterministicChoice.effort;
  }

  const record = {
    path,
    run_dir: dirname(dirname(path)),
    role: data.role ?? null,
    assignment_id: data.assignment_id ?? null,
    attempt: data.attempt ?? null,
    outcome: adoption.outcome,
    decision_model: adoption.decision_model ?? null,
    decision_model_version: adoption.decision_model_version ?? null,
    threshold_basis_points: adoption.threshold_basis_points ?? null,
    confidence_basis_points: adoption.confidence_basis_points ?? null,
    tied,
    proposed_candidate: proposedCandidate,
    deterministic_choice: deterministicChoice,
    agrees,
    run_accepted: null,
  };
  return { record };
}

export function wilson(successes, total) {
  if (total === 0) return null;
  const z = 1.96;
  const p = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (p + (z * z) / (2 * total)) / denominator;
  const half =
    (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) / denominator;
  const low = Math.max(0, round4(center - half));
  const high = Math.min(1, round4(center + half));
  return { low, high };
}

function isConsulted(record) {
  return record.outcome === "adopted" || record.outcome === "below_threshold";
}

export function buildReport(records, runOutcomes, thresholds) {
  const outcomesByPath = new Map();
  for (const outcome of runOutcomes) {
    outcomesByPath.set(outcome.path, outcome);
  }
  for (const record of records) {
    const outcome = outcomesByPath.get(join(record.run_dir, "reports", "supervisor-final.json"));
    record.run_accepted =
      outcome !== undefined && typeof outcome.accepted === "boolean" ? outcome.accepted : null;
  }

  const consultedRecords = records.filter(isConsulted);
  const byOutcome = {};
  for (const outcome of OUTCOMES) {
    byOutcome[outcome] = records.filter((record) => record.outcome === outcome).length;
  }
  const recordedThresholds = [...new Set(records.map((record) => record.threshold_basis_points))]
    .filter((value) => typeof value === "number")
    .sort((a, b) => a - b);
  const adopted = byOutcome.adopted;
  const consulted = consultedRecords.length;
  const adoptedAtRecordedThreshold = {
    adopted,
    consulted,
    rate: consulted === 0 ? null : round4(adopted / consulted),
    interval: wilson(adopted, consulted),
  };
  const totals = {
    records: records.length,
    consulted,
    by_outcome: byOutcome,
    recorded_thresholds: recordedThresholds,
    adopted_at_recorded_threshold: adoptedAtRecordedThreshold,
  };

  const grid = thresholds.map((threshold) => {
    const wouldAdoptRecords = consultedRecords.filter(
      (record) =>
        !record.tied &&
        typeof record.confidence_basis_points === "number" &&
        record.confidence_basis_points >= threshold
    );
    const wouldAdopt = wouldAdoptRecords.length;
    return {
      threshold,
      would_adopt: wouldAdopt,
      would_adopt_disagreeing: wouldAdoptRecords.filter((record) => record.agrees === false)
        .length,
      rate: consulted === 0 ? null : round4(wouldAdopt / consulted),
    };
  });

  function compareGroup(recordsGroup) {
    const knownRecords = recordsGroup.filter((record) => typeof record.run_accepted === "boolean");
    const accepted = knownRecords.filter((record) => record.run_accepted === true).length;
    const known = knownRecords.length;
    return {
      accepted,
      known,
      rate: known === 0 ? null : round4(accepted / known),
      interval: wilson(accepted, known),
    };
  }
  const comparable = consultedRecords.filter(
    (record) => typeof record.run_accepted === "boolean" && record.agrees !== null
  );
  const agree = compareGroup(comparable.filter((record) => record.agrees === true));
  const disagree = compareGroup(comparable.filter((record) => record.agrees === false));
  const difference =
    agree.rate === null || disagree.rate === null ? null : round4(agree.rate - disagree.rate);
  const outcomeComparison = { agree, disagree, difference };

  const sample = agree.known + disagree.known;
  let status;
  let message;
  if (sample < 30) {
    status = "insufficient_evidence";
    message = `${sample} consulted decisions with a known run outcome; at least 30 are needed before the threshold changes`;
  } else {
    status = "shadow_only";
    message =
      "shadow records bind the deterministic choice, so outcomes of disagreeing proposals are unobserved; measure them in applied mode before lowering the threshold";
  }
  const calibration = {
    status,
    minimum_sample: 30,
    sample,
    threshold_change: "none",
    message,
  };

  return {
    schema_version: 1,
    kind: "decision-calibration",
    thresholds,
    records,
    totals,
    grid,
    outcome_comparison: outcomeComparison,
    calibration,
  };
}

function rateSuffix(rate, interval) {
  if (rate === null) return " (rate unknown)";
  return ` (rate ${rate}, 95% CI [${interval.low}, ${interval.high}])`;
}

export function renderSummary(report) {
  const totals = report.totals;
  const byOutcome = totals.by_outcome;
  const lines = [];
  lines.push(`Decision records: ${totals.records} (consulted ${totals.consulted})`);
  lines.push(
    `Outcomes: adopted=${byOutcome.adopted}, below_threshold=${byOutcome.below_threshold}, malformed=${byOutcome.malformed}, no_options=${byOutcome.no_options}, provider_error=${byOutcome.provider_error}, not_consulted=${byOutcome.not_consulted}`
  );
  lines.push(
    `Recorded thresholds: ${
      totals.recorded_thresholds.length === 0
        ? "none"
        : totals.recorded_thresholds.map((value) => `${value} bp`).join(", ")
    }`
  );
  const adoptedAt = totals.adopted_at_recorded_threshold;
  lines.push(
    `Adopted at the recorded threshold: ${adoptedAt.adopted}/${adoptedAt.consulted}` +
      rateSuffix(adoptedAt.rate, adoptedAt.interval)
  );
  lines.push("Would adopt by threshold:");
  for (const row of report.grid) {
    lines.push(
      `  ${row.threshold} bp: ${row.would_adopt}/${totals.consulted} (disagreeing ${row.would_adopt_disagreeing})`
    );
  }
  const agree = report.outcome_comparison.agree;
  const disagree = report.outcome_comparison.disagree;
  lines.push(
    `Run accepted when the proposal agrees: ${agree.accepted}/${agree.known}` +
      rateSuffix(agree.rate, agree.interval)
  );
  lines.push(
    `Run accepted when it disagrees: ${disagree.accepted}/${disagree.known}` +
      rateSuffix(disagree.rate, disagree.interval)
  );
  lines.push(
    `Outcome difference (agree - disagree): ${
      report.outcome_comparison.difference === null
        ? "unknown"
        : report.outcome_comparison.difference
    }`
  );
  lines.push(`Calibration: ${report.calibration.status} - ${report.calibration.message}`);
  return lines.join("\n") + "\n";
}

function writeStdout(text) {
  return new Promise((resolve, reject) => {
    process.stdout.write(text, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

export async function main(argv) {
  let out = null;
  let summary = false;
  const thresholds = [];
  const roots = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--threshold" || arg === "--out") {
      const operand = argv[i + 1];
      if (operand === undefined || operand.startsWith("-")) {
        process.stderr.write(USAGE + "\n");
        return 2;
      }
      if (arg === "--threshold") {
        const value = Number(operand);
        if (!Number.isInteger(value) || value < 1 || value > 10000) {
          process.stderr.write(USAGE + "\n");
          return 2;
        }
        thresholds.push(value);
      } else {
        out = operand;
      }
      i += 1;
    } else if (arg === "--summary") {
      summary = true;
    } else if (arg.startsWith("-")) {
      process.stderr.write(USAGE + "\n");
      return 2;
    } else {
      roots.push(arg);
    }
  }
  if (roots.length === 0) {
    process.stderr.write(USAGE + "\n");
    return 2;
  }
  const gridThresholds =
    thresholds.length === 0
      ? DEFAULT_THRESHOLDS
      : [...new Set(thresholds)].sort((a, b) => a - b);

  const errors = [];
  const files = [];
  for (const root of roots) {
    const scanned = scanDecisionRecords(root);
    errors.push(...scanned.errors);
    files.push(...scanned.files);
  }

  const records = [];
  const parsedFiles = [];
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch (err) {
      errors.push({ path: file, reason: `unreadable file: ${err.message}` });
      continue;
    }
    const parsed = parseDecisionRecord(file, text);
    if (parsed.error) {
      errors.push(parsed.error);
    } else {
      records.push(parsed.record);
      parsedFiles.push(file);
    }
  }

  const outcomes = collectRunOutcomes(parsedFiles, errors);
  const report = buildReport(records, outcomes.run_outcomes, gridThresholds);
  report.errors = errors;
  report.run_outcome_conflicts = outcomes.run_outcome_conflicts;

  if (summary) {
    try {
      await writeStdout(renderSummary(report));
    } catch (err) {
      process.stderr.write("error: cannot write stdout: " + err.message + "\n");
      return 1;
    }
  }
  if (!summary || out !== null) {
    const json = JSON.stringify(report, null, 2) + "\n";
    if (out !== null) {
      try {
        writeFileSync(out, json);
      } catch (err) {
        process.stderr.write("error: cannot write " + out + ": " + err.message + "\n");
        return 1;
      }
    } else {
      try {
        await writeStdout(json);
      } catch (err) {
        process.stderr.write("error: cannot write stdout: " + err.message + "\n");
        return 1;
      }
    }
  }
  return 0;
}

if (process.argv[1]) {
  try {
    if (import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
      main(process.argv.slice(2)).then(
        (code) => {
          process.exitCode = code;
        },
        (err) => {
          process.stderr.write("error: " + (err && err.stack ? err.stack : String(err)) + "\n");
          process.exitCode = 1;
        }
      );
    }
  } catch {
    /* not run as the CLI entry point */
  }
}

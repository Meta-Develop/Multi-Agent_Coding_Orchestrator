// Flatten /api/projects into a run catalog. Pure; no DOM.

export function catalogRows(projects) {
  const rows = [];
  for (const project of Array.isArray(projects) ? projects : []) {
    const repo = String(project && project.id != null ? project.id : "");
    const path = project && project.path != null ? String(project.path) : "";
    const runs = Array.isArray(project && project.runs) ? project.runs : [];
    if (!repo) continue;
    if (runs.length === 0) {
      rows.push({
        repo,
        path,
        family: "",
        run: "",
        eventCount: 0,
        finalReport: false,
        modified: 0,
        empty: true,
      });
      continue;
    }
    for (const run of runs) {
      rows.push({
        repo,
        path,
        family: String(run.family || ""),
        run: String(run.run || ""),
        eventCount: Number(run.event_count) || 0,
        finalReport: Boolean(run.final_report_exists),
        modified: Number(run.modified_unix_seconds) || 0,
        empty: false,
      });
    }
  }
  rows.sort((left, right) => {
    if (right.modified !== left.modified) return right.modified - left.modified;
    if (left.repo !== right.repo) return left.repo.localeCompare(right.repo);
    if (left.family !== right.family) return left.family.localeCompare(right.family);
    return left.run.localeCompare(right.run);
  });
  return rows;
}

export function catalogSummary(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const repos = new Set(list.map((row) => row.repo));
  const runs = list.filter((row) => !row.empty);
  const events = runs.reduce((total, row) => total + row.eventCount, 0);
  const reports = runs.filter((row) => row.finalReport).length;
  return {
    repositories: repos.size,
    runs: runs.length,
    events,
    finalReports: reports,
  };
}

export function liveHref(row) {
  if (!row || row.empty || !row.repo || !row.family || !row.run) return "?#/live";
  const params = new URLSearchParams();
  params.set("repo", row.repo);
  params.set("family", row.family);
  params.set("run", row.run);
  return "?" + params.toString() + "#/live";
}

// ---------------------------------------------------------------------------
// Local switch-cost evidence import (client-only, read-only).
//
// The operator supplies one or more `switch-cost/live-evidence.json` artifacts
// (schema_version: 1, `invocations` array). Everything below is pure: files
// stay in browser memory, nothing is uploaded, persisted or fetched.
// ---------------------------------------------------------------------------

export const EVIDENCE_SCHEMA_VERSION = 1;
export const UNKNOWN_MODEL = "Unknown";
export const MODEL_GROUPINGS = ["resolved", "requested"];

const MODEL_GROUPING_LABELS = {
  resolved: "Resolved / observed model",
  requested: "Requested model",
};

export function modelGroupingLabel(grouping) {
  return MODEL_GROUPING_LABELS[grouping] || MODEL_GROUPING_LABELS.resolved;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function textOrNull(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

// Measured token mass: input_tokens + output_tokens, only when both are
// nonnegative safe integers and the sum is still safe. cached_input_tokens is
// already part of input_tokens and is never added again.
export function measuredTokenMass(record) {
  if (!isPlainObject(record)) return null;
  const input = record.input_tokens;
  const output = record.output_tokens;
  if (!Number.isSafeInteger(input) || input < 0) return null;
  if (!Number.isSafeInteger(output) || output < 0) return null;
  const sum = input + output;
  return Number.isSafeInteger(sum) ? sum : null;
}

// Exact nonnegative integer totals. Individual records are safe integers, but
// their sum can exceed Number.MAX_SAFE_INTEGER, so totals are kept as BigInt
// and only converted to a Number when that conversion is lossless.
export function exactTotal(values) {
  let total = 0n;
  for (const value of Array.isArray(values) ? values : []) {
    if (!Number.isSafeInteger(value) || value < 0) continue;
    total += BigInt(value);
  }
  return total;
}

export function exactToNumber(total) {
  if (typeof total !== "bigint" || total < 0n) return null;
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(total);
}

function identityKey(record) {
  const run = textOrNull(record.optimization_run_id);
  const invocation = textOrNull(record.invocation_id);
  if (!run || !invocation) return null;
  return run + "\u0000" + invocation;
}

// Every field that can distinguish two rows for the same invocation. Raw
// counters are compared verbatim so fractional, negative or unsafe values are
// still detected as conflicts even though they never qualify for token mass.
const CONFLICT_FIELDS = [
  "role",
  "backend",
  "provider",
  "requested_model",
  "resolved_model",
  "input_tokens",
  "cached_input_tokens",
  "output_tokens",
];

function fieldValue(record, field) {
  const value = record[field];
  if (value === undefined) return null;
  if (typeof value === "number" && !Number.isFinite(value)) return String(value);
  return value;
}

function comparableRow(record) {
  return JSON.stringify(CONFLICT_FIELDS.map((field) => fieldValue(record, field)));
}

function describeConflict(existing, incoming) {
  const run = textOrNull(incoming.optimization_run_id) || "?";
  const invocation = textOrNull(incoming.invocation_id) || "?";
  const fields = [];
  for (const field of CONFLICT_FIELDS) {
    const before = fieldValue(existing, field);
    const after = fieldValue(incoming, field);
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      fields.push(field + ": " + JSON.stringify(before) + " vs " + JSON.stringify(after));
    }
  }
  return (
    "Conflicting duplicate invocation " +
    run +
    "/" +
    invocation +
    " (" +
    (fields.length ? fields.join("; ") : "differing measurement fields") +
    ")"
  );
}

// Parse one artifact text. Returns { ok, records, errors }. An artifact with any
// error is rejected as a whole: its records are never returned for charting.
export function parseEvidenceArtifact(text, label) {
  const name = label || "artifact";
  const errors = [];
  let document;
  try {
    document = JSON.parse(String(text == null ? "" : text));
  } catch (cause) {
    return { ok: false, records: [], errors: [name + ": not valid JSON (" + cause.message + ")"] };
  }
  if (!isPlainObject(document)) {
    return { ok: false, records: [], errors: [name + ": expected a JSON object"] };
  }
  if (document.schema_version !== EVIDENCE_SCHEMA_VERSION) {
    errors.push(
      name +
        ": unsupported schema_version " +
        JSON.stringify(document.schema_version) +
        " (expected " +
        EVIDENCE_SCHEMA_VERSION +
        ")",
    );
  }
  if (!Array.isArray(document.invocations)) {
    errors.push(name + ": missing an invocations array");
    return { ok: false, records: [], errors };
  }
  if (document.invocations.length === 0) {
    errors.push(name + ": invocations array is empty; nothing to chart");
  }
  const records = [];
  document.invocations.forEach((entry, index) => {
    if (!isPlainObject(entry)) {
      errors.push(name + ": invocation #" + index + " is not an object");
      return;
    }
    if (!textOrNull(entry.optimization_run_id) || !textOrNull(entry.invocation_id)) {
      errors.push(
        name +
          ": invocation #" +
          index +
          " is missing optimization_run_id or invocation_id",
      );
      return;
    }
    records.push(entry);
  });
  if (errors.length > 0) return { ok: false, records: [], errors };
  return { ok: true, records, errors };
}

// Merge parsed artifacts, deduplicating by optimization_run_id + invocation_id.
// Identical duplicates collapse; conflicting rows are rejected and reported.
// Artifacts that failed to parse contribute no records at all.
export function mergeEvidenceArtifacts(artifacts) {
  const list = Array.isArray(artifacts) ? artifacts : [];
  const errors = [];
  const byKey = new Map();
  const records = [];
  let duplicates = 0;
  let conflicts = 0;
  let rejectedArtifacts = 0;
  for (const artifact of list) {
    const parsed = isPlainObject(artifact) && Array.isArray(artifact.records)
      ? artifact
      : parseEvidenceArtifact(artifact && artifact.text, artifact && artifact.label);
    const artifactErrors = Array.isArray(parsed.errors) ? parsed.errors : [];
    for (const message of artifactErrors) errors.push(message);
    if (parsed.ok === false || artifactErrors.length > 0) {
      rejectedArtifacts += 1;
      continue;
    }
    for (const record of parsed.records || []) {
      const key = identityKey(record);
      if (!key) continue;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, record);
        records.push(record);
        continue;
      }
      if (comparableRow(existing) === comparableRow(record)) {
        duplicates += 1;
        continue;
      }
      conflicts += 1;
      errors.push(describeConflict(existing, record));
    }
  }
  return {
    ok: errors.length === 0,
    records,
    errors,
    duplicates,
    conflicts,
    rejectedArtifacts,
    artifacts: list.length,
  };
}

function groupLabel(record, grouping) {
  const field = grouping === "requested" ? "requested_model" : "resolved_model";
  return textOrNull(record[field]) || UNKNOWN_MODEL;
}

// Percentages stay defined even when the aggregate exceeds Number's safe
// integer range: each record is individually safe, so the ratio is computed
// from finite doubles rather than requiring a safe-integer total.
function percentOf(part, whole) {
  if (typeof whole !== "number" || !Number.isFinite(whole) || whole <= 0) return null;
  if (typeof part !== "number" || !Number.isFinite(part) || part < 0) return null;
  const share = (part / whole) * 100;
  return Number.isFinite(share) ? share : null;
}

// Aggregate records into chart rows for one model grouping. Token totals are
// accumulated exactly; a group with no measured usage keeps null token values
// instead of a fabricated zero.
export function evidenceGroups(records, grouping) {
  const mode = MODEL_GROUPINGS.includes(grouping) ? grouping : "resolved";
  const list = Array.isArray(records) ? records : [];
  const buckets = new Map();
  let measuredRecords = 0;
  const masses = [];
  for (const record of list) {
    const label = groupLabel(record, mode);
    let bucket = buckets.get(label);
    if (!bucket) {
      bucket = { label, invocations: 0, measuredInvocations: 0, masses: [] };
      buckets.set(label, bucket);
    }
    bucket.invocations += 1;
    const mass = measuredTokenMass(record);
    if (mass == null) continue;
    bucket.measuredInvocations += 1;
    bucket.masses.push(mass);
    masses.push(mass);
    measuredRecords += 1;
  }
  const measuredExact = exactTotal(masses);
  const measuredTokens = exactToNumber(measuredExact);
  const rows = [...buckets.values()].map((bucket) => {
    const exact = exactTotal(bucket.masses);
    // No measured usage in this group means no token value at all; a measured
    // zero is a real zero and stays 0.
    const measured = bucket.measuredInvocations > 0;
    const tokens = measured ? exactToNumber(exact) : null;
    return {
      label: bucket.label,
      invocations: bucket.invocations,
      invocationShare: percentOf(bucket.invocations, list.length),
      measuredInvocations: bucket.measuredInvocations,
      tokens,
      tokensExact: measured ? exact.toString() : null,
      tokenShare: tokens == null ? null : percentOf(tokens, measuredTokens),
    };
  });
  rows.sort((left, right) => {
    if (right.invocations !== left.invocations) return right.invocations - left.invocations;
    return left.label.localeCompare(right.label);
  });
  return {
    grouping: mode,
    groupingLabel: modelGroupingLabel(mode),
    rows,
    totalInvocations: list.length,
    measuredInvocations: measuredRecords,
    unknownUsageInvocations: list.length - measuredRecords,
    measuredTokens,
    measuredTokensExact: measuredExact.toString(),
    tokenCoverage: percentOf(measuredRecords, list.length),
  };
}

export function evidenceSummary(records) {
  const list = Array.isArray(records) ? records : [];
  const roles = new Set();
  const runs = new Set();
  const masses = [];
  for (const record of list) {
    roles.add(textOrNull(record.role) || "Unknown");
    runs.add(textOrNull(record.optimization_run_id) || "Unknown");
    const mass = measuredTokenMass(record);
    if (mass == null) continue;
    masses.push(mass);
  }
  const measured = masses.length;
  const measuredExact = exactTotal(masses);
  return {
    invocations: list.length,
    runs: runs.size,
    roles: [...roles].sort(),
    measuredInvocations: measured,
    unknownUsageInvocations: list.length - measured,
    measuredTokens: exactToNumber(measuredExact),
    measuredTokensExact: measuredExact.toString(),
    tokenCoverage: percentOf(measured, list.length),
  };
}

export function formatPercent(value) {
  if (value == null || !Number.isFinite(value)) return "—";
  return value.toFixed(1) + "%";
}

// Exact integer formatting: safe integers print directly, larger exact totals
// print their full decimal digits instead of an em dash.
export function formatCount(value) {
  if (typeof value === "bigint") return value < 0n ? "—" : value.toString();
  if (Number.isSafeInteger(value)) return String(value);
  return "—";
}

export function formatExactCount(value) {
  if (typeof value === "bigint") return value < 0n ? "—" : value.toString();
  if (typeof value === "string" && /^\d+$/.test(value)) return value;
  if (Number.isSafeInteger(value)) return String(value);
  return "—";
}

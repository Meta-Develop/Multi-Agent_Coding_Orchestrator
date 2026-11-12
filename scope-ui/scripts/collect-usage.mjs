import { lstatSync, readdirSync, readFileSync, writeFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const USAGE =
  "usage: node scope-ui/scripts/collect-usage.mjs [--external-manifest FILE] [--out FILE] [--svg FILE] [--summary] ROOT...";

const SKIP_DIRS = new Set([".git", "node_modules"]);

const COMPARE_FIELDS = [
  "role",
  "backend",
  "provider",
  "requested_model",
  "resolved_model",
  "input_tokens",
  "cached_input_tokens",
  "output_tokens",
  "finished_at",
];

function norm(value) {
  return value === undefined ? null : value;
}

function canonical(value) {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
}

function same(a, b) {
  return canonical(a) === canonical(b);
}

function isArtifactRel(rel, rootName) {
  if (rel === "switch-cost" || rel.endsWith("/switch-cost")) return true;
  return rel === "" && rootName === "switch-cost";
}

function normalizeRoot(root) {
  let normalized = root;
  for (;;) {
    const stripped = normalized.replace(/\/+$/, "");
    if (stripped === "") {
      return "/";
    }
    if (stripped !== normalized) {
      normalized = stripped;
      continue;
    }
    if (normalized.length > 1 && normalized.endsWith("/.")) {
      normalized = normalized.slice(0, -2);
      continue;
    }
    return normalized;
  }
}

function resolveRoot(rootInput) {
  if (rootInput === "") return { ok: false, code: "empty" };
  let cur = rootInput.startsWith("/") ? "/" : process.cwd();
  for (const comp of rootInput.split("/")) {
    if (comp === "" || comp === ".") continue;
    if (comp === "..") {
      if (cur !== "/") cur = dirname(cur);
      continue;
    }
    if (SKIP_DIRS.has(comp)) return { ok: false, code: "skipdir" };
    const next = join(cur, comp);
    let stat;
    try {
      stat = lstatSync(next);
    } catch (err) {
      return { ok: false, code: "unreadable", message: err.message };
    }
    if (stat.isSymbolicLink()) return { ok: false, code: "symlink" };
    if (!stat.isDirectory()) return { ok: false, code: "notdir" };
    cur = next;
  }
  return { ok: true, dir: cur, name: cur === "/" ? "/" : basename(cur) };
}

export function scanRoot(rootInput) {
  const files = [];
  const errors = [];
  const resolved = resolveRoot(rootInput);
  if (!resolved.ok) {
    if (resolved.code === "empty") {
      errors.push({ path: rootInput, reason: "empty root" });
    } else if (resolved.code === "notdir") {
      errors.push({ path: rootInput, reason: "not a directory" });
    } else if (resolved.code === "unreadable") {
      errors.push({ path: rootInput, reason: `unreadable directory: ${resolved.message}` });
    }
    return { files, errors };
  }
  if (SKIP_DIRS.has(resolved.name)) return { files, errors };
  const stack = [{ dir: resolved.dir, rel: "", display: normalizeRoot(rootInput) }];
  while (stack.length > 0) {
    const frame = stack.pop();
    let entries;
    try {
      entries = readdirSync(frame.dir, { withFileTypes: true });
    } catch (err) {
      errors.push({ path: frame.display, reason: `unreadable directory: ${err.message}` });
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const childRel = frame.rel === "" ? entry.name : frame.rel + "/" + entry.name;
      const childDisplay = join(frame.display, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push({ dir: join(frame.dir, entry.name), rel: childRel, display: childDisplay });
      } else if (
        entry.isFile() &&
        entry.name === "live-evidence.json" &&
        isArtifactRel(frame.rel, resolved.name)
      ) {
        files.push(childDisplay);
      }
    }
  }
  files.sort();
  return { files, errors };
}

export function parseArtifact(path, text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    return { invalid: true, reason: `invalid JSON: ${err.message}` };
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return { invalid: true, reason: "artifact is not a JSON object" };
  }
  if (data.schema_version !== 1) {
    return { invalid: true, reason: "schema_version is not 1" };
  }
  if (!Array.isArray(data.invocations)) {
    return { invalid: true, reason: "invocations is not an array" };
  }
  const invocations = [];
  for (let i = 0; i < data.invocations.length; i++) {
    const entry = data.invocations[i];
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      return { invalid: true, reason: `invocations[${i}] is not an object` };
    }
    if (typeof entry.optimization_run_id !== "string" || entry.optimization_run_id === "") {
      return {
        invalid: true,
        reason: `invocations[${i}].optimization_run_id is not a non-empty string`,
      };
    }
    if (typeof entry.invocation_id !== "string" || entry.invocation_id === "") {
      return {
        invalid: true,
        reason: `invocations[${i}].invocation_id is not a non-empty string`,
      };
    }
    invocations.push(entry);
  }
  return { invalid: false, invocations };
}

export function mergeInvocations(records) {
  const groups = new Map();
  for (const record of records) {
    for (const invocation of record.invocations) {
      const key = JSON.stringify([
        invocation.optimization_run_id,
        invocation.invocation_id,
        norm(invocation.started_at),
      ]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push({ path: record.path, invocation });
    }
  }
  const invocations = [];
  const conflicts = [];
  let identicalDuplicates = 0;
  for (const versions of groups.values()) {
    const first = versions[0];
    const differing = new Set();
    for (let i = 1; i < versions.length; i++) {
      for (const field of COMPARE_FIELDS) {
        if (!same(norm(first.invocation[field]), norm(versions[i].invocation[field]))) {
          differing.add(field);
        }
      }
    }
    if (differing.size === 0) {
      invocations.push(first.invocation);
      identicalDuplicates += versions.length - 1;
    } else {
      conflicts.push({
        optimization_run_id: first.invocation.optimization_run_id,
        invocation_id: first.invocation.invocation_id,
        started_at: norm(first.invocation.started_at),
        fields: [...differing].sort(),
        paths: versions.map((version) => version.path),
      });
    }
  }
  return { invocations, identicalDuplicates, conflicts };
}

export function sortInvocations(invocations) {
  return invocations.slice().sort((a, b) => {
    if (a.optimization_run_id !== b.optimization_run_id) {
      return a.optimization_run_id < b.optimization_run_id ? -1 : 1;
    }
    if (a.invocation_id !== b.invocation_id) {
      return a.invocation_id < b.invocation_id ? -1 : 1;
    }
    const sa = norm(a.started_at);
    const sb = norm(b.started_at);
    if (sa === sb) return 0;
    if (sa === null) return -1;
    if (sb === null) return 1;
    return sa < sb ? -1 : 1;
  });
}

const OUTCOME_FIELDS = ["success", "accepted", "publishable", "status"];

export function collectRunOutcomes(files, errors) {
  const groups = new Map();
  for (const file of files) {
    const path = join(dirname(dirname(resolve(file))), "reports", "supervisor-final.json");
    let stat;
    try {
      stat = lstatSync(path);
    } catch (err) {
      if (err && err.code === "ENOENT") continue;
      errors.push({ path, reason: `unreadable file: ${err.message}` });
      continue;
    }
    if (!stat.isFile()) continue;
    let text;
    try {
      text = readFileSync(path, "utf8");
    } catch (err) {
      errors.push({ path, reason: `unreadable file: ${err.message}` });
      continue;
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      errors.push({ path, reason: `invalid JSON: ${err.message}` });
      continue;
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      errors.push({ path, reason: "supervisor final is not a JSON object" });
      continue;
    }
    if (typeof data.run_id !== "string" || data.run_id === "") {
      errors.push({ path, reason: "supervisor final has no non-empty string run_id" });
      continue;
    }
    const outcome = {
      run_id: data.run_id,
      success: typeof data.success === "boolean" ? data.success : null,
      accepted: typeof data.accepted === "boolean" ? data.accepted : null,
      publishable: typeof data.publishable === "boolean" ? data.publishable : null,
      status: typeof data.status === "string" ? data.status : null,
      path,
    };
    if (!groups.has(outcome.run_id)) groups.set(outcome.run_id, []);
    groups.get(outcome.run_id).push(outcome);
  }
  const run_outcomes = [];
  const run_outcome_conflicts = [];
  for (const [runId, versions] of groups) {
    const first = versions[0];
    const differing = new Set();
    for (let i = 1; i < versions.length; i++) {
      for (const field of OUTCOME_FIELDS) {
        if (!same(norm(first[field]), norm(versions[i][field]))) {
          differing.add(field);
        }
      }
    }
    if (differing.size === 0) {
      run_outcomes.push({
        run_id: runId,
        success: first.success,
        accepted: first.accepted,
        publishable: first.publishable,
        status: first.status,
        path: first.path,
      });
    } else {
      run_outcome_conflicts.push({
        run_id: runId,
        fields: [...differing].sort(),
        paths: versions.map((version) => version.path),
      });
    }
  }
  const byId = (a, b) => (a.run_id < b.run_id ? -1 : a.run_id > b.run_id ? 1 : 0);
  run_outcomes.sort(byId);
  run_outcome_conflicts.sort(byId);
  return { run_outcomes, run_outcome_conflicts };
}

const ATTEMPT_COMPARE_FIELDS = [
  "run_id",
  "assignment_id",
  "attempt",
  "role",
  "requested_runtime",
  "requested_model",
  "requested_effort",
  "parent_result",
  "parent_cause",
];

function attemptString(value) {
  return typeof value === "string" ? value : null;
}

export function collectAttemptOutcomes(files, errors) {
  const runDirs = new Set();
  for (const file of files) {
    runDirs.add(dirname(dirname(resolve(file))));
  }
  const groups = new Map();
  for (const runDir of runDirs) {
    const dir = join(runDir, "selection-attempts");
    let names;
    try {
      names = readdirSync(dir);
    } catch (err) {
      if (err && err.code === "ENOENT") continue;
      errors.push({ path: dir, reason: `unreadable file: ${err.message}` });
      continue;
    }
    for (const name of [...names].sort()) {
      if (!name.endsWith(".json")) continue;
      const path = join(dir, name);
      let stat;
      try {
        stat = lstatSync(path);
      } catch (err) {
        errors.push({ path, reason: `unreadable file: ${err.message}` });
        continue;
      }
      if (!stat.isFile()) continue;
      let text;
      try {
        text = readFileSync(path, "utf8");
      } catch (err) {
        errors.push({ path, reason: `unreadable file: ${err.message}` });
        continue;
      }
      let data;
      try {
        data = JSON.parse(text);
      } catch (err) {
        errors.push({ path, reason: `invalid JSON: ${err.message}` });
        continue;
      }
      if (data === null || typeof data !== "object" || Array.isArray(data)) {
        errors.push({ path, reason: "attempt outcome is not a JSON object" });
        continue;
      }
      if (
        typeof data.run_id !== "string" ||
        data.run_id === "" ||
        typeof data.assignment_id !== "string" ||
        data.assignment_id === "" ||
        !Number.isSafeInteger(data.attempt) ||
        data.attempt < 1
      ) {
        errors.push({ path, reason: "attempt outcome has no valid run_id, assignment_id or attempt" });
        continue;
      }
      const selection =
        data.selection !== null && typeof data.selection === "object" && !Array.isArray(data.selection)
          ? data.selection
          : null;
      const outcome = {
        run_id: data.run_id,
        assignment_id: data.assignment_id,
        attempt: data.attempt,
        role: selection !== null && typeof selection.role === "string" ? selection.role : null,
        requested_runtime: attemptString(data.requested_runtime),
        requested_model: attemptString(data.requested_model),
        requested_effort: attemptString(data.requested_effort),
        parent_result: attemptString(data.parent_result),
        parent_cause: attemptString(data.parent_cause),
        path,
      };
      if (!groups.has(outcome.run_id)) groups.set(outcome.run_id, new Map());
      const byAssignment = groups.get(outcome.run_id);
      if (!byAssignment.has(outcome.assignment_id)) byAssignment.set(outcome.assignment_id, new Map());
      const byAttempt = byAssignment.get(outcome.assignment_id);
      if (!byAttempt.has(outcome.attempt)) byAttempt.set(outcome.attempt, []);
      byAttempt.get(outcome.attempt).push(outcome);
    }
  }
  const attempt_outcomes = [];
  const attempt_outcome_conflicts = [];
  for (const byAssignment of groups.values()) {
    for (const byAttempt of byAssignment.values()) {
      for (const versions of byAttempt.values()) {
    const first = versions[0];
    const identical = versions.every((version) =>
      ATTEMPT_COMPARE_FIELDS.every((field) => first[field] === version[field])
    );
    if (identical) {
      attempt_outcomes.push(first);
    } else {
      attempt_outcome_conflicts.push({
        run_id: first.run_id,
        assignment_id: first.assignment_id,
        attempt: first.attempt,
        paths: versions.map((version) => version.path),
      });
    }
      }
    }
  }
  const byKey = (a, b) =>
    a.run_id < b.run_id ? -1 : a.run_id > b.run_id ? 1 : a.assignment_id < b.assignment_id ? -1 : a.assignment_id > b.assignment_id ? 1 : a.attempt - b.attempt;
  attempt_outcomes.sort(byKey);
  attempt_outcome_conflicts.sort(byKey);
  return { attempt_outcomes, attempt_outcome_conflicts };
}

function safeCounter(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function parseExternalTranscript(manifestEntry, text) {
  const invocations = [];
  const optimizationRunId =
    typeof manifestEntry.optimization_run_id === "string" && manifestEntry.optimization_run_id !== ""
      ? manifestEntry.optimization_run_id
      : "external:" + manifestEntry.label;
  let turns = 0;
  let malformedLines = 0;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      malformedLines += 1;
      continue;
    }
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
      malformedLines += 1;
      continue;
    }
    if (obj.type !== "turn.completed") continue;
    if (obj.usage === null || typeof obj.usage !== "object" || Array.isArray(obj.usage)) {
      malformedLines += 1;
      continue;
    }
    turns += 1;
    invocations.push({
      optimization_run_id: optimizationRunId,
      invocation_id: manifestEntry.label + ":turn-" + turns,
      started_at: null,
      role: manifestEntry.role,
      requested_model: manifestEntry.requested_model,
      requested_effort: manifestEntry.requested_effort,
      resolved_model: null,
      backend: "codex_cli",
      provider: "openai",
      record_source: "codex_exec_jsonl",
      input_tokens: safeCounter(obj.usage.input_tokens),
      cached_input_tokens: safeCounter(obj.usage.cached_input_tokens),
      output_tokens: safeCounter(obj.usage.output_tokens),
    });
  }
  return { invocations, turns, malformedLines };
}

const ROLE_CATEGORIES = [
  { name: "Manager", roles: new Set(["manager", "childorchestrator", "orchestrator", "supervisor"]) },
  { name: "Review", roles: new Set(["auditor", "reviewer", "review"]) },
  { name: "Worker", roles: new Set(["worker"]) },
];

export function roleCategory(role) {
  const value = typeof role === "string" ? role.toLowerCase() : "";
  for (const category of ROLE_CATEGORIES) {
    if (category.roles.has(value)) return category.name;
  }
  return "Other";
}

function pct(numerator, denominator) {
  return denominator > 0 ? ((100 * numerator) / denominator).toFixed(1) + "%" : "-";
}

function bothCountersKnown(invocation) {
  return (
    safeCounter(invocation.input_tokens) !== null &&
    safeCounter(invocation.output_tokens) !== null
  );
}

function cachedCountersKnown(invocation) {
  const input = safeCounter(invocation.input_tokens);
  const cached = safeCounter(invocation.cached_input_tokens);
  return input !== null && cached !== null && cached <= input;
}

function cachedGroupRows(invocations, keyOf) {
  const groups = new Map();
  for (const invocation of invocations) {
    const key = keyOf(invocation);
    if (!groups.has(key)) groups.set(key, { count: 0, known: 0, input: 0, cached: 0 });
    const group = groups.get(key);
    group.count += 1;
    if (cachedCountersKnown(invocation)) {
      group.known += 1;
      group.input += invocation.input_tokens;
      group.cached += invocation.cached_input_tokens;
    }
  }
  const names = [...groups.keys()].sort();
  if (names.length === 0) return ["(none)"];
  return names.map((name) => {
    const group = groups.get(name);
    const measured = group.known > 0;
    const inputText = measured ? String(group.input).padStart(10) : "-".padStart(10);
    const cachedText = measured ? String(group.cached).padStart(10) : "-".padStart(10);
    const shareText =
      measured && group.input > 0 ? pct(group.cached, group.input).padStart(7) : "-".padStart(7);
    return (
      name.padEnd(24) +
      " known " +
      group.known +
      "/" +
      group.count +
      "  input " +
      inputText +
      "  cached " +
      cachedText +
      " " +
      shareText
    );
  });
}

function groupRows(invocations, keyOf, totalInvocations, knownSubtotal) {
  const groups = new Map();
  for (const invocation of invocations) {
    const key = keyOf(invocation);
    if (!groups.has(key)) groups.set(key, { count: 0, measured: 0, tokens: 0 });
    const group = groups.get(key);
    group.count += 1;
    if (bothCountersKnown(invocation)) {
      group.measured += 1;
      group.tokens += invocation.input_tokens + invocation.output_tokens;
    }
  }
  const names = [...groups.keys()].sort();
  if (names.length === 0) return ["(none)"];
  return names.map((name) => {
    const group = groups.get(name);
    const tokensText =
      group.measured > 0 ? String(group.tokens).padStart(10) : "-".padStart(10);
    const shareText =
      group.measured > 0 ? pct(group.tokens, knownSubtotal).padStart(7) : "-".padStart(7);
    return (
      name.padEnd(24) +
      " count " +
      String(group.count).padStart(6) +
      " " +
      pct(group.count, totalInvocations).padStart(7) +
      "  measured " +
      group.measured +
      "/" +
      group.count +
      "  tokens " +
      tokensText +
      " " +
      shareText
    );
  });
}

function workerModelRows(invocations, runOutcomes) {
  const runs = runOutcomes.filter((outcome) => outcome.accepted === true || outcome.accepted === false);
  const groups = new Map();
  for (const outcome of runs) {
    const runInvocations = invocations.filter((invocation) => invocation.optimization_run_id === outcome.run_id);
    const workerModels = new Set();
    for (const invocation of runInvocations) {
      if (roleCategory(invocation.role) !== "Worker") continue;
      const model = invocation.requested_model;
      workerModels.add(typeof model === "string" && model !== "" ? model : "(missing)");
    }
    const key = workerModels.size === 0 ? "(no Worker)" : [...workerModels].sort().join("+");
    if (!groups.has(key)) groups.set(key, { runs: 0, accepted: 0, notAccepted: 0, tokens: 0, measured: 0, incomplete: 0 });
    const group = groups.get(key);
    group.runs += 1;
    if (outcome.accepted === true) group.accepted += 1;
    else group.notAccepted += 1;
    if (runInvocations.length === 0 || runInvocations.some((invocation) => !bothCountersKnown(invocation))) {
      group.incomplete += 1;
    }
    for (const invocation of runInvocations) {
      if (bothCountersKnown(invocation)) {
        group.measured += 1;
        group.tokens += invocation.input_tokens + invocation.output_tokens;
      }
    }
  }
  const keys = [...groups.keys()].sort();
  if (keys.length === 0) return ["(none)"];
  return keys.map((key) => {
    const group = groups.get(key);
    const tokensText = group.measured > 0 ? String(group.tokens) : "-";
    const perText =
      group.accepted > 0 && tokensText !== "-" ? String(Math.round(group.tokens / group.accepted)) : "-";
    return (
      key.padEnd(24) +
      " runs " +
      String(group.runs).padStart(4) +
      " accepted " +
      String(group.accepted).padStart(4) +
      " not accepted " +
      String(group.notAccepted).padStart(4) +
      " tokens " +
      tokensText.padStart(10) +
      " per accepted run " +
      perText.padStart(10) +
      " incomplete " +
      group.incomplete
    );
  });
}

function workerAttemptRows(attemptOutcomes) {
  const attempts = attemptOutcomes.filter((attempt) => roleCategory(attempt.role) === "Worker");
  const groups = new Map();
  for (const attempt of attempts) {
    const model = attempt.requested_model;
    const name = typeof model === "string" && model !== "" ? model : "(missing)";
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(attempt);
  }
  const names = [...groups.keys()].sort();
  if (names.length === 0) return ["(none)"];
  return names.map((name) => {
    const group = groups.get(name);
    const pairs = new Map();
    for (const attempt of group) {
      if (!pairs.has(attempt.run_id)) pairs.set(attempt.run_id, new Map());
      const byAssignment = pairs.get(attempt.run_id);
      if (!byAssignment.has(attempt.assignment_id)) byAssignment.set(attempt.assignment_id, new Map());
      byAssignment.get(attempt.assignment_id).set(attempt.attempt, attempt.parent_result);
    }
    let accepted = 0;
    let rejected = 0;
    let unknown = 0;
    for (const attempt of group) {
      if (attempt.parent_result === "accepted") accepted += 1;
      else if (attempt.parent_result === "rejected") rejected += 1;
      else unknown += 1;
    }
    let assignments = 0;
    let firstAccepted = 0;
    const lowestAccepted = [];
    for (const byAssignment of pairs.values()) {
      for (const pair of byAssignment.values()) {
        assignments += 1;
        if (pair.get(1) === "accepted") firstAccepted += 1;
        const acceptedAttempts = [...pair.entries()].filter((entry) => entry[1] === "accepted").map((entry) => entry[0]);
        if (acceptedAttempts.length > 0) lowestAccepted.push(Math.min(...acceptedAttempts));
      }
    }
    const meanText =
      lowestAccepted.length > 0
        ? (lowestAccepted.reduce((sum, value) => sum + value, 0) / lowestAccepted.length).toFixed(2)
        : "-";
    return (
      name.padEnd(24) +
      " attempts " + String(group.length).padStart(4) +
      " accepted " + String(accepted).padStart(4) +
      " rejected " + String(rejected).padStart(4) +
      " unknown " + String(unknown).padStart(4) +
      " assignments " + String(assignments).padStart(4) +
      " first-attempt accepted " + String(firstAccepted).padStart(4) +
      " attempts to accept " + meanText
    );
  });
}

function workerAttemptInvocationIndex(invocations) {
  const index = new Map();
  for (const invocation of invocations) {
    if (!bothCountersKnown(invocation)) continue;
    if (!index.has(invocation.optimization_run_id)) index.set(invocation.optimization_run_id, new Map());
    const byInvocationId = index.get(invocation.optimization_run_id);
    if (!byInvocationId.has(invocation.invocation_id)) {
      byInvocationId.set(invocation.invocation_id, invocation);
    }
  }
  return index;
}

function workerAttemptInvocationId(attempt) {
  return (
    attempt.run_id + ":" + attempt.assignment_id + ":" + String(attempt.attempt) + ":" + attempt.role
  );
}

function workerAttemptTokenRows(attemptOutcomes, invocations) {
  const attempts = attemptOutcomes.filter((attempt) => roleCategory(attempt.role) === "Worker");
  const index = workerAttemptInvocationIndex(invocations);
  const modelName = (attempt) => {
    const model = attempt.requested_model;
    return typeof model === "string" && model !== "" ? model : "(missing)";
  };
  const groups = new Map();
  for (const attempt of attempts) {
    const name = modelName(attempt);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(attempt);
  }
  const names = [...groups.keys()].sort();
  if (names.length === 0) return ["(none)"];
  const stats = new Map();
  for (const name of names) {
    stats.set(name, { attempts: 0, joined: 0, tokens: 0, acceptedPairs: 0, completePairs: 0, completeTokens: 0 });
  }
  const pairsByModel = new Map();
  for (const attempt of attempts) {
    const name = modelName(attempt);
    const entry = stats.get(name);
    entry.attempts += 1;
    const byInvocationId = index.get(attempt.run_id);
    const invocation =
      byInvocationId === undefined ? undefined : byInvocationId.get(workerAttemptInvocationId(attempt));
    const attemptTokens =
      invocation === undefined ? null : invocation.input_tokens + invocation.output_tokens;
    if (attemptTokens !== null) {
      entry.joined += 1;
      entry.tokens += attemptTokens;
    }
    if (!pairsByModel.has(name)) pairsByModel.set(name, new Map());
    const pairs = pairsByModel.get(name);
    if (!pairs.has(attempt.run_id)) pairs.set(attempt.run_id, new Map());
    const byAssignment = pairs.get(attempt.run_id);
    if (!byAssignment.has(attempt.assignment_id)) byAssignment.set(attempt.assignment_id, new Map());
    byAssignment.get(attempt.assignment_id).set(attempt.attempt, {
      parent_result: attempt.parent_result,
      tokens: attemptTokens,
    });
  }
  for (const [name, pairs] of pairsByModel) {
    const entry = stats.get(name);
    for (const byAssignment of pairs.values()) {
      for (const byAttempt of byAssignment.values()) {
        const acceptedAttempts = [...byAttempt.entries()]
          .filter((candidate) => candidate[1].parent_result === "accepted")
          .map((candidate) => candidate[0]);
        if (acceptedAttempts.length === 0) continue;
        const lowest = Math.min(...acceptedAttempts);
        entry.acceptedPairs += 1;
        let complete = true;
        let pairTokens = 0;
        for (let n = 1; n <= lowest; n += 1) {
          const attemptEntry = byAttempt.get(n);
          if (attemptEntry === undefined || attemptEntry.tokens === null) {
            complete = false;
            break;
          }
          pairTokens += attemptEntry.tokens;
        }
        if (complete) {
          entry.completePairs += 1;
          entry.completeTokens += pairTokens;
        }
      }
    }
  }
  return names.map((name) => {
    const entry = stats.get(name);
    const meanText =
      entry.completePairs > 0 ? String(Math.round(entry.completeTokens / entry.completePairs)) : "-";
    return (
      name.padEnd(24) +
      " joined " + (String(entry.joined) + "/" + String(entry.attempts)).padStart(9) +
      " tokens " + String(entry.tokens).padStart(12) +
      " accepted assignments " + String(entry.acceptedPairs).padStart(4) +
      " complete " + String(entry.completePairs).padStart(4) +
      " tokens per accepted assignment " + meanText
    );
  });
}
export function summarize(invocations, runOutcomes = [], attemptOutcomes = []) {
  const total = invocations.length;
  let knownSubtotal = 0;
  let coverage = 0;
  for (const invocation of invocations) {
    if (bothCountersKnown(invocation)) {
      knownSubtotal += invocation.input_tokens + invocation.output_tokens;
      coverage += 1;
    }
  }
  const lines = [];
  lines.push("Invocations: " + total);
  lines.push("Known measured input+output tokens: " + knownSubtotal);
  lines.push("Coverage (both counters known): " + coverage + "/" + total + " " + pct(coverage, total));
  lines.push("");
  lines.push("By requested model:");
  lines.push(...groupRows(invocations, (invocation) => {
    const model = invocation.requested_model;
    return typeof model === "string" && model !== "" ? model : "(missing)";
  }, total, knownSubtotal));
  lines.push("");
  lines.push("By role category:");
  lines.push(...groupRows(invocations, (invocation) => roleCategory(invocation.role), total, knownSubtotal));
  const outcomeByRun = new Map(runOutcomes.map((outcome) => [outcome.run_id, outcome]));
  lines.push("");
  lines.push("By run outcome:");
  lines.push(...groupRows(invocations, (invocation) => {
    const outcome = outcomeByRun.get(invocation.optimization_run_id);
    if (outcome === undefined) return "unknown";
    if (outcome.accepted === true) return "accepted";
    if (outcome.accepted === false) return "not accepted";
    return "unknown";
  }, total, knownSubtotal));
  const acceptedRuns = runOutcomes.filter((outcome) => outcome.accepted === true).length;
  const notAcceptedRuns = runOutcomes.filter((outcome) => outcome.accepted === false).length;
  lines.push("Runs with outcome: " + acceptedRuns + " accepted, " + notAcceptedRuns + " not accepted");
  lines.push(
    "Known tokens per accepted run: " +
      (acceptedRuns > 0 ? Math.round(knownSubtotal / acceptedRuns) : "-")
  );
  lines.push("");
  lines.push("By Worker model per run:");
  lines.push(...workerModelRows(invocations, runOutcomes));
  lines.push("");
  lines.push("Cached input (where input and cached counters are known):");
  lines.push("By role category:");
  lines.push(...cachedGroupRows(invocations, (invocation) => roleCategory(invocation.role)));
  lines.push("By requested model:");
  lines.push(...cachedGroupRows(invocations, (invocation) => {
    const model = invocation.requested_model;
    return typeof model === "string" && model !== "" ? model : "(missing)";
  }));
  if (attemptOutcomes.length > 0) {
    lines.push("");
    lines.push("By Worker model per attempt:");
    lines.push(...workerAttemptRows(attemptOutcomes));
    lines.push("");
    lines.push("Worker tokens to acceptance (attempts joined to Worker invocations):");
    lines.push(...workerAttemptTokenRows(attemptOutcomes, invocations));
  }
  return lines.join("\n") + "\n";
}

const SVG_PALETTE = [
  "#1f77b4",
  "#ff7f0e",
  "#2ca02c",
  "#d62728",
  "#9467bd",
  "#8c564b",
  "#e377c2",
  "#7f7f7f",
  "#bcbd22",
  "#17becf",
];

const SVG_BAR_WIDTH = 600;
const SVG_ROW_HEIGHT = 22;
const SVG_SECTION_GAP = 18;
const SVG_TEXT_X = 20;
const SVG_BAR_X = 240;
const SVG_STATS_X = SVG_BAR_X + SVG_BAR_WIDTH + 12;
const SVG_WIDTH = SVG_STATS_X + 760;

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD");
}

function svgText(x, y, text, extra = "") {
  return (
    '<text x="' + x + '" y="' + y + '" font-family="sans-serif"' + extra + ">" +
    escapeXml(text) +
    "</text>"
  );
}

function svgGroupStats(invocations, keyOf) {
  const groups = new Map();
  for (const invocation of invocations) {
    const key = keyOf(invocation);
    if (!groups.has(key)) groups.set(key, { count: 0, measured: 0, tokens: 0, known: 0, input: 0, cached: 0 });
    const group = groups.get(key);
    group.count += 1;
    if (bothCountersKnown(invocation)) {
      group.measured += 1;
      group.tokens += invocation.input_tokens + invocation.output_tokens;
    }
    if (cachedCountersKnown(invocation)) {
      group.known += 1;
      group.input += invocation.input_tokens;
      group.cached += invocation.cached_input_tokens;
    }
  }
  const rows = [...groups.entries()].map(([name, group]) => ({ name, ...group }));
  rows.sort((a, b) => {
    if (b.tokens !== a.tokens) return b.tokens - a.tokens;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  return rows;
}

function svgCachedText(row) {
  if (row.known > 0 && row.input > 0) {
    return " | cached " + pct(row.cached, row.input) + " of input (" + row.known + "/" + row.count + " known)";
  }
  return " | cached unknown";
}

function svgRowText(row, knownSubtotal) {
  if (row.measured === 0) return "unavailable | " + row.count + " invocations" + svgCachedText(row);
  return (
    pct(row.tokens, knownSubtotal) +
    " | " +
    row.tokens +
    " tokens | " +
    row.count +
    " invocations" +
    svgCachedText(row)
  );
}

function svgBarWidth(tokens, knownSubtotal) {
  if (knownSubtotal <= 0 || tokens <= 0) return 0;
  return (SVG_BAR_WIDTH * tokens) / knownSubtotal;
}

function svgModelKey(invocation) {
  const model = invocation.requested_model;
  return typeof model === "string" && model !== "" ? model : "(missing)";
}

export function renderSvg(invocations, runOutcomes = []) {
  const total = invocations.length;
  let knownSubtotal = 0;
  let coverage = 0;
  for (const invocation of invocations) {
    if (bothCountersKnown(invocation)) {
      knownSubtotal += invocation.input_tokens + invocation.output_tokens;
      coverage += 1;
    }
  }

  const outcomeByRun = new Map(runOutcomes.map((outcome) => [outcome.run_id, outcome]));
  const roleRows = svgGroupStats(invocations, (invocation) => roleCategory(invocation.role));
  const modelRows = svgGroupStats(invocations, svgModelKey);
  const outcomeRows = svgGroupStats(invocations, (invocation) => {
    const outcome = outcomeByRun.get(invocation.optimization_run_id);
    if (outcome === undefined) return "unknown";
    if (outcome.accepted === true) return "accepted";
    if (outcome.accepted === false) return "not accepted";
    return "unknown";
  });

  const modelColour = new Map();
  modelRows.forEach((row, index) => {
    modelColour.set(row.name, SVG_PALETTE[index % SVG_PALETTE.length]);
  });

  const pairTokens = new Map();
  for (const invocation of invocations) {
    if (!bothCountersKnown(invocation)) continue;
    const key = roleCategory(invocation.role) + "\u0000" + svgModelKey(invocation);
    pairTokens.set(key, (pairTokens.get(key) || 0) + invocation.input_tokens + invocation.output_tokens);
  }

  const parts = [];
  let y = 0;
  const sectionRows = (rows) => (rows.length === 0 ? 1 : rows.length);
  const height =
    28 +
    20 +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT + sectionRows(roleRows) * SVG_ROW_HEIGHT +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT + sectionRows(modelRows) * SVG_ROW_HEIGHT +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT + sectionRows(outcomeRows) * SVG_ROW_HEIGHT +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT + sectionRows(roleRows) * SVG_ROW_HEIGHT +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT + sectionRows(modelRows) * SVG_ROW_HEIGHT +
    SVG_SECTION_GAP + SVG_ROW_HEIGHT +
    20;

  parts.push(
    '<svg xmlns="http://www.w3.org/2000/svg" width="' + SVG_WIDTH + '" height="' + height + '" viewBox="0 0 ' + SVG_WIDTH + " " + height + '">'
  );
  parts.push('<rect x="0" y="0" width="' + SVG_WIDTH + '" height="' + height + '" fill="#ffffff"/>');
  y += 28;
  parts.push(svgText(SVG_TEXT_X, y, "MACO token usage shares", ' font-size="18" font-weight="bold"'));
  y += 20;
  parts.push(
    svgText(
      SVG_TEXT_X,
      y,
      "Invocations: " +
        total +
        " | Known measured input+output tokens: " +
        knownSubtotal +
        " | Coverage (both counters known): " +
        coverage +
        "/" +
        total,
      ' font-size="12"'
    )
  );

  const drawSection = (heading, rows, colourOf) => {
    y += SVG_SECTION_GAP + SVG_ROW_HEIGHT;
    parts.push(svgText(SVG_TEXT_X, y, heading, ' font-size="14" font-weight="bold"'));
    if (rows.length === 0) {
      y += SVG_ROW_HEIGHT;
      parts.push(svgText(SVG_TEXT_X, y, "(none)", ' font-size="12"'));
      return;
    }
    for (const row of rows) {
      y += SVG_ROW_HEIGHT;
      const width = svgBarWidth(row.tokens, knownSubtotal);
      parts.push(svgText(SVG_TEXT_X, y, row.name, ' font-size="12"'));
      parts.push(
        '<rect x="' + SVG_BAR_X + '" y="' + (y - 11) + '" width="' + width.toFixed(2) + '" height="14" fill="' +
          colourOf(row) +
          '"/>'
      );
      parts.push(svgText(SVG_STATS_X, y, svgRowText(row, knownSubtotal), ' font-size="12"'));
    }
  };

  drawSection("By role category", roleRows, () => SVG_PALETTE[0]);
  drawSection("By requested model", modelRows, (row) => modelColour.get(row.name));
  drawSection("By run outcome", outcomeRows, () => SVG_PALETTE[0]);

  y += SVG_SECTION_GAP + SVG_ROW_HEIGHT;
  parts.push(svgText(SVG_TEXT_X, y, "Role category x requested model", ' font-size="14" font-weight="bold"'));
  if (roleRows.length === 0) {
    y += SVG_ROW_HEIGHT;
    parts.push(svgText(SVG_TEXT_X, y, "(none)", ' font-size="12"'));
  }
  for (const roleRow of roleRows) {
    y += SVG_ROW_HEIGHT;
    parts.push(svgText(SVG_TEXT_X, y, roleRow.name, ' font-size="12"'));
    let x = SVG_BAR_X;
    for (const modelRow of modelRows) {
      const tokens = pairTokens.get(roleRow.name + "\u0000" + modelRow.name) || 0;
      const width = svgBarWidth(tokens, knownSubtotal);
      if (width <= 0) continue;
      parts.push(
        '<rect x="' + x.toFixed(2) + '" y="' + (y - 11) + '" width="' + width.toFixed(2) + '" height="14" fill="' +
          modelColour.get(modelRow.name) +
          '"/>'
      );
      x += width;
    }
  }

  y += SVG_SECTION_GAP + SVG_ROW_HEIGHT;
  parts.push(svgText(SVG_TEXT_X, y, "Legend: requested model", ' font-size="14" font-weight="bold"'));
  if (modelRows.length === 0) {
    y += SVG_ROW_HEIGHT;
    parts.push(svgText(SVG_TEXT_X, y, "(none)", ' font-size="12"'));
  }
  for (const modelRow of modelRows) {
    y += SVG_ROW_HEIGHT;
    parts.push(
      '<rect x="' + SVG_TEXT_X + '" y="' + (y - 11) + '" width="12" height="12" fill="' +
        modelColour.get(modelRow.name) +
        '"/>'
    );
    parts.push(svgText(SVG_TEXT_X + 20, y, modelRow.name, ' font-size="12"'));
  }

  y += SVG_SECTION_GAP + SVG_ROW_HEIGHT;
  parts.push(
    svgText(
      SVG_TEXT_X,
      y,
      "Requested model labels only; served model identity, effort and cost are not recorded. Unknown counters are excluded, not counted as zero. The cached share covers only invocations whose cached counter is known.",
      ' font-size="12"'
    )
  );
  parts.push("</svg>");
  return parts.join("\n") + "\n";
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
  let externalManifest = null;
  let out = null;
  let svg = null;
  let summary = false;
  const roots = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--external-manifest" || arg === "--out" || arg === "--svg") {
      const operand = argv[i + 1];
      if (operand === undefined || operand.startsWith("-")) {
        process.stderr.write(USAGE + "\n");
        return 2;
      }
      if (arg === "--external-manifest") externalManifest = operand;
      else if (arg === "--svg") svg = operand;
      else out = operand;
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

  const errors = [];
  const files = [];
  for (const root of roots) {
    const scanned = scanRoot(root);
    errors.push(...scanned.errors);
    files.push(...scanned.files);
  }

  const records = [];
  const invalidArtifacts = [];
  let artifactsParsed = 0;
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch (err) {
      errors.push({ path: file, reason: `unreadable file: ${err.message}` });
      continue;
    }
    const parsed = parseArtifact(file, text);
    if (parsed.invalid) {
      invalidArtifacts.push({ path: file, reason: parsed.reason });
    } else {
      artifactsParsed += 1;
      records.push({ path: file, invocations: parsed.invocations });
    }
  }

  const outcomes = collectRunOutcomes(files, errors);
  const attemptOutcomes = collectAttemptOutcomes(files, errors);

  const externalSources = [];
  if (externalManifest !== null) {
    let manifestLoaded = false;
    let manifest = null;
    try {
      manifest = JSON.parse(readFileSync(externalManifest, "utf8"));
      manifestLoaded = true;
    } catch (err) {
      errors.push({ path: externalManifest, reason: `unreadable manifest: ${err.message}` });
    }
    if (manifestLoaded && !Array.isArray(manifest)) {
      errors.push({ path: externalManifest, reason: "manifest is not a JSON array" });
      manifestLoaded = false;
    }
    if (manifestLoaded) {
      for (const entry of manifest) {
        if (
          entry === null ||
          typeof entry !== "object" ||
          typeof entry.path !== "string" ||
          typeof entry.label !== "string"
        ) {
          errors.push({ path: externalManifest, reason: "manifest entry missing path or label" });
          continue;
        }
        if (
          entry.optimization_run_id !== undefined &&
          entry.optimization_run_id !== null &&
          (typeof entry.optimization_run_id !== "string" || entry.optimization_run_id === "")
        ) {
          errors.push({
            path: externalManifest,
            reason: "manifest entry " + entry.label + " has an invalid optimization_run_id",
          });
          continue;
        }
        let text;
        try {
          text = readFileSync(entry.path, "utf8");
        } catch (err) {
          errors.push({ path: entry.path, reason: `unreadable transcript: ${err.message}` });
          externalSources.push({ label: entry.label, path: entry.path, turns: 0, malformed_lines: 0 });
          continue;
        }
        const result = parseExternalTranscript(entry, text);
        externalSources.push({
          label: entry.label,
          path: entry.path,
          turns: result.turns,
          malformed_lines: result.malformedLines,
        });
        records.push({ path: entry.path, invocations: result.invocations });
      }
    }
  }

  const merged = mergeInvocations(records);
  const invocations = sortInvocations(merged.invocations);
  const doc = {
    schema_version: 1,
    invocations,
    collection: {
      generated_at: new Date().toISOString(),
      roots,
      files_scanned: files.length,
      artifacts_parsed: artifactsParsed,
      invalid_artifacts: invalidArtifacts,
      identical_duplicates: merged.identicalDuplicates,
      conflicts: merged.conflicts,
      run_outcomes: outcomes.run_outcomes,
      run_outcome_conflicts: outcomes.run_outcome_conflicts,
      attempt_outcomes: attemptOutcomes.attempt_outcomes,
      attempt_outcome_conflicts: attemptOutcomes.attempt_outcome_conflicts,
      external_sources: externalSources,
      errors,
    },
  };

  if (summary) {
    process.stderr.write(summarize(invocations, outcomes.run_outcomes, attemptOutcomes.attempt_outcomes));
  }
  if (svg !== null) {
    try {
      writeFileSync(svg, renderSvg(invocations, outcomes.run_outcomes));
    } catch (err) {
      process.stderr.write("error: cannot write " + svg + ": " + err.message + "\n");
      return 1;
    }
  }
  const json = JSON.stringify(doc, null, 2) + "\n";
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

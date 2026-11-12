import { lstatSync, readdirSync, readFileSync, writeFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const USAGE =
  "usage: node scope-ui/scripts/collect-usage.mjs [--external-manifest FILE] [--out FILE] [--summary] ROOT...";

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

function safeCounter(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function parseExternalTranscript(manifestEntry, text) {
  const invocations = [];
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
      optimization_run_id: "external:" + manifestEntry.label,
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

export function summarize(invocations, runOutcomes = []) {
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
  let externalManifest = null;
  let out = null;
  let summary = false;
  const roots = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--external-manifest" || arg === "--out") {
      const operand = argv[i + 1];
      if (operand === undefined || operand.startsWith("-")) {
        process.stderr.write(USAGE + "\n");
        return 2;
      }
      if (arg === "--external-manifest") externalManifest = operand;
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
      external_sources: externalSources,
      errors,
    },
  };

  if (summary) {
    process.stderr.write(summarize(invocations, outcomes.run_outcomes));
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

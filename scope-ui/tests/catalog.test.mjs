import assert from "node:assert/strict";
import { test } from "node:test";
import {
  catalogRows,
  catalogSummary,
  liveHref,
  EVIDENCE_SCHEMA_VERSION,
  UNKNOWN_MODEL,
  modelGroupingLabel,
  measuredTokenMass,
  parseEvidenceArtifact,
  mergeEvidenceArtifacts,
  runOutcomeIndex,
  evidenceGroups,
  evidenceSummary,
  exactTotal,
  exactToNumber,
  formatPercent,
  formatCount,
  formatExactCount,
} from "../src/catalog.mjs";
import { parseProjectsPayload, streamUrl } from "../src/api.mjs";
import { hrefFor, parseHash } from "../src/router.mjs";

const projects = [
  {
    id: "beta",
    path: "/tmp/beta",
    runs: [
      {
        family: "o2",
        run: "run-2",
        event_count: 3,
        final_report_exists: false,
        modified_unix_seconds: 20,
      },
    ],
  },
  {
    id: "alpha",
    path: "/tmp/alpha",
    runs: [
      {
        family: "autopilot",
        run: "run-1",
        event_count: 9,
        final_report_exists: true,
        modified_unix_seconds: 10,
      },
    ],
  },
  { id: "empty", path: "/tmp/empty", runs: [] },
];

test("catalogRows flattens projects and sorts newest first", () => {
  const rows = catalogRows(projects);
  assert.equal(rows[0].repo, "beta");
  assert.equal(rows[1].repo, "alpha");
  assert.equal(rows[1].finalReport, true);
  assert.equal(rows[2].empty, true);
});

test("catalogSummary counts repositories, runs, and reports", () => {
  const summary = catalogSummary(catalogRows(projects));
  assert.deepEqual(summary, {
    repositories: 3,
    runs: 2,
    events: 12,
    finalReports: 1,
  });
});

test("liveHref uses search params the live observer already understands", () => {
  assert.equal(
    liveHref({ repo: "alpha", family: "o2", run: "run-1" }),
    "?repo=alpha&family=o2&run=run-1#/live",
  );
});

test("parseProjectsPayload ignores a malformed snapshot", () => {
  assert.deepEqual(parseProjectsPayload({ projects: [{ id: "a" }] }).length, 1);
  assert.deepEqual(parseProjectsPayload(null), []);
  assert.deepEqual(parseProjectsPayload({}), []);
});

test("streamUrl keeps the live-first query contract", () => {
  assert.equal(streamUrl({}, "live"), "/api/stream");
  assert.equal(
    streamUrl({ repo: "alpha", family: "o2", run: "run-1" }, "archive"),
    "/api/stream?repo=alpha&family=o2&run=run-1&since=0",
  );
});

test("hash router does not collide with graph view query values", () => {
  assert.equal(parseHash("#/objective").page, "objective");
  assert.equal(parseHash("#/unknown").page, "live");
  assert.equal(hrefFor("catalog"), "#/catalog");
});

// --- Local switch-cost evidence import -------------------------------------

function invocation(overrides) {
  return Object.assign(
    {
      optimization_run_id: "run-a",
      invocation_id: "inv-1",
      role: "worker",
      backend: "vibe",
      provider: "mistral",
      requested_model: "model-x",
      resolved_model: "model-x",
      input_tokens: 100,
      cached_input_tokens: 40,
      output_tokens: 20,
    },
    overrides || {},
  );
}

function artifact(invocations, schemaVersion) {
  return JSON.stringify({
    schema_version: schemaVersion === undefined ? EVIDENCE_SCHEMA_VERSION : schemaVersion,
    invocations,
  });
}

test("measuredTokenMass adds input and output only when both are safe", () => {
  assert.equal(measuredTokenMass({ input_tokens: 100, output_tokens: 20 }), 120);
  assert.equal(measuredTokenMass({ input_tokens: 0, output_tokens: 0 }), 0);
  assert.equal(measuredTokenMass({ input_tokens: 5, output_tokens: null }), null);
  assert.equal(measuredTokenMass({ input_tokens: 5 }), null);
  assert.equal(measuredTokenMass({ input_tokens: -1, output_tokens: 5 }), null);
  assert.equal(measuredTokenMass({ input_tokens: 1.5, output_tokens: 5 }), null);
  assert.equal(
    measuredTokenMass({ input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 1 }),
    null,
  );
});

test("cached_input_tokens is never added to token mass", () => {
  const withCache = measuredTokenMass({
    input_tokens: 100,
    cached_input_tokens: 90,
    output_tokens: 20,
  });
  const withoutCache = measuredTokenMass({ input_tokens: 100, output_tokens: 20 });
  assert.equal(withCache, withoutCache);
  assert.equal(withCache, 120);
});

test("parseEvidenceArtifact rejects malformed and empty input with messages", () => {
  const broken = parseEvidenceArtifact("{not json", "broken.json");
  assert.equal(broken.ok, false);
  assert.match(broken.errors[0], /broken\.json: not valid JSON/);

  const empty = parseEvidenceArtifact(artifact([]), "empty.json");
  assert.equal(empty.ok, false);
  assert.match(empty.errors.join(" "), /invocations array is empty/);

  const wrongSchema = parseEvidenceArtifact(artifact([invocation()], 2), "v2.json");
  assert.equal(wrongSchema.ok, false);
  assert.match(wrongSchema.errors.join(" "), /unsupported schema_version 2/);

  const noArray = parseEvidenceArtifact(JSON.stringify({ schema_version: 1 }), "noarray.json");
  assert.equal(noArray.ok, false);
  assert.match(noArray.errors.join(" "), /missing an invocations array/);

  const missingId = parseEvidenceArtifact(
    artifact([invocation({ invocation_id: null })]),
    "noid.json",
  );
  assert.equal(missingId.ok, false);
  assert.match(missingId.errors.join(" "), /missing optimization_run_id or invocation_id/);
});

test("mergeEvidenceArtifacts dedups identical rows across files and snapshots", () => {
  const first = parseEvidenceArtifact(artifact([invocation()]), "a.json");
  const second = parseEvidenceArtifact(artifact([invocation()]), "b.json");
  const merged = mergeEvidenceArtifacts([first, second]);
  assert.equal(merged.ok, true);
  assert.equal(merged.records.length, 1);
  assert.equal(merged.duplicates, 1);
  assert.equal(merged.conflicts, 0);
});

test("mergeEvidenceArtifacts rejects conflicting measurement rows visibly", () => {
  const first = parseEvidenceArtifact(artifact([invocation()]), "a.json");
  const second = parseEvidenceArtifact(
    artifact([invocation({ input_tokens: 999 })]),
    "b.json",
  );
  const merged = mergeEvidenceArtifacts([first, second]);
  assert.equal(merged.ok, false);
  assert.equal(merged.conflicts, 1);
  assert.equal(merged.records.length, 0);
  assert.match(merged.errors.join(" "), /Conflicting duplicate invocation run-a\/inv-1/);
  assert.match(merged.errors.join(" "), /input_tokens/);
});

test("mergeEvidenceArtifacts rejects conflicting resolved model rows", () => {
  const first = parseEvidenceArtifact(artifact([invocation()]), "a.json");
  const second = parseEvidenceArtifact(
    artifact([invocation({ resolved_model: "model-y" })]),
    "b.json",
  );
  const merged = mergeEvidenceArtifacts([first, second]);
  assert.equal(merged.ok, false);
  assert.match(merged.errors.join(" "), /resolved_model/);
});

test("evidenceGroups groups by resolved model and never falls back to requested", () => {
  const records = [
    invocation({ invocation_id: "i1", resolved_model: "model-a", input_tokens: 10, output_tokens: 10 }),
    invocation({ invocation_id: "i2", resolved_model: "model-a", input_tokens: 30, output_tokens: 10 }),
    invocation({ invocation_id: "i3", resolved_model: null, requested_model: "model-b", input_tokens: 5, output_tokens: 5 }),
  ];
  const resolved = evidenceGroups(records, "resolved");
  const labels = resolved.rows.map((row) => row.label).sort();
  assert.deepEqual(labels, [UNKNOWN_MODEL, "model-a"]);
  const unknown = resolved.rows.find((row) => row.label === UNKNOWN_MODEL);
  assert.equal(unknown.invocations, 1);
  assert.equal(unknown.tokens, 10);
  assert.equal(resolved.totalInvocations, 3);
  assert.equal(resolved.measuredTokens, 70);
  assert.equal(resolved.measuredInvocations, 3);
  assert.equal(resolved.tokenCoverage, 100);

  const requested = evidenceGroups(records, "requested");
  assert.deepEqual(
    requested.rows.map((row) => row.label).sort(),
    ["model-b", "model-x"],
  );
});

test("evidenceGroups keeps unknown usage out of token mass and reports coverage", () => {
  const records = [
    invocation({ invocation_id: "i1", input_tokens: 100, output_tokens: 0 }),
    invocation({ invocation_id: "i2", input_tokens: null, output_tokens: 50 }),
    invocation({ invocation_id: "i3", input_tokens: 10, output_tokens: -5 }),
    invocation({ invocation_id: "i4", input_tokens: 0, output_tokens: 0 }),
  ];
  const groups = evidenceGroups(records, "resolved");
  assert.equal(groups.totalInvocations, 4);
  assert.equal(groups.measuredInvocations, 2);
  assert.equal(groups.unknownUsageInvocations, 2);
  assert.equal(groups.measuredTokens, 100);
  assert.equal(groups.tokenCoverage, 50);
  const row = groups.rows[0];
  assert.equal(row.invocations, 4);
  assert.equal(row.measuredInvocations, 2);
  assert.equal(row.tokens, 100);
  assert.equal(row.tokenShare, 100);
});

test("zero denominators yield unavailable shares, never NaN or 100%", () => {
  const records = [invocation({ invocation_id: "i1", input_tokens: null, output_tokens: null })];
  const groups = evidenceGroups(records, "resolved");
  assert.equal(groups.measuredTokens, 0);
  assert.equal(groups.rows[0].tokenShare, null);
  assert.equal(formatPercent(groups.rows[0].tokenShare), "—");
  assert.equal(formatPercent(groups.rows[0].invocationShare), "100.0%");

  const empty = evidenceGroups([], "resolved");
  assert.equal(empty.rows.length, 0);
  assert.equal(empty.tokenCoverage, null);
  assert.equal(formatPercent(empty.tokenCoverage), "—");
});

test("aggregate token totals stay exact beyond Number safe range per record", () => {
  const big = Number.MAX_SAFE_INTEGER - 10;
  const records = [
    invocation({ invocation_id: "i1", input_tokens: big, output_tokens: 0 }),
    invocation({ invocation_id: "i2", input_tokens: big, output_tokens: 0 }),
  ];
  const groups = evidenceGroups(records, "resolved");
  assert.equal(groups.measuredTokens, null);
  assert.equal(groups.measuredTokensExact, String(BigInt(big) * 2n));
  assert.equal(groups.rows[0].tokens, null);
  assert.equal(groups.rows[0].tokensExact, String(BigInt(big) * 2n));
  assert.equal(groups.rows[0].tokenShare, null);
  assert.equal(formatPercent(groups.rows[0].tokenShare), "—");
  assert.equal(formatExactCount(groups.rows[0].tokensExact), String(BigInt(big) * 2n));
});

test("exact totals do not lose the low bit when safe records overflow", () => {
  // 9007199254740991 + 2 must be 9007199254740993, not 9007199254740992.
  const records = [
    invocation({ invocation_id: "i1", input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 0 }),
    invocation({ invocation_id: "i2", input_tokens: 2, output_tokens: 0 }),
  ];
  const groups = evidenceGroups(records, "resolved");
  assert.equal(groups.measuredTokensExact, "9007199254740993");
  assert.equal(groups.rows[0].tokensExact, "9007199254740993");
  assert.equal(formatExactCount(groups.rows[0].tokensExact), "9007199254740993");
  assert.equal(formatExactCount(groups.measuredTokensExact), "9007199254740993");
  // The subtotal is exact but not representable as a Number, so the share is
  // unavailable rather than a fabricated percentage.
  assert.equal(groups.rows[0].tokenShare, null);
  assert.equal(formatPercent(groups.rows[0].tokenShare), "—");

  const summary = evidenceSummary(records);
  assert.equal(summary.measuredTokensExact, "9007199254740993");
  assert.equal(formatExactCount(summary.measuredTokensExact), "9007199254740993");

  assert.equal(exactTotal([Number.MAX_SAFE_INTEGER, 2]).toString(), "9007199254740993");
  assert.equal(exactToNumber(9007199254740993n), null);
  assert.equal(exactToNumber(7n), 7);
});

test("evidenceSummary counts runs, roles and unknown usage", () => {
  const records = [
    invocation({ invocation_id: "i1", role: "worker" }),
    invocation({ invocation_id: "i2", role: "reviewer", optimization_run_id: "run-b" }),
    invocation({ invocation_id: "i3", role: null, input_tokens: null, output_tokens: null }),
  ];
  const summary = evidenceSummary(records);
  assert.equal(summary.invocations, 3);
  assert.equal(summary.runs, 2);
  assert.deepEqual(summary.roles, ["Unknown", "reviewer", "worker"]);
  assert.equal(summary.measuredInvocations, 2);
  assert.equal(summary.unknownUsageInvocations, 1);
  assert.equal(summary.measuredTokens, 240);
});

test("a group with no measured usage keeps unavailable tokens, not zero", () => {
  const records = [
    invocation({ invocation_id: "i1", resolved_model: "model-a", input_tokens: 60, output_tokens: 40 }),
    invocation({ invocation_id: "i2", resolved_model: "model-b", input_tokens: null, output_tokens: null }),
  ];
  const groups = evidenceGroups(records, "resolved");
  const measured = groups.rows.find((row) => row.label === "model-a");
  const unmeasured = groups.rows.find((row) => row.label === "model-b");
  assert.equal(measured.tokens, 100);
  assert.equal(measured.tokenShare, 100);
  assert.equal(unmeasured.invocations, 1);
  assert.equal(unmeasured.measuredInvocations, 0);
  assert.equal(unmeasured.tokens, null);
  assert.equal(unmeasured.tokenShare, null);
  assert.equal(formatPercent(unmeasured.tokenShare), "—");
  assert.equal(groups.measuredTokens, 100);
  assert.equal(groups.tokenCoverage, 50);
});

test("a genuine measured zero stays zero and is not unavailable", () => {
  const records = [
    invocation({ invocation_id: "i1", resolved_model: "model-a", input_tokens: 0, output_tokens: 0 }),
    invocation({ invocation_id: "i2", resolved_model: "model-b", input_tokens: 10, output_tokens: 10 }),
  ];
  const groups = evidenceGroups(records, "resolved");
  const zero = groups.rows.find((row) => row.label === "model-a");
  assert.equal(zero.measuredInvocations, 1);
  assert.equal(zero.tokens, 0);
  assert.equal(zero.tokensExact, "0");
  assert.equal(zero.tokenShare, 0);
  assert.equal(formatPercent(zero.tokenShare), "0.0%");
  assert.equal(groups.measuredTokens, 20);
});

test("conflicting cached_input_tokens is detected, not silently collapsed", () => {
  const first = parseEvidenceArtifact(
    artifact([invocation({ cached_input_tokens: 40 })]),
    "a.json",
  );
  const second = parseEvidenceArtifact(
    artifact([invocation({ cached_input_tokens: 90 })]),
    "b.json",
  );
  const merged = mergeEvidenceArtifacts([first, second]);
  assert.equal(merged.ok, false);
  assert.equal(merged.conflicts, 1);
  assert.equal(merged.duplicates, 0);
  assert.match(merged.errors.join(" "), /cached_input_tokens: 40 vs 90/);
});

test("fractional and unsafe counters conflict even though they are not token mass", () => {
  for (const field of ["input_tokens", "output_tokens"]) {
    const first = parseEvidenceArtifact(artifact([invocation()]), "a.json");
    const second = parseEvidenceArtifact(
      artifact([invocation({ [field]: 1.5 })]),
      "b.json",
    );
    const merged = mergeEvidenceArtifacts([first, second]);
    assert.equal(merged.ok, false, field);
    assert.equal(merged.conflicts, 1, field);
    assert.match(merged.errors.join(" "), new RegExp(field + ": 100 vs 1.5|" + field + ": 20 vs 1.5"));
  }
  const unsafeFirst = parseEvidenceArtifact(artifact([invocation()]), "a.json");
  const unsafeSecond = parseEvidenceArtifact(
    artifact([invocation({ input_tokens: Number.MAX_SAFE_INTEGER + 2 })]),
    "b.json",
  );
  const unsafe = mergeEvidenceArtifacts([unsafeFirst, unsafeSecond]);
  assert.equal(unsafe.conflicts, 1);
  assert.match(unsafe.errors.join(" "), /input_tokens/);
});

test("an invalid artifact contributes no records to the merged charts", () => {
  const good = parseEvidenceArtifact(artifact([invocation()]), "good.json");
  const wrongSchema = parseEvidenceArtifact(
    artifact([invocation({ invocation_id: "inv-2" })], 2),
    "v2.json",
  );
  assert.equal(wrongSchema.ok, false);
  assert.deepEqual(wrongSchema.records, []);

  const merged = mergeEvidenceArtifacts([good, wrongSchema]);
  assert.equal(merged.ok, false);
  assert.equal(merged.rejectedArtifacts, 1);
  assert.equal(merged.records.length, 1);
  assert.equal(merged.records[0].invocation_id, "inv-1");
  assert.match(merged.errors.join(" "), /unsupported schema_version 2/);

  const groups = evidenceGroups(merged.records, "resolved");
  assert.equal(groups.totalInvocations, 1);
  assert.equal(groups.measuredTokens, 120);
});

test("a malformed entry rejects its whole artifact instead of charting the rest", () => {
  const mixed = parseEvidenceArtifact(
    artifact([invocation(), null]),
    "mixed.json",
  );
  assert.equal(mixed.ok, false);
  assert.deepEqual(mixed.records, []);
  assert.match(mixed.errors.join(" "), /invocation #1 is not an object/);

  const merged = mergeEvidenceArtifacts([mixed]);
  assert.equal(merged.records.length, 0);
  assert.equal(merged.rejectedArtifacts, 1);
  assert.equal(evidenceGroups(merged.records, "resolved").totalInvocations, 0);
});

test("mixed roles and models group once per invocation across artifacts", () => {
  const first = parseEvidenceArtifact(
    artifact([
      invocation({ invocation_id: "i1", role: "worker", resolved_model: "model-a" }),
      invocation({ invocation_id: "i2", role: "reviewer", resolved_model: "model-b" }),
    ]),
    "a.json",
  );
  const second = parseEvidenceArtifact(
    artifact([
      invocation({ invocation_id: "i1", role: "worker", resolved_model: "model-a" }),
      invocation({ invocation_id: "i3", role: "control", resolved_model: null, requested_model: "model-a" }),
    ]),
    "b.json",
  );
  const merged = mergeEvidenceArtifacts([first, second]);
  assert.equal(merged.ok, true);
  assert.equal(merged.duplicates, 1);
  assert.equal(merged.records.length, 3);

  const groups = evidenceGroups(merged.records, "resolved");
  assert.equal(groups.totalInvocations, 3);
  assert.deepEqual(groups.rows.map((row) => row.label).sort(), [UNKNOWN_MODEL, "model-a", "model-b"]);
  const unknown = groups.rows.find((row) => row.label === UNKNOWN_MODEL);
  assert.equal(unknown.invocations, 1);
  assert.equal(unknown.tokens, 120);

  const requested = evidenceGroups(merged.records, "requested");
  assert.deepEqual(requested.rows.map((row) => row.label).sort(), ["model-a", "model-x"]);
  assert.equal(requested.rows.find((row) => row.label === "model-a").invocations, 1);
  assert.equal(requested.rows.find((row) => row.label === "model-x").invocations, 2);

  const summary = evidenceSummary(merged.records);
  assert.deepEqual(summary.roles, ["control", "reviewer", "worker"]);
  assert.equal(summary.runs, 1);
});

// --- Headless DOM wiring ---------------------------------------------------

// Minimal DOM stand-in: enough for catalog-view.js to build rows and charts
// without a browser, a GUI or any network access.
function makeNode(tag) {
  const listeners = new Map();
  return {
    tagName: tag,
    children: [],
    className: "",
    textContent: "",
    colSpan: 0,
    style: {},
    value: "",
    hidden: false,
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren() {
      this.children = [];
    },
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(listener);
    },
    dispatchEvent(event) {
      event.target = this;
      for (const listener of listeners.get(event.type) || []) listener(event);
    },
    setAttribute() {},
    querySelectorAll() {
      return [];
    },
  };
}

// One stable document object: the view IIFE captures it at load time, so each
// test resets the node map instead of replacing the document.
const fakeNodes = new Map();
const fakeDocument = {
  nodes: fakeNodes,
  getElementById(id) {
    return fakeNodes.get(id) || null;
  },
  createElement(tag) {
    return makeNode(tag);
  },
  addEventListener() {},
};

// The view caches element references at load time, so nodes are reset in place
// rather than replaced.
function resetDocument(ids) {
  for (const id of ids) {
    const node = fakeNodes.get(id) || makeNode("div");
    node.children = [];
    node.textContent = "";
    node.className = "";
    node.value = "";
    fakeNodes.set(id, node);
  }
  return fakeDocument;
}

const VIEW_IDS = [
  "catalogView",
  "catalogBody",
  "catalogSummary",
  "catalogError",
  "catalogRefresh",
  "evidenceFiles",
  "evidenceGrouping",
  "evidenceClear",
  "evidenceStatus",
  "evidenceError",
  "evidenceNotice",
  "evidenceBody",
  "evidenceGroupHeading",
  "invocationChart",
  "tokenChart",
  "invocationChartTitle",
  "tokenChartTitle",
  "invocationChartNote",
  "tokenChartNote",
];

function textOf(node) {
  return node.children.map((child) => child.textContent).join(" ");
}

// The view module is an IIFE that binds to globalThis once, so it is loaded a
// single time and each test resets the shared evidence state.
let viewModulePromise = null;
async function loadView(document) {
  globalThis.document = document;
  // Keep one stable namespace object: the view IIFE captures it at load time.
  globalThis.MacoScope = globalThis.MacoScope || {};
  globalThis.MacoScope.catalog = await import("../src/catalog.mjs");
  globalThis.MacoScope.api = { fetchProjects: async () => [] };
  if (!viewModulePromise) viewModulePromise = import("../src/views/catalog-view.js");
  await viewModulePromise;
  const view = globalThis.MacoScope.catalogView;
  view.clearEvidence();
  document.nodes.get("evidenceGrouping").value = "resolved";
  document.nodes.get("evidenceGrouping").dispatchEvent({ type: "change" });
  return view;
}

test("headless view imports artifacts and renders both charts", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  assert.ok(view, "catalog view registered");

  const files = [
    {
      name: "a.json",
      text: async () =>
        artifact([
          invocation({ invocation_id: "i1", resolved_model: "model-a", input_tokens: 60, output_tokens: 40 }),
          invocation({ invocation_id: "i2", resolved_model: "model-b", input_tokens: null, output_tokens: null }),
        ]),
    },
  ];
  await view.importFiles(files);

  const invocationRows = document.nodes.get("invocationChart").children;
  assert.equal(invocationRows.length, 2);
  const unknownCount = invocationRows.find((row) => textOf(row).includes("model-b"));
  assert.equal(unknownCount.className, "chart-row");
  assert.match(textOf(unknownCount), /1 · 50\.0%/);
  assert.equal(unknownCount.children[1].children[0].style.width, "50%");
  const tokenRows = document.nodes.get("tokenChart").children;
  assert.equal(tokenRows.length, 2);
  const unmeasured = tokenRows.find((row) => textOf(row).includes("model-b"));
  assert.match(textOf(unmeasured), /unavailable/);
  assert.equal(unmeasured.className, "chart-row is-unavailable");
  assert.equal(textOf(unmeasured).includes("0 · 0.0%"), false);
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("model-a"))), /100 · 100\.0%/);

  const note = document.nodes.get("tokenChartNote").textContent;
  assert.match(note, /known measured subtotal of 100 tokens/);
  assert.match(note, /1 of 2 invocations have measured usage \(50\.0% coverage\)/);

  // Grouping control switches attribution without re-importing.
  document.nodes.get("evidenceGrouping").value = "requested";
  document.nodes.get("evidenceGrouping").dispatchEvent({ type: "change" });
  assert.match(document.nodes.get("invocationChartTitle").textContent, /requested model/);

});

test("headless view rejects an invalid artifact without charting it", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);

  await view.importFiles([
    {
      name: "v2.json",
      text: async () => artifact([invocation({ invocation_id: "i9" })], 2),
    },
  ]);

  assert.match(document.nodes.get("evidenceError").textContent, /unsupported schema_version 2/);
  assert.equal(document.nodes.get("invocationChart").children.length, 1);
  assert.match(
    document.nodes.get("invocationChart").children[0].textContent,
    /No invocations imported/,
  );
  assert.equal(view.evidenceState.merged.records.length, 0);
});

test("model grouping labels and formatters are explicit", () => {
  assert.equal(modelGroupingLabel("resolved"), "Resolved / observed model");
  assert.equal(modelGroupingLabel("requested"), "Requested model");
  assert.equal(formatPercent(12.345), "12.3%");
  assert.equal(formatPercent(null), "—");
  assert.equal(formatCount(7), "7");
  assert.equal(formatCount(null), "—");
});

test("identity distinguishes trial starts and collapses missing and null starts", () => {
  const first = invocation({ started_at: "2026-11-01T00:00:00Z" });
  const later = invocation({ started_at: "2026-11-02T00:00:00Z", input_tokens: 200 });
  const merged = mergeEvidenceArtifacts([
    { text: artifact([first, later, invocation(), invocation({ started_at: null }), first]) },
  ]);
  assert.equal(merged.ok, true);
  assert.equal(merged.records.length, 3);
  assert.equal(merged.duplicates, 2);
  assert.equal(evidenceGroups(merged.records).totalInvocations, 3);

  // Neither import order nor later repetitions may resurrect a conflicted identity.
  for (const rows of [
    [first, { ...first, cached_input_tokens: 99 }, first, later],
    [{ ...first, cached_input_tokens: 99 }, first, later],
  ]) {
    const conflict = mergeEvidenceArtifacts([{ text: artifact(rows) }]);
    assert.equal(conflict.ok, false);
    assert.deepEqual(conflict.records, [later]);
    assert.match(conflict.errors.join(" "), /2026-11-01T00:00:00Z.*cached_input_tokens/);
  }
});

test("numeric started_at distinguishes trials and identical rows collapse", () => {
  const first = invocation({ started_at: 1761955200000 });
  const later = invocation({ started_at: 1762041600000 });
  const merged = mergeEvidenceArtifacts([
    { text: artifact([first, later, first]) },
  ]);
  assert.equal(merged.ok, true);
  assert.equal(merged.records.length, 2);
  assert.equal(merged.duplicates, 1);
  assert.equal(evidenceGroups(merged.records).totalInvocations, 2);
});

test("same numeric started_at with differing measurement conflicts and is excluded", () => {
  const first = invocation({ started_at: 1761955200000 });
  const conflicting = { ...first, input_tokens: 200 };
  const merged = mergeEvidenceArtifacts([
    { text: artifact([first, conflicting]) },
  ]);
  assert.equal(merged.ok, false);
  assert.equal(merged.conflicts, 1);
  assert.deepEqual(merged.records, []);
  assert.match(merged.errors.join(" "), /Conflicting duplicate invocation .*1761955200000.*input_tokens/);
});

test("role categories match all aliases without losing raw role labels", () => {
  const roles = ["Manager", "CHILDORCHESTRATOR", "orchestrator", "Supervisor",
    "Auditor", "REVIEWER", "review", "Worker", "custom", null];
  const records = roles.map((role, index) => invocation({ invocation_id: String(index), role }));
  const groups = evidenceGroups(records, "role");
  const category = (name) => groups.rows.find((row) => row.label.startsWith(name + " ("));
  assert.equal(groups.rows.length, 4);
  assert.equal(category("Manager").invocations, 4);
  assert.equal(category("Manager").tokens, 480);
  for (const role of roles.slice(0, 4)) assert.ok(category("Manager").label.includes(role));
  assert.equal(category("Review").invocations, 3);
  assert.equal(category("Worker").label, "Worker (Worker)");
  assert.equal(category("Other").label, "Other (Unknown, custom)");
});

test("headless grouping change handler drives both role charts and requested models", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  await view.importFiles([{ name: "roles.json", text: async () => artifact([
    invocation({ invocation_id: "r1", role: "Auditor", requested_model: "<model-a>", resolved_model: "observed", input_tokens: 10, output_tokens: 0 }),
    invocation({ invocation_id: "r2", role: "reviewer", requested_model: "model-b", resolved_model: "observed", input_tokens: 30, output_tokens: 0 }),
    invocation({ invocation_id: "w1", role: "worker", requested_model: "model-b", input_tokens: null, output_tokens: null }),
  ]) }]);

  const control = document.nodes.get("evidenceGrouping");
  control.value = "role";
  control.dispatchEvent({ type: "change" });
  assert.equal(view.evidenceState.grouping, "role");
  assert.equal(document.nodes.get("evidenceGroupHeading").textContent, "Role category");
  for (const id of ["invocationChart", "tokenChart"]) {
    assert.equal(document.nodes.get(id).children.length, 2);
    assert.equal(document.nodes.get(id).children[0].children[0].textContent, "Review (Auditor, reviewer)");
  }
  assert.match(textOf(document.nodes.get("invocationChart").children[0]), /2 · 66\.7%/);
  assert.match(textOf(document.nodes.get("tokenChart").children[0]), /40 · 100\.0%/);

  control.value = "role_requested";
  control.dispatchEvent({ type: "change" });
  assert.equal(view.evidenceState.grouping, "role_requested");
  for (const id of ["invocationChart", "tokenChart"]) {
    const rows = document.nodes.get(id).children;
    assert.equal(rows.length, 3);
    assert.ok(rows.some((row) => row.children[0].textContent === "Review (Auditor) × <model-a>"));
  }
  const tokenRows = document.nodes.get("tokenChart").children;
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("Auditor"))), /10 · 25\.0%/);
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("reviewer"))), /30 · 75\.0%/);
  assert.match(document.nodes.get("tokenChartTitle").textContent, /role category x requested model/);
});

test("headless measured zero and oversized totals retain their values", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  await view.importFiles([{ name: "totals.json", text: async () => artifact([
    invocation({ invocation_id: "big1", resolved_model: "big", input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 0 }),
    invocation({ invocation_id: "big2", resolved_model: "big", input_tokens: 2, output_tokens: 0 }),
    invocation({ invocation_id: "zero", resolved_model: "zero", input_tokens: 0, output_tokens: 0 }),
  ]) }]);
  const rows = document.nodes.get("tokenChart").children;
  assert.match(textOf(rows.find((row) => textOf(row).includes("big"))), /9007199254740993 · —/);
  assert.match(textOf(rows.find((row) => textOf(row).includes("zero"))), /0 · —/);
  for (const row of rows) assert.equal(row.className, "chart-row");
  const tableRows = document.nodes.get("evidenceBody").children;
  assert.ok(tableRows.some((row) => textOf(row).includes("9007199254740993")));
});

test("Clear invalidates pending successful and failed reads through its click handler", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  for (const fails of [false, true]) {
    let finish;
    const pending = view.importFiles([{ name: "late.json", text: () => new Promise((resolve, reject) => {
      finish = () => fails ? reject(new Error("late failure")) : resolve(artifact([invocation()]));
    }) }]);
    document.nodes.get("evidenceClear").dispatchEvent({ type: "click" });
    // New imports after Clear must survive even when the old read finishes later.
    await view.importFiles([{ name: "new.json", text: async () => artifact([invocation({ invocation_id: "new" })]) }]);
    finish();
    await pending;
    assert.equal(view.evidenceState.artifacts.length, 1);
    assert.equal(view.evidenceState.merged.records[0].invocation_id, "new");
    assert.equal(document.nodes.get("evidenceError").textContent, "");
    document.nodes.get("evidenceClear").dispatchEvent({ type: "click" });
    assert.equal(view.evidenceState.merged, null);
    assert.equal(document.nodes.get("evidenceStatus").textContent, "No artifacts imported");
  }
});

test("collected artifacts show one collection notice and accept exec JSONL records", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  const collection = {
    files_scanned: 12, artifacts_parsed: 3, identical_duplicates: 2,
    invalid_artifacts: ["bad-a", "bad-b"], conflicts: [], external_sources: ["external"],
  };
  const text = JSON.stringify({ schema_version: 1, collection, invocations: [invocation({ record_source: "codex_exec_jsonl" })] });
  const parsed = parseEvidenceArtifact(text, "collected.json");
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.collection, collection);
  await view.importFiles([{ name: "collected.json", text: async () => text }]);
  assert.equal(view.evidenceState.merged.records.length, 1);
  assert.match(textOf(document.nodes.get("tokenChart").children[0]), /120 · 100\.0%/);
  const notice = document.nodes.get("evidenceNotice").textContent;
  assert.equal(notice.split("Collection:").length - 1, 1);
  assert.ok(notice.includes("Collection: files_scanned: 12, artifacts_parsed: 3, identical_duplicates: 2, invalid_artifacts: 2, conflicts: 0, external_sources: 1."));

  view.clearEvidence();
  await view.importFiles([{ name: "sparse.json", text: async () => JSON.stringify({
    schema_version: 1, invocations: [invocation()],
    collection: { files_scanned: 0, artifacts_parsed: "3", external_sources: [] },
  }) }]);
  const sparse = document.nodes.get("evidenceNotice").textContent;
  assert.ok(sparse.includes("Collection: files_scanned: 0, external_sources: 0."));
  for (const absent of ["artifacts_parsed", "identical_duplicates", "invalid_artifacts", "conflicts:"]) {
    assert.equal(sparse.includes(absent), false);
  }
});

test("runOutcomeIndex maps outcomes and omits disagreeing or malformed entries", () => {
  const collections = [
    {
      run_outcomes: [
        { run_id: "run-a", success: true, accepted: true, publishable: true, status: "succeeded", path: "a" },
        { run_id: "run-b", accepted: false },
        { run_id: "", accepted: true },
        { run_id: "run-c", accepted: "yes" },
        { run_id: "run-d" },
        { accepted: true },
        "not-an-object",
        null,
      ],
    },
    { run_outcomes: [{ run_id: "run-a", accepted: true }, { run_id: "run-e", accepted: false }] },
    { run_outcomes: [{ run_id: "run-b", accepted: true }, { run_id: "run-b", accepted: true }] },
    {},
    { run_outcomes: "not-an-array" },
  ];
  const index = runOutcomeIndex(collections);
  assert.equal(index.get("run-a"), "Accepted run");
  assert.equal(index.get("run-e"), "Not accepted run");
  assert.equal(index.has("run-b"), false);
  assert.equal(index.has("run-c"), false);
  assert.equal(index.has("run-d"), false);
  assert.equal(index.size, 2);
  assert.equal(runOutcomeIndex([]).size, 0);
  assert.equal(runOutcomeIndex(null).size, 0);
});

test("evidenceGroups outcome mode labels runs and keeps token handling unchanged", () => {
  const outcomes = new Map([
    ["run-a", "Accepted run"],
    ["run-b", "Not accepted run"],
  ]);
  const records = [
    invocation({ invocation_id: "i1", optimization_run_id: "run-a", input_tokens: 60, output_tokens: 40 }),
    invocation({ invocation_id: "i2", optimization_run_id: "run-b", input_tokens: 30, output_tokens: 10 }),
    invocation({ invocation_id: "i3", optimization_run_id: "run-b", input_tokens: 10, output_tokens: 0 }),
    invocation({ invocation_id: "i4", optimization_run_id: "run-z", input_tokens: null, output_tokens: null }),
  ];
  const groups = evidenceGroups(records, "outcome", outcomes);
  assert.equal(groups.grouping, "outcome");
  assert.equal(groups.groupingLabel, "Run outcome (MACO native result)");
  assert.deepEqual(
    groups.rows.map((row) => row.label).sort(),
    ["Accepted run", "Not accepted run", "Unknown outcome"],
  );
  assert.equal(groups.totalInvocations, 4);
  assert.equal(groups.measuredInvocations, 3);
  assert.equal(groups.measuredTokens, 150);
  const accepted = groups.rows.find((row) => row.label === "Accepted run");
  assert.equal(accepted.invocations, 1);
  assert.equal(accepted.invocationShare, 25);
  assert.equal(accepted.tokens, 100);
  assert.equal(accepted.tokenShare, (100 / 150) * 100);
  const notAccepted = groups.rows.find((row) => row.label === "Not accepted run");
  assert.equal(notAccepted.invocations, 2);
  assert.equal(notAccepted.measuredInvocations, 2);
  assert.equal(notAccepted.tokens, 50);
  assert.equal(notAccepted.tokenShare, (50 / 150) * 100);
  const unknown = groups.rows.find((row) => row.label === "Unknown outcome");
  assert.equal(unknown.invocations, 1);
  assert.equal(unknown.measuredInvocations, 0);
  assert.equal(unknown.tokens, null);
  assert.equal(unknown.tokenShare, null);
  assert.equal(formatPercent(unknown.tokenShare), "—");

  // A non-Map third argument is treated as empty: everything is unknown.
  const noIndex = evidenceGroups(records, "outcome", "not a map");
  assert.deepEqual(noIndex.rows.map((row) => row.label), ["Unknown outcome"]);
  assert.equal(noIndex.rows[0].invocations, 4);
  const omitted = evidenceGroups(records, "outcome");
  assert.deepEqual(omitted.rows.map((row) => row.label), ["Unknown outcome"]);

  // Other modes are unchanged by the third argument.
  const resolved = evidenceGroups(records, "resolved", outcomes);
  assert.deepEqual(resolved.rows.map((row) => row.label), ["model-x"]);
});

test("headless view switches the grouping to outcome with collected run_outcomes", async () => {
  const document = resetDocument(VIEW_IDS);
  const view = await loadView(document);
  const text = JSON.stringify({
    schema_version: 1,
    collection: {
      files_scanned: 4,
      run_outcomes: [
        { run_id: "run-a", success: true, accepted: true, publishable: true, status: "succeeded", path: "a" },
        { run_id: "run-b", success: false, accepted: false, publishable: false, status: "failed", path: "b" },
      ],
    },
    invocations: [
      invocation({ invocation_id: "i1", optimization_run_id: "run-a", input_tokens: 60, output_tokens: 40 }),
      invocation({ invocation_id: "i2", optimization_run_id: "run-b", input_tokens: 30, output_tokens: 10 }),
      invocation({ invocation_id: "i3", optimization_run_id: "run-c", input_tokens: 10, output_tokens: 0 }),
    ],
  });
  await view.importFiles([{ name: "outcomes.json", text: async () => text }]);
  const control = document.nodes.get("evidenceGrouping");
  control.value = "outcome";
  control.dispatchEvent({ type: "change" });
  assert.equal(view.evidenceState.grouping, "outcome");
  assert.equal(
    document.nodes.get("evidenceGroupHeading").textContent,
    "Run outcome (MACO native result)",
  );
  assert.match(document.nodes.get("invocationChartTitle").textContent, /run outcome \(maco native result\)/);
  const rows = document.nodes.get("invocationChart").children;
  assert.equal(rows.length, 3);
  for (const label of ["Accepted run", "Not accepted run", "Unknown outcome"]) {
    assert.ok(rows.some((row) => row.children[0].textContent === label), label);
  }
  const tokenRows = document.nodes.get("tokenChart").children;
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("Accepted run"))), /100 · 66\.7%/);
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("Not accepted run"))), /40 · 26\.7%/);
  assert.match(textOf(tokenRows.find((row) => textOf(row).includes("Unknown outcome"))), /10 · 6\.7%/);
  const tableRows = document.nodes.get("evidenceBody").children;
  assert.ok(tableRows.some((row) => textOf(row).includes("Accepted run")));
  assert.ok(tableRows.some((row) => textOf(row).includes("Unknown outcome")));
});

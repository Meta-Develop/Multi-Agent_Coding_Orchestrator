import assert from "node:assert/strict";
import { test } from "node:test";
import { catalogRows, catalogSummary, liveHref } from "../src/catalog.mjs";
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

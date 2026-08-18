import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  DEFAULT_OBJECTIVE,
  cloneObjective,
  loadEvaluationDocument,
  paretoFrontier,
  rescoreLoaded,
  rescoreQualityComponents,
  selectProfile,
  validateObjective,
} from "../src/objective.mjs";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

test("default quality weights reproduce the 50/25/25 compile-time mix", () => {
  assert.deepEqual(DEFAULT_OBJECTIVE.quality, {
    held_out: 50,
    breadth: 25,
    anti_shortcut: 25,
  });
  assert.equal(
    rescoreQualityComponents(
      {
        held_out_basis_points: 8181,
        breadth_basis_points: 10000,
        anti_shortcut_basis_points: 6666,
      },
      DEFAULT_OBJECTIVE.quality,
    ),
    8257,
  );
});

test("validateObjective requires a 100-point quality mix", () => {
  const broken = cloneObjective(DEFAULT_OBJECTIVE);
  broken.quality.held_out = 10;
  assert.ok(validateObjective(broken).some((error) => error.includes("sum to 100")));
  assert.deepEqual(validateObjective(DEFAULT_OBJECTIVE), []);
});

test("summary preview keeps the recorded default ranking when weights are unchanged", () => {
  const document = JSON.parse(readFileSync(join(fixtures, "summary-demo.json"), "utf8"));
  const loaded = loadEvaluationDocument(document);
  const preview = rescoreLoaded(loaded, DEFAULT_OBJECTIVE, document);
  const byId = Object.fromEntries(preview.rows.map((row) => [row.profile_id, row]));
  assert.equal(loaded.source, "summary");
  assert.ok(Math.abs(byId["balanced-all-v1"].preview_overall - 25659 / 3) < 1);
  assert.equal(preview.selection.profile_id, "balanced-all-v1");
  assert.equal(preview.labeled_preview, true);
});

test("raising the cost axis prefers the cheaper recorded profile", () => {
  const document = JSON.parse(readFileSync(join(fixtures, "summary-demo.json"), "utf8"));
  const loaded = loadEvaluationDocument(document);
  const costly = cloneObjective(DEFAULT_OBJECTIVE);
  costly.axes.quality = 40;
  costly.axes.cost = 60;
  const preview = rescoreLoaded(loaded, costly, document);
  assert.equal(preview.selection.profile_id, "frontier-all-v1");
});

test("per-run rescore uses integer division matching evaluation.rs", () => {
  const document = JSON.parse(readFileSync(join(fixtures, "runs-demo.json"), "utf8"));
  const loaded = loadEvaluationDocument(document);
  assert.equal(loaded.source, "runs");
  const preview = rescoreLoaded(loaded, DEFAULT_OBJECTIVE, document);
  const expensive = preview.rows.find((row) => row.profile_id === "expensive-perfect");
  assert.equal(expensive.preview_overall, 10000);
  const cheap = preview.rows.find((row) => row.profile_id === "cheap-high");
  assert.equal(cheap.preview_overall, 8500);
});

test("held-out-only weights change the preview pick on the run fixture", () => {
  const document = JSON.parse(readFileSync(join(fixtures, "runs-demo.json"), "utf8"));
  const loaded = loadEvaluationDocument(document);
  const heldOut = cloneObjective(DEFAULT_OBJECTIVE);
  heldOut.quality = { held_out: 100, breadth: 0, anti_shortcut: 0 };
  const preview = rescoreLoaded(loaded, heldOut, document);
  const cheap = preview.rows.find((row) => row.profile_id === "cheap-high");
  assert.equal(cheap.preview_overall, 8000);
  assert.equal(preview.selection.profile_id, "expensive-perfect");
});

test("paretoFrontier drops the dominated economy profile", () => {
  const rows = [
    { profile_id: "a", mean_cost: 1, preview_overall: 9000 },
    { profile_id: "b", mean_cost: 2, preview_overall: 8000 },
    { profile_id: "c", mean_cost: 1.5, preview_overall: 9500 },
  ];
  const frontier = paretoFrontier(rows).map((row) => row.profile_id).sort();
  assert.deepEqual(frontier, ["a", "c"]);
  const pick = selectProfile(rows, DEFAULT_OBJECTIVE);
  assert.equal(pick.profile_id, "c");
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import * as objectiveApi from "../src/objective.mjs";
import {
  DEFAULT_OBJECTIVE,
  cloneObjective,
  loadEvaluationDocument,
  paretoFrontier,
  rescoreLoaded,
  rescoreQualityComponents,
  selectProfile,
  dominatesCostQuality,
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
  assert.equal(byId["balanced-all-v1"].preview_overall, 8553);
  assert.equal(byId["frontier-all-v1"].preview_overall, 8530);
  assert.equal(byId["economy-all-v1"].preview_overall, 7003);
  assert.equal(preview.selection.profile_id, "balanced-all-v1");
  assert.equal(preview.labeled_preview, true);
});

test("summary rescore rounds component means before the weighted mix", () => {
  const heldOut = cloneObjective(DEFAULT_OBJECTIVE);
  heldOut.quality = { held_out: 100, breadth: 0, anti_shortcut: 0 };
  const component = (total) => ({ total, count: 2 });
  for (const [heldTotal, expected] of [[1, 1], [3, 2]]) {
    const document = {
      profile_summaries: [{
        profile_id: "rounded",
        repetitions: 2,
        mean_cost_usd: 1,
        mean_quality: {
          held_out_basis_points: component(heldTotal),
          breadth_basis_points: component(0),
          anti_shortcut_basis_points: component(0),
          overall_basis_points: component(heldTotal),
        },
      }],
    };
    const loaded = loadEvaluationDocument(document);
    assert.equal(loaded.source, "summary");
    const preview = rescoreLoaded(loaded, heldOut, document);
    assert.equal(preview.rows[0].preview_overall, expected);
  }
});

test("default preview id matches the Rust built-in objective profile", () => {
  const rust = readFileSync(new URL("../../src/objective_profile.rs", import.meta.url), "utf8");
  const match = rust.match(/pub const DEFAULT_OBJECTIVE_PROFILE_ID: &str = "([^"]+)";/);
  assert.ok(match);
  assert.equal(DEFAULT_OBJECTIVE.id, match[1]);
  const view = readFileSync(new URL("../src/views/objective.html", import.meta.url), "utf8");
  assert.ok(view.includes(`<input id="objectiveId" type="text" value="${DEFAULT_OBJECTIVE.id}"`));
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

function run(profile_id, cost, quality = 9000) {
  return {
    profile_id,
    metrics: {
      ...(cost === undefined ? {} : { cost_usd: cost }),
      wall_time_ms: 10,
      churn_count: 1,
      quality: {
        held_out_basis_points: quality,
        breadth_basis_points: quality,
        anti_shortcut_basis_points: quality,
        overall_basis_points: quality,
      },
    },
  };
}

function summary(profile_id, cost, quality = 9000, count = 1) {
  const precise = { total: quality * count, count };
  return {
    profile_id,
    repetitions: count,
    ...(cost === undefined ? {} : { mean_cost_usd: cost }),
    mean_wall_time_ms: { total: 10 * count, count },
    mean_churn_count: { total: count, count },
    mean_quality: {
      held_out_basis_points: precise,
      breadth_basis_points: precise,
      anti_shortcut_basis_points: precise,
      overall_basis_points: precise,
    },
  };
}

function permutations(items) {
  if (!items.length) return [[]];
  return items.flatMap((item, index) =>
    permutations(items.filter((_, other) => other !== index)).map((rest) => [item, ...rest]));
}

const costObjective = cloneObjective(DEFAULT_OBJECTIVE);
costObjective.axes = { quality: 40, cost: 60, latency: 0, rework: 0 };

// Runs can be rescored per sample, or from the loaded aggregation when the
// original document is unavailable. Summaries exercise the third entry path.
function previews(document, profile = DEFAULT_OBJECTIVE) {
  const loaded = loadEvaluationDocument(document);
  return [rescoreLoaded(loaded, profile, document), rescoreLoaded(loaded, profile)];
}

function assertCoverage(row, measured, unknown, mean) {
  assert.equal(row.cost_count, measured);
  assert.equal(row.cost_unknown_count, unknown);
  assert.equal(row.cost_complete, mean !== null);
  assert.equal(row.mean_cost, mean);
}

test("missing, null and non-finite costs stay unknown in runs and summaries", () => {
  for (const cost of [undefined, null, NaN, Infinity, -Infinity, "0"]) {
    for (const document of [{ runs: [run("unknown", cost)] }, {
      profile_summaries: [summary("unknown", cost, 9000, 3)],
    }]) {
      const loaded = loadEvaluationDocument(document);
      const count = document.runs ? 1 : 3;
      assert.equal(loaded.rows[0].cost_count, 0);
      assert.equal(loaded.rows[0].cost_unknown_count, count);
      for (const preview of previews(document)) {
        assertCoverage(preview.rows[0], 0, count, null);
        assert.equal(preview.selection.profile_id, "unknown");
        assert.equal(preview.cost_unavailable_profiles, 1);
        assert.equal(preview.cost_selection_limited, false);
        assert.deepEqual(preview.frontier, []);
      }
    }
  }
});

test("mixed run coverage survives both rescore paths without becoming a complete mean", () => {
  const document = { runs: [run("partial", 2), run("partial", null), run("partial", 4)] };
  const loaded = loadEvaluationDocument(document);
  assert.equal(loaded.rows[0].cost_total, 6);
  assert.equal(loaded.rows[0].cost_count, 2);
  assert.equal(loaded.rows[0].cost_unknown_count, 1);
  for (const preview of previews(document)) {
    assert.equal(preview.rows[0].count, 3);
    assertCoverage(preview.rows[0], 2, 1, null);
    assert.equal(preview.selection.profile_id, "partial");
    assert.equal(preview.cost_unavailable_profiles, 1);
    assert.deepEqual(preview.frontier, []);
  }
  for (const preview of previews(document, costObjective)) assert.equal(preview.selection, null);
});

test("numeric zero and complete measured averages remain comparable", () => {
  for (const document of [{ runs: [run("free", 0), run("free", 0), run("paid", 2), run("paid", 4)] }, {
    profile_summaries: [summary("free", 0, 9000, 2), summary("paid", 3, 9000, 2)],
  }]) {
    for (const preview of previews(document, costObjective)) {
      assertCoverage(preview.rows[0], 2, 0, 0);
      assertCoverage(preview.rows[1], 2, 0, 3);
      assert.equal(preview.selection.profile_id, "free");
      assert.equal(preview.cost_unavailable_profiles, 0);
      assert.deepEqual(preview.frontier.map((row) => row.profile_id), ["free"]);
    }
  }
});

test("zero samples do not manufacture cost measurements even with a numeric summary mean", () => {
  for (const cost of [0, 3, null]) {
    const document = { profile_summaries: [summary("empty", cost, 9000, 0)] };
    const loaded = loadEvaluationDocument(document);
    assert.equal(loaded.rows[0].cost_count, 0);
    for (const preview of previews(document, costObjective)) {
      assert.equal(preview.rows[0].count, 0);
      assertCoverage(preview.rows[0], 0, 0, null);
      assert.equal(preview.selection, null);
      assert.deepEqual(preview.frontier, []);
    }
  }
});

test("unknown and partial costs cannot dominate or win cost-weighted selection", () => {
  const documents = [
    { runs: [run("unknown", null, 10000), run("partial", 0, 10000), run("partial", undefined, 10000), run("measured", 2, 8000)] },
    { profile_summaries: [summary("unknown", null, 10000), summary("measured", 2, 8000)] },
  ];
  for (const document of documents) {
    for (const preview of previews(document, costObjective)) {
      const measured = preview.rows.find((row) => row.profile_id === "measured");
      for (const row of preview.rows.filter((row) => row !== measured)) {
        assert.equal(dominatesCostQuality(row, measured), false);
        assert.equal(dominatesCostQuality(measured, row), false);
      }
      assert.equal(preview.selection.profile_id, "measured");
      assert.equal(preview.cost_selection_limited, true);
      assert.deepEqual(preview.frontier.map((row) => row.profile_id), ["measured"]);
    }
  }
  for (const document of [{ runs: [run("a", null), run("b", undefined)] }, {
    profile_summaries: [summary("a", null), summary("b", undefined)],
  }]) {
    for (const preview of previews(document, costObjective)) {
      assert.equal(preview.selection, null);
      assert.deepEqual(preview.frontier, []);
    }
  }
});

test("frontier preserves original rows in all six orderings around unknown costs", () => {
  const points = [["unknown", null, 10000], ["measured-better", 1, 9000], ["measured-dominated", 2, 8000]];
  const orders = permutations(points);
  assert.equal(orders.length, 6);
  for (const order of orders) {
    for (const document of [{ runs: order.map((args) => run(...args)) }, {
      profile_summaries: order.map((args) => summary(...args)),
    }]) {
      for (const preview of previews(document)) {
        const original = preview.rows.find((row) => row.profile_id === "measured-better");
        assert.equal(preview.frontier.length, 1, order.map(([id]) => id).join(","));
        assert.strictEqual(preview.frontier[0], original);
        assert.deepEqual(paretoFrontier(preview.rows), [original]);
      }
    }
  }
});

test("tied selection uses one total order in all six permutations through every rescore path", () => {
  const orders = permutations([["a-expensive", 2], ["b-unknown", null], ["c-free", 0]]);
  assert.equal(orders.length, 6);
  for (const order of orders) {
    for (const document of [{ runs: order.map((args) => run(...args)) }, {
      profile_summaries: order.map((args) => summary(...args)),
    }]) {
      for (const objective of [DEFAULT_OBJECTIVE, costObjective]) {
        for (const preview of previews(document, objective)) {
          assert.equal(preview.selection.profile_id, "c-free", order.map(([id]) => id).join(","));
          assert.ok(Number.isFinite(preview.selection.score));
        }
      }
    }
  }
});

test("all-unknown quality ties use profile ID and complete measured ties retain cost ordering", () => {
  for (const points of [
    [["c", null], ["a", undefined], ["b", Infinity]],
    [["a-expensive", 2], ["b-cheap", 1], ["c-free", 0]],
  ]) {
    const expected = points[0][1] === null ? "a" : "c-free";
    for (const order of permutations(points)) {
      for (const document of [{ runs: order.map((args) => run(...args)) }, {
        profile_summaries: order.map((args) => summary(...args)),
      }]) {
        for (const preview of previews(document)) assert.equal(preview.selection.profile_id, expected);
      }
    }
  }
  for (const document of [{ runs: [run("z", 1), run("a", 1)] }, {
    profile_summaries: [summary("z", 1), summary("a", 1)],
  }]) {
    for (const preview of previews(document)) assert.equal(preview.selection.profile_id, "a");
  }
});

test("unavailable cost does not override a better quality score in runs or summaries", () => {
  for (const cost of [undefined, null, NaN, Infinity]) {
    for (const document of [{ runs: [run("better", cost, 9500), run("free", 0, 9000)] }, {
      profile_summaries: [summary("better", cost, 9500), summary("free", 0, 9000)],
    }]) {
      for (const preview of previews(document)) assert.equal(preview.selection.profile_id, "better");
      for (const preview of previews(document, costObjective)) assert.equal(preview.selection.profile_id, "free");
    }
  }
  // Cost availability also leaves the existing latency/rework axes intact.
  const objective = cloneObjective(DEFAULT_OBJECTIVE);
  objective.axes = { quality: 0, cost: 0, latency: 50, rework: 50 };
  const document = { runs: [run("fast", null), run("slow", 0)] };
  document.runs[1].metrics.wall_time_ms = 100;
  document.runs[1].metrics.churn_count = 10;
  for (const preview of previews(document, objective)) assert.equal(preview.selection.profile_id, "fast");
});

test("non-finite aggregate costs remain unavailable for comparison", () => {
  for (const document of [{ runs: [run("overflow", Number.MAX_VALUE), run("overflow", Number.MAX_VALUE), run("measured", 2)] }, {
    profile_summaries: [summary("overflow", Number.MAX_VALUE, 9000, 2), summary("measured", 2)],
  }]) {
    for (const preview of previews(document, costObjective)) {
      assertCoverage(preview.rows[0], 2, 0, null);
      assert.equal(preview.selection.profile_id, "measured");
      assert.deepEqual(preview.frontier.map((row) => row.profile_id), ["measured"]);
    }
  }
  for (const cost of [NaN, Infinity, -Infinity, null, undefined]) {
    const rows = [
      { profile_id: "unknown", mean_cost: cost, preview_overall: 10000, mean_wall: 0, mean_churn: 0 },
      { profile_id: "measured", mean_cost: 1, preview_overall: 9000, mean_wall: 0, mean_churn: 0 },
    ];
    assert.equal(selectProfile(rows, DEFAULT_OBJECTIVE).profile_id, "unknown");
    assert.equal(selectProfile(rows, costObjective).profile_id, "measured");
    assert.deepEqual(paretoFrontier(rows), [rows[1]]);
  }
});

const viewSource = readFileSync(new URL("../src/views/objective-view.js", import.meta.url), "utf8");

function createView() {
  function element() {
    return {
      value: "", textContent: "", children: [], dataset: {}, className: "",
      appendChild(child) { this.children.push(child); },
      replaceChildren() { this.children = []; },
      addEventListener() {},
    };
  }
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement: element,
  };
  const context = { document, MacoScope: { objective: objectiveApi } };
  runInNewContext(viewSource, context);
  return {
    api: context.MacoScope.objectiveView,
    get: (id) => document.getElementById(id),
    rows: () => new Map(document.getElementById("objectiveBody").children.map((row) => [row.children[0].textContent, row])),
  };
}

test("view renders unknown coverage separately from zero and explains selection limits", () => {
  const view = createView();
  view.api.adoptDocument({ runs: [
    run("unknown", null), run("partial", 0), run("partial", undefined), run("free", 0),
    run("nan", NaN), run("infinite", Infinity), run("absent", undefined),
    run("overflow", Number.MAX_VALUE), run("overflow", Number.MAX_VALUE),
  ] }, "test");
  const rows = view.rows();
  for (const id of ["unknown", "nan", "infinite", "absent"]) {
    assert.equal(rows.get(id).children[3].textContent, "Unknown (0/1 measured; 1 unknown)");
    assert.equal(rows.get(id).dataset.frontier, undefined);
  }
  assert.equal(rows.get("partial").children[3].textContent, "Unknown (1/2 measured; 1 unknown)");
  assert.equal(rows.get("overflow").children[3].textContent, "Unknown (2/2 measured; 0 unknown; aggregate unavailable)");
  assert.equal(rows.get("free").children[3].textContent, "$0.0000 (1/1 measured; 0 unknown)");
  assert.equal(rows.get("free").dataset.frontier, "true");
  assert.match(view.get("objectiveNotice").textContent, /Cost unavailable for 6 profile\(s\)/);
  assert.match(view.get("objectiveNotice").textContent, /quality-only selection remains available without cost evidence/);
  assert.match(view.get("objectiveNotice").textContent, /cannot establish a cost\/quality frontier/);
  view.get("axisCost").value = "60";
  view.api.renderPreview();
  assert.match(view.get("objectiveNotice").textContent, /cost-weighted selection excludes profiles without complete measured cost coverage/);
  assert.match(view.get("objectiveWinner").textContent, /Preview pick: free/);
  for (const document of [{ runs: [run("unknown", null)] }, {
    profile_summaries: [summary("unknown", undefined)],
  }]) {
    view.api.adoptDocument(document, "test");
    assert.match(view.get("objectiveWinner").textContent, /No selectable profile: cost-weighted selection requires complete measured cost coverage/);
    view.get("axisCost").value = "0";
    view.api.renderPreview();
    assert.match(view.get("objectiveWinner").textContent, /Preview pick: unknown/);
    assert.equal(view.rows().get("unknown").children[3].textContent, "Unknown (0/1 measured; 1 unknown)");
    view.get("axisCost").value = "60";
  }
});

test("view selects measured zero consistently across all six tied input permutations", () => {
  const orders = permutations([["a-expensive", 2], ["b-unknown", null], ["c-free", 0]]);
  assert.equal(orders.length, 6);
  for (const order of orders) {
    for (const document of [{ runs: order.map((args) => run(...args)) }, {
      profile_summaries: order.map((args) => summary(...args)),
    }]) {
      const view = createView();
      view.api.adoptDocument(document, "test");
      for (const cost of ["0", "60"]) {
        view.get("axisCost").value = cost;
        view.api.renderPreview();
        assert.match(view.get("objectiveWinner").textContent, /Preview pick: c-free/);
        assert.equal(view.rows().get("c-free").className, "is-selected");
        assert.equal(view.rows().get("a-expensive").className, "");
        assert.equal(view.rows().get("b-unknown").className, "");
        assert.equal(view.rows().get("c-free").children[3].textContent, "$0.0000 (1/1 measured; 0 unknown)");
      }
    }
  }
});

(function () {
  "use strict";

  var objective = globalThis.MacoScope && globalThis.MacoScope.objective;
  if (!objective) return;

  var root = document.getElementById("objectiveView");
  if (!root) return;

  var state = {
    document: null,
    loaded: null,
    profile: objective.cloneObjective(objective.DEFAULT_OBJECTIVE),
  };

  var fileInput = document.getElementById("objectiveFile");
  var demoButton = document.getElementById("objectiveDemo");
  var exportButton = document.getElementById("objectiveExport");
  var status = document.getElementById("objectiveStatus");
  var error = document.getElementById("objectiveError");
  var tableBody = document.getElementById("objectiveBody");
  var winner = document.getElementById("objectiveWinner");
  var notice = document.getElementById("objectiveNotice");
  var qualitySum = document.getElementById("qualityWeightSum");
  var axisSum = document.getElementById("axisWeightSum");

  var fields = {
    id: document.getElementById("objectiveId"),
    label: document.getElementById("objectiveLabel"),
    held: document.getElementById("weightHeldOut"),
    breadth: document.getElementById("weightBreadth"),
    anti: document.getElementById("weightAntiShortcut"),
    quality: document.getElementById("axisQuality"),
    cost: document.getElementById("axisCost"),
    latency: document.getElementById("axisLatency"),
    rework: document.getElementById("axisRework"),
  };

  function setStatus(message) {
    if (status) status.textContent = message || "";
  }

  function setError(message) {
    if (error) error.textContent = message || "";
  }

  function readProfile() {
    return objective.cloneObjective({
      id: fields.id ? fields.id.value : state.profile.id,
      version: 1,
      label: fields.label ? fields.label.value : state.profile.label,
      quality: {
        held_out: fields.held ? Number(fields.held.value) : 50,
        breadth: fields.breadth ? Number(fields.breadth.value) : 25,
        anti_shortcut: fields.anti ? Number(fields.anti.value) : 25,
      },
      axes: {
        quality: fields.quality ? Number(fields.quality.value) : 100,
        cost: fields.cost ? Number(fields.cost.value) : 0,
        latency: fields.latency ? Number(fields.latency.value) : 0,
        rework: fields.rework ? Number(fields.rework.value) : 0,
      },
    });
  }

  function writeProfile(profile) {
    state.profile = objective.cloneObjective(profile);
    if (fields.id) fields.id.value = state.profile.id;
    if (fields.label) fields.label.value = state.profile.label;
    if (fields.held) fields.held.value = String(state.profile.quality.held_out);
    if (fields.breadth) fields.breadth.value = String(state.profile.quality.breadth);
    if (fields.anti) fields.anti.value = String(state.profile.quality.anti_shortcut);
    if (fields.quality) fields.quality.value = String(state.profile.axes.quality);
    if (fields.cost) fields.cost.value = String(state.profile.axes.cost);
    if (fields.latency) fields.latency.value = String(state.profile.axes.latency);
    if (fields.rework) fields.rework.value = String(state.profile.axes.rework);
    if (qualitySum) qualitySum.textContent = String(objective.qualityWeightSum(state.profile));
    if (axisSum) axisSum.textContent = String(objective.axisWeightSum(state.profile));
  }

  function formatBp(value) {
    return (Math.round(value * 10) / 10).toFixed(1);
  }

  function formatUsd(value) {
    return "$" + value.toFixed(4);
  }

  function renderPreview() {
    state.profile = readProfile();
    if (qualitySum) qualitySum.textContent = String(objective.qualityWeightSum(state.profile));
    if (axisSum) axisSum.textContent = String(objective.axisWeightSum(state.profile));
    if (!state.loaded) {
      if (tableBody) {
        tableBody.replaceChildren();
        var empty = document.createElement("tr");
        var cell = document.createElement("td");
        cell.colSpan = 6;
        cell.className = "table-empty";
        cell.textContent = "Load an evaluation summary or results JSON to preview scores.";
        empty.appendChild(cell);
        tableBody.appendChild(empty);
      }
      if (winner) winner.textContent = "No evaluation loaded.";
      return;
    }
    var preview = objective.rescoreLoaded(state.loaded, state.profile, state.document);
    setError(preview.errors.join(" "));
    if (winner) {
      if (preview.errors.length) {
        winner.textContent = "Fix the profile before a selection can be previewed.";
      } else if (preview.selection) {
        winner.textContent =
          "Preview pick: " +
          preview.selection.profile_id +
          "  (score " +
          preview.selection.score.toFixed(4) +
          ")";
      } else {
        winner.textContent = "No selectable profile.";
      }
    }
    if (notice) {
      var bits = [];
      bits.push("Source: " + state.loaded.source);
      if (state.loaded.pareto_status) bits.push("recorded Pareto: " + state.loaded.pareto_status);
      if (preview.labeled_preview) {
        bits.push("labelled preview — document is not eligible for production decisions");
      }
      bits.push("client holds no authority; nothing is written");
      notice.textContent = bits.join(" · ");
    }
    if (!tableBody) return;
    tableBody.replaceChildren();
    preview.rows
      .slice()
      .sort(function (left, right) {
        return right.preview_overall - left.preview_overall;
      })
      .forEach(function (row) {
        var tr = document.createElement("tr");
        if (preview.selection && row.profile_id === preview.selection.profile_id) {
          tr.className = "is-selected";
        }
        if (preview.frontier.some(function (point) { return point.profile_id === row.profile_id; })) {
          tr.dataset.frontier = "true";
        }
        function td(text) {
          var cell = document.createElement("td");
          cell.textContent = text;
          tr.appendChild(cell);
        }
        td(row.profile_id);
        td(formatBp(row.recorded_overall));
        td(formatBp(row.preview_overall));
        td(formatUsd(row.mean_cost));
        td(preview.selection && row.profile_id === preview.selection.profile_id
          ? preview.selection.score.toFixed(4)
          : "—");
        td(tr.dataset.frontier === "true" ? "frontier" : "");
        tableBody.appendChild(tr);
      });
  }

  function adoptDocument(document, label) {
    state.document = document;
    state.loaded = objective.loadEvaluationDocument(document);
    setStatus(
      "Loaded " +
        state.loaded.experiment_id +
        " (" +
        state.loaded.rows.length +
        " profiles, " +
        label +
        ")",
    );
    setError("");
    renderPreview();
  }

  function demoDocument() {
    return {
      version: 3,
      experiment_id: "scope-ui-demo-v1",
      evidence: {
        kind: "client_demo_fixture",
        eligible_for_production_or_default_decisions: false,
      },
      pareto_conclusion: { status: "available" },
      profile_summaries: [
        {
          profile_id: "frontier-all-v1",
          repetitions: 3,
          mean_cost_usd: 0.0367,
          mean_wall_time_ms: { total: 1442455, count: 3 },
          mean_churn_count: { total: 18, count: 3 },
          mean_quality: {
            held_out_basis_points: { total: 26180, count: 3 },
            breadth_basis_points: { total: 30000, count: 3 },
            anti_shortcut_basis_points: { total: 19998, count: 3 },
            overall_basis_points: { total: 25589, count: 3 },
          },
          pareto_optimal: true,
        },
        {
          profile_id: "balanced-all-v1",
          repetitions: 3,
          mean_cost_usd: 0.0748,
          mean_wall_time_ms: { total: 1515474, count: 3 },
          mean_churn_count: { total: 20, count: 3 },
          mean_quality: {
            held_out_basis_points: { total: 25695, count: 3 },
            breadth_basis_points: { total: 26250, count: 3 },
            anti_shortcut_basis_points: { total: 24999, count: 3 },
            overall_basis_points: { total: 25659, count: 3 },
          },
          pareto_optimal: true,
        },
        {
          profile_id: "economy-all-v1",
          repetitions: 3,
          mean_cost_usd: 0.0803,
          mean_wall_time_ms: { total: 2195314, count: 3 },
          mean_churn_count: { total: 15, count: 3 },
          mean_quality: {
            held_out_basis_points: { total: 23271, count: 3 },
            breadth_basis_points: { total: 22500, count: 3 },
            anti_shortcut_basis_points: { total: 15000, count: 3 },
            overall_basis_points: { total: 21010, count: 3 },
          },
          pareto_optimal: false,
        },
      ],
    };
  }

  if (fileInput) {
    fileInput.addEventListener("change", function () {
      var file = fileInput.files && fileInput.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        try {
          adoptDocument(JSON.parse(String(reader.result || "")), file.name);
        } catch (cause) {
          setError("Could not parse evaluation JSON: " + cause.message);
        }
      };
      reader.readAsText(file);
    });
  }

  if (demoButton) {
    demoButton.addEventListener("click", function () {
      adoptDocument(demoDocument(), "built-in demo");
    });
  }

  if (exportButton) {
    exportButton.addEventListener("click", function () {
      var profile = readProfile();
      var blob = new Blob([JSON.stringify(profile, null, 2) + "\n"], {
        type: "application/json",
      });
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = profile.id + ".json";
      link.click();
      URL.revokeObjectURL(url);
    });
  }

  Object.keys(fields).forEach(function (key) {
    var element = fields[key];
    if (!element) return;
    element.addEventListener("input", renderPreview);
    element.addEventListener("change", renderPreview);
  });

  writeProfile(state.profile);
  renderPreview();

  globalThis.MacoScope.objectiveView = {
    adoptDocument: adoptDocument,
    renderPreview: renderPreview,
    demoDocument: demoDocument,
  };
})();

(function () {
  "use strict";

  var catalog = globalThis.MacoScope && globalThis.MacoScope.catalog;
  var api = globalThis.MacoScope && globalThis.MacoScope.api;
  if (!catalog || !api) return;

  var root = document.getElementById("catalogView");
  if (!root) return;

  var body = document.getElementById("catalogBody");
  var summary = document.getElementById("catalogSummary");
  var error = document.getElementById("catalogError");
  var refresh = document.getElementById("catalogRefresh");

  function showError(message) {
    if (error) error.textContent = message || "";
  }

  function render(projects) {
    var rows = catalog.catalogRows(projects);
    var stats = catalog.catalogSummary(rows);
    if (summary) {
      summary.textContent =
        stats.repositories +
        " repositories · " +
        stats.runs +
        " runs · " +
        stats.events +
        " events · " +
        stats.finalReports +
        " final reports";
    }
    if (!body) return;
    body.replaceChildren();
    if (!rows.length) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = 6;
      cell.className = "table-empty";
      cell.textContent = "No watched repositories were discovered.";
      empty.appendChild(cell);
      body.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      if (row.empty) tr.className = "catalog-empty-repo";
      function td(text) {
        var cell = document.createElement("td");
        cell.textContent = text;
        tr.appendChild(cell);
        return cell;
      }
      td(row.repo);
      td(row.family || "—");
      td(row.run || "—");
      td(row.empty ? "—" : String(row.eventCount));
      td(row.empty ? "no runs" : row.finalReport ? "yes" : "no");
      var action = document.createElement("td");
      if (!row.empty) {
        var link = document.createElement("a");
        link.href = catalog.liveHref(row);
        link.textContent = "Open live";
        action.appendChild(link);
      } else {
        action.textContent = "—";
      }
      tr.appendChild(action);
      body.appendChild(tr);
    });
  }

  async function load() {
    showError("");
    try {
      var projects = await api.fetchProjects();
      render(projects);
    } catch (cause) {
      render([]);
      showError("Could not load projects: " + cause.message);
    }
  }

  // --- Local switch-cost evidence import (client-only, read-only) ---------
  var evidence = {
    artifacts: [],
    merged: null,
    grouping: "resolved",
  };
  var evidenceImportGeneration = 0;

  var evidenceFiles = document.getElementById("evidenceFiles");
  var evidenceGrouping = document.getElementById("evidenceGrouping");
  var evidenceClear = document.getElementById("evidenceClear");
  var evidenceStatus = document.getElementById("evidenceStatus");
  var evidenceError = document.getElementById("evidenceError");
  var evidenceNotice = document.getElementById("evidenceNotice");
  var evidenceBody = document.getElementById("evidenceBody");
  var invocationChart = document.getElementById("invocationChart");
  var tokenChart = document.getElementById("tokenChart");
  var invocationChartTitle = document.getElementById("invocationChartTitle");
  var tokenChartTitle = document.getElementById("tokenChartTitle");
  var invocationChartNote = document.getElementById("invocationChartNote");
  var tokenChartNote = document.getElementById("tokenChartNote");

  function setEvidenceError(message) {
    if (evidenceError) evidenceError.textContent = message || "";
  }

  function setEvidenceNotice(message) {
    if (evidenceNotice) evidenceNotice.textContent = message || "";
  }

  function setEvidenceStatus(message) {
    if (evidenceStatus) evidenceStatus.textContent = message || "";
  }

  function chartRow(label, valueText, share, unavailable) {
    var row = document.createElement("div");
    row.className = unavailable ? "chart-row is-unavailable" : "chart-row";
    var name = document.createElement("span");
    name.className = "chart-label";
    name.textContent = label;
    var track = document.createElement("span");
    track.className = "chart-track";
    var fill = document.createElement("span");
    fill.className = "chart-fill";
    var width = share == null || !isFinite(share) ? 0 : Math.max(0, Math.min(100, share));
    fill.style.width = width + "%";
    track.appendChild(fill);
    var value = document.createElement("span");
    value.className = "chart-value";
    value.textContent = valueText;
    row.appendChild(name);
    row.appendChild(track);
    row.appendChild(value);
    return row;
  }

  function renderChart(container, rows, valueOf, shareOf, emptyText, unavailableOf) {
    if (!container) return;
    container.replaceChildren();
    if (!rows.length) {
      var empty = document.createElement("p");
      empty.className = "chart-empty";
      empty.textContent = emptyText;
      container.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      container.appendChild(
        chartRow(row.label, valueOf(row), shareOf(row), unavailableOf ? unavailableOf(row) : false),
      );
    });
  }

  // A group with no measured usage has no token value at all: show the
  // unavailable marker rather than a fabricated zero.
  function tokenValueText(row) {
    if (row.measuredInvocations === 0) return "unavailable";
    return catalog.formatExactCount(row.tokensExact);
  }

  function tokenShareText(row) {
    if (row.measuredInvocations === 0) return "—";
    return catalog.formatPercent(row.tokenShare);
  }

  function renderEvidence() {
    var merged = evidence.merged;
    var groups = catalog.evidenceGroups(merged ? merged.records : [], evidence.grouping);
    var summary = catalog.evidenceSummary(merged ? merged.records : []);
    var groupingLabel = catalog.modelGroupingLabel(evidence.grouping);
    var groupHeading = document.getElementById("evidenceGroupHeading");
    if (groupHeading) groupHeading.textContent = groupingLabel;
    if (invocationChart) invocationChart.setAttribute("aria-label", "Recorded invocations by " + groupingLabel.toLowerCase());
    if (tokenChart) tokenChart.setAttribute("aria-label", "Measured tokens by " + groupingLabel.toLowerCase());

    if (invocationChartTitle) {
      invocationChartTitle.textContent = "Recorded invocations by " + groupingLabel.toLowerCase();
    }
    if (tokenChartTitle) {
      tokenChartTitle.textContent =
        "Measured input + output tokens by " + groupingLabel.toLowerCase();
    }

    renderChart(
      invocationChart,
      groups.rows,
      function (row) {
        return (
          catalog.formatCount(row.invocations) +
          " · " +
          catalog.formatPercent(row.invocationShare)
        );
      },
      function (row) {
        return row.invocationShare;
      },
      "No invocations imported.",
    );

    renderChart(
      tokenChart,
      groups.rows,
      function (row) {
        return tokenValueText(row) + " · " + tokenShareText(row);
      },
      function (row) {
        return row.tokenShare;
      },
      "No measured tokens imported.",
      function (row) {
        return row.measuredInvocations === 0;
      },
    );

    if (invocationChartNote) {
      invocationChartNote.textContent =
        catalog.formatCount(groups.totalInvocations) +
        " recorded invocations across " +
        catalog.formatCount(summary.runs) +
        " optimization runs. Shares are of the supplied artifacts only.";
    }
    if (tokenChartNote) {
      tokenChartNote.textContent =
        "Token shares are over the known measured subtotal of " +
        catalog.formatExactCount(groups.measuredTokensExact) +
        " tokens; " +
        catalog.formatCount(groups.measuredInvocations) +
        " of " +
        catalog.formatCount(groups.totalInvocations) +
        " invocations have measured usage (" +
        catalog.formatPercent(groups.tokenCoverage) +
        " coverage). Unknown usage is excluded, never counted as zero.";
    }

    if (evidenceBody) {
      evidenceBody.replaceChildren();
      if (!groups.rows.length) {
        var emptyRow = document.createElement("tr");
        var emptyCell = document.createElement("td");
        emptyCell.colSpan = 6;
        emptyCell.className = "table-empty";
        emptyCell.textContent = "Import a live-evidence.json artifact to chart invocations.";
        emptyRow.appendChild(emptyCell);
        evidenceBody.appendChild(emptyRow);
      } else {
        groups.rows.forEach(function (row) {
          var tr = document.createElement("tr");
          function td(text) {
            var cell = document.createElement("td");
            cell.textContent = text;
            tr.appendChild(cell);
          }
          td(row.label);
          td(catalog.formatCount(row.invocations));
          td(catalog.formatPercent(row.invocationShare));
          td(catalog.formatCount(row.measuredInvocations));
          td(tokenValueText(row));
          td(tokenShareText(row));
          evidenceBody.appendChild(tr);
        });
      }
    }

    if (merged) {
      setEvidenceStatus(
        catalog.formatCount(summary.invocations) +
          " invocations · " +
          catalog.formatCount(merged.artifacts) +
          " artifacts · " +
          catalog.formatCount(merged.duplicates) +
          " duplicates collapsed",
      );
      var notices = [];
      (merged.collections || []).forEach(function (collection) {
        var values = [];
        ["files_scanned", "artifacts_parsed", "identical_duplicates"].forEach(function (field) {
          if (typeof collection[field] === "number" && isFinite(collection[field])) {
            values.push(field + ": " + collection[field]);
          }
        });
        ["invalid_artifacts", "conflicts", "external_sources"].forEach(function (field) {
          if (Array.isArray(collection[field])) values.push(field + ": " + collection[field].length);
        });
        notices.push("Collection" + (values.length ? ": " + values.join(", ") : " summary present") + ".");
      });
      if (summary.roles.length) notices.push("Roles present: " + summary.roles.join(", ") + ".");
      if (summary.unknownUsageInvocations > 0) {
        notices.push(
          catalog.formatCount(summary.unknownUsageInvocations) +
            " invocations have unknown or partial usage and are excluded from token mass.",
        );
      }
      if (merged.conflicts > 0) {
        notices.push(
          catalog.formatCount(merged.conflicts) +
            " conflicts found; all rows with those identities were excluded.",
        );
      }
      if (merged.rejectedArtifacts > 0) {
        notices.push(
          catalog.formatCount(merged.rejectedArtifacts) +
            " rejected artifacts contributed no records.",
        );
      }
      setEvidenceNotice(notices.join(" "));
    } else {
      setEvidenceStatus("No artifacts imported");
      setEvidenceNotice("");
    }
  }

  function readFileText(file) {
    if (typeof file.text === "function") return file.text();
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        resolve(String(reader.result || ""));
      };
      reader.onerror = function () {
        reject(reader.error || new Error("could not read file"));
      };
      reader.readAsText(file);
    });
  }

  async function importFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length) return;
    var generation = evidenceImportGeneration;
    setEvidenceError("");
    var loaded = [];
    var failures = [];
    for (var index = 0; index < files.length; index += 1) {
      var file = files[index];
      var label = file && file.name ? String(file.name) : "artifact " + (index + 1);
      try {
        var text = await readFileText(file);
        loaded.push({ label: label, text: text });
      } catch (cause) {
        failures.push(label + ": could not be read (" + cause.message + ")");
      }
      if (generation !== evidenceImportGeneration) return;
    }
    evidence.artifacts = evidence.artifacts.concat(loaded);
    evidence.merged = catalog.mergeEvidenceArtifacts(evidence.artifacts);
    var messages = failures.concat(evidence.merged.errors || []);
    setEvidenceError(messages.join(" "));
    renderEvidence();
  }

  function clearEvidence() {
    evidenceImportGeneration += 1;
    evidence.artifacts = [];
    evidence.merged = null;
    setEvidenceError("");
    if (evidenceFiles) evidenceFiles.value = "";
    renderEvidence();
  }

  if (evidenceFiles) {
    evidenceFiles.addEventListener("change", function (event) {
      importFiles(event.target.files);
    });
  }
  if (evidenceGrouping) {
    evidenceGrouping.addEventListener("change", function (event) {
      evidence.grouping = catalog.MODEL_GROUPINGS.includes(event.target.value) ? event.target.value : "resolved";
      renderEvidence();
    });
  }
  if (evidenceClear) evidenceClear.addEventListener("click", clearEvidence);

  renderEvidence();

  if (refresh) refresh.addEventListener("click", load);
  document.addEventListener("maco-scope-page", function (event) {
    if (event.detail && event.detail.page === "catalog") load();
  });

  globalThis.MacoScope.catalogView = {
    load: load,
    render: render,
    importFiles: importFiles,
    clearEvidence: clearEvidence,
    renderEvidence: renderEvidence,
    evidenceState: evidence,
  };
})();

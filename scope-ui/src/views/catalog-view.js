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

  if (refresh) refresh.addEventListener("click", load);
  document.addEventListener("maco-scope-page", function (event) {
    if (event.detail && event.detail.page === "catalog") load();
  });

  globalThis.MacoScope.catalogView = { load: load, render: render };
})();

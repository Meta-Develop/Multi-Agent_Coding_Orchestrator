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

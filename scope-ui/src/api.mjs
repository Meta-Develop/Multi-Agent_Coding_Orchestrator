// Read-only Scope HTTP client. The GUI holds no authority.

export async function fetchProjects(fetcher = fetch) {
  const response = await fetcher("/api/projects", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("projects request returned HTTP " + response.status);
  }
  const snapshot = await response.json();
  return Array.isArray(snapshot.projects) ? snapshot.projects : [];
}

export async function fetchRunEvents(repo, family, run, fetcher = fetch) {
  const path =
    "/api/runs/" +
    encodeURIComponent(repo) +
    "/" +
    encodeURIComponent(family) +
    "/" +
    encodeURIComponent(run) +
    "/events";
  const response = await fetcher(path, { cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error("run events request returned HTTP " + response.status);
  }
  const events = await response.json();
  return Array.isArray(events) ? events : [];
}

export function streamUrl(filter, mode) {
  const params = new URLSearchParams();
  if (filter && filter.repo) params.set("repo", filter.repo);
  if (filter && filter.family) params.set("family", filter.family);
  if (filter && filter.run) params.set("run", filter.run);
  if (mode === "archive") params.set("since", "0");
  return "/api/stream" + (params.toString() ? "?" + params.toString() : "");
}

export function parseProjectsPayload(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return [];
  return Array.isArray(snapshot.projects) ? snapshot.projects : [];
}

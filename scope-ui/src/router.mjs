// Hash router. Uses #/page so it does not collide with the live view's
// ?view=session|repository|combined graph-projection query.

export const PAGES = ["live", "catalog", "objective"];

export function parseHash(hash) {
  const raw = String(hash || "");
  const trimmed = raw.startsWith("#") ? raw.slice(1) : raw;
  const [pathPart, queryPart] = trimmed.split("?");
  const path = pathPart.replace(/^\/+/, "");
  const page = PAGES.includes(path) ? path : "live";
  const params = new URLSearchParams(queryPart || "");
  return { page, params };
}

export function hrefFor(page, params) {
  const normalized = PAGES.includes(page) ? page : "live";
  const query = params && [...params].length ? "?" + params.toString() : "";
  return "#/" + normalized + query;
}

export function pageFromLocation(location) {
  return parseHash(location && location.hash).page;
}

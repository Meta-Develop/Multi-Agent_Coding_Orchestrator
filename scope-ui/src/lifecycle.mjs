// Shared lifecycle mapping for Scope events. Pure; no DOM.

export const DEFAULT_STATUS = "pending";

const RUNNING = ["running", "active", "in_progress", "started", "retrying"];
const PENDING = ["pending", "ready", "waiting", "idle"];
const QUEUED = ["queued", "escalation_pending", "requested"];
const ACCEPTED = [
  "accepted",
  "accept",
  "safe",
  "approved",
  "passed",
  "pass",
  "succeeded",
  "success",
];
const REJECTED = ["rejected", "reject", "failed", "fail", "failure"];
const BLOCKED = ["blocked", "unsafe", "error"];
const DONE = ["done", "complete", "completed", "finished", "closed", "released", "skipped"];

export function normalizedStatus(value) {
  const raw = String(value || "")
    .toLowerCase()
    .replace(/[- ]/g, "_");
  if (RUNNING.includes(raw)) return "running";
  if (PENDING.includes(raw)) return "pending";
  if (QUEUED.includes(raw)) return "queued";
  if (ACCEPTED.includes(raw)) return "accepted";
  if (REJECTED.includes(raw)) return "rejected";
  if (BLOCKED.includes(raw)) return "blocked";
  if (DONE.includes(raw)) return "done";
  return null;
}

export function explicitLifecycleStatus(payload, fields) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const containers = [payload];
  ["report", "validation", "state", "heartbeat"].forEach((key) => {
    if (payload[key] && typeof payload[key] === "object" && !Array.isArray(payload[key])) {
      containers.push(payload[key]);
    }
  });
  const fieldOrder = fields || ["to", "status", "result", "readiness", "state"];
  for (const container of containers) {
    for (const field of fieldOrder) {
      const status = normalizedStatus(container[field]);
      if (status) return status;
    }
  }
  return null;
}

export function lifecycleStatus(payload, previous, fields) {
  return explicitLifecycleStatus(payload, fields) || previous || DEFAULT_STATUS;
}

export function failedGate(detail) {
  return (
    detail.blocked === true ||
    detail.success === false ||
    detail.accepted === false ||
    detail.rejected === true ||
    (Array.isArray(detail.blockers) && detail.blockers.length > 0)
  );
}

export function passedGate(detail) {
  return detail.success === true || detail.accepted === true;
}

export function gateDetail(payload) {
  return payload.validation &&
    typeof payload.validation === "object" &&
    !Array.isArray(payload.validation)
    ? payload.validation
    : payload;
}

export function gateStatus(detail, previous) {
  if (failedGate(detail)) return "blocked";
  const explicit = explicitLifecycleStatus(detail, [
    "status",
    "readiness",
    "result",
    "to",
    "state",
  ]);
  if (explicit === "rejected") return "blocked";
  if (explicit) return explicit;
  if (passedGate(detail)) return "accepted";
  return previous || DEFAULT_STATUS;
}

export function statusFromEvent(event, previous) {
  const payload = event.payload && typeof event.payload === "object" ? event.payload : {};
  if (event.kind === "accept") return "accepted";
  if (event.kind === "reject") {
    return explicitLifecycleStatus(payload) === "blocked" ? "blocked" : "rejected";
  }
  if (event.kind === "escalate") return "queued";
  if (event.kind === "gate") return gateStatus(gateDetail(payload), previous);
  if (event.kind === "spawn") {
    return lifecycleStatus(payload, event.role === "supervisor" ? "running" : DEFAULT_STATUS);
  }
  if (event.kind === "status" || event.kind === "claim") {
    return lifecycleStatus(payload, previous);
  }
  return previous || DEFAULT_STATUS;
}

export function displayRole(event) {
  if (event.role === "root") return "root";
  if (event.role === "supervisor") return "o2";
  if (event.role === "orchestrator") return "o1";
  if (event.role === "auditor") return "auditor";
  return "worker";
}

export function arrayStrings(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === "string" && item);
}

export function coverageEvidence(event, payload) {
  let targets = [];
  const containers = [event, payload];
  ["report", "audit", "review", "evidence"].forEach((key) => {
    if (payload[key] && typeof payload[key] === "object" && !Array.isArray(payload[key])) {
      containers.push(payload[key]);
    }
  });
  containers.forEach((container) => {
    ["covers", "coverage", "covered_nodes", "worker_ids", "reviewed_worker_ids"].forEach(
      (key) => {
        targets = targets.concat(arrayStrings(container[key]));
      },
    );
  });
  return Array.from(new Set(targets));
}

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  displayRole,
  gateStatus,
  normalizedStatus,
  statusFromEvent,
} from "../src/lifecycle.mjs";

test("normalizedStatus maps common lifecycle vocabularies", () => {
  assert.equal(normalizedStatus("in-progress"), "running");
  assert.equal(normalizedStatus("escalation_pending"), "queued");
  assert.equal(normalizedStatus("approved"), "accepted");
  assert.equal(normalizedStatus("fail"), "rejected");
  assert.equal(normalizedStatus("unsafe"), "blocked");
  assert.equal(normalizedStatus("finished"), "done");
  assert.equal(normalizedStatus("mystery"), null);
});

test("statusFromEvent prefers kind then payload", () => {
  assert.equal(statusFromEvent({ kind: "accept", payload: {} }), "accepted");
  assert.equal(statusFromEvent({ kind: "escalate", payload: {} }), "queued");
  assert.equal(
    statusFromEvent({ kind: "reject", payload: { status: "blocked" } }),
    "blocked",
  );
  assert.equal(
    statusFromEvent({
      kind: "spawn",
      role: "supervisor",
      payload: {},
    }),
    "running",
  );
  assert.equal(
    statusFromEvent({ kind: "status", payload: { to: "succeeded" } }, "pending"),
    "accepted",
  );
});

test("gateStatus fails closed on blockers", () => {
  assert.equal(gateStatus({ blockers: ["dirty tree"] }), "blocked");
  assert.equal(gateStatus({ success: true }), "accepted");
  assert.equal(gateStatus({}), "pending");
});

test("displayRole projects MACO roles onto the live canvas vocabulary", () => {
  assert.equal(displayRole({ role: "supervisor" }), "o2");
  assert.equal(displayRole({ role: "orchestrator" }), "o1");
  assert.equal(displayRole({ role: "auditor" }), "auditor");
  assert.equal(displayRole({ role: "worker" }), "worker");
});

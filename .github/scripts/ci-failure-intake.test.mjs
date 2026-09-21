import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { EXPECTED_WORKFLOW_NAMES, reconcileCiFailureIntake } = require(
  "./ci-failure-intake.js",
);

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOW_PATH = join(HERE, "..", "workflows", "ci-failure-intake.yml");
const OWNER = "Meta-Develop";
const REPO = "Multi-Agent_Coding_Orchestrator";
const REPOSITORY_NAME = `${OWNER}/${REPO}`;
const BRANCH = "main";
const SHA = "a5c66ad5537b7cbf1582dc1b56ec755a79876be8";
const OTHER_SHA = "d67b463000000000000000000000000000000001";
const RUST_WORKFLOW_ID = 1001;
const ACCOUNT_MANAGER_WORKFLOW_ID = 2002;

function extractTriggeredWorkflows(source) {
  const lines = source.split(/\r?\n/);
  const names = [];
  let taking = false;
  let indent = 0;
  for (const line of lines) {
    const workflowsMatch = line.match(/^(\s*)workflows:\s*$/);
    if (workflowsMatch) {
      taking = true;
      indent = workflowsMatch[1].length;
      continue;
    }
    if (!taking) {
      continue;
    }
    const current = line.match(/^(\s*)(.*)$/);
    const currentIndent = current[1].length;
    const text = current[2];
    if (text === "" || text.startsWith("#")) {
      continue;
    }
    if (currentIndent <= indent) {
      break;
    }
    const item = text.match(/^-\s*"([^"]+)"\s*$/);
    if (!item) {
      throw new Error(`Cannot parse workflows entry: ${line}`);
    }
    names.push(item[1]);
  }
  if (names.length === 0) {
    throw new Error("workflow_run.workflows list is empty or missing");
  }
  return names;
}

function markerFor(workflowId, branch = BRANCH) {
  const markerTuple = JSON.stringify([
    "workflow_id",
    workflowId,
    "branch",
    branch,
  ]);
  return `<!-- public-repo-ci-failure:v1:${Buffer.from(markerTuple, "utf8").toString(
    "base64url",
  )} -->`;
}

function evidenceMarkerFor(run) {
  const evidenceTuple = JSON.stringify([
    "run_id",
    run.id,
    "run_number",
    run.run_number,
    "run_attempt",
    run.run_attempt,
    "head_sha",
    String(run.head_sha).toLowerCase(),
  ]);
  return `<!-- public-repo-ci-failure-evidence:v1:${Buffer.from(
    evidenceTuple,
    "utf8",
  ).toString("base64url")} -->`;
}

function trackedIssue(number, run, { state = "open", body } = {}) {
  return {
    number,
    state,
    body:
      body ??
      `${markerFor(run.workflow_id)}\n${evidenceMarkerFor(run)}\n`,
  };
}

function listedView(run) {
  return {
    id: run.id,
    name: run.name,
    workflow_id: run.workflow_id,
    head_branch: run.head_branch,
    head_sha: run.head_sha,
    run_number: run.run_number,
    run_attempt: run.run_attempt,
    conclusion: run.conclusion,
    status: run.status ?? "completed",
  };
}

function baseRun(overrides = {}) {
  const id = overrides.id ?? 101;
  const defaults = {
    id,
    name: "Rust CI",
    workflow_id: RUST_WORKFLOW_ID,
    head_branch: BRANCH,
    head_sha: SHA,
    run_number: id,
    run_attempt: 1,
    conclusion: "failure",
    status: "completed",
    repository: { full_name: REPOSITORY_NAME },
    head_repository: { full_name: REPOSITORY_NAME },
    html_url: `https://github.com/${REPOSITORY_NAME}/actions/runs/${id}`,
    jobs_url: `https://api.github.com/repos/${REPOSITORY_NAME}/actions/runs/${id}/jobs`,
  };
  return { ...defaults, ...overrides, id: overrides.id ?? id };
}

function createHarness({
  run,
  repository = { default_branch: BRANCH, full_name: REPOSITORY_NAME },
  tipSha = SHA,
  issues = [],
  workflowRuns,
  jobs = [],
  listWorkflowRunsError = null,
  listWorkflowRunsPayload = null,
  getBranchError = false,
} = {}) {
  const notices = [];
  const failures = [];
  const calls = [];
  let createdIssue = null;
  const listedRuns =
    workflowRuns === undefined ? [listedView(run)] : workflowRuns.map(listedView);

  const github = {
    paginate: async (_fn, params) => {
      calls.push({ method: "issues.listForRepo", params });
      return issues.map((issue) => ({ ...issue }));
    },
    rest: {
      repos: {
        getBranch: async (params) => {
          calls.push({ method: "repos.getBranch", params });
          if (getBranchError) {
            throw new Error("branch unavailable");
          }
          return { data: { commit: { sha: tipSha } } };
        },
      },
      issues: {
        listForRepo: Symbol("listForRepo"),
        getLabel: async (params) => {
          calls.push({ method: "issues.getLabel", params });
          return { data: { name: params.name } };
        },
        createLabel: async (params) => {
          calls.push({ method: "issues.createLabel", params });
          return { data: params };
        },
        create: async (params) => {
          calls.push({ method: "issues.create", params });
          createdIssue = {
            number: 501,
            state: "open",
            title: params.title,
            body: params.body,
            labels: params.labels,
          };
          return { data: createdIssue };
        },
        update: async (params) => {
          calls.push({ method: "issues.update", params });
          return { data: { number: params.issue_number } };
        },
        createComment: async (params) => {
          calls.push({ method: "issues.createComment", params });
          return { data: { id: 1 } };
        },
        addLabels: async (params) => {
          calls.push({ method: "issues.addLabels", params });
          return { data: [] };
        },
      },
      actions: {
        listWorkflowRuns: async (params) => {
          calls.push({ method: "actions.listWorkflowRuns", params });
          if (listWorkflowRunsError) {
            throw listWorkflowRunsError;
          }
          if (listWorkflowRunsPayload) {
            return { data: listWorkflowRunsPayload };
          }
          const page = params.page ?? 1;
          if (page !== 1) {
            return {
              data: { total_count: listedRuns.length, workflow_runs: [] },
            };
          }
          return {
            data: {
              total_count: listedRuns.length,
              workflow_runs: listedRuns,
            },
          };
        },
      },
    },
  };

  const fetch = async (url, init) => {
    calls.push({ method: "fetch", url: String(url), init });
    return {
      ok: true,
      status: 200,
      json: async () => ({ total_count: jobs.length, jobs }),
    };
  };

  return {
    github,
    context: {
      serverUrl: "https://github.com",
      apiUrl: "https://api.github.com",
      repo: { owner: OWNER, repo: REPO },
      payload: {
        workflow_run: run,
        repository,
      },
    },
    core: {
      notice: (message) => notices.push(String(message)),
      setFailed: (message) => failures.push(String(message)),
    },
    fetch,
    notices,
    failures,
    calls,
    get createdIssue() {
      return createdIssue;
    },
  };
}

async function runIntake(run, options = {}) {
  const harness = createHarness({ run, ...options });
  await reconcileCiFailureIntake({
    github: harness.github,
    context: harness.context,
    core: harness.core,
    fetch: harness.fetch,
  });
  return harness;
}

function callsOf(harness, method) {
  return harness.calls.filter((call) => call.method === method);
}

function mutationMethods(harness) {
  return harness.calls
    .map((call) => call.method)
    .filter((method) =>
      [
        "issues.create",
        "issues.update",
        "issues.createComment",
        "issues.addLabels",
        "issues.createLabel",
      ].includes(method),
    );
}

test("monitored workflow_run names match the expectedWorkflows allowlist", () => {
  const source = readFileSync(WORKFLOW_PATH, "utf8");
  assert.deepEqual(extractTriggeredWorkflows(source), [
    ...EXPECTED_WORKFLOW_NAMES,
  ]);
  assert.deepEqual([...EXPECTED_WORKFLOW_NAMES], [
    "Rust CI",
    "Supply-chain policy",
    "Minimum supported Rust version",
    "Account Manager CI",
  ]);
  assert.match(source, /actions:\s*read/);
  assert.match(
    source,
    /\.github\/scripts\/ci-failure-intake\.js/,
  );
});

test("ignores an unexpected workflow_run payload", async () => {
  const harness = await runIntake(
    baseRun({ name: "Secret scanning" }),
  );
  assert.deepEqual(harness.notices, [
    "Ignoring an unexpected workflow_run payload.",
  ]);
  assert.deepEqual(harness.failures, []);
  assert.deepEqual(mutationMethods(harness), []);
  assert.equal(callsOf(harness, "actions.listWorkflowRuns").length, 0);
});

test("ignores a foreign repository run", async () => {
  const harness = await runIntake(
    baseRun({
      repository: { full_name: "other/fork" },
      head_repository: { full_name: "other/fork" },
    }),
  );
  assert.deepEqual(harness.notices, [
    "Ignoring a workflow run from a foreign repository.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("ignores a non-default-branch workflow run", async () => {
  const harness = await runIntake(baseRun({ head_branch: "feature" }));
  assert.deepEqual(harness.notices, [
    "Ignoring a non-default-branch workflow run.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("ignores a workflow run that is no longer the default-branch tip", async () => {
  const harness = await runIntake(baseRun({ head_sha: OTHER_SHA }), {
    tipSha: SHA,
  });
  assert.deepEqual(harness.notices, [
    "Ignoring a workflow run that is no longer the default-branch tip.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
  assert.equal(callsOf(harness, "actions.listWorkflowRuns").length, 0);
});

test("fails closed when the workflow_run identity is incomplete", async () => {
  const harness = await runIntake(baseRun({ run_attempt: 0 }));
  assert.deepEqual(harness.failures, [
    "The workflow_run identity is incomplete or invalid.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("fails closed when authoritative run state is unavailable", async () => {
  const failed = baseRun({ id: 102, conclusion: "failure" });
  const openIssue = {
    number: 183,
    state: "open",
    body: `${markerFor(RUST_WORKFLOW_ID)}\n- Run URL: ${failed.html_url}\n`,
  };
  const harness = await runIntake(baseRun({ id: 101, conclusion: "success" }), {
    issues: [openIssue],
    workflowRuns: [],
  });
  assert.deepEqual(harness.failures, [
    "The authoritative workflow run state could not be read.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("fails closed when the authoritative run list request fails", async () => {
  const openIssue = {
    number: 183,
    state: "open",
    body: `${markerFor(RUST_WORKFLOW_ID)}\n`,
  };
  const harness = await runIntake(baseRun({ id: 101, conclusion: "success" }), {
    issues: [openIssue],
    listWorkflowRunsError: new Error("api down"),
  });
  assert.deepEqual(harness.failures, [
    "The authoritative workflow run state could not be read.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("fails closed when authoritative run list payload is invalid", async () => {
  const harness = await runIntake(baseRun({ conclusion: "failure" }), {
    listWorkflowRunsPayload: { total_count: 1, workflow_runs: null },
  });
  assert.deepEqual(harness.failures, [
    "The authoritative workflow run state could not be read.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

test("newer failure stays open after an older same-SHA success", async () => {
  const olderSuccess = baseRun({ id: 101, conclusion: "success" });
  const newerFailure = baseRun({ id: 102, conclusion: "failure" });
  const created = await runIntake(newerFailure, {
    workflowRuns: [olderSuccess, newerFailure],
  });
  assert.equal(callsOf(created, "issues.create").length, 1);
  const replay = await runIntake(olderSuccess, {
    issues: [created.createdIssue],
    workflowRuns: [olderSuccess, newerFailure],
  });
  assert.match(
    replay.notices[0],
    /stale workflow run; a newer run or attempt exists/,
  );
  assert.deepEqual(mutationMethods(replay), []);
  assert.equal(callsOf(replay, "issues.createComment").length, 0);
  assert.equal(callsOf(replay, "issues.update").length, 0);
});

test("older same-SHA failure cannot reopen a newer recovery", async () => {
  const olderFailure = baseRun({ id: 101, conclusion: "failure" });
  const newerSuccess = baseRun({ id: 102, conclusion: "success" });
  const opened = await runIntake(olderFailure, {
    workflowRuns: [olderFailure],
  });
  const recovered = await runIntake(newerSuccess, {
    issues: [opened.createdIssue],
    workflowRuns: [olderFailure, newerSuccess],
  });
  assert.equal(callsOf(recovered, "issues.createComment").length, 1);
  assert.equal(
    callsOf(recovered, "issues.update")[0].params.state,
    "closed",
  );
  const closedIssue = {
    ...opened.createdIssue,
    state: "closed",
    body: callsOf(recovered, "issues.update")[0].params.body,
  };
  const staleFailure = await runIntake(olderFailure, {
    issues: [closedIssue],
    workflowRuns: [olderFailure, newerSuccess],
  });
  assert.match(
    staleFailure.notices[0],
    /stale workflow run; a newer run or attempt exists/,
  );
  assert.deepEqual(mutationMethods(staleFailure), []);
});

test("persisted newer failure rejects stale success when the API lists only the older run", async () => {
  const olderSuccess = baseRun({ id: 101, conclusion: "success" });
  const newerFailure = baseRun({ id: 102, conclusion: "failure" });
  const opened = await runIntake(newerFailure, {
    workflowRuns: [newerFailure],
  });
  const stale = await runIntake(olderSuccess, {
    issues: [opened.createdIssue],
    workflowRuns: [olderSuccess],
  });
  assert.match(
    stale.notices[0],
    /tracked issue already records a newer run or attempt/,
  );
  assert.deepEqual(mutationMethods(stale), []);
});

test("rejects a stale earlier attempt of the same run after a newer failure attempt", async () => {
  const attemptOneSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "success",
  });
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const opened = await runIntake(attemptTwoFailure, {
    workflowRuns: [attemptTwoFailure],
  });
  const stale = await runIntake(attemptOneSuccess, {
    issues: [opened.createdIssue],
    workflowRuns: [attemptTwoFailure],
  });
  assert.match(stale.notices[0], /newer run or attempt exists/);
  assert.deepEqual(mutationMethods(stale), []);
});

test("rejects a stale earlier failure attempt after a newer recovery attempt", async () => {
  const attemptOneFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "failure",
  });
  const attemptTwoSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "success",
  });
  const opened = await runIntake(attemptOneFailure, {
    workflowRuns: [attemptOneFailure],
  });
  const recovered = await runIntake(attemptTwoSuccess, {
    issues: [opened.createdIssue],
    workflowRuns: [attemptTwoSuccess],
  });
  assert.equal(callsOf(recovered, "issues.update")[0].params.state, "closed");
  const closedIssue = {
    ...opened.createdIssue,
    state: "closed",
    body: callsOf(recovered, "issues.update")[0].params.body,
  };
  const stale = await runIntake(attemptOneFailure, {
    issues: [closedIssue],
    workflowRuns: [attemptTwoSuccess],
  });
  assert.match(stale.notices[0], /newer run or attempt exists/);
  assert.deepEqual(mutationMethods(stale), []);
});

test("ignores a replayed failure event that was already applied", async () => {
  const failure = baseRun({ id: 102, conclusion: "failure" });
  const opened = await runIntake(failure);
  const replay = await runIntake(failure, {
    issues: [opened.createdIssue],
  });
  assert.deepEqual(replay.notices, [
    "Ignoring a duplicate workflow run event that was already applied.",
  ]);
  assert.deepEqual(mutationMethods(replay), []);
});

test("ignores a replayed recovery event that was already applied", async () => {
  const failure = baseRun({ id: 101, conclusion: "failure" });
  const success = baseRun({ id: 102, conclusion: "success" });
  const opened = await runIntake(failure, { workflowRuns: [failure] });
  const recovered = await runIntake(success, {
    issues: [opened.createdIssue],
    workflowRuns: [failure, success],
  });
  const closedIssue = {
    ...opened.createdIssue,
    state: "closed",
    body: callsOf(recovered, "issues.update")[0].params.body,
  };
  const replay = await runIntake(success, {
    issues: [closedIssue],
    workflowRuns: [failure, success],
  });
  assert.deepEqual(replay.notices, [
    "Ignoring a duplicate workflow run event that was already applied.",
  ]);
  assert.deepEqual(mutationMethods(replay), []);
});

test("Account Manager CI current-tip failure opens a marker-keyed issue", async () => {
  const failure = baseRun({
    id: 301,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "failure",
  });
  const harness = await runIntake(failure);
  const created = callsOf(harness, "issues.create");
  assert.equal(created.length, 1);
  assert.equal(
    created[0].params.title,
    "CI failure: Account Manager CI on main",
  );
  assert.match(created[0].params.body, new RegExp(markerFor(ACCOUNT_MANAGER_WORKFLOW_ID)));
  assert.match(created[0].params.body, /public-repo-ci-failure-evidence:v1:/);
  assert.match(created[0].params.body, /- Run ID: 301/);
  assert.deepEqual(created[0].params.labels, ["agent:inbox", "ci-failure"]);
  const listRuns = callsOf(harness, "actions.listWorkflowRuns");
  assert.equal(listRuns.length, 1);
  assert.equal(listRuns[0].params.workflow_id, ACCOUNT_MANAGER_WORKFLOW_ID);
  assert.equal(listRuns[0].params.branch, BRANCH);
  assert.equal(listRuns[0].params.head_sha, SHA);
});

test("Account Manager CI authoritative recovery closes the marker-keyed issue", async () => {
  const failure = baseRun({
    id: 301,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "failure",
  });
  const success = baseRun({
    id: 302,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "success",
  });
  const opened = await runIntake(failure, { workflowRuns: [failure] });
  const recovered = await runIntake(success, {
    issues: [opened.createdIssue],
    workflowRuns: [failure, success],
  });
  assert.equal(callsOf(recovered, "issues.createComment").length, 1);
  assert.match(
    callsOf(recovered, "issues.createComment")[0].params.body,
    /CI recovered/,
  );
  const update = callsOf(recovered, "issues.update")[0];
  assert.equal(update.params.state, "closed");
  assert.equal(update.params.state_reason, "completed");
  assert.match(update.params.body, /public-repo-ci-failure-evidence:v1:/);
});

test("Account Manager CI current-tip failure reopens a recovered issue", async () => {
  const firstFailure = baseRun({
    id: 301,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "failure",
  });
  const recovery = baseRun({
    id: 302,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "success",
  });
  const secondFailure = baseRun({
    id: 303,
    name: "Account Manager CI",
    workflow_id: ACCOUNT_MANAGER_WORKFLOW_ID,
    conclusion: "failure",
  });
  const opened = await runIntake(firstFailure, { workflowRuns: [firstFailure] });
  const recovered = await runIntake(recovery, {
    issues: [opened.createdIssue],
    workflowRuns: [firstFailure, recovery],
  });
  const closedIssue = {
    ...opened.createdIssue,
    state: "closed",
    body: callsOf(recovered, "issues.update")[0].params.body,
  };
  const reopened = await runIntake(secondFailure, {
    issues: [closedIssue],
    workflowRuns: [firstFailure, recovery, secondFailure],
  });
  const update = callsOf(reopened, "issues.update")[0];
  assert.equal(update.params.state, "open");
  assert.match(update.params.body, /- Run ID: 303/);
  assert.equal(callsOf(reopened, "issues.addLabels").length, 1);
});

test("refuses an unexpected workflow jobs URL", async () => {
  const failure = baseRun({
    jobs_url: `https://api.github.com/repos/${REPOSITORY_NAME}/actions/runs/999/jobs`,
  });
  await assert.rejects(
    () => runIntake(failure),
    /Refusing an unexpected workflow jobs URL/,
  );
});

test("current-tip Rust CI failure still opens a marker-keyed issue", async () => {
  const failure = baseRun({ id: 410, conclusion: "failure" });
  const harness = await runIntake(failure);
  const created = callsOf(harness, "issues.create")[0];
  assert.equal(created.params.title, "CI failure: Rust CI on main");
  assert.match(created.params.body, new RegExp(markerFor(RUST_WORKFLOW_ID)));
  assert.match(created.params.body, /- SHA: a5c66ad5537b7cbf1582dc1b56ec755a79876be8/);
  assert.equal(
    callsOf(harness, "issues.listForRepo")[0].params.labels,
    "ci-failure",
  );
});

function closedIssueNumbers(harness) {
  return callsOf(harness, "issues.update")
    .filter((call) => call.params.state === "closed")
    .map((call) => call.params.issue_number);
}

test("stale attempt-1 success does not close a duplicate that records failed attempt 2", async () => {
  const attemptOneSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "success",
  });
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const harness = await runIntake(attemptOneSuccess, {
    issues: [
      trackedIssue(10, attemptOneSuccess),
      trackedIssue(11, attemptTwoFailure),
    ],
    workflowRuns: [attemptOneSuccess],
  });
  assert.match(
    harness.notices[0],
    /tracked issue already records a newer run or attempt/,
  );
  assert.deepEqual(harness.failures, []);
  assert.deepEqual(mutationMethods(harness), []);
  assert.deepEqual(closedIssueNumbers(harness), []);
});

test("stale success does not close a duplicate that records a newer distinct run", async () => {
  const olderSuccess = baseRun({
    id: 101,
    run_number: 101,
    conclusion: "success",
  });
  const newerFailure = baseRun({
    id: 102,
    run_number: 102,
    conclusion: "failure",
  });
  const harness = await runIntake(olderSuccess, {
    issues: [trackedIssue(10, olderSuccess), trackedIssue(11, newerFailure)],
    workflowRuns: [olderSuccess],
  });
  assert.match(
    harness.notices[0],
    /tracked issue already records a newer run or attempt/,
  );
  assert.deepEqual(mutationMethods(harness), []);
  assert.deepEqual(closedIssueNumbers(harness), []);
});

test("duplicate replay of the newest failure consolidates onto the canonical tracker", async () => {
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const harness = await runIntake(attemptTwoFailure, {
    issues: [
      trackedIssue(10, attemptTwoFailure),
      trackedIssue(11, attemptTwoFailure),
    ],
    workflowRuns: [attemptTwoFailure],
  });
  const updates = callsOf(harness, "issues.update");
  assert.equal(callsOf(harness, "issues.create").length, 0);
  assert.equal(callsOf(harness, "issues.createComment").length, 0);
  assert.equal(updates[0].params.issue_number, 10);
  assert.ok(updates[0].params.body.includes(evidenceMarkerFor(attemptTwoFailure)));
  assert.notEqual(updates[0].params.state, "closed");
  assert.equal(updates[1].params.issue_number, 11);
  assert.equal(updates[1].params.state, "closed");
  assert.equal(updates[1].params.state_reason, "completed");
  assert.deepEqual(closedIssueNumbers(harness), [11]);
});

test("current attempt-2 success recovers duplicated trackers onto the canonical issue", async () => {
  const attemptOneFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "failure",
  });
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const attemptTwoSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "success",
  });
  const harness = await runIntake(attemptTwoSuccess, {
    issues: [
      trackedIssue(10, attemptOneFailure),
      trackedIssue(11, attemptTwoFailure),
    ],
    workflowRuns: [attemptOneFailure, attemptTwoSuccess],
  });
  const comments = callsOf(harness, "issues.createComment");
  const updates = callsOf(harness, "issues.update");
  assert.equal(comments.length, 1);
  assert.equal(comments[0].params.issue_number, 10);
  assert.match(comments[0].params.body, /CI recovered/);
  assert.equal(updates[0].params.issue_number, 10);
  assert.equal(updates[0].params.state, "closed");
  assert.ok(updates[0].params.body.includes(evidenceMarkerFor(attemptTwoSuccess)));
  assert.equal(updates[1].params.issue_number, 11);
  assert.equal(updates[1].params.state, "closed");
  assert.deepEqual(closedIssueNumbers(harness), [10, 11]);
});

test("newest validated evidence is written to the canonical tracker before duplicates close", async () => {
  const attemptOneFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "failure",
  });
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const harness = await runIntake(attemptTwoFailure, {
    issues: [
      trackedIssue(10, attemptOneFailure),
      trackedIssue(11, attemptTwoFailure),
    ],
    workflowRuns: [attemptTwoFailure],
  });
  const updates = callsOf(harness, "issues.update");
  assert.equal(updates[0].params.issue_number, 10);
  assert.ok(updates[0].params.body.includes(evidenceMarkerFor(attemptTwoFailure)));
  assert.notEqual(updates[0].params.state, "closed");
  assert.equal(updates[1].params.issue_number, 11);
  assert.equal(updates[1].params.state, "closed");
});

test("missing evidence on the oldest tracker still honors newer duplicate evidence", async () => {
  const attemptOneSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "success",
  });
  const attemptTwoFailure = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 2,
    conclusion: "failure",
  });
  const harness = await runIntake(attemptOneSuccess, {
    issues: [
      {
        number: 10,
        state: "open",
        body: `${markerFor(RUST_WORKFLOW_ID)}\n`,
      },
      trackedIssue(11, attemptTwoFailure),
    ],
    workflowRuns: [attemptOneSuccess],
  });
  assert.match(
    harness.notices[0],
    /tracked issue already records a newer run or attempt/,
  );
  assert.deepEqual(mutationMethods(harness), []);
});

test("fails closed when a matching tracker has unreadable evidence", async () => {
  const attemptOneSuccess = baseRun({
    id: 50,
    run_number: 50,
    run_attempt: 1,
    conclusion: "success",
  });
  const harness = await runIntake(attemptOneSuccess, {
    issues: [
      trackedIssue(10, attemptOneSuccess),
      {
        number: 11,
        state: "open",
        body: `${markerFor(RUST_WORKFLOW_ID)}\n<!-- public-repo-ci-failure-evidence:v1:not-valid -->\n`,
      },
    ],
    workflowRuns: [attemptOneSuccess],
  });
  assert.deepEqual(harness.failures, [
    "The tracked issue evidence could not be read.",
  ]);
  assert.deepEqual(mutationMethods(harness), []);
});

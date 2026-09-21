"use strict";

const EXPECTED_WORKFLOW_NAMES = Object.freeze([
  "Rust CI",
  "Supply-chain policy",
  "Minimum supported Rust version",
  "Account Manager CI",
]);

const FAILURE_LIKE_CONCLUSIONS = Object.freeze([
  "failure",
  "timed_out",
  "cancelled",
  "action_required",
  "startup_failure",
  "stale",
]);

const EVIDENCE_MARKER_PREFIX = "<!-- public-repo-ci-failure-evidence:v1:";

function identityFrom(run) {
  return {
    runId: run.id,
    runNumber: run.run_number,
    runAttempt: run.run_attempt,
    headSha: String(run.head_sha).toLowerCase(),
  };
}

function compareIdentity(left, right) {
  if (left.runNumber !== right.runNumber) {
    return left.runNumber < right.runNumber ? -1 : 1;
  }
  if (left.runAttempt !== right.runAttempt) {
    return left.runAttempt < right.runAttempt ? -1 : 1;
  }
  if (left.runId !== right.runId) {
    return left.runId < right.runId ? -1 : 1;
  }
  return 0;
}

function formatEvidenceMarker(run) {
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
  return `${EVIDENCE_MARKER_PREFIX}${Buffer.from(evidenceTuple, "utf8").toString(
    "base64url",
  )} -->`;
}

function decodeEvidenceLine(line) {
  const trimmed = String(line).trim();
  if (!trimmed.startsWith(EVIDENCE_MARKER_PREFIX) || !trimmed.endsWith(" -->")) {
    return null;
  }
  const payload = trimmed.slice(
    EVIDENCE_MARKER_PREFIX.length,
    trimmed.length - " -->".length,
  );
  if (!/^[A-Za-z0-9_-]+$/.test(payload)) {
    return null;
  }
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (
    !Array.isArray(decoded) ||
    decoded.length !== 8 ||
    decoded[0] !== "run_id" ||
    decoded[2] !== "run_number" ||
    decoded[4] !== "run_attempt" ||
    decoded[6] !== "head_sha" ||
    !Number.isSafeInteger(decoded[1]) ||
    decoded[1] < 1 ||
    !Number.isSafeInteger(decoded[3]) ||
    decoded[3] < 1 ||
    !Number.isSafeInteger(decoded[5]) ||
    decoded[5] < 1 ||
    typeof decoded[7] !== "string" ||
    !/^[0-9a-f]{40}$/.test(decoded[7])
  ) {
    return null;
  }
  return {
    runId: decoded[1],
    runNumber: decoded[3],
    runAttempt: decoded[5],
    headSha: decoded[7],
  };
}

function parseEvidence(issue) {
  const found = [];
  for (const line of String(issue?.body ?? "").split(/\r?\n/)) {
    const decoded = decodeEvidenceLine(line);
    if (decoded) {
      found.push(decoded);
    }
  }
  if (found.length === 0) {
    return null;
  }
  found.sort(compareIdentity);
  return found[found.length - 1];
}

function replaceEvidenceMarker(body, marker, evidenceMarker) {
  const lines = String(body ?? "").split(/\r?\n/);
  let replaced = false;
  const next = lines.map((line) => {
    if (line.trim().startsWith(EVIDENCE_MARKER_PREFIX)) {
      replaced = true;
      return evidenceMarker;
    }
    return line;
  });
  if (!replaced) {
    const markerIndex = next.findIndex((line) => line.trim() === marker);
    if (markerIndex >= 0) {
      next.splice(markerIndex + 1, 0, evidenceMarker);
    } else {
      next.unshift(evidenceMarker);
    }
  }
  return next.join("\n");
}

async function loadAuthoritativeLatest(github, owner, repo, run) {
  const listed = [];
  const maximumPages = 20;
  for (let page = 1; page <= maximumPages; page += 1) {
    const { data } = await github.rest.actions.listWorkflowRuns({
      owner,
      repo,
      workflow_id: run.workflow_id,
      branch: run.head_branch,
      head_sha: run.head_sha,
      exclude_pull_requests: true,
      per_page: 100,
      page,
    });
    if (
      !data ||
      !Number.isSafeInteger(data.total_count) ||
      data.total_count < 0 ||
      !Array.isArray(data.workflow_runs)
    ) {
      throw new Error("invalid authoritative workflow run list");
    }
    listed.push(...data.workflow_runs);
    if (
      data.workflow_runs.length === 0 ||
      data.workflow_runs.length < 100 ||
      listed.length >= data.total_count
    ) {
      break;
    }
    if (page === maximumPages) {
      throw new Error("authoritative workflow run pagination exceeded its bound");
    }
  }

  const matching = listed.filter(
    (candidate) =>
      candidate.workflow_id === run.workflow_id &&
      candidate.head_branch === run.head_branch &&
      typeof candidate.head_sha === "string" &&
      candidate.head_sha.toLowerCase() === run.head_sha.toLowerCase() &&
      Number.isSafeInteger(candidate.id) &&
      candidate.id >= 1 &&
      Number.isSafeInteger(candidate.run_number) &&
      candidate.run_number >= 1 &&
      Number.isSafeInteger(candidate.run_attempt) &&
      candidate.run_attempt >= 1,
  );
  if (matching.length === 0) {
    throw new Error("no matching authoritative workflow run");
  }
  matching.sort((left, right) =>
    compareIdentity(identityFrom(left), identityFrom(right)),
  );
  return matching[matching.length - 1];
}

async function reconcileCiFailureIntake({
  github,
  context,
  core,
  fetch: fetchImpl,
} = {}) {
  const fetch = fetchImpl ?? globalThis.fetch;
  const run = context.payload.workflow_run;
  const { owner, repo } = context.repo;
  const repositoryName = `${owner}/${repo}`;
  const repository = context.payload.repository;
  const expectedWorkflows = new Set(EXPECTED_WORKFLOW_NAMES);
  const failureLikeConclusions = new Set(FAILURE_LIKE_CONCLUSIONS);

  if (!run || !expectedWorkflows.has(run.name)) {
    core.notice("Ignoring an unexpected workflow_run payload.");
    return;
  }
  if (
    run.repository?.full_name !== repositoryName ||
    run.head_repository?.full_name !== repositoryName
  ) {
    core.notice("Ignoring a workflow run from a foreign repository.");
    return;
  }
  if (
    !Number.isSafeInteger(run.id) ||
    run.id < 1 ||
    !Number.isSafeInteger(run.workflow_id) ||
    run.workflow_id < 1 ||
    !Number.isSafeInteger(run.run_number) ||
    run.run_number < 1 ||
    !Number.isSafeInteger(run.run_attempt) ||
    run.run_attempt < 1 ||
    typeof run.head_branch !== "string" ||
    run.head_branch.length === 0 ||
    !/^[0-9a-f]{40}$/i.test(run.head_sha) ||
    typeof run.jobs_url !== "string"
  ) {
    core.setFailed("The workflow_run identity is incomplete or invalid.");
    return;
  }
  if (
    typeof repository?.default_branch !== "string" ||
    repository.default_branch.length === 0
  ) {
    core.setFailed("The repository default branch is missing or invalid.");
    return;
  }
  if (run.head_branch !== repository.default_branch) {
    core.notice("Ignoring a non-default-branch workflow run.");
    return;
  }
  if (
    run.conclusion !== "success" &&
    !failureLikeConclusions.has(run.conclusion)
  ) {
    core.notice(`Ignoring non-lifecycle conclusion: ${run.conclusion}`);
    return;
  }
  let tipSha;
  try {
    const { data: defaultBranch } = await github.rest.repos.getBranch({
      owner,
      repo,
      branch: repository.default_branch,
    });
    tipSha = defaultBranch.commit?.sha;
  } catch {
    core.setFailed("The default-branch tip SHA could not be read.");
    return;
  }
  if (typeof tipSha !== "string" || !/^[0-9a-f]{40}$/i.test(tipSha)) {
    core.setFailed("The default-branch tip SHA could not be read.");
    return;
  }
  if (run.head_sha.toLowerCase() !== tipSha.toLowerCase()) {
    core.notice(
      "Ignoring a workflow run that is no longer the default-branch tip.",
    );
    return;
  }

  let authoritative;
  try {
    authoritative = await loadAuthoritativeLatest(github, owner, repo, run);
  } catch {
    core.setFailed("The authoritative workflow run state could not be read.");
    return;
  }
  const eventIdentity = identityFrom(run);
  const authoritativeIdentity = identityFrom(authoritative);
  if (compareIdentity(eventIdentity, authoritativeIdentity) < 0) {
    core.notice(
      "Ignoring a stale workflow run; a newer run or attempt exists for this SHA.",
    );
    return;
  }
  if (
    compareIdentity(eventIdentity, authoritativeIdentity) === 0 &&
    typeof authoritative.conclusion === "string" &&
    authoritative.conclusion.length > 0 &&
    run.conclusion !== authoritative.conclusion
  ) {
    core.setFailed(
      "The workflow run conclusion does not match authoritative state.",
    );
    return;
  }

  const serverUrl = new URL(context.serverUrl);
  const safeUrl = (value) => {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.host !== serverUrl.host) {
      throw new Error("Refusing a non-GitHub URL in CI issue data.");
    }
    return url.toString();
  };
  const oneLine = (value) =>
    String(value ?? "")
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  const markdown = (value) =>
    oneLine(value)
      .replace(/&/g, "&amp;")
      .replace(/@/g, "&#64;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/([\\`*_{}[\]()#+\-.!|])/g, "\\$1");

  const markerTuple = JSON.stringify([
    "workflow_id",
    run.workflow_id,
    "branch",
    run.head_branch,
  ]);
  const markerPayload = Buffer.from(markerTuple, "utf8").toString("base64url");
  const marker = `<!-- public-repo-ci-failure:v1:${markerPayload} -->`;
  const evidenceMarker = formatEvidenceMarker(run);
  const hasExactMarker = (issue) =>
    String(issue.body ?? "")
      .split(/\r?\n/)
      .some((line) => line.trim() === marker);

  const allItems = await github.paginate(github.rest.issues.listForRepo, {
    owner,
    repo,
    state: "all",
    labels: "ci-failure",
    per_page: 100,
  });
  const matches = allItems
    .filter((item) => !item.pull_request && hasExactMarker(item))
    .sort((left, right) => left.number - right.number);
  let issue = matches[0];
  const persisted = issue ? parseEvidence(issue) : null;
  if (persisted && compareIdentity(eventIdentity, persisted) < 0) {
    core.notice(
      "Ignoring a stale workflow run; the tracked issue already records a newer run or attempt.",
    );
    return;
  }
  if (persisted && compareIdentity(eventIdentity, persisted) === 0) {
    const needsClose = run.conclusion === "success" && issue.state === "open";
    if (!needsClose) {
      core.notice(
        "Ignoring a duplicate workflow run event that was already applied.",
      );
      return;
    }
  }

  const closeDuplicates = async () => {
    for (const duplicate of matches.slice(1)) {
      if (duplicate.state === "open") {
        await github.rest.issues.update({
          owner,
          repo,
          issue_number: duplicate.number,
          state: "closed",
          state_reason: "completed",
        });
      }
    }
  };

  if (run.conclusion === "success") {
    if (!issue) {
      core.notice("No matching CI failure issue requires recovery.");
      return;
    }

    await closeDuplicates();
    const nextBody = replaceEvidenceMarker(issue.body, marker, evidenceMarker);
    if (issue.state === "open") {
      const recoveryBody = [
        "CI recovered.",
        "",
        `- Workflow: ${markdown(run.name)}`,
        `- Branch: ${markdown(run.head_branch)}`,
        `- SHA: ${run.head_sha}`,
        `- Run ID: ${run.id}`,
        `- Run number: ${run.run_number}`,
        `- Attempt: ${run.run_attempt}`,
        `- Conclusion: ${markdown(run.conclusion)}`,
        `- Run URL: ${safeUrl(run.html_url)}`,
      ].join("\n");
      await github.rest.issues.createComment({
        owner,
        repo,
        issue_number: issue.number,
        body: recoveryBody,
      });
      await github.rest.issues.update({
        owner,
        repo,
        issue_number: issue.number,
        body: nextBody,
        state: "closed",
        state_reason: "completed",
      });
    } else if (nextBody !== issue.body) {
      await github.rest.issues.update({
        owner,
        repo,
        issue_number: issue.number,
        body: nextBody,
      });
    }
    return;
  }

  const apiUrl = new URL(context.apiUrl);
  const jobsUrl = new URL(run.jobs_url);
  const expectedJobsPath = `/repos/${owner}/${repo}/actions/runs/${run.id}/jobs`;
  if (
    jobsUrl.protocol !== "https:" ||
    jobsUrl.origin !== apiUrl.origin ||
    jobsUrl.pathname !== expectedJobsPath ||
    jobsUrl.search !== "" ||
    jobsUrl.hash !== "" ||
    jobsUrl.username !== "" ||
    jobsUrl.password !== ""
  ) {
    throw new Error("Refusing an unexpected workflow jobs URL.");
  }

  const jobs = [];
  const maximumJobPages = 60;
  for (let page = 1; page <= maximumJobPages; page += 1) {
    const pageUrl = new URL(jobsUrl);
    pageUrl.searchParams.set("filter", "latest");
    pageUrl.searchParams.set("per_page", "100");
    pageUrl.searchParams.set("page", String(page));
    const response = await fetch(pageUrl, {
      method: "GET",
      redirect: "error",
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
      },
    });
    if (!response.ok) {
      throw new Error(
        `Public workflow jobs request failed with status ${response.status}.`,
      );
    }
    const payload = await response.json();
    if (
      !payload ||
      !Number.isSafeInteger(payload.total_count) ||
      payload.total_count < 0 ||
      !Array.isArray(payload.jobs)
    ) {
      throw new Error("Public workflow jobs response is invalid.");
    }
    jobs.push(...payload.jobs);
    if (
      payload.jobs.length === 0 ||
      payload.jobs.length < 100 ||
      jobs.length >= payload.total_count
    ) {
      break;
    }
    if (page === maximumJobPages) {
      throw new Error("Public workflow jobs pagination exceeded its bound.");
    }
  }

  const failingJobs = jobs
    .filter((job) => failureLikeConclusions.has(job.conclusion))
    .map((job) => ({
      name: markdown(job.name),
      conclusion: markdown(job.conclusion),
      url: safeUrl(job.html_url),
    }));
  const failingJobLines =
    failingJobs.length > 0
      ? failingJobs.map(
          (job) => `- ${job.name} — ${job.conclusion} — ${job.url}`,
        )
      : [
          `- No failure-like job was returned by the public jobs API; workflow conclusion: ${markdown(run.conclusion)}.`,
        ];
  const runUrl = safeUrl(run.html_url);
  const title = oneLine(
    `CI failure: ${run.name} on ${run.head_branch}`,
  ).slice(0, 256);
  const body = [
    marker,
    evidenceMarker,
    "",
    "## CI failure",
    "",
    `- Workflow: ${markdown(run.name)}`,
    `- Branch: ${markdown(run.head_branch)}`,
    `- SHA: ${run.head_sha}`,
    `- Run ID: ${run.id}`,
    `- Run number: ${run.run_number}`,
    `- Attempt: ${run.run_attempt}`,
    `- Conclusion: ${markdown(run.conclusion)}`,
    `- Run URL: ${runUrl}`,
    "",
    "## Failing jobs",
    ...failingJobLines,
  ].join("\n");

  const ensureLabel = async (name, color, description) => {
    try {
      await github.rest.issues.getLabel({ owner, repo, name });
    } catch (error) {
      if (error.status !== 404) {
        throw error;
      }
      try {
        await github.rest.issues.createLabel({
          owner,
          repo,
          name,
          color,
          description,
        });
      } catch (createError) {
        if (createError.status !== 422) {
          throw createError;
        }
      }
    }
  };
  const lifecycleLabels = ["agent:inbox", "ci-failure"];

  if (!issue) {
    await ensureLabel("agent:inbox", "D4C5F9", "Awaiting agent triage");
    await ensureLabel("ci-failure", "B60205", "Tracked CI failure");
    const created = await github.rest.issues.create({
      owner,
      repo,
      title,
      body,
      labels: lifecycleLabels,
    });
    issue = created.data;
    return;
  }

  await closeDuplicates();
  const reopening = issue.state !== "open";
  await github.rest.issues.update({
    owner,
    repo,
    issue_number: issue.number,
    title,
    body,
    ...(reopening ? { state: "open" } : {}),
  });
  if (reopening) {
    await ensureLabel("agent:inbox", "D4C5F9", "Awaiting agent triage");
    await ensureLabel("ci-failure", "B60205", "Tracked CI failure");
    await github.rest.issues.addLabels({
      owner,
      repo,
      issue_number: issue.number,
      labels: lifecycleLabels,
    });
  }
}

module.exports = {
  EXPECTED_WORKFLOW_NAMES,
  reconcileCiFailureIntake,
};

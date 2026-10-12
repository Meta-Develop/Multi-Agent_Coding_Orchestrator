"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const test = require("node:test");

const entryPath = path.join(__dirname, "managed_entry.cjs");
const childSource = `
  const assert = require("node:assert/strict");
  const [entryPath, socketPath, scenario] = process.argv.slice(1);
  const { runManagedCursor } = require(entryPath);
  const installerError = new Error("fixture installer refusal");
  const deadlineUnixMillis = Date.now() + 3000;
  const report = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
  let parent;
  let pending;
  const bridge = { drainPendingCompletions: async () => report({ phase: "drained" }) };
  runManagedCursor({
    root: "cursor-fixture", argv: ["--fixture"], socketPath, deadlineUnixMillis,
    installPinnedCursorBridge(options) {
      parent = options.parent;
      assert.equal(options.root, "cursor-fixture");
      if (scenario === "installer-throw") {
        pending = parent.authorizeAction({ fixture: true }).then(
          () => false,
          (error) => error === installerError,
        );
        throw installerError;
      }
      assert.equal(scenario, "success", "installer must not run after refused connect");
      return bridge;
    },
  }).then(async (result) => {
    assert.equal(result, bridge);
    assert.deepEqual(process.argv, [process.execPath, "cursor-fixture/index.js", "--fixture"]);
    assert.equal(parent.operationDeadlineUnixMillis, deadlineUnixMillis);
    assert.equal(parent.operationSignal.aborted, false);
    assert.deepEqual(await parent.authorizeAction({ counter: 7n }), { ack: true });
    report({ phase: "success" });
  }).catch(async (error) => {
    process.exitCode = 1;
    report({
      phase: "refused", message: error.message, code: error.code,
      installerErrorPreserved: error === installerError,
      parentAborted: parent?.operationSignal.aborted,
      parentReasonPreserved: parent?.operationSignal.reason === error,
    });
    if (scenario === "installer-throw") {
      // Observe failure without an assertion throwing and forcibly ending a leaked child.
      report({ phase: "pending-rejected", originalReason: await pending });
    }
  });
`;

function socketPath() {
  const name = `maco-cursor-entry-${process.pid}-${randomUUID()}`;
  return process.platform === "win32"
    ? `\\\\.\\pipe\\${name}`
    : path.join(os.tmpdir(), `${name}.sock`);
}

async function listen(server, address) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(address, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function runChild(address, scenario) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", childSource, entryPath, address, scenario], {
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "", stderr = "", refusedAt;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (refusedAt === undefined && stdout.includes('"phase":"refused"')) refusedAt = performance.now();
    });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({
      code, signal, stderr,
      reports: stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)),
      exitAfterRefusalMs: refusedAt === undefined ? undefined : performance.now() - refusedAt,
    }));
  });
}

function assertPromptRefusal(result, t) {
  assert.equal(result.code, 1, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, "");
  assert.equal(result.reports[0]?.phase, "refused");
  assert.ok(result.exitAfterRefusalMs < 1000, `refusal left handles alive for ${result.exitAfterRefusalMs}ms`);
  t.diagnostic(`natural exit ${result.exitAfterRefusalMs.toFixed(1)}ms after refusal`);
}

test("refused parent connection exits before its connection deadline", async (t) => {
  const address = socketPath();
  const server = net.createServer();
  await listen(server, address);
  await close(server);
  const result = await runChild(address, "refused-connect");
  assertPromptRefusal(result, t);
  assert.ok(["ENOENT", "ECONNREFUSED"].includes(result.reports[0].code));
});

test("installer exception closes IPC and rejects pending requests before child exit", async (t) => {
  const address = socketPath();
  let peerClosed = false, fallbackUsed = false;
  const server = net.createServer((socket) => {
    // Bound the fixture even against the old leak, without forcing child exit.
    const fallback = setTimeout(() => { fallbackUsed = true; socket.end(); }, 3000);
    socket.resume();
    socket.once("close", () => { peerClosed = true; clearTimeout(fallback); });
  });
  await listen(server, address);
  try {
    const result = await runChild(address, "installer-throw");
    await close(server);
    assertPromptRefusal(result, t);
    assert.equal(result.reports[0].message, "fixture installer refusal");
    assert.equal(result.reports[0].installerErrorPreserved, true);
    assert.equal(result.reports[0].parentAborted, true);
    assert.equal(result.reports[0].parentReasonPreserved, true);
    assert.deepEqual(result.reports[1], { phase: "pending-rejected", originalReason: true });
    assert.equal(peerClosed, true);
    assert.equal(fallbackUsed, false);
  } finally {
    if (server.listening) await close(server);
  }
});

test("successful bootstrap preserves bridge, argv, RPC encoding and completion drain", async () => {
  const address = socketPath();
  let request;
  const server = net.createServer((socket) => {
    const fallback = setTimeout(() => socket.end(), 3000);
    let buffered = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffered += chunk;
      if (!buffered.includes("\n")) return;
      request = JSON.parse(buffered.trim());
      socket.end(`${JSON.stringify({ id: request.id, ok: true, result: { ack: true } })}\n`);
    });
    socket.once("close", () => clearTimeout(fallback));
  });
  await listen(server, address);
  try {
    const result = await runChild(address, "success");
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.signal, null);
    assert.equal(result.stderr, "");
    assert.deepEqual(result.reports, [{ phase: "success" }, { phase: "drained" }]);
    assert.deepEqual(request, { id: "parent-1", method: "authorizeAction", payload: { counter: { $macoInt: "7" } } });
  } finally {
    await close(server);
  }
});

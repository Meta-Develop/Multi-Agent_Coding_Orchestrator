"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const bridge = require("./managed_bridge.cjs");
const fixtureRoot = path.join(__dirname, "fixtures");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function digest(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function nativeContext(signal = new AbortController().signal) {
  return { signal };
}

function copyFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cursor-managed-bridge-"));
  const indexPath = path.join(root, "index.js");
  const chunkPath = path.join(root, "414.index.js");
  const modelChunkPath = path.join(root, "156.index.js");
  fs.copyFileSync(path.join(fixtureRoot, "index.js"), indexPath);
  fs.copyFileSync(path.join(fixtureRoot, "414.index.js"), chunkPath);
  fs.copyFileSync(path.join(fixtureRoot, "156.index.js"), modelChunkPath);
  return { root, indexPath, chunkPath, modelChunkPath };
}

function parentRecorder({
  authorizeEffects = false,
  authorizeGate = null,
  admitAck = true,
  admissionGate = null,
  cancelAt = null,
  cancelSignal = undefined,
  captureAck = true,
  captureGate = null,
  operationController = new AbortController(),
  operationDeadlineUnixMillis = Date.now() + 5_000,
  resourceAuthorizationGate = null,
  resourcePolicy = null,
  sharedServicesGate = null,
  sharedServicesPolicy = null,
  terminalGate = null,
  terminalAck = true,
} = {}) {
  const evidence = {
    admitted: [],
    captured: [],
    completed: [],
    authorized: [],
    resourceActions: [],
  };
  return {
    evidence,
    operationController,
    operationSignal: operationController.signal,
    operationDeadlineUnixMillis,
    async createSharedServices() {
      if (sharedServicesGate) await sharedServicesGate.promise;
      return sharedServicesPolicy ?? {
        ack: false,
        reason: "fixture keeps the original Q factory closed",
      };
    },
    async createSessionResources() {
      return resourcePolicy ?? {
        ack: true,
        policyVersion: 1,
        moduleId: "../agent-exec/dist/index.js",
        nativeHostExec: false,
        mcp: false,
        hooks: false,
        subagents: false,
        resources: [
          {
            kind: "filesystemRead",
            exportName: "_A",
            protoModule: "../proto/dist/generated/agent/v1/read_exec_pb.js",
            argumentTypeName: "agent.v1.ReadArgs",
            resultExportName: "sV",
            resultTypeName: "agent.v1.ReadResult",
            successExportName: "mE",
            successTypeName: "agent.v1.ReadSuccess",
          },
          {
            kind: "filesystemWrite",
            exportName: "Ln",
            protoModule: "../proto/dist/generated/agent/v1/write_exec_pb.js",
            argumentTypeName: "agent.v1.WriteArgs",
            resultExportName: "v3",
            resultTypeName: "agent.v1.WriteResult",
            successExportName: "j6",
            successTypeName: "agent.v1.WriteSuccess",
          },
          {
            kind: "offlineCheck",
            exportName: "qk",
            protoModule: "../proto/dist/generated/agent/v1/shell_exec_pb.js",
            argumentTypeName: "agent.v1.ShellArgs",
            resultExportName: "W4",
            resultTypeName: "agent.v1.ShellResult",
            successExportName: "QR",
            successTypeName: "agent.v1.ShellSuccess",
          },
        ],
      };
    },
    async authorizeResourceAction(event) {
      evidence.resourceActions.push({ phase: "authorize", ...event });
      if (resourceAuthorizationGate) await resourceAuthorizationGate.promise;
      return { ack: true, attemptId: event.kind, actionId: `${event.kind}-1` };
    },
    async executeResourceAction(event) {
      evidence.resourceActions.push({ phase: event.cancelled ? "cancel" : "execute", ...event });
      if (event.cancelled) {
        return {
          ack: true,
          attemptId: event.kind,
          actionId: event.actionId,
          cancelled: true,
        };
      }
      const result = event.kind === "filesystemRead"
        ? { path: event.arguments.path, text: "parent text", totalLines: 1, fileSize: 11 }
        : event.kind === "filesystemWrite"
          ? {
              path: event.arguments.path,
              linesCreated: event.arguments.text.length === 0 ? 0 : 1,
              fileSize: Buffer.byteLength(event.arguments.text),
            }
          : {
              command: "maco-offline-check assigned-paths-changed-only-utf8",
              workingDirectory: event.arguments.workingDirectory,
              stdout: "assigned path changed\n",
              stderr: "",
              executionTimeMillis: 1,
            };
      return {
        ack: true,
        attemptId: event.kind,
        actionId: event.actionId,
        result,
      };
    },
    async admitRpcAttempt(event) {
      evidence.admitted.push(event);
      if (admissionGate) await admissionGate.promise;
      return { ack: admitAck, attemptId: event.attemptId, cancelSignal };
    },
    async authorizeAction(event) {
      evidence.authorized.push(event);
      if (authorizeGate) await authorizeGate.promise;
      return { ack: authorizeEffects, attemptId: event.attemptId };
    },
    async captureRawEvent(event) {
      evidence.captured.push(event);
      if (captureGate) await captureGate.promise;
      return { ack: captureAck, attemptId: event.attemptId, cancel: event.sequence === cancelAt };
    },
    async completeRpcAttempt(event) {
      evidence.completed.push(event);
      if (terminalGate) await terminalGate.promise;
      return { ack: terminalAck, attemptId: event.attemptId };
    },
  };
}

function installFixture(parent) {
  const files = copyFixture();
  globalThis.__cursorFixtureOriginalSharedServices = 0;
  globalThis.__cursorFixtureOriginalSessionResources = 0;
  globalThis.__cursorFixturePhysicalRpcCalls = 0;
  globalThis.__cursorFixturePhysicalRpcDisposals = 0;
  globalThis.__cursorFixturePhysicalRpcReturns = 0;
  globalThis.__cursorFixtureResourceConstructors = 0;
  globalThis.__cursorFixtureControlledRegistrations = 0;
  globalThis.__cursorFixtureSharedClientConstructors = 0;
  globalThis.__cursorFixtureSharedClientEndpoint = null;
  globalThis.__cursorFixtureTestingModelConstructors = 0;
  globalThis.__cursorFixtureAmbientEntryImports = 0;
  globalThis.__cursorFixtureAmbientDnsStarts = 0;
  globalThis.__cursorFixtureAmbientNativeStarts = 0;
  const installed = bridge._test.installBridge({
    indexPath: files.indexPath,
    chunkPath: files.chunkPath,
    indexSha256: digest(files.indexPath),
    chunkSha256: digest(files.chunkPath),
    additionalPins: [{ filename: files.modelChunkPath, sha256: digest(files.modelChunkPath) }],
    parent,
  });
  return { files, installed };
}

function providerlessSharedServicesPolicy() {
  return {
    ack: true,
    policyVersion: 1,
    moduleId: "./src/acp/shared-services.ts",
    providerlessQualification: true,
    agentEndpoint: "http://127.0.0.1:9",
    auth: "deny-all-parent-fixed",
    fixedModel: "maco-providerless-qualification",
    network: false,
    nativeHostExec: false,
    mcp: false,
    hooks: false,
    skills: false,
    subagents: false,
  };
}

test("hash mismatch refuses before importing any vendor module", () => {
  const files = copyFixture();
  globalThis.__cursorFixtureOriginalSharedServices = 0;
  assert.throws(
    () => bridge._test.installBridge({
      indexPath: files.indexPath,
      chunkPath: files.chunkPath,
      indexSha256: "0".repeat(64),
      chunkSha256: digest(files.chunkPath),
      additionalPins: [{ filename: files.modelChunkPath, sha256: digest(files.modelChunkPath) }],
      parent: parentRecorder(),
    }),
    (error) => error.code === "CURSOR_SOURCE_HASH_MISMATCH",
  );
  assert.equal(require.cache[path.resolve(files.indexPath)], undefined);
  assert.equal(require.cache[path.resolve(files.chunkPath)], undefined);
  assert.equal(require.cache[path.resolve(files.modelChunkPath)], undefined);
  assert.equal(globalThis.__cursorFixtureOriginalSharedServices, 0);
});

test("isolated loader never executes the ambient CLI entry and registers 156 before 414", async () => {
  const parent = parentRecorder({ sharedServicesPolicy: providerlessSharedServicesPolicy() });
  const { installed } = installFixture(parent);
  assert.equal(globalThis.__cursorFixtureAmbientEntryImports, 0);
  assert.equal(globalThis.__cursorFixtureAmbientDnsStarts, 0);
  assert.equal(globalThis.__cursorFixtureAmbientNativeStarts, 0);
  const shared = await installed.exports.Q();
  assert.equal(typeof shared.agentClient.run, "function");
  assert.equal(globalThis.__cursorFixtureSharedClientConstructors, 1);
  assert.equal(globalThis.__cursorFixtureTestingModelConstructors, 1);
  assert.equal(globalThis.__cursorFixtureAmbientEntryImports, 0);
  assert.equal(globalThis.__cursorFixtureAmbientDnsStarts, 0);
  assert.equal(globalThis.__cursorFixtureAmbientNativeStarts, 0);
});

test("isolated loader refuses a foreign model factory while accepting the pinned 156 order", () => {
  const files = copyFixture();
  globalThis.__cursorFixtureAmbientEntryImports = 0;
  const source = fs.readFileSync(files.indexPath, "utf8");
  const anchor = '  "./src/index.tsx": () => {';
  assert.equal(source.split(anchor).length, 2);
  fs.writeFileSync(
    files.indexPath,
    source.replace(
      anchor,
      '  "./src/models/index.ts": () => {},\n  "./src/index.tsx": () => {',
    ),
  );
  assert.throws(
    () => bridge._test.installBridge({
      indexPath: files.indexPath,
      chunkPath: files.chunkPath,
      indexSha256: digest(files.indexPath),
      chunkSha256: digest(files.chunkPath),
      additionalPins: [{ filename: files.modelChunkPath, sha256: digest(files.modelChunkPath) }],
      parent: parentRecorder(),
    }),
    (error) => error.code === "CURSOR_CHUNK_MODULE_COLLISION",
  );
  assert.equal(globalThis.__cursorFixtureAmbientEntryImports, 0);
});

test("actual webpack factory shape is interposed before Q/Y and raw RPC fanout", async () => {
  const parent = parentRecorder();
  const { installed } = installFixture(parent);
  await assert.rejects(
    installed.exports.Q("fixture-context"),
    (error) => error.code === "CURSOR_SHARED_SERVICES_REFUSED",
  );
  assert.equal(globalThis.__cursorFixtureResourceConstructors, 0);
  const session = await installed.exports.Y("fixture-context");
  assert.equal(globalThis.__cursorFixtureResourceConstructors, 1);
  assert.equal(globalThis.__cursorFixtureControlledRegistrations, 0);
  assert.deepEqual(
    session.resources.entries().map(([descriptor]) => descriptor.name),
    ["read", "write", "shell"],
  );
  assert.throws(
    () => session.resources.get({ symbol: Symbol("shell") }),
    (error) => error.code === "CURSOR_RESOURCE_DENIED",
  );
  assert.throws(() => session.resources.register("shell", {}), (error) => error.code === "CURSOR_RESOURCE_MUTATION_DENIED");
  const [readDescriptor, readExecutor] = session.resources.entries()[0];
  assert.equal(session.resources.get(readDescriptor), readExecutor);
  const readResult = await readExecutor.execute(
    nativeContext(),
    new installed.exports.proto.ReadArgs({ path: "assigned.txt" }),
    { execId: "read-1" },
  );
  assert.equal(readResult.constructor.typeName, "agent.v1.ReadResult");
  assert.equal(readResult.result.case, "success");
  assert.equal(readResult.result.value.constructor.typeName, "agent.v1.ReadSuccess");
  assert.equal(readResult.result.value.output.value, "parent text");
  const [, writeExecutor] = session.resources.entries()[1];
  const writeResult = await writeExecutor.execute(
    nativeContext(),
    new installed.exports.proto.WriteArgs({ path: "assigned.txt", fileText: "changed\n" }),
    { execId: "write-1" },
  );
  assert.equal(writeResult.constructor.typeName, "agent.v1.WriteResult");
  assert.equal(writeResult.result.value.constructor.typeName, "agent.v1.WriteSuccess");
  const [, checkExecutor] = session.resources.entries()[2];
  await assert.rejects(
    checkExecutor.execute(
      nativeContext(),
      new installed.exports.proto.ShellArgs({ command: "git status", workingDirectory: "/workspace" }),
      { execId: "shell-denied" },
    ),
    (error) => error.code === "CURSOR_RESOURCE_ARGUMENT_INVALID",
  );
  const checkResult = await checkExecutor.execute(
    nativeContext(),
    new installed.exports.proto.ShellArgs({
      command: "maco-offline-check assigned-paths-changed-only-utf8",
      workingDirectory: "/workspace",
    }),
    { execId: "check-1" },
  );
  assert.equal(checkResult.constructor.typeName, "agent.v1.ShellResult");
  assert.equal(checkResult.result.value.constructor.typeName, "agent.v1.ShellSuccess");
  assert.equal(checkResult.result.value.exitCode, 0);
  assert.deepEqual(
    parent.evidence.resourceActions.map(({ phase, kind }) => [phase, kind]),
    [
      ["authorize", "filesystemRead"], ["execute", "filesystemRead"],
      ["authorize", "filesystemWrite"], ["execute", "filesystemWrite"],
      ["authorize", "offlineCheck"], ["execute", "offlineCheck"],
    ],
  );
  const descriptor = { symbol: Symbol("owned-read-only-resource") };
  const implementation = { readOnly: true };
  const admittedResources = bridge._test.createDefaultDenyResources([[descriptor, implementation]]);
  assert.equal(admittedResources.get(descriptor), implementation);
  assert.deepEqual(admittedResources.entries(), [[descriptor, implementation]]);
  assert.throws(
    () => admittedResources.get({ symbol: descriptor.symbol }),
    (error) => error.code === "CURSOR_RESOURCE_DENIED",
  );

  const raw = [
    { message: { case: "interactionUpdate", value: { message: { case: "heartbeat" } } } },
    { message: { case: "interactionUpdate", value: { message: { case: "turnEnded", value: {
      inputTokens: 7n,
      outputTokens: 3n,
      cacheReadTokens: 2n,
      cacheWriteTokens: 1n,
    } } } } },
  ];
  const result = await installed.exports.createAgent(raw).run({});
  assert.deepEqual(result.observed, raw);
  assert.equal(parent.evidence.admitted.length, 1);
  assert.equal(parent.evidence.captured.length, 2);
  assert.equal(parent.evidence.captured[1].raw.message.value.message.value.inputTokens, 7n);
  assert.equal(parent.evidence.captured[1].actualProviderModel, null);
  assert.equal(parent.evidence.captured[1].actualEffort, null);
  assert.equal(parent.evidence.captured[1].usd, null);
  assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["eof"]);
  assert.equal(globalThis.__cursorFixtureOriginalSharedServices, 0);
  assert.equal(globalThis.__cursorFixtureOriginalSessionResources, 0);
  assert.deepEqual(installed.binding.originalFactoriesCaptured, {
    sharedServices: true,
    sessionResources: true,
  });
  assert.deepEqual(installed.binding.originalFactoriesInvoked, {
    sharedServices: false,
    sessionResources: false,
  });
  assert.equal(installed.binding.primaryAuthorityEnabled, false);
  assert.equal(installed.binding.lowerRpcReturnShape.nativeRpcResultSynchronousDisposalProven, false);
  assert.equal(installed.binding.lowerRpcReturnShape.nearbyHandshakeSpanSynchronouslyDisposed, true);
});

test("resource constructor and physical action wait for exact parent policy and ACK", async () => {
  const invalidParent = parentRecorder({
    resourcePolicy: {
      ack: true,
      policyVersion: 1,
      moduleId: "../agent-exec/dist/index.js",
      nativeHostExec: false,
      mcp: false,
      hooks: false,
      subagents: false,
      resources: [
        { kind: "filesystemRead", exportName: "_A" },
        { kind: "filesystemWrite", exportName: "Ln" },
      ],
    },
  });
  const invalid = installFixture(invalidParent).installed;
  await assert.rejects(
    invalid.exports.Y("fixture-context"),
    (error) => error.code === "CURSOR_RESOURCE_POLICY_INVALID",
  );
  assert.equal(globalThis.__cursorFixtureResourceConstructors, 0);
  assert.equal(globalThis.__cursorFixtureOriginalSessionResources, 0);

  const resourceAuthorizationGate = deferred();
  const parent = parentRecorder({ resourceAuthorizationGate });
  const { installed } = installFixture(parent);
  const session = await installed.exports.Y("fixture-context");
  const [readDescriptor, readExecutor] = session.resources.entries()[0];
  assert.equal(session.resources.get(readDescriptor), readExecutor);
  const pending = readExecutor.execute(
    nativeContext(),
    new installed.exports.proto.ReadArgs({ path: "assigned.txt" }),
    { execId: "read-2" },
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    parent.evidence.resourceActions.map(({ phase }) => phase),
    ["authorize"],
  );
  resourceAuthorizationGate.resolve();
  assert.equal((await pending).constructor.typeName, "agent.v1.ReadResult");
  assert.deepEqual(
    parent.evidence.resourceActions.map(({ phase }) => phase),
    ["authorize", "execute"],
  );
  assert.equal(globalThis.__cursorFixtureOriginalSharedServices, 0);
  assert.equal(globalThis.__cursorFixtureOriginalSessionResources, 0);
});

test("providerless shared services wait for parent ACK and construct exact hO PW P3 leaf", async () => {
  const gate = deferred();
  const parent = parentRecorder({
    sharedServicesGate: gate,
    sharedServicesPolicy: providerlessSharedServicesPolicy(),
  });
  const { installed } = installFixture(parent);
  let settled = false;
  const shared = installed.exports.Q().finally(() => {
    settled = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  assert.equal(globalThis.__cursorFixtureSharedClientConstructors, 0);
  assert.equal(globalThis.__cursorFixtureTestingModelConstructors, 0);
  gate.resolve();
  const constructed = await shared;
  assert.deepEqual(Object.keys(constructed).sort(), [
    "agentClient",
    "configProvider",
    "credentialManager",
    "modelManager",
  ]);
  assert.equal(globalThis.__cursorFixtureSharedClientConstructors, 1);
  assert.equal(globalThis.__cursorFixtureTestingModelConstructors, 1);
  assert.equal(globalThis.__cursorFixtureSharedClientEndpoint, "http://127.0.0.1:9");
  assert.equal(globalThis.__cursorFixtureOriginalSharedServices, 0);

  const invalid = installFixture(parentRecorder({
    sharedServicesPolicy: {
      ...providerlessSharedServicesPolicy(),
      network: true,
    },
  }));
  await assert.rejects(
    invalid.installed.exports.Q(),
    (error) => error.code === "CURSOR_SHARED_SERVICES_POLICY_INVALID",
  );
});

test("native resource cancellation after admission ACK releases authority before effects", async () => {
  {
    const controller = new AbortController();
    controller.abort(new Error("cancel before admission"));
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    const session = await installed.exports.Y("fixture-context");
    const [, readExecutor] = session.resources.entries()[0];
    await assert.rejects(
      readExecutor.execute(
        nativeContext(controller.signal),
        new installed.exports.proto.ReadArgs({ path: "assigned.txt" }),
        { execId: "read-pre-cancelled" },
      ),
      (error) => error.code === "CURSOR_PARENT_CANCELLED",
    );
    assert.deepEqual(parent.evidence.resourceActions, []);
  }
  const authorization = deferred();
  const controller = new AbortController();
  const parent = parentRecorder({ resourceAuthorizationGate: authorization });
  const { installed } = installFixture(parent);
  const session = await installed.exports.Y("fixture-context");
  const [, readExecutor] = session.resources.entries()[0];
  const pending = readExecutor.execute(
    nativeContext(controller.signal),
    new installed.exports.proto.ReadArgs({ path: "assigned.txt" }),
    { execId: "read-cancelled" },
  );
  while (parent.evidence.resourceActions.length === 0) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  authorization.resolve();
  controller.abort(new Error("native request cancelled"));
  await assert.rejects(pending, (error) => error.code === "CURSOR_PARENT_CANCELLED");
  assert.deepEqual(
    parent.evidence.resourceActions.map(({ phase }) => phase),
    ["authorize", "cancel"],
  );
});

test("async parent admission gates physical RPC and async terminal ACK gates acceptance", async () => {
  const admissionGate = deferred();
  const terminalGate = deferred();
  const parent = parentRecorder({ admissionGate, terminalGate });
  const source = {
    returnPromise: true,
    createStream() {
      return {
        async *[Symbol.asyncIterator]() {},
        [Symbol.dispose]() {},
      };
    },
  };
  const { installed } = installFixture(parent);
  let settled = false;
  const run = installed.exports.createAgent(source).run({}).finally(() => {
    settled = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(parent.evidence.admitted.length, 1);
  assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 0);
  assert.equal(settled, false);
  admissionGate.resolve();
  while (parent.evidence.completed.length === 0) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 1);
  assert.equal(settled, false);
  terminalGate.resolve();
  await run;
  assert.equal(settled, true);

  const refusedParent = parentRecorder({ admitAck: false });
  const refused = installFixture(refusedParent);
  await assert.rejects(
    refused.installed.exports.createAgent([]).run({}),
    (error) => error.code === "CURSOR_PARENT_ACK_REFUSED",
  );
  assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 0);
});

test("operation cancellation after admission ACK wins before deferred physical invocation", async () => {
  const admissionGate = deferred();
  const operationController = new AbortController();
  const parent = parentRecorder({ admissionGate, operationController });
  const { installed } = installFixture(parent);
  const run = installed.exports.createAgent([]).run({});
  while (parent.evidence.admitted.length === 0) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  admissionGate.resolve();
  operationController.abort(new Error("cancel after admission ACK"));
  await assert.rejects(run, (error) => error.code === "CURSOR_PARENT_CANCELLED");
  assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 0);
  assert.deepEqual(parent.evidence.completed, []);
  assert.equal(installed.activeAttemptCount(), 0);
});

test("unknown, effectful, prewarmed, and cancelled paths fail closed", async () => {
  {
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([{ message: { case: "futureAction", value: {} } }]).run({}),
      (error) => error.code === "CURSOR_RAW_MESSAGE_UNKNOWN",
    );
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["error"]);
  }
  {
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([{ message: { case: "interactionQuery", value: {} } }]).run({}),
      (error) => error.code === "CURSOR_PARENT_ACK_REFUSED",
    );
    assert.equal(parent.evidence.authorized.length, 1);
    assert.equal(parent.evidence.captured.length, 0);
  }
  {
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([]).run({ prewarmedStream: {} }),
      (error) => error.code === "CURSOR_PREWARMED_STREAM_DENIED",
    );
    assert.equal(parent.evidence.admitted.length, 0);
  }
  {
    const parent = parentRecorder({ cancelAt: 1 });
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([{ message: { case: "interactionUpdate", value: {} } }]).run({}),
      (error) => error.code === "CURSOR_PARENT_CANCELLED",
    );
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["parent_cancelled"]);
  }
});

test("refusal latch blocks vendor retries and terminal ACK loss", async () => {
  {
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([
        { message: { case: "futureAction", value: {} } },
      ]).run({ retryAfterCatch: true }),
      (error) => error.code === "CURSOR_BRIDGE_LATCHED",
    );
    assert.equal(parent.evidence.admitted.length, 1);
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["error"]);
  }
  {
    const parent = parentRecorder({ terminalAck: false });
    const { installed } = installFixture(parent);
    const agent = installed.exports.createAgent([]);
    await assert.rejects(agent.run({}), (error) => error.code === "CURSOR_PARENT_ACK_REFUSED");
    await assert.rejects(agent.run({}), (error) => error.code === "CURSOR_BRIDGE_LATCHED");
    assert.equal(parent.evidence.admitted.length, 1);
  }
  {
    const parent = parentRecorder({ captureAck: false });
    const { installed } = installFixture(parent);
    const agent = installed.exports.createAgent([
      { message: { case: "interactionUpdate", value: {} } },
    ]);
    await assert.rejects(agent.run({}), (error) => error.code === "CURSOR_PARENT_ACK_REFUSED");
    await assert.rejects(agent.run({}), (error) => error.code === "CURSOR_BRIDGE_LATCHED");
    assert.equal(parent.evidence.admitted.length, 1);
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["error"]);
  }
  {
    const parent = parentRecorder();
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([
        { message: { case: "interactionUpdate", value: {} } },
      ]).run({ disposeAfterOne: true }),
      (error) => error.code === "CURSOR_BRIDGE_LATCHED",
    );
    assert.equal(installed.pendingCompletionCount(), 1);
    assert.deepEqual(await installed.drainPendingCompletions(), {
      drained: ["cursor-rpc-1"],
      remaining: 0,
    });
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["consumer_dispose"]);
  }
});

test("parent cancellation wakes an idle uncooperative source and ACKs terminal state", async () => {
  const cancellation = new AbortController();
  const parent = parentRecorder({ cancelSignal: cancellation.signal });
  const idle = {
    [Symbol.asyncIterator]() {
      return this;
    },
    next() {
      return new Promise(() => {});
    },
    return() {
      return new Promise(() => {});
    },
    [Symbol.dispose]() {},
  };
  const { installed } = installFixture(parent);
  const run = installed.exports.createAgent(idle).run({});
  setTimeout(() => cancellation.abort(new Error("parent cancelled fixture")), 5);
  await assert.rejects(
    Promise.race([
      run,
      new Promise((_resolve, reject) => setTimeout(() => reject(new Error("idle cancellation stalled")), 500)),
    ]),
    (error) => error.code === "CURSOR_PARENT_CANCELLED",
  );
  assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["parent_cancelled"]);
  assert.equal(parent.evidence.captured.length, 0);
});

test("cancellation during action or capture ACK never releases the raw message", async () => {
  for (const phase of ["action", "capture"]) {
    const gate = deferred();
    const cancellation = new AbortController();
    const parent = parentRecorder({
      authorizeEffects: true,
      authorizeGate: phase === "action" ? gate : null,
      captureGate: phase === "capture" ? gate : null,
      cancelSignal: cancellation.signal,
    });
    const { installed } = installFixture(parent);
    const run = installed.exports.createAgent([
      { message: { case: phase === "action" ? "interactionQuery" : "interactionUpdate", value: {} } },
    ]).run({});
    while ((phase === "action" ? parent.evidence.authorized : parent.evidence.captured).length === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    cancellation.abort(new Error(`cancel during ${phase} ACK`));
    gate.resolve();
    await assert.rejects(run, (error) => error.code === "CURSOR_PARENT_CANCELLED");
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["parent_cancelled"]);
    assert.equal(installed.activeAttemptCount(), 0);
    if (phase === "action") assert.equal(parent.evidence.captured.length, 0);
  }
});

test("parent operation bounds held admission, setup, and terminal phases", async () => {
  {
    const admissionGate = deferred();
    const operationController = new AbortController();
    const parent = parentRecorder({ admissionGate, operationController });
    const { installed } = installFixture(parent);
    const run = installed.exports.createAgent([]).run({});
    while (parent.evidence.admitted.length === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    operationController.abort(new Error("cancel held admission"));
    await assert.rejects(run, (error) => error.code === "CURSOR_PARENT_CANCELLED");
    assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 0);
    assert.equal(installed.activeAttemptCount(), 0);
  }
  {
    const sourceGate = deferred();
    const cancellation = new AbortController();
    const parent = parentRecorder({ cancelSignal: cancellation.signal });
    const source = {
      physicalResultPromise: sourceGate.promise,
    };
    const physical = {
      async *[Symbol.asyncIterator]() {},
      [Symbol.dispose]() {
        globalThis.__cursorFixturePhysicalRpcDisposals += 1;
      },
    };
    const { installed } = installFixture(parent);
    const run = installed.exports.createAgent(source).run({});
    while (globalThis.__cursorFixturePhysicalRpcCalls === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    cancellation.abort(new Error("cancel held setup"));
    sourceGate.resolve(physical);
    await assert.rejects(run, (error) => error.code === "CURSOR_PARENT_CANCELLED");
    assert.equal(globalThis.__cursorFixturePhysicalRpcDisposals, 1);
    assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["parent_cancelled"]);
    assert.equal(installed.activeAttemptCount(), 0);
  }
  {
    const terminalGate = deferred();
    const parent = parentRecorder({
      terminalGate,
      operationDeadlineUnixMillis: Date.now() + 500,
    });
    const { installed } = installFixture(parent);
    await assert.rejects(
      installed.exports.createAgent([]).run({}),
      (error) => error.code === "CURSOR_PARENT_DEADLINE",
    );
    assert.equal(parent.evidence.completed.length, 1);
    assert.equal(installed.activeAttemptCount(), 0);
  }
});

test("sync disposal after physical invocation waits for cleanup and one terminal ACK", async () => {
  const sourceGate = deferred();
  const parent = parentRecorder();
  const physical = {
    async *[Symbol.asyncIterator]() {},
    [Symbol.dispose]() {
      globalThis.__cursorFixturePhysicalRpcDisposals += 1;
    },
  };
  const { installed } = installFixture(parent);
  const run = installed.exports.createAgent({ physicalResultPromise: sourceGate.promise })
    .run({ disposeDuringSetup: true });
  while (installed.pendingCompletionCount() === 0) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(globalThis.__cursorFixturePhysicalRpcCalls, 1);
  let drained = false;
  const drain = installed.drainPendingCompletions().finally(() => {
    drained = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(drained, false);
  assert.equal(parent.evidence.completed.length, 0);
  sourceGate.resolve(physical);
  await assert.rejects(run, (error) => error.code === "CURSOR_CONSUMER_DISPOSED");
  assert.deepEqual(await drain, { drained: ["cursor-rpc-1"], remaining: 0 });
  assert.equal(globalThis.__cursorFixturePhysicalRpcDisposals, 1);
  assert.deepEqual(
    parent.evidence.completed.map((event) => event.outcome),
    ["consumer_dispose_after_physical_invoke"],
  );
  assert.equal(installed.activeAttemptCount(), 0);
});

test("sync disposal of initialized non-disposable iterable drains wrapped return", async () => {
  let yielded = false;
  const physical = {
    [Symbol.asyncIterator]() {
      return this;
    },
    async next() {
      if (yielded) return { done: true, value: undefined };
      yielded = true;
      return {
        done: false,
        value: { message: { case: "interactionUpdate", value: {} } },
      };
    },
    async return() {
      globalThis.__cursorFixturePhysicalRpcReturns += 1;
      return { done: true, value: undefined };
    },
  };
  const parent = parentRecorder();
  const { installed } = installFixture(parent);
  await assert.rejects(
    installed.exports.createAgent(physical).run({ disposeAfterOne: true }),
    (error) => error.code === "CURSOR_BRIDGE_LATCHED",
  );
  assert.equal(installed.pendingCompletionCount(), 1);
  assert.deepEqual(await installed.drainPendingCompletions(), {
    drained: ["cursor-rpc-1"],
    remaining: 0,
  });
  assert.equal(globalThis.__cursorFixturePhysicalRpcReturns, 1);
  assert.deepEqual(parent.evidence.completed.map((event) => event.outcome), ["consumer_return"]);
  assert.equal(installed.activeAttemptCount(), 0);
});

test("cancelled or expired owner drain observes rejecting cleanup and terminal completion", async () => {
  for (const interruption of ["cancelled", "expired"]) {
    const operationController = new AbortController();
    const parent = parentRecorder({
      operationController,
      operationDeadlineUnixMillis: Date.now() + 50,
    });
    parent.completeRpcAttempt = (event) => {
      parent.evidence.completed.push(event);
      return Promise.reject(new Error(`${interruption} terminal rejection`));
    };
    let valueReads = 0;
    const raw = { message: { case: "interactionUpdate", value: {} } };
    const step = { done: false };
    Object.defineProperty(step, "value", {
      get() {
        valueReads += 1;
        if (valueReads === 3) {
          if (interruption === "cancelled") {
            operationController.abort(new Error("cancel before synchronous disposal"));
          } else {
            while (Date.now() < parent.operationDeadlineUnixMillis) {}
          }
        }
        return raw;
      },
    });
    let delivered = false;
    const physical = {
      [Symbol.asyncIterator]() {
        return this;
      },
      async next() {
        if (delivered) return { done: true, value: undefined };
        delivered = true;
        return step;
      },
      return() {
        globalThis.__cursorFixturePhysicalRpcReturns += 1;
        return Promise.reject(new Error(`${interruption} cleanup rejection`));
      },
    };
    const unhandled = [];
    const observeUnhandled = (error) => unhandled.push(error);
    process.on("unhandledRejection", observeUnhandled);
    try {
      const { installed } = installFixture(parent);
      await assert.rejects(
        installed.exports.createAgent(physical).run({ disposeAfterOne: true }),
        (error) => error.code === "CURSOR_BRIDGE_LATCHED",
      );
      assert.equal(installed.pendingCompletionCount(), 1);
      await assert.rejects(
        installed.drainPendingCompletions(),
        (error) => error.code === (interruption === "cancelled"
          ? "CURSOR_PARENT_CANCELLED"
          : "CURSOR_PARENT_DEADLINE"),
      );
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(unhandled, []);
      assert.equal(globalThis.__cursorFixturePhysicalRpcReturns, 1);
      assert.equal(parent.evidence.completed.length, 1);
      assert.equal(installed.activeAttemptCount(), 0);
    } finally {
      process.removeListener("unhandledRejection", observeUnhandled);
    }
  }
});

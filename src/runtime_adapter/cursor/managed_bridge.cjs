"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");

const PINNED = Object.freeze({
  version: "2026.04.08-a41fba1",
  indexSha256: "13acf826c5205ffd8ee7ceb32e0366f150f792891ab5f48ca5554b9934ce1457",
  chunkSha256: "338f9c221055bdc46f70844de78ea6e83e27e45718a207b66d2becbeb017a064",
  additionalSources: Object.freeze([
    Object.freeze({ file: "357.index.js", sha256: "4e932032048be5846917173a1351b8b5a99a22b5e5b47b6117c908311644eaa5" }),
    Object.freeze({ file: "361.index.js", sha256: "f75f351cf81ea0852a07df9376357b62b103fb4535591b728c6ffbdafcceb3d9" }),
    Object.freeze({ file: "156.index.js", sha256: "b3c48d6d171a8fc25437a7049e979a1e3234d726408bcb9b6ff14b7b6c67e6f1" }),
  ]),
});

const SHARED_SERVICES_MODULE = "./src/acp/shared-services.ts";
const SESSION_RESOURCES_MODULE = "./src/acp/session-resources.ts";
const AGENT_CLIENT_MODULE = "../agent-client/dist/index.js";
const AGENT_EXEC_MODULE = "../agent-exec/dist/index.js";
const CLIENT_MODULE = "./src/client.ts";
const MODELS_MODULE = "./src/models/index.ts";
const READ_PROTO_MODULE = "../proto/dist/generated/agent/v1/read_exec_pb.js";
const WRITE_PROTO_MODULE = "../proto/dist/generated/agent/v1/write_exec_pb.js";
const SHELL_PROTO_MODULE = "../proto/dist/generated/agent/v1/shell_exec_pb.js";
const RESOURCE_POLICY_VERSION = 1;
const SHARED_SERVICES_POLICY_VERSION = 1;
const PROVIDERLESS_QUALIFICATION_MODEL = "maco-providerless-qualification";
const MANAGED_RESOURCE_SPECS = Object.freeze([
  Object.freeze({
    kind: "filesystemRead",
    exportName: "_A",
    protoModule: READ_PROTO_MODULE,
    argumentTypeName: "agent.v1.ReadArgs",
    resultExportName: "sV",
    resultTypeName: "agent.v1.ReadResult",
    successExportName: "mE",
    successTypeName: "agent.v1.ReadSuccess",
  }),
  Object.freeze({
    kind: "filesystemWrite",
    exportName: "Ln",
    protoModule: WRITE_PROTO_MODULE,
    argumentTypeName: "agent.v1.WriteArgs",
    resultExportName: "v3",
    resultTypeName: "agent.v1.WriteResult",
    successExportName: "j6",
    successTypeName: "agent.v1.WriteSuccess",
  }),
  Object.freeze({
    kind: "offlineCheck",
    exportName: "qk",
    protoModule: SHELL_PROTO_MODULE,
    argumentTypeName: "agent.v1.ShellArgs",
    resultExportName: "W4",
    resultTypeName: "agent.v1.ShellResult",
    successExportName: "QR",
    successTypeName: "agent.v1.ShellSuccess",
  }),
]);
const OFFLINE_CHECK_COMMAND = "maco-offline-check assigned-paths-changed-only-utf8";
const KNOWN_RAW_CASES = new Set([
  "interactionUpdate",
  "interactionQuery",
  "execServerMessage",
  "execServerControlMessage",
  "conversationCheckpointUpdate",
  "kvServerMessage",
]);
const EFFECTFUL_RAW_CASES = new Set([
  "interactionQuery",
  "execServerMessage",
  "execServerControlMessage",
]);
const LOWER_RPC_RETURN_SHAPE = Object.freeze({
  callExpressionAwaited: false,
  resultConsumedAsAsyncIterable: true,
  nativeRpcResultSynchronousDisposalProven: false,
  nearbyHandshakeSpanSynchronouslyDisposed: true,
  handshakeSpanDisposeByteOffset: 3702426,
  bridgeAcceptsPromiseOrAsyncIterable: true,
  callByteOffset: 3702334,
  clientMethodByteOffset: 3702337,
  splitterPrecedesAcp: true,
});

class CursorBridgeRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CursorBridgeRefusal";
    this.code = code;
  }
}

function refuse(code, message) {
  throw new CursorBridgeRefusal(code, message);
}

function latchRefusal(state, error, attemptId = null) {
  const refusal = error instanceof CursorBridgeRefusal
    ? error
    : new CursorBridgeRefusal("CURSOR_VENDOR_STREAM_ERROR", "vendor RPC stream failed");
  if (!state.refusal) {
    state.refusal = Object.freeze({
      code: refusal.code,
      attemptId,
    });
    for (const controller of state.activeAttempts.values()) {
      if (!controller.signal.aborted) controller.abort(refusal);
    }
  }
  return refusal;
}

function assertNotLatched(state) {
  if (state.refusal) {
    refuse(
      "CURSOR_BRIDGE_LATCHED",
      `bridge stopped after ${state.refusal.code}`,
    );
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function readPinnedFile(filename, expectedSha256) {
  const resolved = path.resolve(filename);
  const before = fs.lstatSync(resolved);
  if (!before.isFile() || before.isSymbolicLink()) {
    refuse("CURSOR_SOURCE_NOT_REGULAR", `${resolved} is not a non-symbolic regular file`);
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const descriptor = fs.openSync(resolved, flags);
  try {
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    if (
      openedBefore.dev !== openedAfter.dev ||
      openedBefore.ino !== openedAfter.ino ||
      openedBefore.size !== openedAfter.size ||
      openedBefore.mtimeNs !== openedAfter.mtimeNs
    ) {
      refuse("CURSOR_SOURCE_CHANGED", `${resolved} changed while it was read`);
    }
    const observedSha256 = sha256(bytes);
    if (observedSha256 !== expectedSha256) {
      refuse(
        "CURSOR_SOURCE_HASH_MISMATCH",
        `${resolved} expected ${expectedSha256}, observed ${observedSha256}`,
      );
    }
    return Object.freeze({
      path: resolved,
      bytes,
      sha256: observedSha256,
      dev: openedAfter.dev.toString(),
      ino: openedAfter.ino.toString(),
      size: Number(openedAfter.size),
    });
  } finally {
    fs.closeSync(descriptor);
  }
}

function compileVerifiedModule(source) {
  if (require.cache[source.path]) {
    refuse("CURSOR_SOURCE_ALREADY_IMPORTED", `${source.path} was imported before bridge guards`);
  }
  const loaded = new Module(source.path, module);
  loaded.filename = source.path;
  loaded.paths = Module._nodeModulePaths(path.dirname(source.path));
  require.cache[source.path] = loaded;
  try {
    loaded._compile(source.bytes.toString("utf8"), source.path);
    loaded.loaded = true;
    return loaded;
  } catch (error) {
    delete require.cache[source.path];
    throw error;
  }
}

const INDEX_BOOTSTRAP_PREFIX = "(()=>{var __webpack_modules__=";
const INDEX_ENTRY_SUFFIX = 'var __webpack_exports__=__webpack_require__("./src/index.tsx")})();';
const CHUNK_EXPORT_PREFIX = "exports.id=";

function decodePinnedSource(source) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(source.bytes);
  } catch {
    refuse("CURSOR_SOURCE_ENCODING_INVALID", `${source.path} is not valid UTF-8`);
  }
}

function compileVerifiedSlice(source, code) {
  return compileVerifiedModule(Object.freeze({ ...source, bytes: Buffer.from(code, "utf8") }));
}

function compileVerifiedWebpackLoader(source) {
  const text = decodePinnedSource(source);
  const executable = text.endsWith("\n") && !text.endsWith("\n\n") ? text.slice(0, -1) : text;
  const start = executable.indexOf(INDEX_BOOTSTRAP_PREFIX);
  if (start < 0 || executable.indexOf(INDEX_BOOTSTRAP_PREFIX, start + 1) >= 0) {
    refuse("CURSOR_INDEX_BOOTSTRAP_SHAPE_MISMATCH", "pinned webpack bootstrap anchor drifted");
  }
  if (!executable.endsWith(INDEX_ENTRY_SUFFIX)) {
    refuse("CURSOR_INDEX_ENTRY_SHAPE_MISMATCH", "pinned CLI entry tail drifted");
  }
  const isolated = `${executable.slice(start, -INDEX_ENTRY_SUFFIX.length)}module.exports=__webpack_require__})();`;
  const loaded = compileVerifiedSlice(source, isolated);
  const webpackRequire = loaded.exports;
  if (
    typeof webpackRequire !== "function" ||
    !webpackRequire.m || typeof webpackRequire.m !== "object" ||
    !webpackRequire.f || typeof webpackRequire.f.require !== "function"
  ) {
    refuse("CURSOR_INDEX_BOOTSTRAP_SHAPE_MISMATCH", "isolated webpack loader shape drifted");
  }
  return webpackRequire;
}

function compileVerifiedChunk(source) {
  const text = decodePinnedSource(source);
  const start = text.indexOf(CHUNK_EXPORT_PREFIX);
  if (start < 0 || text.indexOf(CHUNK_EXPORT_PREFIX, start + 1) >= 0) {
    refuse("CURSOR_CHUNK_EXPORT_SHAPE_MISMATCH", `${source.path} chunk export anchor drifted`);
  }
  return compileVerifiedSlice(source, text.slice(start)).exports;
}

function registerVerifiedChunk(webpackRequire, chunk, expectedId) {
  if (
    chunk?.id !== expectedId ||
    !Array.isArray(chunk.ids) || chunk.ids.length !== 1 || chunk.ids[0] !== expectedId ||
    !chunk.modules || typeof chunk.modules !== "object"
  ) {
    refuse("CURSOR_CHUNK_SHAPE_MISMATCH", `pinned chunk ${expectedId} shape drifted`);
  }
  for (const [moduleId, factory] of Object.entries(chunk.modules)) {
    if (typeof factory !== "function") {
      refuse("CURSOR_CHUNK_FACTORY_INVALID", `pinned chunk ${expectedId} module ${moduleId} is invalid`);
    }
    if (Object.prototype.hasOwnProperty.call(webpackRequire.m, moduleId)) {
      refuse("CURSOR_CHUNK_MODULE_COLLISION", `pinned chunk ${expectedId} module ${moduleId} was preloaded`);
    }
    webpackRequire.m[moduleId] = factory;
  }
  if (chunk.runtime !== undefined) {
    if (typeof chunk.runtime !== "function") {
      refuse("CURSOR_RUNTIME_HOOK_INVALID", `pinned chunk ${expectedId} runtime hook is invalid`);
    }
    chunk.runtime(webpackRequire);
  }
}

function requireParentMethod(parent, name) {
  if (!parent || typeof parent[name] !== "function") {
    refuse("CURSOR_PARENT_METHOD_MISSING", `parent method ${name} is required`);
  }
  return parent[name].bind(parent);
}

function parentOperation(parent) {
  const signal = parent?.operationSignal;
  const deadlineUnixMillis = parent?.operationDeadlineUnixMillis;
  if (!isAbortSignal(signal)) {
    refuse("CURSOR_PARENT_OPERATION_INVALID", "parent operation cancellation signal is required");
  }
  if (!Number.isSafeInteger(deadlineUnixMillis) || deadlineUnixMillis <= Date.now()) {
    refuse("CURSOR_PARENT_OPERATION_INVALID", "parent operation deadline must be a future integer Unix millisecond");
  }
  return Object.freeze({ signal, deadlineUnixMillis });
}

function operationRefusal(operation, extraSignals = []) {
  for (const signal of [operation.signal, ...extraSignals]) {
    if (signal?.aborted) {
      return signal.reason instanceof CursorBridgeRefusal
        ? signal.reason
        : new CursorBridgeRefusal("CURSOR_PARENT_CANCELLED", "parent cancelled the RPC attempt");
    }
  }
  if (Date.now() >= operation.deadlineUnixMillis) {
    return new CursorBridgeRefusal("CURSOR_PARENT_DEADLINE", "parent operation deadline elapsed");
  }
  return null;
}

async function waitForParentPhase(value, phase, operation, extraSignals = []) {
  const pending = Promise.resolve(value);
  pending.catch(() => {});
  const immediate = operationRefusal(operation, extraSignals);
  if (immediate) throw immediate;
  const watchedSignals = [operation.signal, ...extraSignals].filter(isAbortSignal);
  let timer;
  const listeners = [];
  const interrupted = new Promise((_resolve, reject) => {
    for (const signal of watchedSignals) {
      const rejectCancelled = () => reject(
        signal.reason instanceof CursorBridgeRefusal
          ? signal.reason
          : new CursorBridgeRefusal("CURSOR_PARENT_CANCELLED", `${phase} was cancelled by the parent`),
      );
      signal.addEventListener("abort", rejectCancelled, { once: true });
      listeners.push([signal, rejectCancelled]);
    }
    const alreadyAborted = watchedSignals.find((signal) => signal.aborted);
    if (alreadyAborted) {
      reject(
        alreadyAborted.reason instanceof CursorBridgeRefusal
          ? alreadyAborted.reason
          : new CursorBridgeRefusal("CURSOR_PARENT_CANCELLED", `${phase} was cancelled by the parent`),
      );
    }
    timer = setTimeout(
      () => reject(new CursorBridgeRefusal(
        "CURSOR_PARENT_DEADLINE",
        `${phase} exceeded the parent operation deadline`,
      )),
      Math.max(1, operation.deadlineUnixMillis - Date.now()),
    );
  });
  try {
    const resolved = await Promise.race([pending, interrupted]);
    const postResolution = operationRefusal(operation, extraSignals);
    if (postResolution) throw postResolution;
    return resolved;
  } finally {
    clearTimeout(timer);
    for (const [signal, listener] of listeners) {
      signal.removeEventListener("abort", listener);
    }
  }
}

async function requireAck(value, phase, attemptId, operation, extraSignals = []) {
  const resolved = await waitForParentPhase(value, phase, operation, extraSignals);
  if (!resolved || resolved.ack !== true || resolved.attemptId !== attemptId) {
    refuse("CURSOR_PARENT_ACK_REFUSED", `${phase} was not acknowledged`);
  }
  return resolved;
}

function createDefaultDenyResources(entries = []) {
  if (!Array.isArray(entries)) {
    refuse("CURSOR_RESOURCE_POLICY_INVALID", "resource entries must be an array");
  }
  const admitted = new Map();
  for (const entry of entries) {
    if (
      !Array.isArray(entry) ||
      entry.length !== 2 ||
      !entry[0] ||
      typeof entry[0] !== "object" ||
      typeof entry[0].symbol !== "symbol" ||
      admitted.has(entry[0].symbol)
    ) {
      refuse(
        "CURSOR_RESOURCE_POLICY_INVALID",
        "resource entries must use unique pinned agent-exec descriptor symbols",
      );
    }
    admitted.set(entry[0].symbol, { resource: entry[0], value: entry[1] });
  }
  return Object.freeze({
    get(resource) {
      const accepted = resource && typeof resource === "object"
        ? admitted.get(resource.symbol)
        : undefined;
      if (!accepted || accepted.resource !== resource) {
        refuse("CURSOR_RESOURCE_DENIED", "resource descriptor is not admitted");
      }
      return accepted.value;
    },
    entries() {
      return Array.from(admitted.values(), ({ resource, value }) => [resource, value]);
    },
    register() {
      refuse("CURSOR_RESOURCE_MUTATION_DENIED", "runtime resource registration is disabled");
    },
  });
}

function validateManagedResourcePolicy(policy) {
  if (
    !policy ||
    policy.ack !== true ||
    policy.policyVersion !== RESOURCE_POLICY_VERSION ||
    policy.moduleId !== AGENT_EXEC_MODULE ||
    policy.nativeHostExec !== false ||
    policy.mcp !== false ||
    policy.hooks !== false ||
    policy.subagents !== false ||
    !Array.isArray(policy.resources) ||
    policy.resources.length !== MANAGED_RESOURCE_SPECS.length
  ) {
    refuse("CURSOR_RESOURCE_POLICY_INVALID", "parent resource policy is not the exact managed policy");
  }
  for (let index = 0; index < MANAGED_RESOURCE_SPECS.length; index += 1) {
    const expected = MANAGED_RESOURCE_SPECS[index];
    const observed = policy.resources[index];
    if (
      !observed ||
      Object.keys(observed).length !== Object.keys(expected).length ||
      Object.entries(expected).some(([key, value]) => observed[key] !== value)
    ) {
      refuse("CURSOR_RESOURCE_POLICY_INVALID", `managed resource ${expected.kind} drifted`);
    }
  }
}

function validateProviderlessSharedServicesPolicy(policy) {
  const expectedKeys = [
    "ack",
    "agentEndpoint",
    "auth",
    "fixedModel",
    "hooks",
    "mcp",
    "moduleId",
    "nativeHostExec",
    "network",
    "policyVersion",
    "providerlessQualification",
    "skills",
    "subagents",
  ];
  if (
    !policy || typeof policy !== "object" || Array.isArray(policy) ||
    Object.keys(policy).sort().join("\0") !== expectedKeys.sort().join("\0") ||
    policy.ack !== true ||
    policy.policyVersion !== SHARED_SERVICES_POLICY_VERSION ||
    policy.moduleId !== SHARED_SERVICES_MODULE ||
    policy.providerlessQualification !== true ||
    policy.agentEndpoint !== "http://127.0.0.1:9" ||
    policy.auth !== "deny-all-parent-fixed" ||
    policy.fixedModel !== PROVIDERLESS_QUALIFICATION_MODEL ||
    policy.network !== false ||
    policy.nativeHostExec !== false ||
    policy.mcp !== false ||
    policy.hooks !== false ||
    policy.skills !== false ||
    policy.subagents !== false
  ) {
    refuse(
      "CURSOR_SHARED_SERVICES_POLICY_INVALID",
      "parent shared-services policy is not the exact providerless qualification policy",
    );
  }
}

function constructProviderlessSharedServices(factoryContext, policy) {
  validateProviderlessSharedServicesPolicy(policy);
  const { webpackRequire } = factoryContext;
  if (typeof webpackRequire !== "function") {
    refuse("CURSOR_FACTORY_SHAPE_MISMATCH", "shared-services factory lacks the live webpack loader");
  }
  const createAgentClient = webpackRequire(CLIENT_MODULE)?.hO;
  const AgentClient = webpackRequire(AGENT_CLIENT_MODULE)?.PW;
  const ModelManager = webpackRequire(MODELS_MODULE)?.P3;
  if (
    typeof createAgentClient !== "function" ||
    typeof AgentClient !== "function" ||
    typeof ModelManager?.createForTesting !== "function"
  ) {
    refuse("CURSOR_SHARED_SERVICES_SHAPE_MISMATCH", "pinned hO/PW/P3 constructors drifted");
  }
  const credentials = Object.freeze({
    getAccessToken() {
      refuse("CURSOR_PROVIDER_AUTH_DENIED", "providerless qualification cannot read credentials");
    },
  });
  const configProvider = Object.freeze({
    get() {
      return Object.freeze({
        privacyCache: Object.freeze({ ghostMode: false }),
        network: Object.freeze({ useHttp1ForAgent: true }),
      });
    },
  });
  const agentClient = createAgentClient(credentials, {
    backendUrl: policy.agentEndpoint,
    agentEndpoint: policy.agentEndpoint,
    insecure: true,
    configProvider,
  });
  if (!(agentClient instanceof AgentClient) || agentClient.constructor !== AgentClient) {
    refuse("CURSOR_SHARED_SERVICES_SHAPE_MISMATCH", "pinned hO did not construct the exact PW client");
  }
  const modelManager = ModelManager.createForTesting();
  if (!(modelManager instanceof ModelManager)) {
    refuse("CURSOR_SHARED_SERVICES_SHAPE_MISMATCH", "P3.createForTesting returned an unexpected value");
  }
  return Object.freeze({
    agentClient,
    modelManager,
    credentialManager: credentials,
    configProvider,
  });
}

function requireExactProto(value, typeName, label) {
  if (!value || typeof value !== "object" || value.constructor?.typeName !== typeName) {
    refuse("CURSOR_RESOURCE_ARGUMENT_INVALID", `${label} does not use the pinned protobuf type`);
  }
}

function normalizeResourceArguments(spec, value) {
  requireExactProto(value, spec.argumentTypeName, `${spec.kind} arguments`);
  if (spec.kind === "filesystemRead") {
    if (
      typeof value.path !== "string" || value.path.length === 0 ||
      value.offset !== undefined || value.limit !== undefined || value.encodingHint !== undefined
    ) {
      refuse("CURSOR_RESOURCE_ARGUMENT_INVALID", "filesystem read requires one complete text file");
    }
    return Object.freeze({ path: value.path });
  }
  if (spec.kind === "filesystemWrite") {
    if (
      typeof value.path !== "string" || value.path.length === 0 ||
      typeof value.fileText !== "string" ||
      value.returnFileContentAfterWrite !== false ||
      !(value.fileBytes instanceof Uint8Array) || value.fileBytes.byteLength !== 0 ||
      value.encodingHint !== undefined
    ) {
      refuse("CURSOR_RESOURCE_ARGUMENT_INVALID", "filesystem write requires bounded UTF-8 text");
    }
    return Object.freeze({ path: value.path, text: value.fileText });
  }
  if (spec.kind === "offlineCheck") {
    if (
      value.command !== OFFLINE_CHECK_COMMAND ||
      typeof value.workingDirectory !== "string" || value.workingDirectory.length === 0 ||
      value.timeout !== 0 || !Array.isArray(value.simpleCommands) || value.simpleCommands.length !== 0 ||
      value.hasInputRedirect !== false || value.hasOutputRedirect !== false ||
      value.parsingResult !== undefined || value.requestedSandboxPolicy !== undefined ||
      value.fileOutputThresholdBytes !== undefined || value.isBackground !== false ||
      value.skipApproval !== false || value.timeoutBehavior !== 0 ||
      value.hardTimeout !== undefined || value.description !== undefined ||
      value.classifierResult !== undefined || value.closeStdin !== false
    ) {
      refuse("CURSOR_RESOURCE_ARGUMENT_INVALID", "shell authority is limited to the exact virtual offline check");
    }
    return Object.freeze({
      check: "assignedPathsChangedOnlyUtf8",
      workingDirectory: value.workingDirectory,
    });
  }
  refuse("CURSOR_RESOURCE_POLICY_INVALID", `unknown managed resource kind ${spec.kind}`);
}

function normalizeExecutionOptions(value) {
  if (value === undefined || value === null) return;
  if (
    typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).some((key) => key !== "execId") ||
    (value.execId !== undefined && typeof value.execId !== "string")
  ) {
    refuse("CURSOR_RESOURCE_ARGUMENT_INVALID", "resource execution options drifted");
  }
}

function bindResultCodec(webpackRequire, spec) {
  const proto = webpackRequire(spec.protoModule);
  const Result = proto?.[spec.resultExportName];
  const Success = proto?.[spec.successExportName];
  if (
    typeof Result !== "function" || Result.typeName !== spec.resultTypeName ||
    typeof Success !== "function" || Success.typeName !== spec.successTypeName
  ) {
    refuse("CURSOR_RESOURCE_PROTO_MISMATCH", `${spec.kind} protobuf constructors drifted`);
  }
  return (value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      refuse("CURSOR_RESOURCE_RESULT_INVALID", `${spec.kind} parent result is not an object`);
    }
    if (spec.kind === "filesystemRead") {
      const expected = ["fileSize", "path", "text", "totalLines"];
      if (
        Object.keys(value).sort().join("\0") !== expected.join("\0") ||
        typeof value.path !== "string" || typeof value.text !== "string" ||
        !Number.isSafeInteger(value.totalLines) || value.totalLines < 0 ||
        !Number.isSafeInteger(value.fileSize) || value.fileSize < 0
      ) {
        refuse("CURSOR_RESOURCE_RESULT_INVALID", "filesystem read result shape drifted");
      }
      return new Result({
        result: {
          case: "success",
          value: new Success({
            path: value.path,
            output: { case: "content", value: value.text },
            totalLines: value.totalLines,
            fileSize: BigInt(value.fileSize),
            truncated: false,
            rangeApplied: false,
          }),
        },
      });
    }
    if (spec.kind === "filesystemWrite") {
      const expected = ["fileSize", "linesCreated", "path"];
      if (
        Object.keys(value).sort().join("\0") !== expected.join("\0") ||
        typeof value.path !== "string" ||
        !Number.isSafeInteger(value.linesCreated) || value.linesCreated < 0 ||
        !Number.isSafeInteger(value.fileSize) || value.fileSize < 0
      ) {
        refuse("CURSOR_RESOURCE_RESULT_INVALID", "filesystem write result shape drifted");
      }
      return new Result({
        result: {
          case: "success",
          value: new Success({
            path: value.path,
            linesCreated: value.linesCreated,
            fileSize: value.fileSize,
          }),
        },
      });
    }
    const expected = ["command", "executionTimeMillis", "stderr", "stdout", "workingDirectory"];
    if (
      Object.keys(value).sort().join("\0") !== expected.join("\0") ||
      value.command !== OFFLINE_CHECK_COMMAND ||
      typeof value.workingDirectory !== "string" ||
      typeof value.stdout !== "string" || typeof value.stderr !== "string" ||
      !Number.isSafeInteger(value.executionTimeMillis) || value.executionTimeMillis < 0
    ) {
      refuse("CURSOR_RESOURCE_RESULT_INVALID", "offline check result shape drifted");
    }
    return new Result({
      result: {
        case: "success",
        value: new Success({
          command: value.command,
          workingDirectory: value.workingDirectory,
          exitCode: 0,
          stdout: value.stdout,
          stderr: value.stderr,
          executionTime: value.executionTimeMillis,
        }),
      },
    });
  };
}

function createParentBackedExecutor(parent, operation, spec, decodeResult) {
  const authorize = requireParentMethod(parent, "authorizeResourceAction");
  const execute = requireParentMethod(parent, "executeResourceAction");
  return Object.freeze({
    async execute(context, argumentsValue, executionOptions) {
      const nativeSignal = context?.signal;
      if (!isAbortSignal(nativeSignal)) {
        refuse("CURSOR_RESOURCE_CONTEXT_INVALID", `${spec.kind} requires the native cancellation signal`);
      }
      const signals = [nativeSignal];
      const beforeAdmission = operationRefusal(operation, signals);
      if (beforeAdmission) throw beforeAdmission;
      const normalizedArguments = normalizeResourceArguments(spec, argumentsValue);
      normalizeExecutionOptions(executionOptions);
      const admissionCall = authorize({ kind: spec.kind, arguments: normalizedArguments });
      let admission;
      try {
        admission = await requireAck(
          admissionCall,
          `${spec.kind} admission`,
          spec.kind,
          operation,
          signals,
        );
      } catch (error) {
        if (nativeSignal.aborted && !operation.signal.aborted && Date.now() < operation.deadlineUnixMillis) {
          try {
            const lateAdmission = await requireAck(
              admissionCall,
              `${spec.kind} cancelled admission drain`,
              spec.kind,
              operation,
            );
            if (typeof lateAdmission.actionId === "string" && lateAdmission.actionId.length > 0) {
              await waitForParentPhase(
                execute({
                  kind: spec.kind,
                  actionId: lateAdmission.actionId,
                  arguments: normalizedArguments,
                  cancelled: true,
                }),
                `${spec.kind} cancelled admission release`,
                operation,
              );
            }
          } catch (_cleanupError) {
            // The owner operation boundary remains authoritative over cleanup failure.
          }
        }
        throw error;
      }
      if (typeof admission.actionId !== "string" || admission.actionId.length === 0) {
        refuse("CURSOR_RESOURCE_ACTION_INVALID", `${spec.kind} admission omitted its action id`);
      }
      const interruption = operationRefusal(operation, signals);
      if (interruption) {
        await waitForParentPhase(
          execute({
            kind: spec.kind,
            actionId: admission.actionId,
            arguments: normalizedArguments,
            cancelled: true,
          }),
          `${spec.kind} cancellation`,
          operation,
        );
        throw interruption;
      }
      const outcome = await waitForParentPhase(
        execute({
          kind: spec.kind,
          actionId: admission.actionId,
          arguments: normalizedArguments,
          cancelled: false,
        }),
        `${spec.kind} execution`,
        operation,
        signals,
      );
      if (
        !outcome ||
        outcome.ack !== true ||
        outcome.attemptId !== spec.kind ||
        outcome.actionId !== admission.actionId ||
        !Object.prototype.hasOwnProperty.call(outcome, "result")
      ) {
        refuse("CURSOR_RESOURCE_RESULT_INVALID", `${spec.kind} execution result was not acknowledged`);
      }
      return decodeResult(outcome.result);
    },
  });
}

function constructManagedResources(factoryContext, parent, operation, policy) {
  validateManagedResourcePolicy(policy);
  const { webpackRequire } = factoryContext;
  if (typeof webpackRequire !== "function") {
    refuse("CURSOR_FACTORY_SHAPE_MISMATCH", "session factory lacks the live webpack loader");
  }
  const agentExec = webpackRequire(AGENT_EXEC_MODULE);
  const ResourceContainer = agentExec?.h;
  if (typeof ResourceContainer !== "function") {
    refuse("CURSOR_RESOURCE_CONSTRUCTOR_MISSING", "pinned agent-exec resource constructor drifted");
  }
  const resources = new ResourceContainer();
  if (
    !resources ||
    typeof resources.register !== "function" ||
    typeof resources.get !== "function" ||
    typeof resources.entries !== "function"
  ) {
    refuse("CURSOR_RESOURCE_CONSTRUCTOR_MISMATCH", "pinned resource container shape drifted");
  }
  for (const spec of MANAGED_RESOURCE_SPECS) {
    const descriptor = agentExec[spec.exportName];
    if (
      !descriptor ||
      typeof descriptor !== "object" ||
      typeof descriptor.symbol !== "symbol" ||
      typeof descriptor.remoteImplementation !== "function" ||
      typeof descriptor.registerControlledImplementation !== "function"
    ) {
      refuse("CURSOR_RESOURCE_DESCRIPTOR_MISMATCH", `${spec.kind} descriptor shape drifted`);
    }
    resources.register(
      descriptor,
      createParentBackedExecutor(parent, operation, spec, bindResultCodec(webpackRequire, spec)),
    );
  }
  const entries = resources.entries();
  const sealed = createDefaultDenyResources(entries);
  return Object.freeze({
    get: sealed.get,
    entries: sealed.entries,
    register: sealed.register,
    dispose() {},
  });
}

function ownedFactory(exportName, implementation, factoryContext) {
  return (_module, exports, webpackRequire) => {
    if (!webpackRequire || typeof webpackRequire.d !== "function") {
      refuse("CURSOR_FACTORY_SHAPE_MISMATCH", `${exportName} factory lacks webpack export support`);
    }
    const managedImplementation = (...args) => implementation(
      Object.freeze({ ...factoryContext, webpackRequire }),
      ...args,
    );
    webpackRequire.d(exports, { [exportName]: () => managedImplementation });
  };
}

function inspectRawMessage(raw) {
  if (!raw || typeof raw !== "object" || !raw.message || typeof raw.message.case !== "string") {
    refuse("CURSOR_RAW_MESSAGE_INVALID", "raw RPC message lacks a discriminated case");
  }
  const messageCase = raw.message.case;
  if (!KNOWN_RAW_CASES.has(messageCase)) {
    refuse("CURSOR_RAW_MESSAGE_UNKNOWN", `raw RPC message case ${messageCase} is not admitted`);
  }
  const nestedCase = raw.message.value?.message?.case;
  return {
    messageCase,
    nestedCase: typeof nestedCase === "string" ? nestedCase : null,
    effectful: EFFECTFUL_RAW_CASES.has(messageCase),
  };
}

function queuePendingCompletion(state, attemptId, completion, operation) {
  if (state.pendingCompletions.size >= state.maxPendingCompletions) {
    throw latchRefusal(
      state,
      new CursorBridgeRefusal(
        "CURSOR_PENDING_TERMINAL_OVERFLOW",
        "too many synchronous disposals await owner terminal drain",
      ),
      attemptId,
    );
  }
  const entry = { status: "pending", result: null };
  entry.observed = waitForParentPhase(
    completion,
    "pending owner terminal drain",
    operation,
  ).then(
    (value) => {
      entry.status = "acknowledged";
      entry.result = value;
      return entry;
    },
    (error) => {
      entry.status = "refused";
      entry.result = latchRefusal(state, error, attemptId);
      return entry;
    },
  );
  state.pendingCompletions.set(attemptId, entry);
}

async function drainPendingCompletions(state) {
  const drained = [];
  for (const [attemptId, entry] of Array.from(state.pendingCompletions.entries())) {
    await entry.observed;
    if (entry.status !== "acknowledged") throw entry.result;
    state.pendingCompletions.delete(attemptId);
    drained.push(attemptId);
  }
  return Object.freeze({ drained, remaining: state.pendingCompletions.size });
}

function wrapRawIterable(source, parent, attemptId, state, abortController, operation) {
  if (!source || typeof source[Symbol.asyncIterator] !== "function") {
    refuse("CURSOR_RPC_STREAM_INVALID", "agent client did not return an async iterable");
  }
  const iterator = source[Symbol.asyncIterator]();
  const capture = requireParentMethod(parent, "captureRawEvent");
  const complete = requireParentMethod(parent, "completeRpcAttempt");
  let sequence = 0;
  let terminalState = "open";
  let terminalPromise = null;

  function terminalEvent(outcome, error) {
    return {
      attemptId,
      outcome,
      errorClass: error && error.name ? String(error.name) : null,
    };
  }

  async function finish(outcome, error) {
    if (terminalState === "acknowledged") return;
    if (terminalState === "awaiting_ack") return terminalPromise;
    if (terminalState !== "open") {
      const refusal = new CursorBridgeRefusal(
        "CURSOR_TERMINAL_ACK_REENTRY",
        "RPC terminal acknowledgement was re-entered",
      );
      throw latchRefusal(state, refusal, attemptId);
    }
    terminalState = "awaiting_ack";
    terminalPromise = (async () => {
      try {
        await requireAck(
          complete(terminalEvent(outcome, error)),
          "RPC terminal",
          attemptId,
          operation,
        );
        terminalState = "acknowledged";
      } catch (ackError) {
        terminalState = "refused";
        throw latchRefusal(state, ackError, attemptId);
      } finally {
        state.activeAttempts.delete(attemptId);
      }
    })();
    return terminalPromise;
  }

  function queueFinish(outcome, error) {
    if (terminalState === "acknowledged" || terminalState === "pending_owner_drain") return;
    if (terminalState !== "open") {
      throw latchRefusal(
        state,
        new CursorBridgeRefusal(
          "CURSOR_TERMINAL_ACK_REENTRY",
          "RPC terminal acknowledgement was re-entered",
        ),
        attemptId,
      );
    }
    terminalState = "pending_owner_drain";
    let completion;
    try {
      completion = requireAck(
        complete(terminalEvent(outcome, error)),
        "RPC terminal",
        attemptId,
        operation,
      );
    } catch (ackError) {
      completion = Promise.reject(ackError);
    }
    queuePendingCompletion(
      state,
      attemptId,
      completion.then(() => {
        terminalState = "acknowledged";
        return { ack: true, attemptId };
      }).finally(() => state.activeAttempts.delete(attemptId)),
      operation,
    );
  }

  function stopSource(reason) {
    if (!abortController.signal.aborted) abortController.abort(reason);
    if (typeof iterator.return === "function") {
      try {
        const cleanup = iterator.return();
        if (cleanup && typeof cleanup.then === "function") cleanup.catch(() => {});
      } catch (_error) {
        // The refusal latch already owns this attempt. Cleanup cannot reopen it.
      }
    }
  }

  function assertAttemptCanRelease() {
    assertNotLatched(state);
    const interruption = operationRefusal(operation, [abortController.signal]);
    if (interruption) throw interruption;
  }

  async function nextWithAbort(args) {
    return waitForParentPhase(
      Promise.resolve().then(() => iterator.next(...args)),
      "lower RPC stream read",
      operation,
      [abortController.signal],
    );
  }

  async function next(...args) {
    try {
      assertNotLatched(state);
      const step = await nextWithAbort(args);
      assertAttemptCanRelease();
      if (step.done) {
        await finish("eof", null);
        return step;
      }
      sequence += 1;
      const classification = inspectRawMessage(step.value);
      if (classification.effectful) {
        const authorize = requireParentMethod(parent, "authorizeAction");
        await requireAck(
          authorize({ attemptId, sequence, ...classification, raw: step.value }),
          "effectful raw message",
          attemptId,
          operation,
          [abortController.signal],
        );
        assertAttemptCanRelease();
      }
      const ack = await requireAck(
        capture({
          attemptId,
          sequence,
          ...classification,
          raw: step.value,
          actualProviderModel: null,
          actualEffort: null,
          usd: null,
        }),
        "raw RPC event",
        attemptId,
        operation,
        [abortController.signal],
      );
      assertAttemptCanRelease();
      if (ack.cancel === true) {
        const refusal = latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_PARENT_CANCELLED", "parent cancelled the RPC attempt"),
          attemptId,
        );
        stopSource(refusal);
        await finish("parent_cancelled", refusal);
        throw refusal;
      }
      assertAttemptCanRelease();
      return step;
    } catch (error) {
      const refusal = latchRefusal(state, error, attemptId);
      stopSource(refusal);
      if (terminalState === "open") {
        await finish(
          refusal.code === "CURSOR_PARENT_CANCELLED" ? "parent_cancelled" : "error",
          refusal,
        );
      }
      throw refusal;
    }
  }

  const wrapped = {
    [Symbol.asyncIterator]() {
      return this;
    },
    next,
    async return(value) {
      if (terminalState === "open") {
        const refusal = latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_CONSUMER_RETURNED", "consumer returned before stream EOF"),
          attemptId,
        );
        stopSource(refusal);
        await finish("consumer_return", refusal);
      }
      return { done: true, value };
    },
    async throw(error) {
      const refusal = latchRefusal(state, error, attemptId);
      stopSource(refusal);
      await finish("consumer_throw", refusal);
      throw refusal;
    },
  };
  if (typeof Symbol.dispose === "symbol" && typeof source[Symbol.dispose] === "function") {
    wrapped[Symbol.dispose] = () => {
      if (terminalState === "open") {
        const refusal = latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_CONSUMER_DISPOSED", "consumer disposed before stream EOF"),
          attemptId,
        );
        stopSource(refusal);
        queueFinish("consumer_dispose", refusal);
      }
      return source[Symbol.dispose]();
    };
  }
  if (typeof Symbol.asyncDispose === "symbol" && typeof source[Symbol.asyncDispose] === "function") {
    wrapped[Symbol.asyncDispose] = async () => {
      if (terminalState === "open") {
        const refusal = latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_CONSUMER_DISPOSED", "consumer disposed before stream EOF"),
          attemptId,
        );
        stopSource(refusal);
        await finish("consumer_dispose", refusal);
      }
      return source[Symbol.asyncDispose]();
    };
  }
  return wrapped;
}

function rejectUnsafeRunOptions(options) {
  if (!options || typeof options !== "object") return;
  if (options.prewarmedStream !== undefined) {
    refuse("CURSOR_PREWARMED_STREAM_DENIED", "prewarmed streams bypass the bound RPC collector");
  }
  for (const key of ["resume", "resumeSession", "loadSession", "allowAlways", "force"] ) {
    if (options[key] !== undefined && options[key] !== false && options[key] !== null) {
      refuse("CURSOR_SESSION_OPTION_DENIED", `session option ${key} is not admitted`);
    }
  }
}

function isAbortSignal(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    typeof value.aborted === "boolean" &&
    typeof value.addEventListener === "function" &&
    typeof value.removeEventListener === "function",
  );
}

function combineAbortSignals(signals) {
  const present = signals.filter(isAbortSignal);
  if (present.length === 0) return undefined;
  if (present.length === 1) return present[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(present);
  const combined = new AbortController();
  for (const signal of present) {
    const abort = () => {
      if (!combined.signal.aborted) combined.abort(signal.reason);
    };
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  return combined.signal;
}

function createAdmittedRpcIterable({
  originalClientRun,
  receiver,
  clientArgs,
  parent,
  state,
  attemptId,
  ordinal,
  operation,
}) {
  const options = clientArgs[2];
  if (!options || typeof options !== "object") {
    refuse(
      "CURSOR_RPC_OPTIONS_SHAPE_MISMATCH",
      "pinned lower client.run options are unavailable",
    );
  }
  const admit = requireParentMethod(parent, "admitRpcAttempt");
  const complete = requireParentMethod(parent, "completeRpcAttempt");
  let admissionPromise = null;
  let initializationPromise = null;
  let wrapped = null;
  let synchronousDisposeQueued = false;
  let disposeRequested = false;
  let physicalInvocationStarted = false;
  let physicalSourcePromise = null;
  let physicalSourceCleaned = false;
  let abortController = null;
  let setupTerminalPromise = null;
  let resolveSetupSettlement;
  let rejectSetupSettlement;
  const setupSettlement = new Promise((resolve, reject) => {
    resolveSetupSettlement = resolve;
    rejectSetupSettlement = reject;
  });
  setupSettlement.catch(() => {});

  function setupOutcome(refusal) {
    if (disposeRequested) {
      return physicalInvocationStarted
        ? "consumer_dispose_after_physical_invoke"
        : "consumer_dispose_before_open";
    }
    if (refusal.code === "CURSOR_PARENT_CANCELLED") return "parent_cancelled";
    if (refusal.code === "CURSOR_PARENT_DEADLINE") return "parent_deadline";
    return "setup_error";
  }

  function settleSetup(outcome, refusal) {
    if (setupTerminalPromise) return setupTerminalPromise;
    setupTerminalPromise = (async () => {
      try {
        await requireAck(
          complete({ attemptId, outcome, errorClass: refusal.name }),
          "RPC terminal",
          attemptId,
          operation,
        );
        resolveSetupSettlement({ ack: true, attemptId });
      } catch (ackError) {
        const terminalRefusal = latchRefusal(state, ackError, attemptId);
        rejectSetupSettlement(terminalRefusal);
        throw terminalRefusal;
      } finally {
        state.activeAttempts.delete(attemptId);
      }
    })();
    setupTerminalPromise.catch(() => {});
    return setupTerminalPromise;
  }

  async function cleanupPhysicalSource(source) {
    if (physicalSourceCleaned || !source || typeof source !== "object") return;
    physicalSourceCleaned = true;
    if (typeof Symbol.asyncDispose === "symbol" && typeof source[Symbol.asyncDispose] === "function") {
      await waitForParentPhase(
        source[Symbol.asyncDispose](),
        "lower RPC async cleanup",
        operation,
      );
      return;
    }
    if (typeof Symbol.dispose === "symbol" && typeof source[Symbol.dispose] === "function") {
      source[Symbol.dispose]();
      return;
    }
    if (typeof source[Symbol.asyncIterator] === "function") {
      const iterator = source[Symbol.asyncIterator]();
      if (typeof iterator.return === "function") {
        await waitForParentPhase(iterator.return(), "lower RPC iterator cleanup", operation);
      }
    }
  }

  function beginAdmission() {
    if (!admissionPromise) {
      admissionPromise = requireAck(
        admit({
          attemptId,
          ordinal,
          actualProviderModel: null,
          actualEffort: null,
          usd: null,
        }),
        "RPC attempt",
        attemptId,
        operation,
      );
    }
    return admissionPromise;
  }

  async function initialize() {
    if (initializationPromise) return initializationPromise;
    initializationPromise = (async () => {
      assertNotLatched(state);
      let admitted = false;
      try {
        const admission = await beginAdmission();
        admitted = true;
        const postAdmissionInterruption = operationRefusal(operation);
        if (postAdmissionInterruption) throw postAdmissionInterruption;
        if (admission.cancel === true) {
          refuse("CURSOR_PARENT_CANCELLED", "parent cancelled before the RPC attempt opened");
        }
        if (admission.cancelSignal !== undefined && !isAbortSignal(admission.cancelSignal)) {
          refuse("CURSOR_PARENT_CANCEL_SIGNAL_INVALID", "parent cancellation signal is invalid");
        }
        abortController = new AbortController();
        if (admission.cancelSignal) {
          const cancel = () => {
            if (!abortController.signal.aborted) {
              abortController.abort(admission.cancelSignal.reason);
            }
          };
          if (admission.cancelSignal.aborted) cancel();
          else admission.cancelSignal.addEventListener("abort", cancel, { once: true });
        }
        state.activeAttempts.set(attemptId, abortController);
        if (disposeRequested) {
          abortController.abort(new CursorBridgeRefusal(
            "CURSOR_CONSUMER_DISPOSED",
            "consumer disposed before the physical RPC invocation",
          ));
          throw new CursorBridgeRefusal(
            "CURSOR_CONSUMER_DISPOSED",
            "consumer disposed before the physical RPC invocation",
          );
        }
        assertNotLatched(state);
        if (abortController.signal.aborted) {
          refuse("CURSOR_PARENT_CANCELLED", "parent cancelled before the RPC attempt opened");
        }
        const physicalArgs = [...clientArgs];
        physicalArgs[2] = {
          ...options,
          signal: combineAbortSignals([options.signal, abortController.signal]),
        };
        physicalSourcePromise = Promise.resolve().then(() => {
          assertNotLatched(state);
          const preInvocationInterruption = operationRefusal(operation, [abortController.signal]);
          if (preInvocationInterruption) throw preInvocationInterruption;
          if (disposeRequested) {
            throw new CursorBridgeRefusal(
              "CURSOR_CONSUMER_DISPOSED",
              "consumer disposed before the physical RPC invocation",
            );
          }
          physicalInvocationStarted = true;
          return originalClientRun.apply(receiver, physicalArgs);
        });
        physicalSourcePromise.catch(() => {});
        const source = await waitForParentPhase(
          physicalSourcePromise,
          "lower RPC setup",
          operation,
          [abortController.signal],
        );
        if (disposeRequested) {
          await cleanupPhysicalSource(source);
          const refusal = latchRefusal(
            state,
            new CursorBridgeRefusal(
              "CURSOR_CONSUMER_DISPOSED",
              "consumer disposed after the physical RPC invocation",
            ),
            attemptId,
          );
          await settleSetup(setupOutcome(refusal), refusal);
          throw refusal;
        }
        assertNotLatched(state);
        const interruption = operationRefusal(operation, [abortController.signal]);
        if (interruption) throw interruption;
        wrapped = wrapRawIterable(source, parent, attemptId, state, abortController, operation);
        return wrapped;
      } catch (error) {
        const refusal = latchRefusal(state, error, attemptId);
        if (admitted && physicalInvocationStarted && !wrapped && physicalSourcePromise) {
          try {
            const source = await waitForParentPhase(
              physicalSourcePromise,
              "lower RPC cleanup acquisition",
              operation,
            );
            await cleanupPhysicalSource(source);
          } catch (_cleanupError) {
            // The original refusal remains authoritative. Process containment owns any
            // physical child that cannot finish cleanup before the parent deadline.
          }
        }
        if (admitted && !wrapped) await settleSetup(setupOutcome(refusal), refusal);
        if (!admitted) rejectSetupSettlement(refusal);
        throw refusal;
      }
    })();
    return initializationPromise;
  }

  const iterator = {
    [Symbol.asyncIterator]() {
      return this;
    },
    async next(...args) {
      return (await initialize()).next(...args);
    },
    async return(value) {
      if (!admissionPromise) {
        throw latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_CONSUMER_RETURNED", "consumer returned before admission"),
          attemptId,
        );
      }
      return (await initialize()).return(value);
    },
    async throw(error) {
      return (await initialize()).throw(error);
    },
  };

  const lazy = {
    [Symbol.asyncIterator]() {
      return iterator;
    },
  };
  if (typeof Symbol.dispose === "symbol") {
    lazy[Symbol.dispose] = () => {
      if (wrapped && typeof wrapped[Symbol.dispose] === "function") {
        return wrapped[Symbol.dispose]();
      }
      if (wrapped) {
        if (!synchronousDisposeQueued) {
          synchronousDisposeQueued = true;
          queuePendingCompletion(state, attemptId, wrapped.return(), operation);
        }
        return undefined;
      }
      const refusal = latchRefusal(
        state,
        new CursorBridgeRefusal("CURSOR_CONSUMER_DISPOSED", "consumer disposed before stream initialization"),
        attemptId,
      );
      disposeRequested = true;
      if (abortController && !abortController.signal.aborted) abortController.abort(refusal);
      if (admissionPromise && !synchronousDisposeQueued) {
        synchronousDisposeQueued = true;
        queuePendingCompletion(state, attemptId, setupSettlement, operation);
      }
      if (initializationPromise) initializationPromise.catch(() => {});
      return undefined;
    };
  }
  if (typeof Symbol.asyncDispose === "symbol") {
    lazy[Symbol.asyncDispose] = async () => {
      if (!admissionPromise) {
        throw latchRefusal(
          state,
          new CursorBridgeRefusal("CURSOR_CONSUMER_DISPOSED", "consumer disposed before admission"),
          attemptId,
        );
      }
      const initialized = await initialize();
      if (typeof initialized[Symbol.asyncDispose] === "function") {
        return initialized[Symbol.asyncDispose]();
      }
      return initialized.return();
    };
  }
  return lazy;
}

function patchAgentClientFactory(webpackRequire, parent, state, operation) {
  const originalFactory = webpackRequire.m?.[AGENT_CLIENT_MODULE];
  if (typeof originalFactory !== "function") {
    refuse("CURSOR_AGENT_CLIENT_FACTORY_MISSING", "pinned agent client factory is unavailable");
  }
  webpackRequire.m[AGENT_CLIENT_MODULE] = (moduleObject, exports, innerRequire) => {
    originalFactory(moduleObject, exports, innerRequire);
    const AgentClient = exports.PW;
    if (typeof AgentClient !== "function" || typeof AgentClient.prototype?.run !== "function") {
      refuse("CURSOR_AGENT_CLIENT_SHAPE_MISMATCH", "pinned PW client class shape drifted");
    }
    if (AgentClient.prototype.run.__macoCursorBridge === true) {
      refuse("CURSOR_AGENT_CLIENT_ALREADY_PATCHED", "PW client was patched before bridge admission");
    }
    const originalRun = AgentClient.prototype.run;
    async function guardedRun(...args) {
      assertNotLatched(state);
      rejectUnsafeRunOptions(args.at(-1));
      if (!this.client || typeof this.client.run !== "function") {
        refuse("CURSOR_RPC_CLIENT_SHAPE_MISMATCH", "PW instance lacks its lower RPC client");
      }
      const lowerClient = this.client;
      const originalClientRun = lowerClient.run;
      const guardedClientRun = function (...clientArgs) {
        assertNotLatched(state);
        state.attempts += 1;
        const attemptId = `cursor-rpc-${state.attempts}`;
        return createAdmittedRpcIterable({
          originalClientRun,
          receiver: this,
          clientArgs,
          parent,
          state,
          attemptId,
          ordinal: state.attempts,
          operation,
        });
      };
      lowerClient.run = guardedClientRun;
      try {
        const result = await originalRun.apply(this, args);
        assertNotLatched(state);
        return result;
      } catch (error) {
        throw latchRefusal(state, error);
      } finally {
        const replaced = lowerClient.run !== guardedClientRun;
        lowerClient.run = originalClientRun;
        if (replaced) {
          throw latchRefusal(
            state,
            new CursorBridgeRefusal(
              "CURSOR_RPC_INTERPOSER_REPLACED",
              "lower RPC interposer was replaced during the run",
            ),
          );
        }
      }
    }
    Object.defineProperty(guardedRun, "__macoCursorBridge", { value: true });
    AgentClient.prototype.run = guardedRun;
    state.agentFactoryPatched = true;
  };
  state.agentFactoryWrapped = true;
}

function installBridge({
  indexPath,
  chunkPath,
  indexSha256,
  chunkSha256,
  additionalPins = [],
  parent,
}) {
  const operation = parentOperation(parent);
  const indexSource = readPinnedFile(indexPath, indexSha256);
  const chunkSource = readPinnedFile(chunkPath, chunkSha256);
  const additionalSources = additionalPins.map(({ filename, sha256: expectedSha256 }) =>
    readPinnedFile(filename, expectedSha256));
  if (
    require.cache[indexSource.path] ||
    require.cache[chunkSource.path] ||
    additionalSources.some((source) => require.cache[source.path])
  ) {
    refuse("CURSOR_SOURCE_ALREADY_IMPORTED", "vendor code was imported before source binding");
  }

  const state = {
    attempts: 0,
    runtimeHooks: 0,
    agentFactoryWrapped: false,
    agentFactoryPatched: false,
    refusal: null,
    activeAttempts: new Map(),
    pendingCompletions: new Map(),
    maxPendingCompletions: 32,
    webpackRequire: null,
  };
  const chunk = compileVerifiedChunk(chunkSource);
  const modelSource = additionalSources.find((source) => path.basename(source.path) === "156.index.js");
  const modelChunk = modelSource ? compileVerifiedChunk(modelSource) : null;
  if (
    modelChunk &&
    (modelChunk.id !== 156 || !Array.isArray(modelChunk.ids) || modelChunk.ids.length !== 1 ||
      modelChunk.ids[0] !== 156 || !modelChunk.modules || typeof modelChunk.modules !== "object" ||
      typeof modelChunk.modules[MODELS_MODULE] !== "function" || modelChunk.runtime !== undefined)
  ) {
    refuse("CURSOR_MODEL_CHUNK_SHAPE_MISMATCH", "pinned model chunk shape drifted");
  }
  if (
    chunk?.id !== 414 ||
    !Array.isArray(chunk.ids) ||
    chunk.ids.length !== 1 ||
    chunk.ids[0] !== 414 ||
    !chunk.modules ||
    typeof chunk.modules !== "object"
  ) {
    refuse("CURSOR_CHUNK_SHAPE_MISMATCH", "pinned ACP chunk table shape drifted");
  }
  if (
    typeof chunk.modules[SHARED_SERVICES_MODULE] !== "function" ||
    typeof chunk.modules[SESSION_RESOURCES_MODULE] !== "function"
  ) {
    refuse("CURSOR_FACTORY_SHAPE_MISMATCH", "pinned Q/Y module factories are unavailable");
  }
  if (chunk.runtime !== undefined) {
    refuse("CURSOR_RUNTIME_HOOK_OCCUPIED", "ACP chunk already has a runtime hook");
  }
  const originalSharedServicesFactory = chunk.modules[SHARED_SERVICES_MODULE];
  const originalSessionResourcesFactory = chunk.modules[SESSION_RESOURCES_MODULE];

  async function createSharedServices(factoryContext, ...args) {
    const create = requireParentMethod(parent, "createSharedServices");
    const result = await waitForParentPhase(
      create({
        moduleId: SHARED_SERVICES_MODULE,
        originalFactoryInvocation: "forbidden",
        arguments: args,
      }),
      "shared services setup",
      operation,
    );
    if (result?.ack !== true) {
      refuse(
        "CURSOR_SHARED_SERVICES_REFUSED",
        result?.reason ?? "parent-backed shared-services construction is not installed",
      );
    }
    return constructProviderlessSharedServices(factoryContext, result);
  }

  async function createSessionResources(factoryContext, ...args) {
    const policy = requireParentMethod(parent, "createSessionResources");
    const result = await waitForParentPhase(
      policy({ arguments: args }),
      "session resources setup",
      operation,
    );
    return {
      resources: constructManagedResources(factoryContext, parent, operation, result),
      hookExecutor: null,
    };
  }

  chunk.modules[SHARED_SERVICES_MODULE] = ownedFactory("Q", createSharedServices, {
    moduleId: SHARED_SERVICES_MODULE,
    originalFactory: originalSharedServicesFactory,
  });
  chunk.modules[SESSION_RESOURCES_MODULE] = ownedFactory("Y", createSessionResources, {
    moduleId: SESSION_RESOURCES_MODULE,
    originalFactory: originalSessionResourcesFactory,
  });
  chunk.runtime = (webpackRequire) => {
    state.runtimeHooks += 1;
    if (state.runtimeHooks !== 1) {
      refuse("CURSOR_RUNTIME_HOOK_REPEATED", "ACP chunk runtime hook ran more than once");
    }
    if (modelChunk) {
      for (const [moduleId, factory] of Object.entries(modelChunk.modules)) {
        if (webpackRequire.m[moduleId] !== factory) {
          refuse(
            "CURSOR_MODEL_CHUNK_IDENTITY_MISMATCH",
            `pinned model module ${moduleId} was absent or replaced`,
          );
        }
      }
    }
    state.webpackRequire = webpackRequire;
    patchAgentClientFactory(webpackRequire, parent, state, operation);
  };

  const webpackRequire = compileVerifiedWebpackLoader(indexSource);
  if (modelChunk) registerVerifiedChunk(webpackRequire, modelChunk, 156);
  registerVerifiedChunk(webpackRequire, chunk, 414);
  if (state.runtimeHooks !== 1 || !state.agentFactoryWrapped) {
    refuse("CURSOR_RUNTIME_HOOK_NOT_REACHED", "isolated loader did not install the guarded PW client");
  }
  async function runProviderlessQualification(request) {
    if (
      !request || typeof request !== "object" || Array.isArray(request) ||
      Object.keys(request).sort().join("\0") !== "path\0text\0workingDirectory" ||
      typeof request.path !== "string" || request.path.length === 0 ||
      typeof request.text !== "string" ||
      typeof request.workingDirectory !== "string" || request.workingDirectory.length === 0
    ) {
      refuse("CURSOR_QUALIFICATION_REQUEST_INVALID", "providerless qualification request drifted");
    }
    assertNotLatched(state);
    const webpackRequire = state.webpackRequire;
    if (typeof webpackRequire !== "function") {
      refuse("CURSOR_RUNTIME_HOOK_NOT_REACHED", "providerless qualification lacks the live loader");
    }
    const shared = await webpackRequire(SHARED_SERVICES_MODULE).Q();
    if (
      !shared ||
      Object.keys(shared).sort().join("\0") !==
        "agentClient\0configProvider\0credentialManager\0modelManager" ||
      typeof shared.agentClient?.run !== "function" ||
      !shared.modelManager
    ) {
      refuse("CURSOR_SHARED_SERVICES_SHAPE_MISMATCH", "providerless shared services drifted");
    }
    const session = await webpackRequire(SESSION_RESOURCES_MODULE).Y();
    const entries = session?.resources?.entries?.();
    if (!Array.isArray(entries) || entries.length !== MANAGED_RESOURCE_SPECS.length) {
      refuse("CURSOR_RESOURCE_CONSTRUCTOR_MISMATCH", "managed qualification resources drifted");
    }
    const executorByKind = new Map();
    for (const spec of MANAGED_RESOURCE_SPECS) {
      const descriptor = webpackRequire(AGENT_EXEC_MODULE)?.[spec.exportName];
      executorByKind.set(spec.kind, session.resources.get(descriptor));
    }
    const argumentFor = (spec, values) => {
      const constructors = Object.values(webpackRequire(spec.protoModule)).filter(
        (value) => typeof value === "function" && value.typeName === spec.argumentTypeName,
      );
      if (constructors.length !== 1) {
        refuse("CURSOR_RESOURCE_PROTO_MISMATCH", `${spec.kind} argument constructor drifted`);
      }
      return new constructors[0](values);
    };
    const writeSpec = MANAGED_RESOURCE_SPECS.find(({ kind }) => kind === "filesystemWrite");
    const checkSpec = MANAGED_RESOURCE_SPECS.find(({ kind }) => kind === "offlineCheck");
    const write = await executorByKind.get("filesystemWrite").execute(
      { signal: operation.signal },
      argumentFor(writeSpec, { path: request.path, fileText: request.text }),
      { execId: "maco-providerless-write" },
    );
    const check = await executorByKind.get("offlineCheck").execute(
      { signal: operation.signal },
      argumentFor(checkSpec, {
        command: OFFLINE_CHECK_COMMAND,
        workingDirectory: request.workingDirectory,
      }),
      { execId: "maco-providerless-check" },
    );
    return Object.freeze({
      providerlessQualification: true,
      fixedModel: PROVIDERLESS_QUALIFICATION_MODEL,
      writeResultType: write?.constructor?.typeName,
      checkResultType: check?.constructor?.typeName,
      checkExitCode: check?.result?.value?.exitCode,
      actualProviderModel: null,
      actualEffort: null,
      usd: null,
    });
  }

  return Object.freeze({
    exports: Object.freeze({
      get Q() { return webpackRequire(SHARED_SERVICES_MODULE).Q; },
      get Y() { return webpackRequire(SESSION_RESOURCES_MODULE).Y; },
      get proto() {
        return Object.freeze({
          ReadArgs: webpackRequire(MANAGED_RESOURCE_SPECS[0].protoModule).a2,
          WriteArgs: webpackRequire(MANAGED_RESOURCE_SPECS[1].protoModule).hY,
          ShellArgs: webpackRequire(MANAGED_RESOURCE_SPECS[2].protoModule).a,
        });
      },
      createAgent(messages) {
        const AgentClient = webpackRequire(AGENT_CLIENT_MODULE)?.PW;
        if (typeof AgentClient !== "function") {
          refuse("CURSOR_AGENT_CLIENT_SHAPE_MISMATCH", "pinned PW client class is unavailable");
        }
        return new AgentClient(messages);
      },
    }),
    runProviderlessQualification,
    drainPendingCompletions: () => drainPendingCompletions(state),
    pendingCompletionCount: () => state.pendingCompletions.size,
    activeAttemptCount: () => state.activeAttempts.size,
    binding: Object.freeze({
      version: PINNED.version,
      index: indexSource,
      chunk: chunkSource,
      additionalSources,
      primaryAuthorityEnabled: false,
      actualProviderModel: null,
      actualEffort: null,
      usd: null,
      lowerRpcReturnShape: LOWER_RPC_RETURN_SHAPE,
      originalFactoriesCaptured: Object.freeze({
        sharedServices: typeof originalSharedServicesFactory === "function",
        sessionResources: typeof originalSessionResourcesFactory === "function",
      }),
      get originalFactoriesInvoked() {
        return Object.freeze({
          sharedServices: false,
          sessionResources: false,
        });
      },
      managedResourcePolicy: Object.freeze({
        version: RESOURCE_POLICY_VERSION,
        moduleId: AGENT_EXEC_MODULE,
        resources: MANAGED_RESOURCE_SPECS,
      }),
    }),
  });
}

function installPinnedCursorBridge({ root, parent }) {
  return installBridge({
    indexPath: path.join(root, "index.js"),
    chunkPath: path.join(root, "414.index.js"),
    indexSha256: PINNED.indexSha256,
    chunkSha256: PINNED.chunkSha256,
    additionalPins: PINNED.additionalSources.map(({ file, sha256: expectedSha256 }) => ({
      filename: path.join(root, file),
      sha256: expectedSha256,
    })),
    parent,
  });
}

module.exports = Object.freeze({
  CursorBridgeRefusal,
  LOWER_RPC_RETURN_SHAPE,
  PINNED,
  installPinnedCursorBridge,
  _test: Object.freeze({
    createDefaultDenyResources,
    constructManagedResources,
    installBridge,
    inspectRawMessage,
  }),
});

// Source-bound bootstrap. Offline installed-module tests cannot mint parent custody.
import { registerHooks, syncBuiltinESMExports, isBuiltin } from "node:module";
import {
  closeSync, constants as fsConstants, existsSync, fstatSync, fsyncSync,
  lstatSync, openSync, readFileSync, readdirSync, realpathSync, writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import childProcess from "node:child_process";
import { attachCodeAssist0412, bindCodeAssistClient0412, createCodeAssistWireUnit } from "./gemini_code_assist_wire.mjs";

export const VENDOR_ROOT = "/nix/store/xxd1smzi0a54ldwpc3l8d4v7k2bgjcpl-gemini-cli-0.41.2/share/gemini-cli";
export const CLOSURE = Object.freeze({
  "chunk-NWPRPA5T.js": "b63fba1de60ac1725785b27ec761c5085fa1dcc02a38f04bb300e07a769333b8",
  "chunk-34MYV7JD.js": "019fd0819c9e85555d6a6fbe468a53f647955dca2b5d629c6a920ef9ca8de6de",
  "chunk-RJTRUG2J.js": "d4003c271f32186f0b8928e6e0cc913dbd6d2771d697d88b4dc45fac58afe84d",
  "chunk-XRLFHCHC.js": "212695ba37862c484ca6a0617e52715b5338754a6e9fbc3733facad82db411e4",
  "chunk-664ZODQF.js": "0e5e41b8af7ca2ddd1bc3509c7276559d48a99705d6716b6d45c4c64b4f9168c",
  "chunk-ZP3RCUP6.js": "2caaf0808ed644ec464f4ac8c3298dfaa48a0b094578f72a1193c31a19cd847c",
  "chunk-IUUIT4SU.js": "878469f1440495db8e40b033dde88ab96c0ee7d9e40c3deb4cee91dde1c8031a",
  "chunk-CJMONNRN.js": "1481a97361a19cc0aa30fb6d2fdae54d775cd3523f461f7b15676bd898ea8a16",
  "chunk-R5DYDU46.js": "59100d73f5bd20731ce189d306cc5c5e26da805aa57cd1485beb526c33e8f3f9",
  "chunk-LMTL6SIF.js": "251677a3482db9cc987fb48b2c8d1b201dcfc7c5054e98d41a7d0e6d453100e5",
  "chunk-5PS3AYFU.js": "7163d845e3ddca0d222e60d4dd8b7a1f402f69d720f69c3ed16b89f74b16d515",
  "core-3VUBXSSG.js": "edd5b5ba72c989cb052718fe68792e354a54c1a1b81fbebc22a772a63e86e995",
});
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const guardKey = "__MACO_CODE_ASSIST_0412_PHASE_J__";
const guard = `globalThis.${guardKey}`;
const zName = "chunk-ZP3RCUP6.js";
const xName = "chunk-XRLFHCHC.js";
const nativeFetch = globalThis.fetch.bind(globalThis);
const once = (text, anchor, replacement) => {
  if (text.split(anchor).length !== 2) throw new Error("bootstrap: insertion_anchor");
  return text.replace(anchor, replacement);
};

// Pure transformation, with complete original bytes bound BEFORE any insertion.
export function instrumentVendor(name, bytes) {
  if (!(bytes instanceof Uint8Array) || digest(bytes) !== CLOSURE[name]) throw new Error("bootstrap: source_drift");
  let source = Buffer.from(bytes).toString("utf8");
  if (name === zName) {
    source = once(source, "constructor(params) {\n    this._sessionId = params.sessionId;",
      `constructor(params) {\n    params = ${guard}.config(params);\n    this._sessionId = params.sessionId;`);
    source = once(source, "async function initOauthClient(authType, config2) {\n  const credentials3 = await fetchCachedCredentials();",
      `async function initOauthClient(authType, config2) {\n  const credentials3 = await fetchCachedCredentials();\n  ${guard}.credentials(authType, credentials3);`);
    source = once(source, "  const useEncryptedStorage = getUseEncryptedStorageFlag();\n  if (process.env[\"GOOGLE_GENAI_USE_GCA\"]",
      `  ${guard}.client(client);\n  const useEncryptedStorage = getUseEncryptedStorageFlag();\n  if (process.env["GOOGLE_GENAI_USE_GCA"]`);
    source = once(source, "    this.paidTier = paidTier;\n    this.config = config2;\n  }\n  async generateContentStream",
      `    this.paidTier = paidTier;\n    this.config = config2;\n    ${guard}.server(this);\n  }\n  async generateContentStream`);
    // Owned test seam, NOT an original vendor export. Never call auth factories.
    source += "\nexport const MACO_TEST_ONLY_OAuth2Client = import_google_auth_library2.OAuth2Client;\n";
  }
  if (name === xName) {
    source = once(source, "var GoogleGenAI = class {\n  constructor(options) {",
      `var GoogleGenAI = class {\n  constructor(options) {\n    ${guard}.deny("sdk_constructor");`);
  }
  return { source, originalSha256: digest(bytes), instrumentedSha256: digest(source) };
}

// These checks corroborate the synthetic installed-module namespace. Production
// custody is established separately by the Rust-owned peer and containment checks.
export function inspectOfflineProfile() {
  if (process.version !== "v22.22.2" || process.platform !== "linux" || process.cwd() !== "/candidate"
      || process.env.HOME !== "/profile" || process.env.GEMINI_CLI_HOME !== "/profile"
      || process.env.GEMINI_CLI_SYSTEM_SETTINGS_PATH !== "/profile/system.json"
      || process.env.GEMINI_CLI_SYSTEM_DEFAULTS_PATH !== "/profile/defaults.json"
      || process.execArgv.length !== 0) throw new Error("bootstrap: profile_binding");
  const allowedEnv = new Set(["HOME", "GEMINI_CLI_HOME", "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH", "PATH", "LANG"]);
  if (Object.keys(process.env).some((key) => !allowedEnv.has(key))) throw new Error("bootstrap: ambient_environment");
  for (const directory of ["/", "/candidate", "/profile"]) {
    if (readdirSync(directory).some((entry) => entry === ".env" || entry === ".gemini")) throw new Error("bootstrap: ambient_profile");
  }
  if (readdirSync("/profile").some((entry) => !["system.json", "defaults.json"].includes(entry))
      || readFileSync("/profile/system.json", "utf8") !== "{}\n"
      || readFileSync("/profile/defaults.json", "utf8") !== "{}\n") throw new Error("bootstrap: profile_not_empty");
  const mounts = readFileSync("/proc/self/mountinfo", "utf8");
  const mountRows = mounts.trim().split("\n").map((line) => line.split(" "));
  for (const target of ["/nix/store", "/owned", "/candidate"]) {
    if (!mountRows.some((row) => row[4] === target && row[5].split(",").includes("ro"))) throw new Error("bootstrap: readonly_mount");
  }
  const interfaces = readdirSync("/sys/class/net");
  if (interfaces.length !== 1 || interfaces[0] !== "lo" || readFileSync("/sys/class/net/lo/operstate", "utf8").trim() !== "down") {
    throw new Error("bootstrap: network_namespace");
  }
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trim();
  if (!cgroup.includes("/user.slice/") || !cgroup.includes(".scope")) throw new Error("bootstrap: delegated_scope");
  return Object.freeze({ cgroup, network: "isolated_loopback_down", profile: "empty_private", mountsSha256: digest(mounts), productionEvidence: false });
}

export async function loadOfflineCodeAssist({ parent, physicalSink }) {
  const profile = inspectOfflineProfile();
  if (typeof physicalSink !== "function") throw new Error("bootstrap: offline_sink_or_duplicate");
  return loadGuardedCodeAssist({ parent, physicalSink, profile, candidate: "/candidate" });
}

// Called only by the source-bound native invocation wrapper below. An ACK means
// the parent appended and synced the observation, never that a check succeeded.
export function createNativeToolJournal(parent, candidate) {
  let actionId = 0, stopped = false, tail = Promise.resolve();
  return Object.freeze({ run(tool, params, signal, snapshot, execute) {
    const operation = tail.then(async () => {
      if (stopped || process.cwd() !== candidate || typeof parent?.observeTool !== "function" || ++actionId > 1024
          || !["read_file", "write_file", "replace"].includes(tool)
          || typeof params?.file_path !== "string") throw new Error("bootstrap: tool_journal_binding");
      const argumentsJson = JSON.stringify(params, (_key, value) => {
        if (value === undefined || typeof value === "function" || typeof value === "symbol"
            || (typeof value === "number" && !Number.isFinite(value))) throw new Error("bootstrap: tool_arguments");
        return value;
      });
      if (Buffer.byteLength(argumentsJson) > 8192) throw new Error("bootstrap: tool_arguments");
      const before = snapshot();
      const common = { actionId, tool, cwd: process.cwd(), argumentsJson, beforeSha256: before };
      if (await parent.observeTool({ ...common, kind: "begin", afterSha256: before }) !== true) {
        throw new Error("bootstrap: tool_journal_ack");
      }
      let result, failure;
      try { if (!signal?.aborted) result = await execute(); }
      catch (error) { failure = error; }
      const after = snapshot();
      const kind = signal?.aborted ? "cancelled" : failure || result?.error ? "failed" : "completed";
      if (await parent.observeTool({ ...common, kind, afterSha256: after }) !== true) {
        throw new Error("bootstrap: tool_journal_ack");
      }
      if (kind !== "completed") stopped = true;
      if (failure) throw failure;
      if (signal?.aborted) throw new Error("bootstrap: native_tool_cancelled");
      if (kind === "failed") throw new Error("bootstrap: native_tool_failed");
      return result;
    });
    tail = operation.catch(() => { stopped = true; });
    return operation;
  } });
}

async function loadGuardedCodeAssist({
  parent, physicalSink, profile, candidate,
  authorizedPersonalOAuth = false, writableWorker = false,
}) {
  if (globalThis[guardKey]) throw new Error("bootstrap: offline_sink_or_duplicate");
  const unit = createCodeAssistWireUnit({ parent });
  let stopped = false;
  let firstRefusal;
  const deny = (reason) => { stopped = true; unit.cancel(); firstRefusal ??= new Error(`bootstrap: ${reason}`); throw firstRefusal; };
  const active = () => { if (stopped) throw firstRefusal; };
  const receipts = new Map();
  const deniedOptionalImports = new Set();
  const servers = new WeakSet();
  const clients = new WeakSet();
  let core;
  let actualOAuth2Client;
  let toolMutationObserved = false;
  const toolJournal = createNativeToolJournal(parent, candidate);
  const source = readFileSync(`${VENDOR_ROOT}/${zName}`);
  if (digest(source) !== CLOSURE[zName]) deny("source_drift");
  // All ordinary external I/O is denied before vendor evaluation. The only
  // online handles retained are the original fetch functions passed through
  // the source-bound transporter and user-info wrappers below.
  for (const [object, names] of [[http, ["request", "get"]], [https, ["request", "get"]],
    [net, ["connect", "createConnection"]], [tls, ["connect"]], [dgram, ["createSocket"]],
    [childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]]]) {
    for (const name of names) object[name] = () => deny("external_io");
  }
  const extensionBytes = readFileSync(`${VENDOR_ROOT}/chunk-NWPRPA5T.js`);
  if (digest(extensionBytes) !== CLOSURE["chunk-NWPRPA5T.js"]) deny("source_drift");
  const embedded = [...extensionBytes.toString("utf8").matchAll(/H2 = "(data:application\/octet-stream;base64,[A-Za-z0-9+/=]+)";/g)];
  if (embedded.length !== 1) deny("embedded_wasm_shape");
  const wasm = Buffer.from(embedded[0][1].split(",")[1], "base64");
  const userInfoFetch = authorizedPersonalOAuth ? unit.wrapFetch(nativeFetch) : null;
  globalThis.fetch = (url, options = {}) => {
    if (url === embedded[0][1] && options?.credentials === "same-origin"
        && Object.keys(options).length === 1) {
      return Promise.resolve({ ok: true, arrayBuffer: async () => Uint8Array.from(wasm).buffer });
    }
    if (userInfoFetch) return userInfoFetch(url, options);
    return deny("unclassified_fetch");
  };
  syncBuiltinESMExports();
  const client = (value) => {
    active();
    if (!actualOAuth2Client || Object.getPrototypeOf(value) !== actualOAuth2Client.prototype) deny("oauth_client_identity");
    if (clients.has(value)) { bindCodeAssistClient0412(value, unit, source); return; }
    // Pass only the retained original fetch implementation. All actual OAuth,
    // DefaultTransporter and Gaxios preparation/translation methods still run.
    const transportFetch = physicalSink
      ? async (...args) => { active(); return physicalSink(...args); }
      : authorizedPersonalOAuth ? nativeFetch : undefined;
    bindCodeAssistClient0412(value, unit, source,
      transportFetch ? { offlineTestFetch: transportFetch } : {});
    clients.add(value);
  };
  const config = (params) => {
    active();
    if (!core || !params || Object.getPrototypeOf(params) !== Object.prototype) deny("config_shape");
    if (Object.values(Object.getOwnPropertyDescriptors(params)).some((d) => !Object.hasOwn(d, "value"))) deny("config_accessor");
    const allowed = new Set(["sessionId", "model", "targetDir", "cwd", "debugMode"]);
    if (Object.keys(params).some((key) => !allowed.has(key)) || params.targetDir !== candidate
        || params.cwd !== candidate) deny("config_authority");
    const permittedTools = writableWorker ? ["ReadFileTool", "WriteFileTool", "EditTool"] : ["ReadFileTool"];
    const permittedMainTools = writableWorker
      ? [core.ReadFileTool.Name, core.WriteFileTool.Name, core.EditTool.Name]
      : [core.ReadFileTool.Name];
    if (permittedMainTools.some((name) => typeof name !== "string" || !name)
        || new Set(permittedMainTools).size !== permittedMainTools.length) deny("tool_identity_drift");
    return { ...params, includeDirectories: [], mcpEnabled: false, mcpServers: {}, extensionsEnabled: false,
      extensionLoader: new core.SimpleExtensionLoader([]), enabledExtensions: [],
      coreTools: [...permittedTools], allowedTools: [], mainAgentTools: [...permittedMainTools],
      enableAgents: false, agents: {}, enableHooks: false, enableHooksUI: false,
      disabledHooks: [], skillsSupport: false, adminSkillsEnabled: false, disabledSkills: [],
      experimentalJitContext: false, experimentalMemoryV2: false, experimentalAutoMemory: false,
      experimentalGemma: false, enableConseca: false, disableLLMCorrection: true, plan: false, tracker: false, planSettings: { modelRouting: false }, useWriteTodos: false,
      adk: { agentSessionNoninteractiveEnabled: false, agentSessionInteractiveEnabled: false },
      gemmaModelRouter: { enabled: false, autoStartServer: false },
      telemetry: { enabled: false, logPrompts: false }, usageStatisticsEnabled: false,
      noBrowser: true, interactive: false, extensionManagement: false, enableExtensionReloading: false,
      fileFiltering: { enableFileWatcher: false }, includeDirectoryTree: false, loadMemoryFromIncludeDirectories: false,
      useRipgrep: false, useRenderProcess: false, enableEventDrivenScheduler: false,
      retryFetchErrors: false, maxAttempts: 1, billing: { overageStrategy: "never" },
    };
  };
  Object.defineProperty(globalThis, guardKey, { value: Object.freeze({
    config, client, deny,
    credentials: (authType, credentials) => {
      if (!authorizedPersonalOAuth || authType !== "oauth-personal" || !plain(credentials)
          || Object.values(Object.getOwnPropertyDescriptors(credentials)).some((d) => !Object.hasOwn(d, "value"))) {
        deny("auth_not_authorized");
      }
      const allowed = new Set(["refresh_token", "access_token", "expiry_date", "token_type", "scope", "id_token"]);
      if (Object.keys(credentials).some((key) => !allowed.has(key))
          || typeof credentials.refresh_token !== "string" || credentials.refresh_token.length === 0
          || credentials.refresh_token.length > 16384
          || (Object.hasOwn(credentials, "access_token")
            && (typeof credentials.access_token !== "string" || credentials.access_token.length === 0
              || credentials.access_token.length > 16384))
          || (Object.hasOwn(credentials, "expiry_date")
            && (!Number.isSafeInteger(credentials.expiry_date) || credentials.expiry_date < 0))
          || ["token_type", "scope", "id_token"].some((key) => Object.hasOwn(credentials, key)
            && (typeof credentials[key] !== "string" || credentials[key].length > 16384))) {
        deny("credential_shape");
      }
    },
    server: (server) => {
      active();
      try { client(server.client); attachCodeAssist0412(server, unit, source); } catch { deny("server_binding"); }
      servers.add(server);
      for (const name of ["generateContent", "generateContentStream"]) {
        const original = server[name];
        Object.defineProperty(server, name, { value: function (...args) {
          active();
          if (this !== server || unit.snapshot().activeCalls !== 0) deny("concurrent_or_foreign_generation");
          return Reflect.apply(original, this, args);
        } });
      }
    },
  }) });
  function canonical(url) {
    if (!url.startsWith("file:")) deny("import_scheme");
    const parsed = new URL(url);
    if (parsed.search || parsed.hash) deny("import_alias");
    const filename = fileURLToPath(parsed);
    const name = path.basename(filename);
    if (filename !== `${VENDOR_ROOT}/${name}` || !Object.hasOwn(CLOSURE, name)
        || realpathSync(filename) !== filename || lstatSync(filename).isSymbolicLink()) deny("import_closure");
    return name;
  }
  registerHooks({
    resolve(specifier, context, next) {
      if (isBuiltin(specifier)) return next(specifier, context);
      // Source-bound optional lookups: node-fetch (Z:6816), ws (664:88/727),
      // protobuf inquire (Z:24203/24485). Always deny, even if installed.
      // No optional bytes execute; all other resolution failures latch.
      const optionalOwners = { encoding: zName, long: zName, bufferutil: "chunk-664ZODQF.js", "utf-8-validate": "chunk-664ZODQF.js" };
      if (Object.hasOwn(optionalOwners, specifier) && context.parentURL === pathToFileURL(`${VENDOR_ROOT}/${specifier === "long" ? zName : "chunk-34MYV7JD.js"}`).href
          && receipts.has(optionalOwners[specifier]) && receipts.has("chunk-34MYV7JD.js")) {
        deniedOptionalImports.add(specifier);
        throw Object.assign(new Error("bootstrap: optional_dependency_absent"), { code: "MODULE_NOT_FOUND" });
      }
      let resolved;
      try { resolved = next(specifier, context); } catch { deny(`import_resolution_${digest(specifier)}`); }
      canonical(resolved.url);
      return resolved;
    },
    load(url, context, next) {
      if (url.startsWith("node:")) return next(url, context);
      const name = canonical(url);
      const loaded = next(url, context);
      if (loaded.format !== "module" || loaded.source == null || receipts.has(name)) deny("load_shape");
      const bytes = typeof loaded.source === "string" ? Buffer.from(loaded.source) : Buffer.from(loaded.source);
      const transformed = instrumentVendor(name, bytes);
      receipts.set(name, { path: fileURLToPath(url), originalSha256: transformed.originalSha256, instrumentedSha256: transformed.instrumentedSha256 });
      return { ...loaded, source: transformed.source };
    },
  });
  core = await import(pathToFileURL(`${VENDOR_ROOT}/core-3VUBXSSG.js`).href);
  const extensions = await import(pathToFileURL(`${VENDOR_ROOT}/chunk-NWPRPA5T.js`).href);
  const z = await import(pathToFileURL(`${VENDOR_ROOT}/${zName}`).href);
  actualOAuth2Client = z.MACO_TEST_ONLY_OAuth2Client;
  const sdk = await import(pathToFileURL(`${VENDOR_ROOT}/${xName}`).href);
  if (receipts.size !== Object.keys(CLOSURE).length) deny("prior_evaluation_or_closure_loss");
  for (const name of Object.keys(CLOSURE)) if (!receipts.has(name)) deny("prior_evaluation");
  function replace(prototype, name, value) {
    if (typeof prototype?.[name] !== "function") deny("guard_shape");
    Object.defineProperty(prototype, name, { value, configurable: false, writable: false });
  }
  for (const name of ["generateContent", "generateContentStream"]) {
    const original = core.LoggingContentGenerator.prototype[name];
    replace(core.LoggingContentGenerator.prototype, name, function (...args) {
      active();
      if (!servers.has(this.wrapped) || !(this.wrapped instanceof core.CodeAssistServer)) deny("logging_backend");
      return Reflect.apply(original, this, args);
    });
  }
  for (const name of ["recordConversationOffered", "recordConversationInteraction"]) {
    replace(core.CodeAssistServer.prototype, name, async () => { active(); });
  }
  replace(core.ExtensionLoader.prototype, "startExtension", () => deny("extension_start"));
  replace(extensions.ExtensionManager.prototype, "loadExtensions", async function () {
    active(); this.loadedExtensions = Object.freeze([]); return this.loadedExtensions;
  });
  for (const name of Object.getOwnPropertyNames(extensions.ExtensionManager.prototype)) {
    if (/^(start|reload|install)/i.test(name) && typeof extensions.ExtensionManager.prototype[name] === "function") {
      replace(extensions.ExtensionManager.prototype, name, () => deny("extension_mutation"));
    }
  }
  for (const name of ["getMcpClientManager", "getLocalLiteRtLmClient"]) {
    replace(core.Config.prototype, name, () => deny("forbidden_config_route"));
  }
  replace(core.Config.prototype, "getMcpServers", function (...args) {
    active();
    if (args.length !== 0 || !(this instanceof core.Config)) deny("forbidden_config_route");
    return Object.freeze({});
  });
  replace(core.Config.prototype, "getMcpServerCommand", function (...args) {
    active();
    if (args.length !== 0 || !(this instanceof core.Config)) deny("forbidden_config_route");
    return undefined;
  });
  const allowedPath = (relative, allowMissing = false) => {
    active();
    if (typeof relative !== "string" || path.isAbsolute(relative) || relative.split(/[\\/]/).some((part) => !part || part.startsWith("."))) deny("tool_path");
    const absolute = path.resolve(candidate, relative);
    if (!absolute.startsWith(`${candidate}/`)) deny("tool_path");
    if (!existsSync(absolute)) {
      const parent = path.dirname(absolute);
      if (!allowMissing || realpathSync(parent) !== parent || !lstatSync(parent).isDirectory()
          || lstatSync(parent).isSymbolicLink()) deny("tool_path");
      return absolute;
    }
    if (realpathSync(absolute) !== absolute || !lstatSync(absolute).isFile()
        || lstatSync(absolute).isSymbolicLink()) deny("tool_path");
    return absolute;
  };
  const observedFileDigest = (absolute, allowMissing) => {
    if (!existsSync(absolute)) {
      if (allowMissing) return null;
      deny("tool_path");
    }
    const metadata = lstatSync(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 4 * 1024 * 1024) deny("tool_result_bound");
    return digest(readFileSync(absolute));
  };
  const authorizedTools = new Map();
  function authorizeTool(Tool, { mutating = false, allowMissing = false } = {}) {
    if (typeof Tool?.prototype?.build !== "function" || typeof Tool.Name !== "string") deny("tool_shape");
    const originalBuild = Tool.prototype.build;
    Object.defineProperty(Tool.prototype, "build", { value: function (params) {
      if (Object.getPrototypeOf(this) !== Tool.prototype || this.name !== Tool.Name) deny("tool_identity");
      const absolute = allowedPath(params?.file_path, allowMissing);
      const copy = Object.freeze({ ...params });
      const invocation = Reflect.apply(originalBuild, this, [copy]);
      const execute = invocation.execute;
      Object.defineProperty(invocation, "execute", { value: async function (...args) {
        const rebound = allowedPath(copy.file_path, allowMissing);
        if (this !== invocation || rebound !== absolute || this.resolvedPath !== absolute
            || this.params !== copy || typeof execute !== "function") deny("tool_rebound");
        const snapshot = () => observedFileDigest(allowedPath(copy.file_path, allowMissing), allowMissing);
        const before = snapshot();
        const result = await toolJournal.run(Tool.Name, copy, args[0]?.abortSignal, snapshot,
          () => Reflect.apply(execute, this, args));
        allowedPath(copy.file_path, false);
        if (mutating && snapshot() !== before) toolMutationObserved = true;
        return result;
      } });
      return invocation;
    }, configurable: false, writable: false });
    authorizedTools.set(Tool.prototype, Tool);
  }
  authorizeTool(core.ReadFileTool);
  if (writableWorker) {
    authorizeTool(core.WriteFileTool, { mutating: true, allowMissing: true });
    authorizeTool(core.EditTool, { mutating: true });
  }
  const register = core.ToolRegistry.prototype.registerTool;
  replace(core.ToolRegistry.prototype, "registerTool", function (tool) {
    active();
    const Tool = authorizedTools.get(Object.getPrototypeOf(tool));
    if (!Tool || tool.name !== Tool.Name || tool.build !== Tool.prototype.build) deny("tool_not_authorized");
    return Reflect.apply(register, this, [tool]);
  });
  return Object.freeze({ core, extensions, sdk, OAuth2Client: z.MACO_TEST_ONLY_OAuth2Client,
    registerClient: client, unit, profile, closure: Object.freeze([...receipts.values()]),
    deniedOptionalImports: Object.freeze([...deniedOptionalImports]),
    toolMutationObserved: () => toolMutationObserved,
    testOnly: Boolean(physicalSink), productionEvidence: false,
  });
}

// Capture the original connector before the vendor guard denies all new I/O.
// This one connection is established before imports; no reconnect or TCP path.
const privateConnect = net.createConnection.bind(net);
export async function connectManagedParent(socketPath, nonce, { timeoutMs = 5000, onCancel = () => {} } = {}) {
  if (!path.isAbsolute(socketPath) || !/^[a-f0-9]{64}$/.test(nonce)
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw new Error("bootstrap: channel_binding");
  const socket = privateConnect({ path: socketPath });
  let sequence = 0, stopped = false, pending, buffered = Buffer.alloc(0), queue = Promise.resolve();
  const stop = () => {
    if (stopped) return;
    stopped = true; pending?.reject(new Error("bootstrap: parent_channel_lost")); pending = undefined;
    socket.destroy(); onCancel();
  };
  socket.on("error", stop); socket.on("close", stop);
  socket.on("data", (bytes) => {
    buffered = Buffer.concat([buffered, bytes]);
    if (buffered.length > 4096) return stop();
    const end = buffered.indexOf(10);
    if (end < 0) return;
    // Only one outstanding request. Unsolicited/trailing replies fail closed.
    if (end !== buffered.length - 1 || !pending) return stop();
    const bytesToReply = buffered.subarray(0, end).toString("utf8");
    let reply;
    try { reply = JSON.parse(bytesToReply); } catch { return stop(); }
    buffered = Buffer.alloc(0);
    if (Object.keys(reply).sort().join(",") !== "nonce,ok,sequence" || reply.nonce !== nonce
        || reply.sequence !== sequence || reply.ok !== true
        || JSON.stringify({ nonce: reply.nonce, sequence: reply.sequence, ok: reply.ok }) !== bytesToReply) return stop();
    const accepted = pending; pending = undefined; accepted.resolve(true);
  });
  const send = (message) => {
    const operation = queue.then(async () => {
      if (stopped || sequence >= 16384) throw new Error("bootstrap: parent_channel_lost");
      const bytes = Buffer.from(JSON.stringify({ nonce, sequence: ++sequence, message }) + "\n");
      if (bytes.length > 16384) { stop(); throw new Error("bootstrap: channel_bound"); }
      let timer;
      try {
        return await new Promise((resolve, reject) => {
          pending = { resolve, reject };
          timer = setTimeout(stop, timeoutMs);
          socket.write(bytes, (error) => { if (error) stop(); });
        });
      } finally { clearTimeout(timer); }
    });
    queue = operation.catch(() => {});
    return operation;
  };
  return Object.freeze({ send, admit: (event) => send({ type: "event", event }),
    record: (event) => send({ type: "event", event }),
    observeTool: (event) => send({ type: "native_tool", event }), close: stop });
}

function requirePrivatePath(filename, { directory = false, maxBytes = 65536, empty = false } = {}) {
  const metadata = lstatSync(filename);
  if (realpathSync(filename) !== filename || metadata.isSymbolicLink()
      || metadata.uid !== process.getuid() || (metadata.mode & 0o077)
      || (directory ? !metadata.isDirectory() : !metadata.isFile())
      || (!directory && (metadata.nlink !== 1 || metadata.size > maxBytes || (empty && metadata.size !== 0)))) {
    throw new Error("bootstrap: private_profile");
  }
  return metadata;
}

export function managedEnvironmentKeysAllowed(environment, cwd, personalOAuth = false) {
  const allowedEnv = new Set(["HOME", "GEMINI_CLI_HOME", "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
    "GEMINI_CLI_SYSTEM_DEFAULTS_PATH", "PATH", "LANG", "MACO_RUN_ID", "MACO_TASK_ID"]);
  if (personalOAuth === true) allowedEnv.add("GOOGLE_GENAI_USE_GCA");
  return Object.keys(environment).every((key) => {
    if (key === "PWD") return environment.PWD === cwd;
    if (key === "SHLVL") return environment.SHLVL === "0";
    return allowedEnv.has(key);
  });
}

function inspectManagedProfile(root, candidate, promptPath, resultPath) {
  const profile = `${root}/profile`;
  const credentialDirectory = `${profile}/.gemini`;
  const credentialPath = `${credentialDirectory}/oauth_creds.json`;
  if (!managedEnvironmentKeysAllowed(process.env, process.cwd(), true) || process.env.HOME !== profile
      || process.env.GEMINI_CLI_HOME !== profile
      || process.env.GEMINI_CLI_SYSTEM_SETTINGS_PATH !== `${profile}/system.json`
      || process.env.GEMINI_CLI_SYSTEM_DEFAULTS_PATH !== `${profile}/defaults.json`
      || process.env.GOOGLE_GENAI_USE_GCA !== "true"
      || process.cwd() !== candidate || root === candidate || root.startsWith(`${candidate}/`)
      || candidate.startsWith(`${root}/`) || promptPath !== `${root}/prompt.txt`
      || resultPath !== `${profile}/result.txt`) throw new Error("bootstrap: private_profile");
  requirePrivatePath(profile, { directory: true });
  requirePrivatePath(credentialDirectory, { directory: true });
  requirePrivatePath(credentialPath, { maxBytes: 65536 });
  requirePrivatePath(`${profile}/system.json`, { maxBytes: 3 });
  requirePrivatePath(`${profile}/defaults.json`, { maxBytes: 3 });
  requirePrivatePath(promptPath, { maxBytes: 1024 * 1024 });
  requirePrivatePath(resultPath, { maxBytes: 1024 * 1024, empty: true });
  if (readdirSync(profile).sort().join(",") !== ".gemini,defaults.json,result.txt,system.json"
      || readdirSync(credentialDirectory).join(",") !== "oauth_creds.json"
      || readFileSync(`${profile}/system.json`, "utf8") !== "{}\n"
      || readFileSync(`${profile}/defaults.json`, "utf8") !== "{}\n") {
    throw new Error("bootstrap: private_profile");
  }
  const mounts = readFileSync("/proc/self/mountinfo", "utf8");
  const rows = mounts.trim().split("\n").map((line) => line.split(" "));
  if (!rows.some((row) => row[4] === "/nix/store" && row[5].split(",").includes("ro"))) {
    throw new Error("bootstrap: readonly_mount");
  }
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trim();
  if (!cgroup.includes("/user.slice/") || !cgroup.includes(".scope")) {
    throw new Error("bootstrap: delegated_scope");
  }
  return Object.freeze({ cgroup, network: "parent_verified_online", profile: "selected_personal_oauth",
    mountsSha256: digest(mounts), productionEvidence: false });
}

function writeHeldResult(filename, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 1024 * 1024) {
    throw new Error("bootstrap: result_bound");
  }
  requirePrivatePath(filename, { maxBytes: 1024 * 1024, empty: true });
  const descriptor = openSync(filename, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.uid !== process.getuid() || metadata.nlink !== 1
        || (metadata.mode & 0o077) || metadata.size !== 0) throw new Error("bootstrap: result_binding");
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  requirePrivatePath(filename, { maxBytes: 1024 * 1024 });
}

let privateHandshakeAcknowledged = false;
let managedStartupStage = "manifest";

async function managedEntry(manifestPath) {
  const root = path.dirname(manifestPath);
  const metadata = lstatSync(manifestPath);
  if (process.version !== "v22.22.2" || process.platform !== "linux" || process.execArgv.length
      || realpathSync(manifestPath) !== manifestPath || !metadata.isFile() || metadata.nlink !== 1
      || metadata.uid !== process.getuid() || (metadata.mode & 0o077) || metadata.size > 16384) throw new Error("bootstrap: manifest_binding");
  const m = JSON.parse(readFileSync(manifestPath, "utf8"));
  const manifestKeys = Object.keys(m).sort().join(",");
  const offline = manifestKeys === "bootstrapSha256,candidate,model,nonce,promptSha256,wireSha256";
  const online = manifestKeys === "bootstrapSha256,candidate,model,nonce,promptPath,promptSha256,resultPath,wireSha256,workspaceAccess";
  if ((!offline && !online) || !path.isAbsolute(m.candidate) || process.cwd() !== m.candidate
      || realpathSync(m.candidate) !== m.candidate || root.startsWith(`${m.candidate}/`)
      || (online && (m.workspaceAccess !== "read_write" || !path.isAbsolute(m.promptPath)
        || !path.isAbsolute(m.resultPath)))
      || typeof m.model !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(m.model)
      || !/^[a-f0-9]{64}$/.test(m.promptSha256)
      || digest(readFileSync(`${root}/gemini_managed_bootstrap.mjs`)) !== m.bootstrapSha256
      || digest(readFileSync(`${root}/gemini_code_assist_wire.mjs`)) !== m.wireSha256) throw new Error("bootstrap: manifest_binding");
  if (offline) {
    managedStartupStage = "profile";
    const profilePath = `${root}/profile`;
    if (!managedEnvironmentKeysAllowed(process.env, process.cwd()) || process.env.HOME !== profilePath
        || process.env.GEMINI_CLI_HOME !== profilePath
        || process.env.GEMINI_CLI_SYSTEM_SETTINGS_PATH !== `${profilePath}/system.json`
        || process.env.GEMINI_CLI_SYSTEM_DEFAULTS_PATH !== `${profilePath}/defaults.json`
        || readdirSync(profilePath).sort().join(",") !== "defaults.json,system.json"
        || readFileSync(`${profilePath}/system.json`, "utf8") !== "{}\n"
        || readFileSync(`${profilePath}/defaults.json`, "utf8") !== "{}\n") {
      throw new Error("bootstrap: private_profile");
    }
    let offlineUnit;
    managedStartupStage = "parent_connect";
    const offlineParent = await connectManagedParent(`${root}/parent.sock`, m.nonce,
      { onCancel: () => offlineUnit?.cancel() });
    try {
      managedStartupStage = "hello_ack";
      await offlineParent.send({ type: "hello", bootstrapSha256: m.bootstrapSha256,
        wireSha256: m.wireSha256, promptSha256: m.promptSha256 });
      privateHandshakeAcknowledged = true;
      const loaded = await loadGuardedCodeAssist({ parent: offlineParent, candidate: m.candidate,
        profile: Object.freeze({ productionEvidence: false, network: "parent_verified_offline" }) });
      offlineUnit = loaded.unit;
      new loaded.core.Config({ sessionId: "maco-private-bootstrap", model: m.model,
        targetDir: m.candidate, cwd: m.candidate, debugMode: false });
      await offlineParent.send({ type: "ready", closure: loaded.closure });
      await offlineParent.send({ type: "refused", reason: "auth_not_authorized" });
      return;
    } finally { offlineParent.close(); }
  }
  const prompt = readFileSync(m.promptPath);
  if (digest(prompt) !== m.promptSha256) throw new Error("bootstrap: prompt_binding");
  managedStartupStage = "profile";
  const profile = inspectManagedProfile(root, m.candidate, m.promptPath, m.resultPath);
  let unit;
  managedStartupStage = "parent_connect";
  const parent = await connectManagedParent(`${root}/parent.sock`, m.nonce, { onCancel: () => unit?.cancel() });
  try {
    managedStartupStage = "hello_ack";
    await parent.send({ type: "hello", bootstrapSha256: m.bootstrapSha256, wireSha256: m.wireSha256, promptSha256: m.promptSha256 });
    privateHandshakeAcknowledged = true;
    const loaded = await loadGuardedCodeAssist({ parent, candidate: m.candidate,
      profile, authorizedPersonalOAuth: true, writableWorker: true });
    unit = loaded.unit;
    const config = new loaded.core.Config({ sessionId: "maco-private-bootstrap", model: m.model,
      targetDir: m.candidate, cwd: m.candidate, debugMode: false });
    await parent.send({ type: "ready", closure: loaded.closure });
    await config.initialize();
    await config.refreshAuth("oauth-personal");
    const session = new loaded.core.LegacyAgentSession({ config, promptId: `maco-${m.promptSha256.slice(0, 16)}` });
    const output = [];
    let terminalReason;
    for await (const event of session.sendStream({ message: {
      content: [{ type: "text", text: prompt.toString("utf8") }],
      displayContent: "MACO managed assignment",
    } })) {
      if (event?.type === "message" && event.role === "agent" && Array.isArray(event.content)) {
        for (const part of event.content) {
          if (part?.type === "text" && typeof part.text === "string") output.push(part.text);
        }
      } else if (event?.type === "error" && event.fatal !== false) {
        throw new Error("bootstrap: agent_error");
      } else if (event?.type === "agent_end") {
        terminalReason = event.reason;
      }
    }
    if (terminalReason !== "completed" || !loaded.toolMutationObserved()) {
      throw new Error("bootstrap: managed_worker_incomplete");
    }
    const resultText = output.join("").trimEnd();
    if (!resultText) throw new Error("bootstrap: empty_worker_result");
    const result = Buffer.from(resultText + "\n", "utf8");
    writeHeldResult(m.resultPath, result);
    await parent.send({ type: "completed", resultSha256: digest(result), toolMutationObserved: true });
  } finally { parent.close(); }
}

if (process.argv[2] === "--maco-managed") {
  if (process.argv.length !== 4) throw new Error("bootstrap: fixed_argv");
  try { await managedEntry(process.argv[3]); } catch {
    process.stderr.write(`bootstrap: ${privateHandshakeAcknowledged ? "post_handshake" : `pre_handshake_${managedStartupStage}`}\n`);
    process.exitCode = 1;
  }
}

// Phase J only: source-bound installed-module proof. No production launcher or custody.
import { registerHooks, syncBuiltinESMExports, isBuiltin } from "node:module";
import { readFileSync, realpathSync, lstatSync, readdirSync } from "node:fs";
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

// These checks corroborate the test namespace; they are NOT a future Rust peer /
// launch authentication protocol. Production admission remains absent in phase J.
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
  if (typeof physicalSink !== "function" || globalThis[guardKey]) throw new Error("bootstrap: offline_sink_or_duplicate");
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
  const source = readFileSync(`${VENDOR_ROOT}/${zName}`);
  if (digest(source) !== CLOSURE[zName]) deny("source_drift");
  // All external I/O is denied before vendor evaluation. Only the explicit
  // original Gaxios final adapter below receives synthetic offline responses.
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
  globalThis.fetch = (url, options) => {
    if (url !== embedded[0][1] || options?.credentials !== "same-origin"
        || Object.keys(options).length !== 1) return deny("unclassified_fetch");
    return Promise.resolve({ ok: true, arrayBuffer: async () => Uint8Array.from(wasm).buffer });
  };
  syncBuiltinESMExports();
  const client = (value) => {
    active();
    if (!actualOAuth2Client || Object.getPrototypeOf(value) !== actualOAuth2Client.prototype) deny("oauth_client_identity");
    if (clients.has(value)) { bindCodeAssistClient0412(value, unit, source); return; }
    // Pass only the pinned Gaxios final fetchImplementation option. All actual
    // OAuth/DefaultTransporter/Gaxios preparation and response methods still run.
    bindCodeAssistClient0412(value, unit, source, { offlineTestFetch: async (...args) => {
      active(); return physicalSink(...args);
    } });
    clients.add(value);
  };
  const config = (params) => {
    active();
    if (!core || !params || Object.getPrototypeOf(params) !== Object.prototype) deny("config_shape");
    if (Object.values(Object.getOwnPropertyDescriptors(params)).some((d) => !Object.hasOwn(d, "value"))) deny("config_accessor");
    const allowed = new Set(["sessionId", "model", "targetDir", "cwd", "debugMode"]);
    if (Object.keys(params).some((key) => !allowed.has(key)) || params.targetDir !== "/candidate"
        || params.cwd !== "/candidate") deny("config_authority");
    return { ...params, includeDirectories: [], mcpEnabled: false, mcpServers: {}, extensionsEnabled: false,
      extensionLoader: new core.SimpleExtensionLoader([]), enabledExtensions: [], coreTools: ["ReadFileTool"],
      allowedTools: [], mainAgentTools: [], enableAgents: false, agents: {}, enableHooks: false, enableHooksUI: false,
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
    // Phase J has no authorized credential channel. Even apparently personal
    // credentials cannot enable this offline bootstrap's auth factory.
    credentials: () => deny("auth_not_authorized"),
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
  for (const name of ["getMcpClientManager", "getMcpServers", "getMcpServerCommand", "getLocalLiteRtLmClient"]) {
    replace(core.Config.prototype, name, () => deny("forbidden_config_route"));
  }
  const allowedPath = (relative) => {
    active();
    if (typeof relative !== "string" || path.isAbsolute(relative) || relative.split(/[\\/]/).some((part) => !part || part.startsWith("."))) deny("tool_path");
    const absolute = path.resolve("/candidate", relative);
    if (!absolute.startsWith("/candidate/") || realpathSync(absolute) !== absolute || !lstatSync(absolute).isFile()) deny("tool_path");
    return absolute;
  };
  const originalBuild = core.ReadFileTool.prototype.build;
  Object.defineProperty(core.ReadFileTool.prototype, "build", { value: function (params) {
    if (Object.getPrototypeOf(this) !== core.ReadFileTool.prototype || this.name !== core.ReadFileTool.Name) deny("tool_identity");
    allowedPath(params?.file_path);
    const copy = Object.freeze({ ...params });
    const invocation = Reflect.apply(originalBuild, this, [copy]);
    const execute = invocation.execute;
    Object.defineProperty(invocation, "execute", { value: function (...args) {
      allowedPath(copy.file_path);
      if (this !== invocation || this.resolvedPath !== path.resolve("/candidate", copy.file_path) || this.params !== copy) deny("tool_rebound");
      return Reflect.apply(execute, this, args);
    } });
    return invocation;
  } });
  const register = core.ToolRegistry.prototype.registerTool;
  replace(core.ToolRegistry.prototype, "registerTool", function (tool) {
    active();
    if (Object.getPrototypeOf(tool) !== core.ReadFileTool.prototype || tool.name !== core.ReadFileTool.Name
        || tool.build !== core.ReadFileTool.prototype.build) deny("tool_not_authorized");
    return Reflect.apply(register, this, [tool]);
  });
  return Object.freeze({ core, extensions, sdk, OAuth2Client: z.MACO_TEST_ONLY_OAuth2Client,
    registerClient: client, unit, profile, closure: Object.freeze([...receipts.values()]),
    deniedOptionalImports: Object.freeze([...deniedOptionalImports]),
    testOnly: true, productionEvidence: false,
  });
}

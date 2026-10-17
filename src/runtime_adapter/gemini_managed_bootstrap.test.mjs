import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmdirSync, readFileSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";
import net from "node:net";
import { loadOfflineCodeAssist, instrumentVendor, VENDOR_ROOT, CLOSURE, connectManagedParent, managedEnvironmentKeysAllowed, createNativeToolJournal, managedSessionResult } from "./gemini_managed_bootstrap.mjs";

import { bindCodeAssistClient0412, createCodeAssistWireUnit } from "./gemini_code_assist_wire.mjs";
const envelope = { traceId: "synthetic-offline", response: {
  candidates: [{ content: { role: "model", parts: [{ text: "Synthetic response" }] }, finishReason: "STOP" }],
  modelVersion: "unverified-response-model", usageMetadata: {
    promptTokenCount: 10, candidatesTokenCount: 5, thoughtsTokenCount: 2, cachedContentTokenCount: 4, totalTokenCount: 17,
  },
} };
function physicalResponse(text, status = 200) {
  return { status, statusText: status === 200 ? "OK" : "Unauthorized", headers: new Headers(),
    body: Readable.from([Buffer.from(text)]), url: "https://cloudcode-pa.googleapis.com/", ok: status === 200 };
}

async function scenario(name) {
  process.chdir("/candidate");
  const events = []; let sends = 0; let refreshes = 0; let quotaSends = 0;
  let terminalGate;
  function holdNextQuotaTerminal() {
    let observe; let acknowledge;
    const observed = new Promise((resolve) => { observe = resolve; });
    const ack = new Promise((resolve) => { acknowledge = resolve; });
    terminalGate = { observe, ack };
    return { observed, acknowledge };
  }
  if (name === "preloaded") {
    // Still inside the empty, network-denied namespace. A cached core may not
    // certify source hook coverage, even if all remaining imports are guarded.
    await import(pathToFileURL(`${VENDOR_ROOT}/core-3VUBXSSG.js`).href);
  }
  if (name === "profile") process.env.NODE_OPTIONS = "--inspect";
  if (name === "ambient-file") mkdirSync("/profile/.gemini");
  const load = () => loadOfflineCodeAssist({
    parent: {
      observeTool: async (event) => { events.push(event); return true; },
      admit: async (event) => { events.push(event); return true; },
      record: async (event) => {
        events.push(event);
        if (terminalGate && event.kind === "terminal" && event.requestClass === "quota") {
          const gate = terminalGate;
          terminalGate = undefined;
          gate.observe(event);
          return gate.ack;
        }
        return true;
      },
    },
    physicalSink: async (url, options) => {
      sends++;
      assert.equal(options.retry, false); assert.equal(options.maxRedirects, 0);
      assert.equal(events.at(-1).kind, "release");
      if (url === "https://oauth2.googleapis.com/token") {
        refreshes++;
        assert.equal(events.at(-1).requestClass, "oauth_refresh");
        return physicalResponse(JSON.stringify({ access_token: "synthetic-refreshed", token_type: "Bearer", expires_in: 3600 }));
      }
      if (name === "setup-methods" && url.endsWith(":retrieveUserQuota")) {
        quotaSends++;
        if (quotaSends === 1) return physicalResponse("{}", 401);
      }
      if (name === "replay" && sends === 1) return physicalResponse("{}", 401);
      return physicalResponse(options.params?.alt === "sse" ? `data: ${JSON.stringify(envelope)}\n\n` : JSON.stringify(envelope));
    },
  });
  if (["preloaded", "profile", "ambient-file"].includes(name)) {
    await assert.rejects(load(), name === "profile" ? /ambient_environment/ : name === "ambient-file" ? /ambient_profile/ : /prior_evaluation/);
    assert.equal(sends, 0); return;
  }
  const b = await load();
  assert.equal(b.testOnly, true); assert.equal(b.productionEvidence, false);
  assert.equal(b.closure.length, 12);
  assert.deepEqual([...b.deniedOptionalImports].sort(), ["bufferutil", "encoding", "long"]);
  if (name === "unknown-dependency") {
    await assert.rejects(import("maco-unlisted-package"), /import_resolution_/);
    assert.equal(b.unit.snapshot().stopped, true); assert.equal(sends, 0); return;
  }
  if (name === "userinfo") {
    assert.throws(() => globalThis.fetch("https://www.googleapis.com/oauth2/v2/userinfo"), /unclassified_fetch/);
    assert.equal(b.unit.snapshot().stopped, true); assert.equal(sends, 0); return;
  }
  const params = { sessionId: "phase-j-offline", model: "gemini-2.5-pro", cwd: "/candidate", targetDir: "/candidate", debugMode: false };
  if (name === "hostile-config") {
    assert.throws(() => new b.core.Config({ ...params, mcpServers: { required: { command: "forbidden" } } }), /config_authority/);
    assert.throws(() => new b.core.Config(params), /config_authority/); assert.equal(sends, 0); return;
  }
  if (name === "sdk") {
    let touched = false;
    assert.throws(() => new b.sdk.GoogleGenAI({ get apiKey() { touched = true; return "never"; } }), /sdk_constructor/);
    assert.equal(touched, false); assert.equal(sends, 0); return;
  }
  if (name === "alias") {
    await assert.rejects(import(pathToFileURL(`${VENDOR_ROOT}/core-3VUBXSSG.js`).href + "?copy=1"), /import_alias/);
    assert.equal(sends, 0); return;
  }
  const config = new b.core.Config(params);
  for (const field of ["enableAgents", "mcpEnabled", "extensionsEnabled", "skillsSupport", "adminSkillsEnabled", "enableHooks", "enableHooksUI", "planEnabled", "trackerEnabled", "experimentalJitContext", "experimentalAutoMemory", "enableConseca", "agentSessionNoninteractiveEnabled", "agentSessionInteractiveEnabled", "usageStatisticsEnabled", "interactive", "retryFetchErrors"]) assert.equal(config[field], false, field);
  assert.equal(config.gemmaModelRouter.autoStartServer, false);
  assert.equal(config.telemetrySettings.enabled, false);
  assert.equal(config.disableLLMCorrection, true);
  assert.equal(config.noBrowser, true);
  if (name === "shell") {
    const registry = new b.core.ToolRegistry(config, config.getMessageBus());
    // Z:288468 starts shell-parser import before registry registration. The
    // source-closure guard refuses that import even though the vendor catches
    // its rejection. It must remain latched and prevent subsequent generation.
    assert.throws(() => registry.registerTool(new b.core.ShellTool(config, config.getMessageBus())), /import_closure/);
    assert.equal(b.unit.snapshot().stopped, true);
    assert.throws(() => new b.core.Config(params), /import_closure/);
    assert.equal(sends, 0); return;
  }
  if (["tools", "tools-write-refusal", "tools-edit-refusal"].includes(name)) {
    await config.initialize();
    const registry = new b.core.ToolRegistry(config, config.getMessageBus(), true);
    const reader = new b.core.ReadFileTool(config, config.getMessageBus());
    registry.registerTool(reader);
    assert.ok(registry.getFunctionDeclarations().some((declaration) =>
      declaration.name === b.core.ReadFileTool.Name));
    const invocation = reader.build({ file_path: "sample.txt" });
    const result = await invocation.execute({ abortSignal: new AbortController().signal });
    assert.match(result.llmContent, /Substantive confined source packet/);
    const observations = events.filter((event) => event.tool === b.core.ReadFileTool.Name);
    assert.deepEqual(observations.map((event) => event.kind), ["begin", "completed"]);
    assert.equal(observations[0].actionId, observations[1].actionId);
    assert.equal(observations[0].argumentsJson, JSON.stringify({ file_path: "sample.txt" }));
    assert.equal(observations[1].argumentsJson, observations[0].argumentsJson);
    assert.equal(observations[1].cwd, process.cwd());
    assert.equal(observations[1].afterSha256, observations[0].beforeSha256);
    assert.deepEqual(registry.getFunctionDeclarations().map((entry) => entry.name), [b.core.ReadFileTool.Name]);
    if (name === "tools") {
      assert.throws(() => reader.build({ file_path: "../profile/system.json" }), /tool_path/);
    } else {
      // Each denial uses its own unit: a prior denial is permanently latched.
      const Tool = name === "tools-write-refusal" ? b.core.WriteFileTool : b.core.EditTool;
      assert.throws(() => registry.registerTool(new Tool(config, config.getMessageBus())), /tool_not_authorized/);
    }
    assert.equal(sends, 0); return;
  }
  if (name === "mcp-empty") {
    await config.initialize();
    assert.deepEqual(config.getMcpServers(), {});
    assert.equal(config.getMcpServerCommand(), undefined);
    assert.throws(() => config.getMcpServers("unexpected"), /forbidden_config_route/);
    assert.equal(sends, 0); return;
  }
  if (name === "tool-spoof") {
    const registry = new b.core.ToolRegistry(config, config.getMessageBus());
    assert.throws(() => registry.registerTool({ name: b.core.ReadFileTool.Name, build() { throw new Error("effect"); } }), /tool_not_authorized/);
    assert.equal(sends, 0); return;
  }
  if (name === "extensions") {
    const loader = new b.core.SimpleExtensionLoader([]);
    await assert.rejects(async () => loader.startExtension({}), /extension_start/);
    assert.equal(sends, 0); return;
  }
  if (name === "logging-backend") {
    let called = false;
    const logging = new b.core.LoggingContentGenerator({ generateContent() { called = true; } }, config);
    assert.throws(() => logging.generateContent({}), /logging_backend/);
    assert.equal(called, false); assert.equal(sends, 0); return;
  }
  const makeClient = () => {
    const client = new b.OAuth2Client({ clientId: "synthetic-client", clientSecret: "synthetic-secret" });
    client.setCredentials({ access_token: "synthetic-token", refresh_token: "synthetic-refresh", expiry_date: Date.now() + 3600000 });
    client.forceRefreshOnFailure = true;
    return client;
  };
  const client = makeClient(); b.registerClient(client); const transport = client.transporter.request;
  const server = new b.core.CodeAssistServer(client, "synthetic-project", {}, "offline");
  const second = new b.core.CodeAssistServer(client, "synthetic-project", {}, "offline");
  assert.equal(client.transporter.request, transport);
  const fresh = makeClient(); const third = new b.core.CodeAssistServer(fresh, "synthetic-project", {}, "offline");
  assert.notEqual(fresh.transporter.request, transport);
  if (name === "setup-methods") {
    await server.loadCodeAssist({ metadata: {} });
    await server.onboardUser({ metadata: {} });
    await server.getOperation("operations/operation-1");
    client.setCredentials({ access_token: "synthetic-expired", refresh_token: "synthetic-refresh", expiry_date: Date.now() - 1 });
    const replayGate = holdNextQuotaTerminal();
    const quota = server.retrieveUserQuota({});
    const failedQuota = await replayGate.observed;
    assert.equal(failedQuota.terminal, "http_error");
    const experiments = server.listExperiments({});
    replayGate.acknowledge(true);
    await Promise.all([quota, experiments]);
    assert.deepEqual(b.unit.snapshot().attempts.map((attempt) => attempt.requestClass),
      ["setup_user", "setup_user", "setup_user", "oauth_refresh", "quota", "experiments", "oauth_refresh", "quota"]);
    assert.equal(refreshes, 2);
    assert.equal(quotaSends, 2);
    assert.equal(sends, 8);

    const cancelGate = holdNextQuotaTerminal();
    const cancelQuota = server.retrieveUserQuota({});
    assert.equal((await cancelGate.observed).terminal, "eof");
    const cancelExperiments = server.listExperiments({});
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(b.unit.snapshot().activeCalls, 2);
    b.unit.cancel();
    cancelGate.acknowledge(true);
    const cancelled = await Promise.allSettled([cancelQuota, cancelExperiments]);
    assert.deepEqual(cancelled.map((result) => result.status), ["rejected", "rejected"]);
    const startup = b.unit.snapshot();
    assert.equal(startup.stopped, true);
    assert.equal(startup.activeCalls, 0);
    assert.deepEqual(startup.attempts.map((attempt) => attempt.requestClass),
      ["setup_user", "setup_user", "setup_user", "oauth_refresh", "quota", "experiments", "oauth_refresh", "quota", "quota"]);
    assert.equal(sends, 9);
    return;
  }
  if (name === "receiver") {
    await assert.rejects(b.unit.request("unary", () => client.transporter.request.call({}, {
      url: "https://cloudcode-pa.googleapis.com/v1internal:generateContent", method: "POST",
    })));
    assert.equal(b.unit.snapshot().stopped, true); assert.equal(sends, 0); return;
  }
  if (name === "ownership") {
    const foreign = createCodeAssistWireUnit({ parent: { admit: async () => assert.fail("foreign admission"), record: async () => true } });
    assert.throws(() => bindCodeAssistClient0412(client, foreign, readFileSync(`${VENDOR_ROOT}/chunk-ZP3RCUP6.js`)), /client_owner_drift/);
    assert.equal(b.unit.snapshot().stopped, true); assert.equal(foreign.snapshot().stopped, true);
    assert.equal(sends, 0); return;
  }
  if (name === "unclassified") {
    await assert.rejects(client.request({ url: "https://oauth2.googleapis.com/tokeninfo?copy=1", method: "GET" }), /unexpected_send/);
    assert.equal(sends, 0); assert.equal(b.unit.snapshot().stopped, true); return;
  }
  const request = { model: "gemini-2.5-pro", contents: [{ role: "user", parts: [{ text: "Synthetic offline only" }] }] };
  const logging = new b.core.LoggingContentGenerator(server, config);
  const result = await logging.generateContent(request, "synthetic-prompt", "main");
  assert.equal(result.usageMetadata.totalTokenCount, 17);
  const stream = await new b.core.LoggingContentGenerator(second, config).generateContentStream(request, "synthetic-prompt", "main");
  const chunks = []; for await (const item of stream) chunks.push(item);
  assert.equal(chunks.length, 1);
  await third.generateContent(request, "synthetic-prompt", "main");
  assert.equal(refreshes, name === "replay" ? 1 : 0);
  assert.equal(sends, name === "replay" ? 5 : 3);
  const snapshot = b.unit.snapshot();
  assert.equal(snapshot.stopped, false); assert.equal(snapshot.activeCalls, 0);
  assert.equal(snapshot.attempts.filter((a) => a.requestClass === "generation" && a.terminal === "eof").length, 3);
  assert.equal(events.filter((e) => e.kind === "admission").length, sends);
  assert.equal(events.filter((e) => e.kind === "release").length, sends);
  for (const attempt of snapshot.attempts) { assert.equal(attempt.qualified, false); assert.equal(attempt.cost, null); }
  assert.doesNotMatch(JSON.stringify(events), /synthetic-(token|secret|refresh|prompt)/);
  console.log(JSON.stringify({ installedModuleProof: name, profile: b.profile, closure: b.closure, deniedOptionalImports: b.deniedOptionalImports, attempts: snapshot.attempts.length, productionEvidence: false }));
}

if (process.argv[2] === "--offline-scenario") {
  await scenario(process.argv[3]);
} else {
  test("read-only managed result preserves Worker mutation and terminal requirements", () => {
    assert.equal(managedSessionResult("read_only", "completed", false, ["Observed ", "read-only result"]).toString(),
      "Observed read-only result\n");
    assert.throws(() => managedSessionResult("read_only", "completed", true, ["changed"]), /managed_session_incomplete/);
    assert.throws(() => managedSessionResult("read_write", "completed", false, ["no mutation"]), /managed_session_incomplete/);
    assert.equal(managedSessionResult("read_write", "completed", true, ["actual edit"]).toString(), "actual edit\n");
    for (const reason of ["cancelled", "failed", undefined]) {
      assert.throws(() => managedSessionResult("read_only", reason, false, ["partial"]), /managed_session_incomplete/);
    }
    assert.throws(() => managedSessionResult("read_only", "completed", false, []), /managed_result_bound/);
    assert.throws(() => managedSessionResult("read_only", "completed", false, ["x".repeat(1024 * 1024)]), /managed_result_bound/);
    assert.throws(() => managedSessionResult("foreign", "completed", false, ["text"]), /managed_session_incomplete/);
  });
  test("native tool journal waits for begin and terminal ACK with original arguments", async () => {
    const root = mkdtempSync(join(tmpdir(), "maco-native-journal-"));
    const filename = join(root, "sample.txt"), candidate = process.cwd();
    const events = []; let beginAck, terminalAck, beginSeen, terminalSeen;
    const began = new Promise((resolve) => { beginSeen = resolve; });
    const ended = new Promise((resolve) => { terminalSeen = resolve; });
    const begin = new Promise((resolve) => { beginAck = resolve; });
    const terminal = new Promise((resolve) => { terminalAck = resolve; });
    const parent = { observeTool: async (event) => {
      events.push(event);
      if (event.kind === "begin") { beginSeen(); await begin; }
      else { terminalSeen(); await terminal; }
      return true;
    } };
    const snapshot = () => {
      try { return createHash("sha256").update(readFileSync(filename)).digest("hex"); }
      catch (error) { if (error.code === "ENOENT") return null; throw error; }
    };
    try {
      const journal = createNativeToolJournal(parent, candidate);
      const params = Object.freeze({ file_path: "sample.txt", content: "exact\nquoted \"argument\"" });
      let settled = false;
      const run = journal.run("write_file", params, new AbortController().signal, snapshot,
        async () => { writeFileSync(filename, params.content); return { llmContent: "written" }; });
      run.then(() => { settled = true; });
      await began;
      assert.equal(snapshot(), null);
      beginAck(); await ended;
      assert.equal(readFileSync(filename, "utf8"), params.content);
      assert.equal(settled, false);
      terminalAck(); await run;
      assert.deepEqual(events.map((event) => [event.kind, event.actionId]), [["begin", 1], ["completed", 1]]);
      assert.equal(events[0].argumentsJson, JSON.stringify(params));
      assert.equal(events[1].argumentsJson, events[0].argumentsJson);
      assert.equal(events[0].beforeSha256, null);
      assert.equal(events[1].afterSha256, snapshot());
      assert.equal(events[0].cwd, candidate);
    } finally { unlinkSync(filename); rmdirSync(root); }
  });
  test("native tool journal cancellation retains observed mutation and blocks another action", async () => {
    const events = [], controller = new AbortController(); let digest = null;
    const journal = createNativeToolJournal({ observeTool: async (event) => { events.push(event); return true; } }, process.cwd());
    await assert.rejects(journal.run("replace", { file_path: "sample.txt", old_string: "a", new_string: "b" },
      controller.signal, () => digest, async () => { digest = "b".repeat(64); controller.abort(); }), /native_tool_cancelled/);
    assert.deepEqual(events.map((event) => event.kind), ["begin", "cancelled"]);
    assert.equal(events[1].afterSha256, "b".repeat(64));
    let executed = false;
    await assert.rejects(journal.run("read_file", { file_path: "sample.txt" }, new AbortController().signal,
      () => digest, async () => { executed = true; }), /tool_journal_binding/);
    assert.equal(executed, false);
  });
  test("native tool journal missing or refused custody cannot execute; failed native result stays failed", async () => {
    let executed = false;
    for (const parent of [{}, { observeTool: async () => false }, { observeTool: async () => { throw new Error("held journal refused"); } }]) {
      await assert.rejects(createNativeToolJournal(parent, process.cwd()).run("read_file", { file_path: "sample.txt" },
        new AbortController().signal, () => "a".repeat(64), async () => { executed = true; }));
    }
    assert.equal(executed, false);
    const events = [];
    await assert.rejects(createNativeToolJournal({ observeTool: async (event) => { events.push(event); return true; } }, process.cwd())
      .run("read_file", { file_path: "sample.txt" }, new AbortController().signal, () => "a".repeat(64),
        async () => ({ error: { type: "file_error" } })), /native_tool_failed/);
    assert.deepEqual(events.map((event) => event.kind), ["begin", "failed"]);
  });
  test("managed environment keys admit only exact shell intrinsics", () => {
    const cwd = "/synthetic-candidate";
    const fixed = { HOME: "/synthetic-profile", GEMINI_CLI_HOME: "/synthetic-profile",
      GEMINI_CLI_SYSTEM_SETTINGS_PATH: "/synthetic-profile/system.json",
      GEMINI_CLI_SYSTEM_DEFAULTS_PATH: "/synthetic-profile/defaults.json", PATH: "/nonexistent", LANG: "C.UTF-8" };
    for (const personalOAuth of [false, true]) {
      const environment = personalOAuth ? { ...fixed, GOOGLE_GENAI_USE_GCA: "true" } : fixed;
      for (const intrinsics of [{}, { PWD: cwd }, { SHLVL: "0" }, { PWD: cwd, SHLVL: "0" }]) {
        assert.equal(managedEnvironmentKeysAllowed({ ...environment, ...intrinsics }, cwd, personalOAuth), true);
      }
      for (const refused of [{ PWD: `${cwd}/other` }, { SHLVL: "1" }, { SHLVL: "" },
        { _: "" }, { FOREIGN_KEY: "synthetic" }, { LD_LIBRARY_PATH: "/synthetic-lib" }, { NODE_OPTIONS: "--trace-warnings" }]) {
        assert.equal(managedEnvironmentKeysAllowed({ ...environment, ...refused }, cwd, personalOAuth), false);
      }
    }
    assert.equal(managedEnvironmentKeysAllowed({ ...fixed, GOOGLE_GENAI_USE_GCA: "true" }, cwd), false);
  });

  async function privateChannelCase(reply, operation) {
    const root = mkdtempSync(join(tmpdir(), "maco-gemini-private-channel-"));
    assert.match(root, /^\/tmp\/maco-gemini-private-channel-[A-Za-z0-9]+$/);
    const connections = new Set(); const messages = []; let cancelled = 0;
    const server = net.createServer((socket) => {
      connections.add(socket); socket.on("error", () => {});
      let data = "";
      socket.on("data", (bytes) => {
        data += bytes.toString("utf8");
        const end = data.indexOf("\n");
        if (end < 0) return;
        const message = JSON.parse(data.slice(0, end)); data = data.slice(end + 1);
        messages.push(message); reply(socket, message);
      });
    });
    let client;
    try {
      await new Promise((resolve, reject) => { server.once("error", reject); server.listen(join(root, "parent.sock"), resolve); });
      client = await connectManagedParent(join(root, "parent.sock"), "a".repeat(64), { timeoutMs: 500, onCancel: () => cancelled++ });
      await operation(client, messages, () => cancelled);
    } finally {
      client?.close(); for (const socket of connections) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
      rmdirSync(root); // Empty owned leaf only; unexpected contents fail cleanup.
    }
  }
  const acknowledge = (socket, message) => socket.write(JSON.stringify({ nonce: message.nonce, sequence: message.sequence, ok: true }) + "\n");
  test("managed private channel requires a fresh ordered ACK for each callback", async () => {
    await privateChannelCase(acknowledge, async (client, messages) => {
      assert.equal(await client.admit({ kind: "admission", attemptId: 1 }), true);
      assert.equal(await client.record({ kind: "release", attemptId: 1 }), true);
      assert.deepEqual(messages.map((m) => m.sequence), [1, 2]);
      assert.deepEqual(messages.map((m) => m.message.event.kind), ["admission", "release"]);
    });
  });
  for (const failure of ["lost", "wrong-nonce", "replay", "duplicate", "malformed", "oversized"]) {
    test(`managed private channel ${failure} latches cancellation and denies queued callbacks`, async () => {
      await privateChannelCase((socket, m) => {
        if (failure === "lost") return;
        if (failure === "malformed") return socket.write("{\n");
        if (failure === "oversized") return socket.write("x".repeat(4097));
        if (failure === "duplicate") return socket.write(`{"nonce":"${m.nonce}","sequence":${m.sequence},"ok":false,"ok":true}\n`);
        socket.write(JSON.stringify({ nonce: failure === "wrong-nonce" ? "b".repeat(64) : m.nonce,
          sequence: failure === "replay" ? m.sequence - 1 : m.sequence, ok: true }) + "\n");
      }, async (client, messages, cancelled) => {
        const first = client.admit({ kind: "admission" });
        const second = client.record({ kind: "release" });
        const results = await Promise.allSettled([first, second]);
        assert.deepEqual(results.map((r) => r.status), ["rejected", "rejected"]);
        assert.equal(messages.length, 1); assert.equal(cancelled(), 1);
        await assert.rejects(client.admit({ kind: "admission", attemptId: 2 }), /parent_channel_lost/);
        assert.equal(messages.length, 1);
      });
    });
  }
  const directory = dirname(fileURLToPath(import.meta.url));
  test("managed bootstrap reports only an allowlisted pre-handshake category", () => {
    const root = mkdtempSync(join(tmpdir(), "maco-gemini-bootstrap-category-"));
    const control = join(root, "control");
    const profile = join(control, "profile");
    const candidate = join(root, "candidate");
    const files = [];
    try {
      mkdirSync(control, { mode: 0o700 });
      mkdirSync(profile, { mode: 0o700 });
      mkdirSync(candidate, { mode: 0o700 });
      const put = (filename, bytes) => {
        writeFileSync(filename, bytes, { mode: 0o600, flag: "wx" });
        files.push(filename);
      };
      const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
      const bootstrap = readFileSync(join(directory, "gemini_managed_bootstrap.mjs"));
      const wire = readFileSync(join(directory, "gemini_code_assist_wire.mjs"));
      put(join(control, "gemini_managed_bootstrap.mjs"), bootstrap);
      put(join(control, "gemini_code_assist_wire.mjs"), wire);
      put(join(profile, "system.json"), "{}\n");
      put(join(profile, "defaults.json"), "{}\n");
      const manifest = join(control, "launch.json");
      const launch = { candidate, model: "synthetic-model", nonce: "a".repeat(64),
        promptSha256: hash("synthetic-prompt"), bootstrapSha256: hash(bootstrap), wireSha256: hash(wire) };
      put(manifest, JSON.stringify(launch));
      const invalidChannel = join(control, "invalid-channel.json");
      put(invalidChannel, JSON.stringify({ ...launch, nonce: "sensitive-invalid-nonce" }));
      const environment = { HOME: profile, GEMINI_CLI_HOME: profile,
        GEMINI_CLI_SYSTEM_SETTINGS_PATH: join(profile, "system.json"),
        GEMINI_CLI_SYSTEM_DEFAULTS_PATH: join(profile, "defaults.json"), PATH: "/nonexistent", LANG: "C.UTF-8" };
      for (const [manifestPath, env, stage] of [
        [join(control, "sensitive-manifest-name.json"), {}, "manifest"],
        [manifest, { ...environment, FOREIGN_KEY: "sensitive-environment-value" }, "profile"],
        [manifest, { ...environment, PWD: control }, "profile"],
        [manifest, { ...environment, SHLVL: "1" }, "profile"],
        [manifest, { ...environment, _: "" }, "profile"],
        [invalidChannel, environment, "parent_connect"],
        [manifest, { ...environment, PWD: candidate, SHLVL: "0" }, "hello_ack"],
      ]) {
        const result = spawnSync(process.execPath,
          [join(directory, "gemini_managed_bootstrap.mjs"), "--maco-managed", manifestPath],
          { cwd: candidate, encoding: "utf8", env, timeout: 5000, maxBuffer: 4096 });
        assert.equal(result.error, undefined, String(result.error));
        assert.equal(result.status, 1);
        assert.equal(result.stdout, "");
        assert.equal(result.stderr, `bootstrap: pre_handshake_${stage}\n`);
        assert.doesNotMatch(result.stderr, /sensitive-|FOREIGN_KEY|ENOENT|Error:|synthetic-/);
      }
    } finally {
      for (const filename of files) unlinkSync(filename);
      rmdirSync(profile);
      rmdirSync(control);
      rmdirSync(candidate);
      rmdirSync(root);
    }
  });
  const sandbox = String.raw`
set -euo pipefail
root="$1"
owned="$2"
node="$3"
scenario="$4"
mount --make-rprivate /
mount -t tmpfs -o mode=700 tmpfs "$root"
mkdir -p "$root"/{nix/store,owned,candidate,profile,proc,sys,dev,tmp}
mount --bind /nix/store "$root/nix/store"
mount -o remount,bind,ro "$root/nix/store"
mount --bind "$owned" "$root/owned"
mount -o remount,bind,ro "$root/owned"
printf 'Substantive confined source packet: export const answer = 42;\n' > "$root/candidate/sample.txt"
mount --bind "$root/candidate" "$root/candidate"
mount -o remount,bind,ro "$root/candidate"
printf '{}\n' > "$root/profile/system.json"
printf '{}\n' > "$root/profile/defaults.json"
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
touch "$root/dev/null"
mount --bind /dev/null "$root/dev/null"
cd "$root/candidate"
exec env -i HOME=/profile GEMINI_CLI_HOME=/profile GEMINI_CLI_SYSTEM_SETTINGS_PATH=/profile/system.json GEMINI_CLI_SYSTEM_DEFAULTS_PATH=/profile/defaults.json PATH=/nonexistent LANG=C.UTF-8 /usr/sbin/chroot "$root" "$node" /owned/gemini_managed_bootstrap.test.mjs --offline-scenario "$scenario"
`;
  for (const name of ["installed", "replay", "hostile-config", "sdk", "alias", "profile", "ambient-file", "preloaded", "tools", "tools-write-refusal", "tools-edit-refusal", "mcp-empty", "tool-spoof", "shell", "extensions", "logging-backend", "setup-methods", "receiver", "ownership", "unclassified", "unknown-dependency", "userinfo"]) {
    test(`installed 0.41.2 offline namespace: ${name}`, { timeout: 45000 }, () => {
      const root = mkdtempSync(join(tmpdir(), "maco-gemini-phase-j-"));
      assert.match(root, /^\/tmp\/maco-gemini-phase-j-[A-Za-z0-9]+$/);
      try {
        const result = spawnSync("/usr/bin/unshare", ["--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "/bin/bash", "-c", sandbox, "phase-j", root, directory, process.execPath, name], { encoding: "utf8", timeout: 40000, maxBuffer: 1024 * 1024 });
        if (result.stdout) console.log(result.stdout.trim());
        assert.equal(result.error, undefined, String(result.error));
        assert.equal(result.status, 0, result.stderr);
      } finally {
        // The tmpfs mount exists only in the terminated child namespace. Never
        // recursively delete: an unexpected retained entry prevents cleanup.
        rmdirSync(root);
      }
    });
  }
  test("bound source transformer refuses changed bytes and unknown closure members", () => {
    const original = readFileSync(`${VENDOR_ROOT}/chunk-ZP3RCUP6.js`);
    const modified = Buffer.from(original); modified[100] ^= 1;
    assert.throws(() => instrumentVendor("chunk-ZP3RCUP6.js", modified), /source_drift/);
    assert.throws(() => instrumentVendor("unlisted.js", original), /source_drift/);
    assert.equal(instrumentVendor("chunk-ZP3RCUP6.js", original).originalSha256, CLOSURE["chunk-ZP3RCUP6.js"]);
  });
}

import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmdirSync, readFileSync, mkdirSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { Readable } from "node:stream";
import { loadOfflineCodeAssist, instrumentVendor, VENDOR_ROOT, CLOSURE } from "./gemini_managed_bootstrap.mjs";

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
  const events = []; let sends = 0; let refreshes = 0;
  if (name === "preloaded") {
    // Still inside the empty, network-denied namespace. A cached core may not
    // certify source hook coverage, even if all remaining imports are guarded.
    await import(pathToFileURL(`${VENDOR_ROOT}/core-3VUBXSSG.js`).href);
  }
  if (name === "profile") process.env.NODE_OPTIONS = "--inspect";
  if (name === "ambient-file") mkdirSync("/profile/.gemini");
  const load = () => loadOfflineCodeAssist({
    parent: { admit: async (event) => { events.push(event); return true; }, record: async (event) => { events.push(event); return true; } },
    physicalSink: async (url, options) => {
      sends++;
      assert.equal(options.retry, false); assert.equal(options.maxRedirects, 0);
      assert.equal(events.at(-1).kind, "release");
      if (url === "https://oauth2.googleapis.com/token") {
        refreshes++;
        assert.equal(events.at(-1).requestClass, "oauth_refresh");
        return physicalResponse(JSON.stringify({ access_token: "synthetic-refreshed", token_type: "Bearer", expires_in: 3600 }));
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
  if (name === "tools") {
    const registry = new b.core.ToolRegistry(config, config.getMessageBus());
    const reader = new b.core.ReadFileTool(config, config.getMessageBus());
    registry.registerTool(reader);
    const invocation = reader.build({ file_path: "sample.txt" });
    const result = await invocation.execute({ abortSignal: new AbortController().signal });
    assert.match(result.llmContent, /Substantive confined source packet/);
    assert.throws(() => reader.build({ file_path: "../profile/system.json" }), /tool_path/);
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
    await assert.rejects(client.request({ url: "https://oauth2.googleapis.com/tokeninfo", method: "GET" }), /unscoped_send/);
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
  const directory = dirname(fileURLToPath(import.meta.url));
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
  for (const name of ["installed", "replay", "hostile-config", "sdk", "alias", "profile", "ambient-file", "preloaded", "tools", "tool-spoof", "shell", "extensions", "logging-backend", "receiver", "ownership", "unclassified", "unknown-dependency", "userinfo"]) {
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

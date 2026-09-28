import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import {
  attachCodeAssist0412, CODE_ASSIST_SOURCE, createCodeAssistWireUnit,
} from "./gemini_code_assist_wire.mjs";

const envelope = (total = 17, extra = {}) => ({
  traceId: "fixture-trace",
  response: {
    candidates: [{ content: { parts: [{ text: "Substantive fixture response" }] }, finishReason: "STOP" }],
    modelVersion: "gemini-2.5-pro",
    usageMetadata: { promptTokenCount: 10, candidatesTokenCount: total - 12, thoughtsTokenCount: 2, totalTokenCount: total, cachedContentTokenCount: 4 },
    ...extra,
  },
});
const sse = (value) => `data: ${JSON.stringify(value)}\n\n`;
async function* body(...parts) {
  for (const part of parts) {
    if (part instanceof Error) throw part;
    yield typeof part === "string" ? Buffer.from(part) : part;
  }
}
const options = (mode) => ({
  url: `https://cloudcode-pa.googleapis.com/v1internal:${mode === "unary" ? "generateContent" : "streamGenerateContent"}`,
  method: "POST", body: "request-secret", headers: { Authorization: "Bearer credential-secret" },
  retry: true, retryConfig: { retry: 3, shouldRetry: () => true },
});
function harness(send, callbacks = {}, limits) {
  const events = [];
  const receiver = { fixture: "original receiver" };
  let sends = 0;
  const unit = createCodeAssistWireUnit({
    parent: {
      admit: async (event) => { events.push(event); return callbacks.admit ? callbacks.admit(event) : true; },
      record: async (event) => { events.push(event); return callbacks.record ? callbacks.record(event) : true; },
    }, limits,
  });
  const transport = unit.wrapTransport(async function (opts) {
    assert.equal(this, receiver);
    ++sends;
    assert.equal(opts.retry, false);
    assert.deepEqual(opts.retryConfig, { retry: 0, noResponseRetries: 0 });
    assert.equal(opts.responseType, "stream");
    assert.equal(opts.maxRedirects, 0);
    assert.equal(opts.redirect, "error");
    return send(opts, sends);
  });
  return {
    unit, events, receiver, transport,
    sends: () => sends,
    call: (mode, signal) => unit.request(mode, async () => (await transport.call(receiver, options(mode))).data, signal),
  };
}
async function collect(stream) {
  const result = [];
  for await (const item of stream) result.push(item);
  return result;
}

test("unary wire capture precedes later client translation failure and exports no secrets", async () => {
  const value = envelope();
  value.headers = { authorization: "response-secret" };
  value.response.candidates[0].content.parts[0].text = "private-content-secret";
  const h = harness(async () => ({ status: 200, headers: { cookie: "cookie-secret" }, data: body(JSON.stringify(value)) }));
  await assert.rejects(h.unit.request("unary", async () => {
    const response = await h.transport.call(h.receiver, options("unary"));
    assert.equal(response.data.response.usageMetadata.totalTokenCount, 17);
    assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
    throw new Error("later vendor translation/logging-secret");
  }), /client_failed/);
  const state = h.unit.snapshot();
  assert.equal(state.stopped, true);
  assert.equal(state.attempts[0].terminal, "eof");
  assert.equal(state.attempts[0].observedModelVersion, "gemini-2.5-pro");
  assert.equal(state.attempts[0].qualified, false);
  assert.equal(state.attempts[0].cost, null);
  assert.doesNotMatch(JSON.stringify(h.events), /secret|Authorization|cookie|private-content/);
  assert.deepEqual(h.events.map((event) => event.kind), ["admission", "release", "observation", "terminal"]);
});

test("bounded SSE decodes split UTF-8 and CRLF; overlapping usage is not added", async () => {
  const first = envelope(17);
  first.response.candidates[0].content.parts[0].text = "解析";
  delete first.response.candidates[0].finishReason;
  const bytes = Buffer.from((sse(first) + sse(first) + sse(envelope(23))).replaceAll("\n", "\r\n"));
  const split = bytes.indexOf(Buffer.from("解析")) + 1;
  const h = harness(async () => ({ status: 200, data: body(bytes.subarray(0, split), bytes.subarray(split)) }));
  const result = await collect(await h.call("stream"));
  assert.equal(result.length, 3);
  assert.equal(result[0].response.candidates[0].content.parts[0].text, "解析");
  const observed = h.unit.snapshot().attempts[0];
  assert.equal(observed.usageLowerBound, 23);
  assert.equal(observed.usage.candidatesTokenCount, 11);
  assert.equal(observed.terminal, "eof");
  assert.equal(observed.usageCoverage, "observed_lower_bound_only");
  assert.equal(h.sends(), 1);
});

test("malformed or trailing SSE and lost final frame preserve prior usage but fail", async () => {
  const unfinished = envelope();
  delete unfinished.response.candidates[0].finishReason;
  for (const tail of ["data: {bad}\n\n", "data: {}", "", "event: unknown\n\n", "data: [DONE]\n\n"]) {
    const h = harness(async () => ({ status: 200, data: body(sse(unfinished), tail) }));
    await assert.rejects(collect(await h.call("stream")), /stream_failed/);
    assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
    assert.equal(h.unit.snapshot().attempts[0].terminal, "stream_error");
    assert.equal(h.unit.snapshot().stopped, true);
    await assert.rejects(h.call("unary"), /cancelled/);
    assert.equal(h.sends(), 1);
  }
});

test("stream transport error retains before-translation observations", async () => {
  const h = harness(async () => ({ status: 200, data: body(sse(envelope()), new Error("socket secret")) }));
  const iterator = await h.call("stream");
  assert.equal((await iterator.next()).value.response.usageMetadata.totalTokenCount, 17);
  await assert.rejects(iterator.next(), /stream_failed/);
  assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
  assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
});

test("duplicate JSON keys, invalid UTF-8, empty bodies and unary trailing bytes refuse", async () => {
  for (const bytes of [
    '{"response":{"usageMetadata":{"totalTokenCount":17,"totalTokenCount":0}}}',
    Buffer.from([0xff]), "", JSON.stringify(envelope()) + "{}",
  ]) {
    const h = harness(async () => ({ status: 200, data: body(bytes) }));
    await assert.rejects(h.call("unary"));
    assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, null);
    assert.equal(h.unit.snapshot().attempts[0].terminal, "transport_error");
  }
});

test("missing model or usage remains unknown and requested labels are never substituted", async () => {
  for (const response of [{}, { usageMetadata: { totalTokenCount: 17 } }, { modelVersion: "gemini-2.5-pro" }]) {
    const h = harness(async () => ({ status: 200, data: body(JSON.stringify({ response })) }));
    await h.call("unary");
    const record = h.unit.snapshot().attempts[0];
    assert.equal(record.observedModelVersion, response.modelVersion ?? null);
    assert.equal(record.usageLowerBound, response.usageMetadata?.totalTokenCount ?? null);
    assert.equal(record.cost, null);
    assert.equal(record.actualEffort, null);
    assert.equal(record.qualified, false);
  }
});

test("invalid, unsafe, regressing, conflicting and subset counters never replace valid usage", async () => {
  for (const changed of [
    { usageMetadata: { totalTokenCount: -1 } },
    { usageMetadata: { totalTokenCount: Number.MAX_SAFE_INTEGER + 1 } },
    { usageMetadata: { totalTokenCount: "23" } },
    { usageMetadata: { totalTokenCount: 12 } },
    { usageMetadata: { promptTokenCount: 10, cachedContentTokenCount: 11 } },
    { usageMetadata: { promptTokenCount: 40, totalTokenCount: 23 } },
    { usageMetadata: { thoughtsTokenCount: 30 } },
    { candidates: [{ finishReason: "INVENTED" }] },
    { modelVersion: "different-model" },
  ]) {
    const h = harness(async () => ({ status: 200, data: body(sse(envelope()), sse(envelope(23, changed))) }));
    await assert.rejects(collect(await h.call("stream")), /stream_failed/);
    assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
    assert.equal(h.unit.snapshot().attempts[0].usage.totalTokenCount, 17);
  }
});

test("observation ACK precedes downstream delivery and output mutation cannot rewrite retained facts", async () => {
  let release;
  let captured;
  const capturedPromise = new Promise((resolve) => { captured = resolve; });
  const h = harness(async () => ({ status: 200, data: body(sse(envelope())) }), {
    record: (event) => {
      if (event.kind !== "observation") return true;
      assert.ok(Object.isFrozen(event.usage));
      captured();
      return new Promise((resolve) => { release = resolve; });
    },
  });
  const iterator = await h.call("stream");
  let delivered = false;
  const pending = iterator.next().then((result) => { delivered = true; return result; });
  await capturedPromise;
  assert.equal(delivered, false);
  assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
  release(true);
  const result = await pending;
  result.value.response.usageMetadata.totalTokenCount = 0;
  assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
  await iterator.next();
});

test("transport binding drift latches refusal before admission or send", async () => {
  const unit = createCodeAssistWireUnit({ parent: {
    admit: async () => assert.fail("drift must precede admission"), record: async () => true,
  } });
  const transport = unit.wrapTransport(async () => assert.fail("drifted send"), () => { throw new Error("changed"); });
  await assert.rejects(unit.request("unary", () => transport(options("unary"))));
  assert.equal(unit.snapshot().stopped, true);
  assert.equal(unit.snapshot().attempts.length, 0);
});

test("each physical OAuth replay needs a new admission, even with identical request options", async () => {
  const h = harness(async (_, number) => number === 1
    ? { status: 401, data: body(JSON.stringify({ error: { message: "auth-secret" } })) }
    : { status: 200, data: body(JSON.stringify(envelope())) });
  const opts = options("unary");
  const result = await h.unit.request("unary", async () => {
    try { return await h.transport.call(h.receiver, opts); }
    catch (error) {
      assert.equal(error.response.status, 401);
      // Offline OAuth requestAsync replay analogue; no credential refresh call.
      return h.transport.call(h.receiver, opts);
    }
  });
  assert.equal(result.data.response.usageMetadata.totalTokenCount, 17);
  assert.equal(h.sends(), 2);
  assert.deepEqual(h.events.filter((event) => event.kind === "admission").map((event) => event.attemptId), [1, 2]);
  const attempts = h.unit.snapshot().attempts;
  assert.equal(attempts[0].terminal, "http_error");
  assert.equal(attempts[0].usageLowerBound, null);
  assert.equal(attempts[1].usageLowerBound, 17);
  assert.equal(attempts[1].qualified, false);
});

test("replay refusal prevents second physical send without erasing first attempt", async () => {
  const h = harness(async () => ({ status: 403, data: body(JSON.stringify(envelope())) }), {
    admit: (event) => event.attemptId === 1,
  });
  await assert.rejects(h.unit.request("unary", async () => {
    try { return await h.transport.call(h.receiver, options("unary")); }
    catch { return h.transport.call(h.receiver, options("unary")); }
  }));
  const records = h.unit.snapshot().attempts;
  assert.equal(h.sends(), 1);
  assert.equal(records[0].usageLowerBound, 17);
  assert.equal(records[0].terminal, "http_error");
  assert.equal(records[1].released, false);
  assert.equal(records[1].terminal, "not_released");
});

test("cancellation while admissions are pending denies all queued calls", async () => {
  const waiters = [];
  const h = harness(async () => { assert.fail("No send after cancelled admission"); }, {
    admit: () => new Promise((resolve) => waiters.push(resolve)),
  });
  const first = h.call("unary");
  const second = h.call("unary");
  while (waiters.length !== 2) await new Promise(setImmediate);
  h.unit.cancel();
  waiters.forEach((resolve) => resolve(true));
  const results = await Promise.allSettled([first, second]);
  assert.ok(results.every((result) => result.status === "rejected"));
  assert.equal(h.sends(), 0);
  assert.ok(h.unit.snapshot().attempts.every((attempt) => attempt.terminal === "not_released"));
});

test("lost release ACK forbids send; lost observation ACK retains private unit lower bound", async () => {
  for (const denied of ["release", "observation"]) {
    const h = harness(async () => ({ status: 200, data: body(JSON.stringify(envelope())) }), {
      record: (event) => event.kind !== denied,
    });
    await assert.rejects(h.call("unary"));
    const attempt = h.unit.snapshot().attempts[0];
    assert.equal(h.sends(), denied === "release" ? 0 : 1);
    assert.equal(attempt.usageLowerBound, denied === "release" ? null : 17);
    assert.equal(h.unit.snapshot().stopped, true);
  }
});

test("stalled parent callback expires without a physical send", async () => {
  const h = harness(async () => assert.fail("send"), { admit: () => new Promise(() => {}) }, { ackTimeoutMs: 10 });
  await assert.rejects(h.call("unary"));
  assert.equal(h.sends(), 0);
  assert.equal(h.unit.snapshot().attempts[0].terminal, "not_released");
});

test("consumer return before or after first frame is accounted once and latches cancellation", async () => {
  for (const readFirst of [false, true]) {
    const h = harness(async () => ({ status: 200, data: body(sse(envelope()), sse(envelope(23))) }));
    const iterator = await h.call("stream");
    if (readFirst) await iterator.next();
    await iterator.return();
    await iterator.return();
    assert.equal(h.unit.snapshot().attempts[0].terminal, "consumer_return");
    assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, readFirst ? 17 : null);
    assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
    await assert.rejects(h.call("unary"), /cancelled/);
  }
});

test("abort after a frame retains usage and prevents further frame release", async () => {
  const controller = new AbortController();
  const h = harness(async () => ({ status: 200, data: body(sse(envelope()), sse(envelope(23))) }));
  const iterator = await h.call("stream", controller.signal);
  await iterator.next();
  controller.abort();
  await assert.rejects(iterator.next(), /stream_failed/);
  assert.equal(h.unit.snapshot().attempts[0].terminal, "aborted");
  assert.equal(h.unit.snapshot().attempts[0].usageLowerBound, 17);
});

test("idle released stream cancellation before first read terminalizes without consumer progress", { timeout: 1000 }, async () => {
  for (const external of [false, true]) {
    const controller = new AbortController();
    const h = harness(async () => ({ status: 200, data: {
      [Symbol.asyncIterator]() { return this; },
      next() { assert.fail("No consumer read is needed for terminalization"); },
      return() { return new Promise(() => {}); },
    } }));
    const iterator = await h.call("stream", controller.signal);
    assert.equal(h.unit.snapshot().activeCalls, 1);
    if (external) controller.abort(); else h.unit.cancel();
    await new Promise(setImmediate);
    const state = h.unit.snapshot();
    assert.equal(state.activeCalls, 0);
    assert.equal(state.attempts[0].terminal, "aborted");
    assert.equal(state.attempts[0].terminalAck, "acknowledged");
    assert.equal(state.attempts[0].usageLowerBound, null);
    assert.equal(state.attempts[0].cost, null);
    assert.equal(state.attempts[0].quiescence, "unproven");
    assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
    // Only AFTER the idle assertion: late consumer cleanup cannot repeat ACK.
    await assert.rejects(iterator.next(), /stream_failed/);
    await iterator.return();
    h.unit.cancel();
    assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
  }
});

test("idle stream abort after one frame retains usage and unregisters without another read", { timeout: 1000 }, async () => {
  const controller = new AbortController();
  const h = harness(async () => ({ status: 200, data: body(sse(envelope()), sse(envelope(23))) }));
  const iterator = await h.call("stream", controller.signal);
  await iterator.next();
  controller.abort();
  await new Promise(setImmediate);
  const state = h.unit.snapshot();
  assert.equal(state.activeCalls, 0);
  assert.equal(state.attempts[0].terminal, "aborted");
  assert.equal(state.attempts[0].terminalAck, "acknowledged");
  assert.equal(state.attempts[0].usageLowerBound, 17);
  assert.equal(state.attempts[0].frames, 1);
  assert.equal(state.attempts[0].cost, null);
  assert.equal(state.attempts[0].quiescence, "unproven");
  assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
});

test("another call's failed admission ACK terminalizes a released idle stream", { timeout: 1000 }, async () => {
  const h = harness(async () => ({ status: 200, data: body(sse(envelope())) }), {
    admit: (event) => event.callId === 1,
  });
  await h.call("stream"); // Deliberately never next()/return().
  await assert.rejects(h.call("unary"));
  await new Promise(setImmediate);
  const state = h.unit.snapshot();
  assert.equal(h.sends(), 1);
  assert.equal(state.activeCalls, 0);
  assert.equal(state.attempts[0].terminal, "aborted");
  assert.equal(state.attempts[0].terminalAck, "acknowledged");
  assert.equal(state.attempts[0].usageLowerBound, null);
  assert.equal(state.attempts[1].terminal, "not_released");
  assert.equal(h.events.filter((event) => event.kind === "terminal" && event.attemptId === 1).length, 1);
});

test("idle stream terminal ACK deadline still unregisters and records failed delivery", { timeout: 1000 }, async () => {
  const h = harness(async () => ({ status: 200, data: body(sse(envelope())) }), {
    record: (event) => event.kind === "terminal" ? new Promise(() => {}) : true,
  }, { ackTimeoutMs: 10 });
  await h.call("stream"); // No consumer progress, even after cancellation.
  h.unit.cancel();
  await new Promise((resolve) => setTimeout(resolve, 30));
  const state = h.unit.snapshot();
  assert.equal(state.activeCalls, 0);
  assert.equal(state.attempts[0].terminal, "aborted");
  assert.equal(state.attempts[0].terminalAck, "failed");
  assert.equal(state.attempts[0].quiescence, "unproven");
  assert.equal(h.events.filter((event) => event.kind === "terminal").length, 1);
});

test("abort settles an uncooperative read conservatively without claiming quiescence", async () => {
  let reading;
  const started = new Promise((resolve) => { reading = resolve; });
  const controller = new AbortController();
  const h = harness(async () => ({ status: 200, data: {
    [Symbol.asyncIterator]() { return this; },
    next() { reading(); return new Promise(() => {}); },
    return() { return new Promise(() => {}); },
  } }));
  const pending = h.call("unary", controller.signal);
  await started;
  controller.abort();
  await assert.rejects(pending);
  const record = h.unit.snapshot().attempts[0];
  assert.equal(record.released, true);
  assert.equal(record.terminal, "transport_error");
  assert.equal(record.usageLowerBound, null);
  assert.equal(record.quiescence, "unproven");
});

test("response, frame and attempt bounds fail closed without later sends", async () => {
  for (const limits of [{ maxResponseBytes: 10 }, { maxFrameBytes: 10 }, { maxFrames: 1 }]) {
    const h = harness(async () => ({ status: 200, data: body(sse(envelope()), sse(envelope(23))) }), {}, limits);
    await assert.rejects(collect(await h.call("stream")));
    assert.equal(h.unit.snapshot().stopped, true);
  }
  const h = harness(async () => ({ status: 200, data: body(JSON.stringify(envelope())) }), {}, { maxAttempts: 1 });
  await h.call("unary");
  await assert.rejects(h.call("unary"));
  assert.equal(h.sends(), 1);
});

test("unscoped calls, unexpected endpoints and non-generation auth requests refuse", async () => {
  const h = harness(async () => assert.fail("unscoped network"));
  await assert.rejects(h.transport.call(h.receiver, options("unary")), /unscoped_send/);
  const other = harness(async () => assert.fail("unowned auth send"));
  await assert.rejects(other.unit.request("unary", () => other.transport.call(other.receiver, {
    ...options("unary"), url: "https://oauth2.googleapis.com/token",
  })));
  assert.equal(other.sends(), 0);
});

test("exact source fingerprint is required and unknown client shapes cannot install", async () => {
  const unit = createCodeAssistWireUnit({ parent: { admit: async () => true, record: async () => true } });
  assert.throws(() => attachCodeAssist0412({}, unit, Buffer.from("wrong bundle")), /source_binding/);
  // Only public text is read; the CLI/module is NEVER imported or executed.
  const sourcePath = process.env.MACO_CODE_ASSIST_PUBLIC_SOURCE;
  assert.ok(sourcePath, "Verification must supply the pinned public source path (no skipped binding test)");
  const bytes = await readFile(sourcePath);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), CODE_ASSIST_SOURCE.sha256);
  assert.throws(() => attachCodeAssist0412({ client: { request() {} } }, unit, bytes), /unsupported_method_shape/);
  assert.equal(unit.snapshot().attempts.length, 0);
});

test("explicit OAuth refresh requires separate admission and never exports its tokens", async () => {
  for (const allowed of [true, false]) {
    const events = []; let sends = 0;
    const unit = createCodeAssistWireUnit({ parent: {
      admit: async (event) => { events.push(event); return allowed; },
      record: async (event) => { events.push(event); return true; },
    } });
    const transport = unit.wrapTransport(async (options) => {
      sends++;
      assert.equal(options.retry, false);
      assert.equal(options.adapter, undefined);
      assert.equal(options.fetchImplementation, undefined);
      return { status: 200, data: body(JSON.stringify({ access_token: "never-export-secret", token_type: "Bearer", expires_in: 3600 })) };
    }, () => {}, { oauthRefresh: true });
    const pending = unit.request("unary", () => transport({
      url: "https://oauth2.googleapis.com/token", method: "POST",
      data: "grant_type=refresh_token&refresh_token=secret&client_id=owned&client_secret=secret",
      adapter: () => assert.fail("hidden adapter"), fetchImplementation: () => assert.fail("hidden fetch"),
    }));
    if (allowed) assert.equal((await pending).data.access_token, "never-export-secret");
    else await assert.rejects(pending);
    assert.equal(sends, allowed ? 1 : 0);
    assert.equal(events[0].requestClass, "oauth_refresh");
    assert.doesNotMatch(JSON.stringify(events), /never-export-secret|client_secret|refresh_token/);
    assert.equal(unit.snapshot().attempts[0].usageLowerBound, null);
    assert.equal(unit.snapshot().attempts[0].qualified, false);
  }
});

test("malformed refresh, duplicate grants and arbitrary non-generation URLs have no send authority", async () => {
  for (const patch of [
    { url: "https://oauth2.googleapis.com/token?copy=1" },
    { url: "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist" },
    { data: "grant_type=refresh_token&grant_type=refresh_token&client_id=owned&client_secret=secret" },
    { data: "grant_type=authorization_code&refresh_token=secret&client_id=owned&client_secret=secret" },
  ]) {
    let sends = 0;
    const unit = createCodeAssistWireUnit({ parent: { admit: async () => true, record: async () => true } });
    const transport = unit.wrapTransport(async () => { sends++; }, () => {}, { oauthRefresh: true });
    await assert.rejects(unit.request("unary", () => transport({
      url: "https://oauth2.googleapis.com/token", method: "POST",
      data: "grant_type=refresh_token&refresh_token=secret&client_id=owned&client_secret=secret", ...patch,
    })));
    assert.equal(sends, 0); assert.equal(unit.snapshot().stopped, true);
  }
});

test("cancellation interrupts an uncooperative refresh body without claiming quiescence", async () => {
  let started;
  const reading = new Promise((resolve) => { started = resolve; });
  const unit = createCodeAssistWireUnit({ parent: { admit: async () => true, record: async () => true } });
  const transport = unit.wrapTransport(async () => ({ status: 200, data: {
    [Symbol.asyncIterator]() { return this; }, next() { started(); return new Promise(() => {}); },
  } }), () => {}, { oauthRefresh: true });
  const pending = unit.request("unary", () => transport({ url: "https://oauth2.googleapis.com/token", method: "POST",
    data: "grant_type=refresh_token&refresh_token=secret&client_id=owned&client_secret=secret" }));
  await reading; unit.cancel(); await assert.rejects(pending);
  assert.equal(unit.snapshot().activeCalls, 0);
  assert.equal(unit.snapshot().attempts[0].terminal, "transport_error");
  assert.equal(unit.snapshot().attempts[0].quiescence, "unproven");
});

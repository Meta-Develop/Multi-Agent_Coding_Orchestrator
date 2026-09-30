// Isolated Code Assist 0.41.2 foundation. Not connected to a MACO launcher.
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";

export const CODE_ASSIST_SOURCE = Object.freeze({
  version: "0.41.2",
  bundle: "chunk-ZP3RCUP6.js",
  sha256: "2caaf0808ed644ec464f4ac8c3298dfaa48a0b094578f72a1193c31a19cd847c",
});

const endpoint = "https://cloudcode-pa.googleapis.com/v1internal:";
const operationEndpoint = "https://cloudcode-pa.googleapis.com/v1internal/";
function validOperationName(name) {
  if (typeof name !== "string" || name.length > 512) return false;
  const segments = name.split("/");
  return segments.length >= 2 && segments[0] === "operations"
    && segments.slice(1).every((segment) => segment !== "." && segment !== ".."
      && /^[A-Za-z0-9._-]+$/.test(segment));
}
const requestClasses = new Set([
  "generation", "oauth_refresh", "oauth_token_info", "oauth_userinfo",
  "setup_user", "experiments", "quota", "admin_control",
]);
const defaults = Object.freeze({
  maxCalls: 64,
  maxAttempts: 128,
  maxResponseBytes: 4 * 1024 * 1024,
  maxFrameBytes: 64 * 1024,
  maxFrames: 4096,
  ackTimeoutMs: 5000,
});
const usageKeys = [
  "promptTokenCount", "candidatesTokenCount", "totalTokenCount",
  "cachedContentTokenCount", "thoughtsTokenCount", "toolUsePromptTokenCount",
];
const finishReasons = new Set([
  "STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "LANGUAGE", "OTHER", "BLOCKLIST",
  "PROHIBITED_CONTENT", "SPII", "MALFORMED_FUNCTION_CALL", "IMAGE_SAFETY",
  "UNEXPECTED_TOOL_CALL", "IMAGE_PROHIBITED_CONTENT", "NO_IMAGE",
]);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const plain = (value) => value !== null && typeof value === "object"
  && Object.getPrototypeOf(value) === Object.prototype;
const fault = (code) => Object.assign(new Error(`Code Assist wire: ${code}`), { code });
function parseEnvelope(text) {
  let value;
  try { value = JSON.parse(text); } catch { throw fault("malformed_json"); }
  // JSON.parse accepts duplicate keys; usage/identity must not use last-wins
  // decoding. Syntax is already checked, so only object-key tracking is needed.
  const stack = [];
  let previous;
  for (const [token] of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]/g)) {
    if (token === "{") stack.push(new Set());
    else if (token === "[") stack.push(null);
    else if (token === "}" || token === "]") stack.pop();
    else if (token === ":") {
      const key = JSON.parse(previous);
      const keys = stack.at(-1);
      if (keys.has(key)) throw fault("duplicate_json_key");
      keys.add(key);
    }
    previous = token;
  }
  return value;
}
function untilAbort(promise, signal) {
  if (signal.aborted) return Promise.reject(fault("cancelled"));
  return new Promise((resolve, reject) => {
    const abort = () => reject(fault("cancelled"));
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
const frozenCopy = (value) => {
  const copy = structuredClone(value);
  const freeze = (item) => {
    if (item && typeof item === "object") {
      Object.values(item).forEach(freeze);
      Object.freeze(item);
    }
    return item;
  };
  return freeze(copy);
};

// No native request options, headers, response text, prompts or exception messages
// cross this interface. These observations are NOT private Rust custody evidence.
export function createCodeAssistWireUnit({ parent, limits = {} }) {
  if (typeof parent?.admit !== "function" || typeof parent?.record !== "function") {
    throw fault("parent_shape");
  }
  const bounds = { ...defaults, ...limits };
  for (const [key, value] of Object.entries(bounds)) {
    if (!(key in defaults) || !Number.isSafeInteger(value) || value < 1
        || value > defaults[key]) throw fault("limits");
  }
  const context = new AsyncLocalStorage();
  const calls = new Map();
  const attempts = new Map();
  let stopped = false;
  let nextCall = 0;
  let nextAttempt = 0;
  let physicalTail = Promise.resolve();

  function cancel() {
    stopped = true;
    for (const call of calls.values()) call.controller.abort();
  }
  function active(call) {
    if (stopped || call?.controller.signal.aborted) throw fault("cancelled");
  }
  async function acknowledge(callback, event) {
    let timer;
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => callback(frozenCopy(event))),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(fault("ack_deadline")), bounds.ackTimeoutMs);
        }),
      ]);
      if (result !== true) throw fault("ack_refused");
    } catch {
      cancel();
      throw fault("parent_ack_failed");
    } finally {
      clearTimeout(timer);
    }
  }
  function observation(attempt) {
    return {
      callId: attempt.call.id, attemptId: attempt.id, mode: attempt.call.mode, requestClass: attempt.requestClass ?? "generation",
      released: attempt.released, terminal: attempt.terminal,
      terminalAck: attempt.terminalAck,
      frames: attempt.frames, wireBytes: attempt.bytes,
      usage: attempt.usage, observedModelVersion: attempt.model,
      usageLowerBound: attempt.lowerBound,
      usageCoverage: "observed_lower_bound_only",
      identityAuthority: "unverified_response_field",
      actualEffort: null, cost: null, qualified: false, quiescence: "unproven",
    };
  }
  async function finish(attempt, terminal) {
    if (attempt.terminal !== null) return;
    attempt.terminal = terminal;
    attempt.terminalAck = "pending";
    try {
      await acknowledge(parent.record, { kind: "terminal", ...observation(attempt) });
      attempt.terminalAck = "acknowledged";
    } catch (error) {
      attempt.terminalAck = "failed";
      throw error;
    } finally {
      attempt.releasePhysical?.();
      attempt.releasePhysical = null;
    }
  }
  function releaseCall(call) {
    call.signal?.removeEventListener("abort", call.onAbort);
    calls.delete(call.id);
  }
  async function acquirePhysical(call) {
    active(call);
    const prior = physicalTail;
    let release;
    const complete = new Promise((resolve) => { release = resolve; });
    physicalTail = prior.then(() => complete);
    try {
      await untilAbort(prior, call.controller.signal);
      active(call);
      return release;
    } catch (error) {
      release();
      throw error;
    }
  }
  function readEnvelope(attempt, text) {
    const envelope = parseEnvelope(text);
    if (!plain(envelope) || !plain(envelope.response)) throw fault("envelope_shape");
    const response = envelope.response;
    let model = attempt.model;
    if (Object.hasOwn(response, "modelVersion")) {
      if (typeof response.modelVersion !== "string"
          || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(response.modelVersion)) {
        throw fault("model_shape");
      }
      if (model !== null && model !== response.modelVersion) throw fault("model_conflict");
      model = response.modelVersion;
    }
    let usage = attempt.usage;
    if (Object.hasOwn(response, "usageMetadata")) {
      if (!plain(response.usageMetadata)) throw fault("usage_shape");
      const current = {};
      for (const key of usageKeys) {
        if (Object.hasOwn(response.usageMetadata, key)) {
          const value = response.usageMetadata[key];
          if (!Number.isSafeInteger(value) || value < 0) throw fault("usage_counter");
          if (usage?.[key] !== undefined && value < usage[key]) throw fault("usage_regressed");
          current[key] = value;
        }
      }
      const retained = { ...usage, ...current };
      if (retained.cachedContentTokenCount !== undefined
          && (retained.promptTokenCount === undefined
            || retained.cachedContentTokenCount > retained.promptTokenCount)) {
        throw fault("usage_subset");
      }
      if (retained.totalTokenCount !== undefined
          && Object.values(retained).some((value) => value > retained.totalTokenCount)) {
        throw fault("usage_total");
      }
      // Native counters have different semantics (thoughts are NOT asserted to
      // be an output subset). Never invent a sum, fill missing counters with zero,
      // or add overlapping stream snapshots. Retain validated available facts.
      usage = retained;
    }
    let sawFinish = attempt.sawFinish;
    if (Array.isArray(response.candidates)) {
      // Narrow supported response: one candidate. A final marker is necessary
      // to detect a cut stream, but does NOT prove no intermediate frame loss.
      if (response.candidates.length > 1) throw fault("multiple_candidates");
      const reason = response.candidates[0]?.finishReason;
      if (reason !== undefined) {
        if (!finishReasons.has(reason)) throw fault("finish_reason");
        sawFinish = true;
      }
    }
    attempt.model = model;
    attempt.usage = usage;
    attempt.sawFinish = sawFinish;
    if (usage?.totalTokenCount !== undefined) {
      attempt.lowerBound = Math.max(attempt.lowerBound ?? 0, usage.totalTokenCount);
    }
    return envelope;
  }
  async function capture(attempt, text) {
    if (++attempt.frames > bounds.maxFrames) throw fault("frame_limit");
    const envelope = readEnvelope(attempt, text);
    await acknowledge(parent.record, {
      kind: "observation", ...observation(attempt), envelopeSha256: hash(text),
    });
    active(attempt.call);
    return envelope;
  }
  async function* decode(attempt, body) {
    if (!body || typeof body[Symbol.asyncIterator] !== "function") throw fault("body_shape");
    const iterator = body[Symbol.asyncIterator]();
    const readable = {
      [Symbol.asyncIterator]() { return this; },
      next: () => untilAbort(iterator.next(), attempt.call.controller.signal),
      async return() {
        body.destroy?.();
        if (iterator.return) void Promise.resolve(iterator.return()).catch(() => {});
        return { done: true };
      },
    };
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let buffer = "";
    let data = [];
    let frameBytes = 0;
    for await (const chunk of readable) {
      active(attempt.call);
      if (!(chunk instanceof Uint8Array)) throw fault("body_chunk_shape");
      attempt.bytes += chunk.byteLength;
      if (attempt.bytes > bounds.maxResponseBytes) throw fault("response_limit");
      buffer += decoder.decode(chunk, { stream: true });
      if (attempt.call.mode === "unary") continue;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        let line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);
        frameBytes += Buffer.byteLength(line) + 1;
        if (frameBytes > bounds.maxFrameBytes) throw fault("frame_limit");
        if (line === "") {
          if (data.length > 0) yield await capture(attempt, data.join("\n"));
          data = [];
          frameBytes = 0;
        } else if (line.startsWith("data:")) {
          data.push(line.slice(5).replace(/^ /, ""));
        } else if (!line.startsWith(":")) {
          throw fault("sse_field");
        }
      }
      if (frameBytes + Buffer.byteLength(buffer) > bounds.maxFrameBytes) throw fault("frame_limit");
    }
    buffer += decoder.decode();
    active(attempt.call);
    if (attempt.call.mode === "unary") {
      yield await capture(attempt, buffer);
    } else if (buffer.length !== 0 || data.length !== 0) {
      throw fault("sse_trailing_data");
    }
    if (attempt.frames === 0) throw fault("empty_response");
    if (attempt.call.mode === "stream" && !attempt.sawFinish) throw fault("missing_terminal_candidate");
  }
  function stream(attempt, body) {
    if (!body || typeof body[Symbol.asyncIterator] !== "function") throw fault("body_shape");
    const generator = decode(attempt, body);
    let ended = false;
    let endPromise;
    const signal = attempt.call.controller.signal;
    function stopSource() {
      // Do not wait on an uncooperative source or let source cleanup prevent
      // the terminal ACK. Quiescence remains explicitly unproven.
      try { body.destroy?.(); } catch { /* no quiescence claim */ }
      void generator.return().catch(() => {});
    }
    function end(terminal) {
      if (ended) return endPromise;
      ended = true;
      signal.removeEventListener("abort", onAbort);
      endPromise = finish(attempt, terminal).finally(() => releaseCall(attempt.call));
      return endPromise;
    }
    function onAbort() {
      const terminal = end("aborted");
      stopSource();
      // finish records ACK failure and latches cancellation; an event listener
      // cannot await it. Its bounded completion still unregisters this call.
      void terminal.catch(() => {});
    }
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    return {
      [Symbol.asyncIterator]() { return this; },
      async next() {
        if (ended) {
          await endPromise;
          if (attempt.terminal === "aborted") throw fault("stream_failed");
          return { done: true, value: undefined };
        }
        try {
          active(attempt.call);
          const result = await untilAbort(generator.next(), attempt.call.controller.signal);
          if (result.done) await end("eof");
          return result;
        } catch (error) {
          const terminal = end(error?.code === "cancelled" ? "aborted" : "stream_error");
          cancel();
          stopSource();
          await terminal;
          throw fault("stream_failed");
        }
      },
      async return() {
        if (!ended) {
          const terminal = end("consumer_return");
          cancel();
          stopSource();
          await terminal;
        } else {
          await endPromise;
        }
        return { done: true, value: undefined };
      },
      async throw() {
        await this.return();
        throw fault("consumer_error");
      },
    };
  }

  // Low-level dependency-injection interface for offline tests / a future owned
  // bootstrap. Supplying callbacks here does not authenticate vendor execution.
  function classifyTransport(options, oauthRefresh) {
    const refresh = oauthRefresh && options?.url === "https://oauth2.googleapis.com/token"
      && options.method === "POST" && typeof options.data === "string"
      && new URLSearchParams(options.data).get("grant_type") === "refresh_token"
      && [...new URLSearchParams(options.data).keys()].every((key) =>
        ["grant_type", "refresh_token", "client_id", "client_secret"].includes(key))
      && options.data.length <= bounds.maxFrameBytes
      && ["grant_type", "refresh_token", "client_id", "client_secret"].every((key) =>
        new URLSearchParams(options.data).getAll(key).length === 1
          && new URLSearchParams(options.data).get(key));
    if (refresh) return "oauth_refresh";
    if (options?.url === "https://oauth2.googleapis.com/tokeninfo" && options.method === "POST"
        && options.data === undefined) {
      return "oauth_token_info";
    }
    if (typeof options?.url === "string" && options.method === "GET"
        && options.url.startsWith(`${operationEndpoint}operations/`)
        && validOperationName(options.url.slice(operationEndpoint.length))) {
      return "setup_user";
    }
    if (typeof options?.url !== "string" || options.method !== "POST"
        || !options.url.startsWith(endpoint)) return null;
    const method = options.url.slice(endpoint.length);
    if (["generateContent", "streamGenerateContent"].includes(method)) return "generation";
    if (["loadCodeAssist", "onboardUser"].includes(method)) return "setup_user";
    if (method === "listExperiments") return "experiments";
    if (method === "retrieveUserQuota") return "quota";
    if (method === "fetchAdminControls") return "admin_control";
    return null;
  }
  async function readBoundedJson(attempt, body) {
    const chunks = [];
    const iterator = body?.[Symbol.asyncIterator]?.();
    if (!iterator) throw fault("json_body_shape");
    while (true) {
      const step = await untilAbort(iterator.next(), attempt.call.controller.signal);
      if (step.done) break;
      if (!(step.value instanceof Uint8Array)) throw fault("json_body_shape");
      attempt.bytes += step.value.byteLength;
      if (attempt.bytes > bounds.maxResponseBytes) throw fault("response_limit");
      chunks.push(step.value);
    }
    const data = parseEnvelope(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
    if (!plain(data)) throw fault("json_response_shape");
    return data;
  }
  function wrapTransport(original, verifyShape = () => {}, { oauthRefresh = false, offlineTestFetch } = {}) {
    if (typeof original !== "function") throw fault("transport_shape");
    async function dispatch(receiver, options, call, requestClass) {
      active(call);
      try { verifyShape(receiver); } catch { cancel(); throw fault("transport_shape_changed"); }
      const classified = classifyTransport(options, oauthRefresh);
      const method = call.mode === "unary" ? "generateContent" : "streamGenerateContent";
      if (!requestClasses.has(requestClass) || classified !== requestClass
          || (requestClass === "generation" && options.url !== endpoint + method)) {
        cancel();
        throw fault("unexpected_send");
      }
      const releasePhysical = await acquirePhysical(call);
      let attempt;
      try {
        active(call);
        if (++nextAttempt > bounds.maxAttempts) { cancel(); throw fault("attempt_limit"); }
        attempt = {
          id: nextAttempt, call, released: false, terminal: null, terminalAck: null, frames: 0,
          bytes: 0, usage: null, model: null, lowerBound: null, sawFinish: false,
          requestClass, releasePhysical,
        };
        attempts.set(attempt.id, attempt);
        await acknowledge(parent.admit, { kind: "admission", ...observation(attempt) });
        active(call);
        await acknowledge(parent.record, { kind: "release", ...observation(attempt) });
        active(call);
        verifyShape(receiver);
        // 0.41.2's Gaxios merges defaults. Refuse nonempty defaults/interceptors
        // in the bound adapter and overwrite BOTH retry switches on EVERY send.
        // Redirects could also replay POST below this boundary: refuse those.
        const safe = {
          ...options, signal: call.controller.signal, responseType: "stream",
          adapter: undefined, fetchImplementation: offlineTestFetch,
          retry: false, retryConfig: { retry: 0, noResponseRetries: 0 },
          maxRedirects: 0, redirect: "error", maxContentLength: bounds.maxResponseBytes,
          validateStatus: () => true,
        };
        attempt.released = true;
        const response = await untilAbort(Reflect.apply(original, receiver, [safe]), call.controller.signal);
        if (!Number.isInteger(response?.status)) throw fault("status_shape");
        if (response.status < 200 || response.status >= 300) {
          // Never claim a failed HTTP attempt consumed zero. Preserve any
          // well-formed generation facts before OAuth sees the error/replays.
          // Non-generation bodies have their own bounded JSON shape and must
          // never be interpreted as Code Assist generation envelopes.
          try {
            if (requestClass === "generation") {
              for await (const _ of decode(attempt, response.data)) { /* retained */ }
            } else {
              await readBoundedJson(attempt, response.data);
            }
          } catch { /* still incomplete */ }
          await finish(attempt, "http_error");
          if (response.status !== 401 && response.status !== 403) cancel();
          const error = fault("http_error");
          error.response = { status: response.status, config: { data: options.data } };
          throw error;
        }
        if (requestClass === "oauth_refresh") {
          const data = await readBoundedJson(attempt, response.data);
          if (!plain(data) || typeof data.access_token !== "string" || !data.access_token
              || data.token_type !== "Bearer" || !Number.isSafeInteger(data.expires_in)
              || data.expires_in < 1) throw fault("refresh_response_shape");
          await finish(attempt, "eof");
          return { ...response, data };
        }
        if (requestClass !== "generation") {
          const data = await readBoundedJson(attempt, response.data);
          await finish(attempt, "eof");
          return { ...response, data };
        }
        if (call.mode === "stream") return { ...response, data: stream(attempt, response.data) };
        let envelope;
        for await (const item of decode(attempt, response.data)) envelope = item;
        await finish(attempt, "eof");
        return { ...response, data: envelope };
      } catch (error) {
        if (!attempt) {
          releasePhysical();
          throw error;
        }
        if (attempt.terminal === "http_error") throw error; // OAuth may replay, with fresh admission.
        cancel();
        await finish(attempt, attempt.released ? "transport_error" : "not_released");
        throw fault("send_failed");
      }
    }
    return async function (options) {
      const requestClass = classifyTransport(options, oauthRefresh);
      if (!requestClass) { cancel(); throw fault("unexpected_send"); }
      const receiver = this;
      const activeCall = context.getStore();
      if (activeCall && activeCall.requestClass === requestClass) {
        return dispatch(receiver, options, activeCall, requestClass);
      }
      if (requestClass === "generation") {
        cancel();
        throw fault("unscoped_send");
      }
      return request("unary", () => {
        const scoped = context.getStore();
        if (!scoped) throw fault("unscoped_send");
        return dispatch(receiver, options, scoped, requestClass);
      }, options?.signal, requestClass);
    };
  }
  async function executeRequest(mode, invokeClient, signal, requestClass) {
    active();
    if (!['unary', 'stream'].includes(mode) || typeof invokeClient !== "function"
        || !requestClasses.has(requestClass)) throw fault("call_shape");
    if (++nextCall > bounds.maxCalls) { cancel(); throw fault("call_limit"); }
    const call = { id: nextCall, mode, requestClass, signal, controller: new AbortController() };
    call.onAbort = cancel;
    calls.set(call.id, call);
    signal?.addEventListener("abort", call.onAbort, { once: true });
    if (signal?.aborted) cancel();
    try {
      active(call);
      const response = await context.run(call, () => invokeClient(call.controller.signal));
      active(call);
      if (![...attempts.values()].some((attempt) => attempt.call === call && attempt.released)) {
        throw fault("no_observed_send");
      }
      if (mode === "unary") releaseCall(call);
      return response;
    } catch {
      cancel();
      for (const attempt of attempts.values()) {
        if (attempt.call === call) await finish(attempt, "client_error");
      }
      releaseCall(call);
      throw fault("client_failed");
    }
  }
  function request(mode, invokeClient, signal, requestClass = "generation") {
    return executeRequest(mode, invokeClient, signal, requestClass);
  }
  function wrapFetch(original) {
    if (typeof original !== "function") throw fault("fetch_shape");
    return async function (url, options = {}) {
      if (url !== "https://www.googleapis.com/oauth2/v2/userinfo"
          || (options.method !== undefined && options.method !== "GET")
          || !plain(options) || !plain(options.headers)
          || Object.keys(options.headers).some((key) => key !== "Authorization")
          || typeof options.headers.Authorization !== "string"
          || !options.headers.Authorization.startsWith("Bearer ")) {
        cancel();
        throw fault("unexpected_fetch");
      }
      return request("unary", async (signal) => {
        const call = context.getStore();
        if (!call || !calls.has(call.id)) throw fault("unscoped_send");
        const releasePhysical = await acquirePhysical(call);
        let attempt;
        try {
          active(call);
          if (++nextAttempt > bounds.maxAttempts) { cancel(); throw fault("attempt_limit"); }
          attempt = {
            id: nextAttempt, call, released: false, terminal: null, terminalAck: null,
            frames: 0, bytes: 0, usage: null, model: null, lowerBound: null,
            sawFinish: false, requestClass: "oauth_userinfo", releasePhysical,
          };
          attempts.set(attempt.id, attempt);
          await acknowledge(parent.admit, { kind: "admission", ...observation(attempt) });
          active(call);
          await acknowledge(parent.record, { kind: "release", ...observation(attempt) });
          active(call);
          attempt.released = true;
          const response = await untilAbort(original(url, { ...options, signal }), signal);
          if (typeof response?.ok !== "boolean" || !Number.isInteger(response.status)) {
            throw fault("fetch_response_shape");
          }
          if (!response.ok) {
            await finish(attempt, "http_error");
            return response;
          }
          const originalJson = response.json?.bind(response);
          if (!originalJson) throw fault("fetch_response_shape");
          return new Proxy(response, {
            get(target, property) {
              if (property !== "json") {
                const value = Reflect.get(target, property, target);
                return typeof value === "function" ? value.bind(target) : value;
              }
              return async () => {
                try {
                  const data = await untilAbort(originalJson(), signal);
                  const encoded = JSON.stringify(data);
                  if (!plain(data) || typeof encoded !== "string"
                      || Buffer.byteLength(encoded) > bounds.maxFrameBytes) throw fault("userinfo_shape");
                  const bytes = Buffer.byteLength(encoded);
                  attempt.frames = 1;
                  attempt.bytes = bytes;
                  await finish(attempt, "eof");
                  return data;
                } catch {
                  cancel();
                  await finish(attempt, attempt.released ? "transport_error" : "not_released");
                  throw fault("fetch_failed");
                }
              };
            },
          });
        } catch (error) {
          if (!attempt) {
            releasePhysical();
            throw error;
          }
          if (attempt.terminal === "http_error") return Promise.reject(error);
          cancel();
          await finish(attempt, attempt.released ? "transport_error" : "not_released");
          throw fault("fetch_failed");
        }
      }, options.signal, "oauth_userinfo");
    };
  }
  return Object.freeze({
    request, wrapTransport, wrapFetch, cancel,
    snapshot: () => frozenCopy({ stopped, activeCalls: calls.size, attempts: [...attempts.values()].map(observation) }),
  });

}

// Function-source fingerprints from the exact published bundle above. These
// guards detect unsupported objects, not hostile in-process JS or private custody.
const signatures = {
  post: "ef735987989a799696da99f972af46ee0c5df3322d65bd3194a31d70c315b8c8",
  stream: "b857f6155e9696ab56ebf1be09af67580418e34c153b4842d224c631ded0df62",
  getOperation: "d1b31e732ded9cb3b9fe58963ec3e070d4b92a9c573136abe3fb1e2801aa8002",
  clientRequest: "73f427b53359b7ea9bfa19ab313b86547e6d94ab2e89568775ecffc1bfaf1b7c",
  requestAsync: "0cd4d0e90e5184ac9259a9170f5a2b52ce027dee3095c3e28326e76cf286af07",
  transportRequest: "7767d83ddd48d3ce012b6768f85f584c8a39613dccf61acfdec4ad5ee6c9d4ae",
  configure: "e873885d9120a01ae4ed8dd112d9ead6151f571a76878efdd82a3df8685589ef",
  processError: "31a9973c852350ccfd33ed79475a9e5e18f13c8c9fa44790d685a2b614947762",
  gaxiosRequest: "9ed0ba6d56bccded8375fae639008ee47aa12441082dbab98bb29e2a61ab1652",
  gaxiosRetry: "08a043c2b33ab72f0aaf4abf0a3e04bf0c9528223d340a4f26d150a49745a636",
  gaxiosAdapter: "4f68e4c7390e85bca08ffa4e89e77fe231274819e571be03c42873760eb22696",
  gaxiosResponse: "a9f008d139bf89ca2136210bb2b4c3d27da1e57ec131ad02915fa061a079b8ed",
};

const clientBindings = new WeakMap();
export function bindCodeAssistClient0412(client, unit, sourceBytes, { offlineTestFetch } = {}) {
  if (!(sourceBytes instanceof Uint8Array) || hash(sourceBytes) !== CODE_ASSIST_SOURCE.sha256) {
    throw fault("source_binding");
  }
  const existing = clientBindings.get(client);
  if (existing) {
    if (existing.unit !== unit || (offlineTestFetch && existing.offlineTestFetch !== offlineTestFetch)) {
      existing.unit.cancel(); unit.cancel(); throw fault("client_owner_drift");
    }
    existing.verify();
    return existing;
  }
  const transporter = client?.transporter;
  const gaxios = transporter?.instance;
  const original = transporter?.request;
  const methods = () => ({
    clientRequest: client?.request, requestAsync: client?.requestAsync,
    transportRequest: original, configure: transporter?.configure, processError: transporter?.processError,
    gaxiosRequest: gaxios?.request, gaxiosRetry: gaxios?._request,
    gaxiosAdapter: gaxios?._defaultAdapter, gaxiosResponse: gaxios?.getResponseData,
  });
  function verify(functions) {
    for (const [key, fn] of Object.entries(functions)) {
      if (typeof fn !== "function" || hash(Function.prototype.toString.call(fn)) !== signatures[key]) {
        throw fault("unsupported_method_shape");
      }
    }
    if (client.transporter !== transporter || transporter.instance !== gaxios
        || client.refreshHandler != null
        || !plain(gaxios.defaults) || Reflect.ownKeys(gaxios.defaults).length !== 0
        || !(gaxios.interceptors?.request instanceof Set) || gaxios.interceptors.request.size !== 0
        || !(gaxios.interceptors?.response instanceof Set) || gaxios.interceptors.response.size !== 0) {
      throw fault("unsupported_transport_shape");
    }
  }
  verify(methods());
  if (!Object.isExtensible(transporter) || Object.hasOwn(transporter, "request")) throw fault("already_bound");
  let wrapped;
  const recheck = (receiver) => {
    if (receiver !== undefined && receiver !== transporter) throw fault("transport_receiver");
    verify(methods());
    if (transporter.request !== wrapped) throw fault("transport_owner_drift");
  };
  wrapped = unit.wrapTransport(original, recheck, { oauthRefresh: true, offlineTestFetch });
  Object.defineProperty(transporter, "request", { value: wrapped });
  const binding = Object.freeze({ unit, offlineTestFetch, verify: recheck });
  clientBindings.set(client, binding);
  return binding;
}

export function attachCodeAssist0412(server, unit, sourceBytes) {
  if (!(sourceBytes instanceof Uint8Array) || hash(sourceBytes) !== CODE_ASSIST_SOURCE.sha256) throw fault("source_binding");
  for (const [key, signature] of [["requestPost", "post"], ["requestStreamingPost", "stream"],
    ["requestGetOperation", "getOperation"]]) {
    if (!Object.isExtensible(server) || Object.hasOwn(server, key)
        || typeof server[key] !== "function" || hash(Function.prototype.toString.call(server[key])) !== signatures[signature]) {
      throw fault("unsupported_method_shape");
    }
  }
  const client = server.client;
  const binding = bindCodeAssistClient0412(client, unit, sourceBytes);
  const verify = () => {
    if (server.client !== client) throw fault("client_owner_drift");
    binding.verify();
  };
  const postClasses = Object.freeze({
    generateContent: "generation",
    loadCodeAssist: "setup_user",
    onboardUser: "setup_user",
    listExperiments: "experiments",
    retrieveUserQuota: "quota",
    fetchAdminControls: "admin_control",
  });
  function installPost() {
    Object.defineProperty(server, "requestPost", { value: async function (selected, req, signal) {
      const requestClass = postClasses[selected];
      if (this !== server || !requestClass || !plain(req) || req.enabled_credit_types !== undefined) {
        unit.cancel();
        throw fault("unsupported_call");
      }
      try { verify(); } catch { unit.cancel(); throw fault("transport_shape_changed"); }
      return unit.request("unary", async (ownedSignal) => {
        const result = await Reflect.apply(client.request, client, [{
          url: endpoint + selected, method: "POST", responseType: "stream",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(req), signal: ownedSignal, retry: false,
          retryConfig: { retry: 0, noResponseRetries: 0 },
        }]);
        return result.data;
      }, signal, requestClass);
    } });
  }
  function installGenerationStream() {
    const key = "requestStreamingPost";
    const method = "streamGenerateContent";
    Object.defineProperty(server, key, { value: async function (selected, req, signal) {
      if (this !== server || selected !== method || !plain(req)
          || req.enabled_credit_types !== undefined) {
        unit.cancel();
        throw fault("unsupported_call");
      }
      try { verify(); } catch { unit.cancel(); throw fault("transport_shape_changed"); }
      return unit.request("stream", async (ownedSignal) => {
        const result = await Reflect.apply(client.request, client, [{
          url: endpoint + method, method: "POST", responseType: "stream",
          params: { alt: "sse" },
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(req), signal: ownedSignal, retry: false,
          retryConfig: { retry: 0, noResponseRetries: 0 },
        }]);
        return result.data;
      }, signal, "generation");
    } });
  }
  function installSetupOperation() {
    Object.defineProperty(server, "requestGetOperation", { value: async function (name, signal) {
      if (this !== server || !validOperationName(name)) {
        unit.cancel();
        throw fault("unsupported_call");
      }
      try { verify(); } catch { unit.cancel(); throw fault("transport_shape_changed"); }
      return unit.request("unary", async (ownedSignal) => {
        const result = await Reflect.apply(client.request, client, [{
          url: operationEndpoint + name, method: "GET", responseType: "stream",
          headers: { "Content-Type": "application/json" }, signal: ownedSignal,
          retry: false, retryConfig: { retry: 0, noResponseRetries: 0 },
        }]);
        return result.data;
      }, signal, "setup_user");
    } });
  }
  installPost();
  installGenerationStream();
  installSetupOperation();
  return unit;
}

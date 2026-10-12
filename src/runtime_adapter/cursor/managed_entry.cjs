"use strict";

const net = require("node:net");

const MAX_LINE_BYTES = 4 * 1024 * 1024;

function refusal(message) {
  const error = new Error(message);
  error.name = "CursorManagedParentRefusal";
  return error;
}

function encode(value) {
  if (typeof value === "bigint") return { $macoInt: value.toString(10) };
  if (Array.isArray(value)) return value.map(encode);
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = encode(item);
    return out;
  }
  return value;
}

function connectParent(socketPath, deadlineUnixMillis) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    const timer = setTimeout(() => {
      fail(refusal("parent socket connection deadline elapsed"));
    }, Math.max(1, deadlineUnixMillis - Date.now()));
    function cleanup() {
      clearTimeout(timer);
      socket.removeListener("error", fail);
      socket.removeListener("close", closed);
      socket.removeListener("connect", connected);
    }
    function fail(error) {
      cleanup();
      socket.destroy();
      reject(error);
    }
    function closed() {
      fail(refusal("parent socket closed before connection"));
    }
    function connected() {
      cleanup();
      resolve(socket);
    }
    socket.once("error", fail);
    socket.once("close", closed);
    socket.once("connect", connected);
  });
}

async function runManagedCursor({ installPinnedCursorBridge, root, argv, socketPath, deadlineUnixMillis }) {
  if (typeof installPinnedCursorBridge !== "function") throw refusal("bridge installer unavailable");
  if (!root || !socketPath || !Number.isSafeInteger(deadlineUnixMillis) || deadlineUnixMillis <= Date.now()) {
    throw refusal("managed launch environment is incomplete");
  }
  const socket = await connectParent(socketPath, deadlineUnixMillis);
  socket.setEncoding("utf8");
  const operationController = new AbortController();
  const pending = new Map();
  let sequence = 0;
  let buffered = "";

  function stop(reason) {
    if (!operationController.signal.aborted) operationController.abort(reason);
    for (const { reject } of pending.values()) reject(reason);
    pending.clear();
  }

  socket.on("data", (chunk) => {
    buffered += chunk;
    if (Buffer.byteLength(buffered, "utf8") > MAX_LINE_BYTES) {
      socket.destroy(refusal("parent response exceeded line limit"));
      return;
    }
    while (true) {
      const newline = buffered.indexOf("\n");
      if (newline < 0) break;
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      let message;
      try { message = JSON.parse(line); } catch (_error) {
        socket.destroy(refusal("parent response was not JSON"));
        return;
      }
      if (message && message.type === "cancel") {
        stop(refusal("parent cancelled managed Cursor operation"));
        continue;
      }
      const waiter = pending.get(message?.id);
      if (!waiter) {
        socket.destroy(refusal("parent response id was unknown"));
        return;
      }
      pending.delete(message.id);
      if (message.ok === true) waiter.resolve(message.result);
      else waiter.reject(refusal(String(message.error || "parent refused request")));
    }
  });
  socket.once("close", () => stop(refusal("parent socket closed")));
  socket.once("error", (error) => stop(refusal(`parent socket failed: ${error.message}`)));

  function request(method, payload) {
    if (operationController.signal.aborted) return Promise.reject(operationController.signal.reason);
    if (Date.now() >= deadlineUnixMillis) return Promise.reject(refusal("parent operation deadline elapsed"));
    const id = `parent-${++sequence}`;
    const line = `${JSON.stringify({ id, method, payload: encode(payload) })}\n`;
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) return Promise.reject(refusal("parent request exceeded line limit"));
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      socket.write(line, "utf8", (error) => {
        if (error && pending.delete(id)) reject(error);
      });
    });
  }

  const parent = Object.freeze({
    operationSignal: operationController.signal,
    operationDeadlineUnixMillis: deadlineUnixMillis,
    createSharedServices: (payload) => request("createSharedServices", payload),
    createSessionResources: (payload) => request("createSessionResources", payload),
    authorizeResourceAction: (payload) => request("authorizeResourceAction", payload),
    executeResourceAction: (payload) => request("executeResourceAction", payload),
    admitRpcAttempt: (payload) => request("admitRpcAttempt", payload),
    authorizeAction: (payload) => request("authorizeAction", payload),
    captureRawEvent: (payload) => request("captureRawEvent", payload),
    completeRpcAttempt: (payload) => request("completeRpcAttempt", payload),
  });

  process.argv = [process.execPath, `${root}/index.js`, ...argv];
  let bridge;
  try {
    bridge = installPinnedCursorBridge({ root, parent });
  } catch (error) {
    stop(error);
    socket.destroy();
    throw error;
  }
  process.once("beforeExit", async () => {
    try {
      await bridge.drainPendingCompletions();
      socket.end();
    } catch (error) {
      process.exitCode = 1;
      socket.destroy(error);
    }
  });
  return bridge;
}

module.exports = { runManagedCursor };

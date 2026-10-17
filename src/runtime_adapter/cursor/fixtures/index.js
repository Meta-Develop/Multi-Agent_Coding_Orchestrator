(()=>{var __webpack_modules__={
  "../proto/dist/generated/agent/v1/read_exec_pb.js": (_module, exports, webpackRequire) => {
    class ReadArgs {
      static typeName = "agent.v1.ReadArgs";
      constructor(value = {}) {
        Object.assign(this, { path: "", toolCallId: "", offset: undefined, limit: undefined, encodingHint: undefined }, value);
      }
    }
    class ReadSuccess {
      static typeName = "agent.v1.ReadSuccess";
      constructor(value = {}) { Object.assign(this, value); }
    }
    class ReadResult {
      static typeName = "agent.v1.ReadResult";
      constructor(value = {}) { Object.assign(this, { result: { case: undefined } }, value); }
    }
    webpackRequire.d(exports, { a2: () => ReadArgs, mE: () => ReadSuccess, sV: () => ReadResult });
  },
  "../proto/dist/generated/agent/v1/write_exec_pb.js": (_module, exports, webpackRequire) => {
    class WriteArgs {
      static typeName = "agent.v1.WriteArgs";
      constructor(value = {}) {
        Object.assign(this, {
          path: "",
          fileText: "",
          toolCallId: "",
          returnFileContentAfterWrite: false,
          fileBytes: new Uint8Array(0),
          encodingHint: undefined,
        }, value);
      }
    }
    class WriteSuccess {
      static typeName = "agent.v1.WriteSuccess";
      constructor(value = {}) { Object.assign(this, value); }
    }
    class WriteResult {
      static typeName = "agent.v1.WriteResult";
      constructor(value = {}) { Object.assign(this, { result: { case: undefined } }, value); }
    }
    webpackRequire.d(exports, { hY: () => WriteArgs, j6: () => WriteSuccess, v3: () => WriteResult });
  },
  "../proto/dist/generated/agent/v1/shell_exec_pb.js": (_module, exports, webpackRequire) => {
    class ShellArgs {
      static typeName = "agent.v1.ShellArgs";
      constructor(value = {}) {
        Object.assign(this, {
          command: "",
          workingDirectory: "",
          timeout: 0,
          toolCallId: "",
          simpleCommands: [],
          hasInputRedirect: false,
          hasOutputRedirect: false,
          parsingResult: undefined,
          requestedSandboxPolicy: undefined,
          fileOutputThresholdBytes: undefined,
          isBackground: false,
          skipApproval: false,
          timeoutBehavior: 0,
          hardTimeout: undefined,
          description: undefined,
          classifierResult: undefined,
          closeStdin: false,
        }, value);
      }
    }
    class ShellSuccess {
      static typeName = "agent.v1.ShellSuccess";
      constructor(value = {}) { Object.assign(this, value); }
    }
    class ShellResult {
      static typeName = "agent.v1.ShellResult";
      constructor(value = {}) { Object.assign(this, { result: { case: undefined } }, value); }
    }
    webpackRequire.d(exports, { a: () => ShellArgs, QR: () => ShellSuccess, W4: () => ShellResult });
  },
  "../agent-exec/dist/index.js": (_module, exports, webpackRequire) => {
    function descriptor(name) {
      const resource = {
        name,
        symbol: Symbol(name),
        remoteImplementation() {},
        registerControlledImplementation(implementation, controlledManager) {
          globalThis.__cursorFixtureControlledRegistrations += 1;
          controlledManager.register(resource, implementation);
        },
      };
      return resource;
    }
    class FixtureResources {
      constructor() {
  globalThis.__cursorFixtureResourceConstructors += 1;
        this.values = new Map();
      }
      register(resource, value) {
        this.values.set(resource.symbol, { resource, value });
      }
      get(resource) {
        return this.values.get(resource.symbol)?.value;
      }
      entries() {
        return Array.from(this.values.values(), ({ resource, value }) => [resource, value]);
      }
    }
    const read = descriptor("read");
    const write = descriptor("write");
    const shell = descriptor("shell");
    webpackRequire.d(exports, {
      _A: () => read,
      Ln: () => write,
      qk: () => shell,
      h: () => FixtureResources,
    });
  },
  "../agent-client/dist/index.js": (_module, exports, webpackRequire) => {
    class FixtureAgentClient {
      constructor(messages) {
        this.client = {
          run(_context, _requests, _options) {
            globalThis.__cursorFixturePhysicalRpcCalls += 1;
            if (messages && messages.physicalResultPromise) {
              return messages.physicalResultPromise;
            }
            if (messages && typeof messages.createStream === "function") {
              const stream = messages.createStream();
              return messages.returnPromise ? Promise.resolve(stream) : stream;
            }
            if (messages && typeof messages[Symbol.asyncIterator] === "function") {
              return messages;
            }
            return {
              async *[Symbol.asyncIterator]() {
                for (const message of messages) yield message;
              },
              [Symbol.dispose]() {},
            };
          },
        };
      }

      async run(options = {}) {
        const consume = async () => {
          const stream = this.client.run({}, [], { signal: options.signal });
          const observed = [];
          if (options.disposeImmediately) {
            stream[Symbol.dispose]();
            return observed;
          }
          if (options.disposeAfterOne) {
            const iterator = stream[Symbol.asyncIterator]();
            const first = await iterator.next();
            if (!first.done) observed.push(first.value);
            stream[Symbol.dispose]();
            return observed;
          }
          if (options.disposeDuringSetup) {
            const iterator = stream[Symbol.asyncIterator]();
            const first = iterator.next();
            await new Promise((resolve) => setImmediate(resolve));
            stream[Symbol.dispose]();
            await first;
            return observed;
          }
          try {
            for await (const message of stream) observed.push(message);
          } finally {
            if (typeof Symbol.dispose === "symbol" && typeof stream[Symbol.dispose] === "function") {
              stream[Symbol.dispose]();
            }
          }
          return observed;
        };
        if (options.retryAfterCatch) {
          try {
            await consume();
          } catch (_error) {}
          return { observed: await consume(), options };
        }
        return { observed: await consume(), options };
      }
    }
    webpackRequire.d(exports, { PW: () => FixtureAgentClient });
  },
  "./src/index.tsx": () => {
    globalThis.__cursorFixtureAmbientEntryImports += 1;
    globalThis.__cursorFixtureAmbientDnsStarts += 1;
    globalThis.__cursorFixtureAmbientNativeStarts += 1;
    throw new Error("fixture ambient CLI entry must not execute");
  },
};
const cache = {};
function __webpack_require__(id) {
  if (cache[id]) return cache[id].exports;
  if (typeof __webpack_require__.m[id] !== "function") throw new Error(`missing fixture module ${id}`);
  const module = { exports: {} };
  cache[id] = module;
  __webpack_require__.m[id](module, module.exports, __webpack_require__);
  return module.exports;
}
__webpack_require__.m = __webpack_modules__;
__webpack_require__.o = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
__webpack_require__.d = (exports, definitions) => {
  for (const [key, getter] of Object.entries(definitions)) {
    if (!__webpack_require__.o(exports, key)) {
      Object.defineProperty(exports, key, { enumerable: true, get: getter });
    }
  }
};
__webpack_require__.u = (id) => `${id}.index.js`;
__webpack_require__.f = {};
const installedChunks = { 792: 1 };
__webpack_require__.f.require = (chunkId) => {
  if (!installedChunks[chunkId]) {
    ((chunk) => {
      const chunkModules = chunk.modules;
      const chunkIds = chunk.ids;
      const runtime = chunk.runtime;
      for (const id in chunkModules) {
        if (__webpack_require__.o(chunkModules, id)) __webpack_require__.m[id] = chunkModules[id];
      }
      if (runtime) runtime(__webpack_require__);
      for (const id of chunkIds) installedChunks[id] = 1;
    })(require(`./${__webpack_require__.u(chunkId)}`));
  }
};
var __webpack_exports__=__webpack_require__("./src/index.tsx")})();

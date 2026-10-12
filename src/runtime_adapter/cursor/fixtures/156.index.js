exports.id=156,exports.ids=[156],exports.modules={
  "./src/client.ts": (_module, exports, webpackRequire) => {
    const { PW } = webpackRequire("../agent-client/dist/index.js");
    function createAgentClient(_credentials, options) {
      globalThis.__cursorFixtureSharedClientConstructors += 1;
      globalThis.__cursorFixtureSharedClientEndpoint = options.agentEndpoint;
      return new PW([]);
    }
    webpackRequire.d(exports, { hO: () => createAgentClient });
  },
  "./src/models/index.ts": (_module, exports, webpackRequire) => {
    class FixtureModelManager {
      static createForTesting() {
        globalThis.__cursorFixtureTestingModelConstructors += 1;
        return new FixtureModelManager();
      }
    }
    webpackRequire.d(exports, { P3: () => FixtureModelManager });
  },
};

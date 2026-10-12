exports.id=414,exports.ids=[414],exports.modules={
  "./src/acp/shared-services.ts": (_module, exports, webpackRequire) => {
    webpackRequire.d(exports, { Q: () => originalSharedServices });
    async function originalSharedServices() {
      globalThis.__cursorFixtureOriginalSharedServices += 1;
      throw new Error("original shared services factory must not run");
    }
  },
  "./src/acp/session-resources.ts": (_module, exports, webpackRequire) => {
    webpackRequire.d(exports, { Y: () => originalSessionResources });
    async function originalSessionResources() {
      globalThis.__cursorFixtureOriginalSessionResources += 1;
      throw new Error("original session resource factory must not run");
    }
  },
};

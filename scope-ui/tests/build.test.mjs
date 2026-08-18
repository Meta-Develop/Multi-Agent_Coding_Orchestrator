import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const uiRoot = fileURLToPath(new URL("..", import.meta.url));

test("built client keeps the live-first HTML contract and adds the new pages", () => {
  const temp = mkdtempSync(join(tmpdir(), "maco-scope-ui-"));
  const out = join(temp, "index.html");
  try {
    const result = spawnSync(process.execPath, ["scripts/build.mjs", out], {
      cwd: uiRoot,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const html = readFileSync(out, "utf8");

    assert.match(html, /MACO_SCOPE_LIVE_MULTIPROJECT_UI/);
    assert.match(
      html,
      /<select id="projectSelect"><option value="" selected>All projects<\/option><\/select>/,
    );
    assert.match(
      html,
      /<select id="familySelect"><option value="" selected>All families<\/option><\/select>/,
    );
    assert.match(
      html,
      /<select id="runSelect"><option value="" selected>All runs<\/option><\/select>/,
    );
    for (const control of ["id=\"modeSelect\"", "id=\"viewSelect\"", "id=\"scrubber\"", "id=\"jumpToLive\""]) {
      assert.match(html, new RegExp(control));
    }
    assert.match(
      html,
      /var streamUrl = "\/api\/stream" \+ \(params\.toString\(\) \? "\?" \+ params\.toString\(\) : ""\);/,
    );
    assert.match(html, /if \(state\.selectedProject\) params\.set\("repo", state\.selectedProject\);/);
    assert.match(html, /if \(state\.selectedFamily\) params\.set\("family", state\.selectedFamily\);/);
    assert.match(html, /if \(state\.selectedRun\) params\.set\("run", state\.selectedRun\);/);
    assert.match(
      html,
      /var initialMode = initialParams\.get\("mode"\) === "archive" \? "archive" : "live";/,
    );
    assert.match(html, /if \(state\.mode === "archive"\) params\.set\("since", "0"\);/);
    assert.match(html, /appendEvent\(event, message\.lastEventId\)/);
    assert.match(html, /state\.eventIds\.has\(normalizedId\)/);
    assert.equal(html.includes("if (!state.selectedProject || !state.selectedRun) return"), false);
    assert.match(html, /var projectionGroups = new Map\(\)/);
    assert.match(html, /state\.view === "repository"/);
    assert.match(html, /state\.view === "combined"/);

    const scrubberStart = html.indexOf('elements.scrubber.addEventListener("input"');
    const speedStart = html.indexOf("elements.speed.addEventListener", scrubberStart);
    assert.ok(scrubberStart >= 0 && speedStart > scrubberStart);
    const handler = html.slice(scrubberStart, speedStart);
    const cursor = handler.indexOf("var requestedCursor = Number(elements.scrubber.value);");
    const stop = handler.indexOf("stopPlayback();");
    assert.ok(cursor >= 0 && stop > cursor);

    assert.match(html, /id="catalogView"/);
    assert.match(html, /id="objectiveView"/);
    assert.match(html, /data-maco-scope-ui="client-v1"/);
    assert.match(html, /MacoScope\.objective/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

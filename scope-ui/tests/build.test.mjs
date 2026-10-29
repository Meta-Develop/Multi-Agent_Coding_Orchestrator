import assert from "node:assert/strict";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const uiRoot = fileURLToPath(new URL("..", import.meta.url));
const embedded = fileURLToPath(new URL("../../src/scope/placeholder.html", import.meta.url));

function embeddedFixture(t) {
  const root = mkdtempSync(join(tmpdir(), "maco-scope-embedded-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const ui = join(root, "scope-ui");
  cpSync(uiRoot, ui, { recursive: true });
  mkdirSync(join(root, "src/scope"), { recursive: true });
  const artifact = join(root, "src/scope/placeholder.html");
  cpSync(embedded, artifact);
  return {
    ui,
    artifact,
    check: () => spawnSync(process.execPath, [join(ui, "scripts/check-embedded.mjs")], {
      cwd: root,
      encoding: "utf8",
    }),
  };
}

test("embedded check matches the shipped client without rewriting it", (t) => {
  const fixture = embeddedFixture(t);
  const before = readFileSync(fixture.artifact);
  const result = fixture.check();
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Embedded Scope UI matches/);
  assert.deepEqual(readFileSync(fixture.artifact), before);
});

test("embedded check accepts LF and CRLF artifact newlines", (t) => {
  const fixture = embeddedFixture(t);
  const lf = readFileSync(fixture.artifact, "utf8").replace(/\r\n/g, "\n");
  for (const content of [lf, lf.replace(/\n/g, "\r\n")]) {
    writeFileSync(fixture.artifact, content);
    const result = fixture.check();
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(readFileSync(fixture.artifact, "utf8"), content);
  }
});

test("embedded check rejects a source edit without regenerating the artifact", (t) => {
  const fixture = embeddedFixture(t);
  const before = readFileSync(fixture.artifact);
  appendFileSync(join(fixture.ui, "src/views/app.css"), "\nbody { color: rebeccapurple; }\n");
  const result = fixture.check();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Embedded Scope UI is stale/);
  assert.match(result.stderr, /npm --prefix scope-ui run build/);
  assert.deepEqual(readFileSync(fixture.artifact), before);
});

test("embedded check preserves whitespace, lone CR bytes, and final newlines", (t) => {
  const fixture = embeddedFixture(t);
  const original = readFileSync(fixture.artifact, "utf8").replace(/\r\n/g, "\n");
  for (const content of [original + " ", original + "\r", original.replace(/\n$/, "")]) {
    writeFileSync(fixture.artifact, content);
    const result = fixture.check();
    assert.equal(result.status, 1, result.stderr || result.stdout);
    assert.match(result.stderr, /Embedded Scope UI is stale/);
  }
});

test("embedded check propagates build subprocess failures", (t) => {
  const fixture = embeddedFixture(t);
  const before = readFileSync(fixture.artifact);
  writeFileSync(join(fixture.ui, "scripts/build.mjs"), 'console.error("fixture build failure"); process.exit(23);\n');
  const result = fixture.check();
  assert.equal(result.status, 23);
  assert.match(result.stderr, /fixture build failure/);
  assert.match(result.stderr, /Scope UI build failed/);
  assert.deepEqual(readFileSync(fixture.artifact), before);
});

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

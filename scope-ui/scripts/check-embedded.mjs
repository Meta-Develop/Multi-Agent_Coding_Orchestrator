#!/usr/bin/env node
// Verify the embedded client without rewriting the tracked artifact.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const buildScript = fileURLToPath(new URL("./build.mjs", import.meta.url));
const embedded = fileURLToPath(new URL("../../src/scope/placeholder.html", import.meta.url));
const temp = mkdtempSync(join(tmpdir(), "maco-scope-embedded-"));

// Ignore only the CR byte in CRLF pairs; preserve every other byte, including
// whitespace, lone CR bytes, and the presence or absence of a final newline.
function normalizeNewlines(bytes) {
  return bytes.filter((byte, index) => byte !== 0x0d || bytes[index + 1] !== 0x0a);
}

try {
  const generated = join(temp, "placeholder.html");
  const result = spawnSync(process.execPath, [buildScript, generated], {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    console.error("Scope UI build failed; embedded HTML was not checked.");
    process.exitCode = result.status ?? 1;
  } else if (!normalizeNewlines(readFileSync(generated)).equals(
    normalizeNewlines(readFileSync(embedded)),
  )) {
    console.error(
      "Embedded Scope UI is stale. Run npm --prefix scope-ui run build and include src/scope/placeholder.html.",
    );
    process.exitCode = 1;
  } else {
    console.log("Embedded Scope UI matches the sources (CRLF/LF normalized).");
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

test("health reports deployment metadata without caching", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/index.ts"), "utf8");

  assert.match(source, /app\.get\("\/health"/);
  assert.match(source, /app\.get\("\/version"/);
  assert.match(source, /Cache-Control",\s*"no-store"/);
  assert.match(source, /service:\s*"pidp-codecollective"/);
  assert.match(source, /time:\s*new Date\(\)\.toISOString\(\)/);
  assert.match(source, /\.\.\.buildMetadata/);
  assert.match(source, /workerVersionId:\s*c\.env\.CF_VERSION_METADATA\?\.id \?\? null/);
  assert.match(source, /hostname:\s*url\.hostname/);
});

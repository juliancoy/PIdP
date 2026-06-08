import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

test("browser app login redirects do not expose bearer tokens", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/index.ts"), "utf8");

  assert.match(source, /function redirectWithSession/);
  assert.match(source, /headers\.set\("location",\s*target\)/);
  assert.doesNotMatch(source, /function redirectWithToken/);
});

test("native app login redirects keep the explicit deep-link token handoff", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/index.ts"), "utf8");

  assert.match(source, /allowedNativeRedirect\(env,\s*target\)/);
  assert.match(source, /new URLSearchParams\(\{\s*token,\s*token_type:\s*"bearer"\s*\}\)/);
});

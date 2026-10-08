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

test("browser sessions can be scoped to the parent portal domain", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/index.ts"), "utf8");
  const oauthSource = readFileSync(path.join(import.meta.dirname, "../src/oauth.ts"), "utf8");

  assert.match(source, /SESSION_COOKIE_DOMAIN/);
  assert.match(source, /Domain=\$\{domain\}/);
  assert.match(oauthSource, /SESSION_COOKIE_DOMAIN/);
  assert.match(oauthSource, /\.\.\.\(domain \? \{ domain \} : \{\}\)/);
});

test("browser app login uses the shared destination policy", async () => {
  const {browserReturn}=await import('../src/portalClients.ts');
  const env={PUBLIC_BASE_URL:'https://id.example',PORTAL_AUTH_ORIGINS:'https://medtech.social'};
  assert.equal(browserReturn(env,'https://medtech.social/auth/callback'),'https://medtech.social/auth/callback');
  for(const value of ['//evil.example','/\\evil.example','https://evil.example','https://name:password@medtech.social/auth/callback'])assert.equal(browserReturn(env,value),null);
});

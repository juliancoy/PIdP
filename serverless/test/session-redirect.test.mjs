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

test("sign-in replaces the host session and expires the legacy parent-domain cookie", async () => {
  const {default:app}=await import('../src/index.ts');
  const {hashPassword}=await import('../src/crypto.ts');
  const user={id:'owner',email:'owner@example.test',is_active:1,hashed_password:await hashPassword('fixture')};
  const env={SECRET_KEY:'fixture',SESSION_COOKIE_DOMAIN:'example.test',DB:{prepare(){return{bind(){return{async first(){return user}}}}}}};
  const result=await app.request('https://id.example.test/auth/session/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username=owner%40example.test&password=fixture'},env);
  assert.equal(result.status,200);
  const cookies=result.headers.getSetCookie();
  assert.ok(cookies.some(cookie=>cookie.includes('Max-Age=0')&&cookie.includes('Domain=example.test')));
  const active=cookies.find(cookie=>!cookie.includes('Max-Age=0'));
  assert.match(active,/HttpOnly/);assert.doesNotMatch(active,/Domain=/);
});

test("browser app login uses the shared destination policy", async () => {
  const {browserReturn}=await import('../src/portalClients.ts');
  const env={PUBLIC_BASE_URL:'https://id.example',PORTAL_AUTH_ORIGINS:'https://medtech.social'};
  assert.equal(browserReturn(env,'https://medtech.social/auth/callback'),'https://medtech.social/auth/callback');
  for(const value of ['//evil.example','/\\evil.example','https://evil.example','https://name:password@medtech.social/auth/callback'])assert.equal(browserReturn(env,value),null);
});

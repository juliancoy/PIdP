import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

test("token exchange body includes OAuth authorization code grant type", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/oauth.ts"), "utf8");

  assert.match(source, /grant_type:\s*"authorization_code"/);
});

test("OAuth login and token exchange use PKCE S256", () => {
  const source = readFileSync(path.join(import.meta.dirname, "../src/oauth.ts"), "utf8");

  assert.match(source, /code_challenge/);
  assert.match(source, /code_challenge_method",\s*"S256"/);
  assert.match(source, /code_verifier:\s*codeVerifier/);
  assert.match(source, /crypto\.subtle\.digest\("SHA-256"/);
});

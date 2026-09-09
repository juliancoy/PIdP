import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, jwtVerify, importJWK } from 'jose';
import { mcpAuthorization as app } from '../src/mcpAuthorization.ts';
import { signJwt, sha256Hex } from '../src/crypto.ts';
import fullApp from '../src/index.ts';

async function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE users(id TEXT PRIMARY KEY, is_active INTEGER); INSERT INTO users VALUES ('alice',1),('bob',1);
    CREATE TABLE website_users(id TEXT, website_id TEXT, is_active INTEGER);`);
  sql.exec(readFileSync(new URL('../migrations/0006_mcp_authorization.sql', import.meta.url), 'utf8'));
  const db = { prepare(query) { const stmt = sql.prepare(query); return { bind(...params) { return {
    async first() { return stmt.get(...params) ?? null; }, async all() { return { results: stmt.all(...params) }; },
    async run() { return { meta: stmt.run(...params) }; },
  }; } }; } };
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const key = { ...await exportJWK(privateKey), kid: 'test-key' };
  const issuer = 'https://id.example'; const resource = 'https://portal.example/api/org/mcp';
  const env = { DB: db, SECRET_KEY: 'test-session-key', MCP_OAUTH_ISSUER: issuer,
    MCP_OAUTH_PRIVATE_JWK: JSON.stringify(key),
    MCP_OAUTH_CLIENTS_JSON: JSON.stringify({ chatgpt: { name: '<ChatGPT>', secretHash: await sha256Hex('client-secret-for-tests-at-least-32-chars'),
      redirectUris: ['https://chatgpt.example/callback'], resources: [resource], scopes: ['org:events.read', 'org:events.write'] } }),
    MCP_OAUTH_RESOURCES_JSON: JSON.stringify({ [resource]: { secretHash: await sha256Hex('resource-secret-for-tests-at-least-32-chars') } }) };
  const cookie = `pidp_session=${await signJwt(env, { sub: 'alice' })}`;
  const bobCookie = `pidp_session=${await signJwt(env, { sub: 'bob' })}`;
  const verifier = 'v'.repeat(43);
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
  const params = { response_type: 'code', client_id: 'chatgpt', redirect_uri: 'https://chatgpt.example/callback',
    resource, scope: 'org:events.read org:events.write', code_challenge: challenge, code_challenge_method: 'S256', state: 'original-state' };
  const request = (path, init = {}) => app.request(issuer + path, init, env);
  const post = (path, body, headers = {}) => request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body) });
  async function consent() {
    const response = await request('/oauth/mcp/authorize?' + new URLSearchParams(params), { headers: { cookie } });
    assert.equal(response.status, 200);
    const html = await response.text(); assert.ok(html.includes('&lt;ChatGPT&gt;'));
    return html.match(/name="request" value="([^"]+)"/)[1];
  }
  async function code() {
    const nonce = await consent();
    const response = await post('/oauth/mcp/authorize', { request: nonce, decision: 'allow' }, { cookie, origin: issuer });
    assert.equal(response.status, 303); const location = new URL(response.headers.get('location'));
    assert.equal(location.searchParams.get('state'), 'original-state'); return location.searchParams.get('code');
  }
  const exchange = (code, changes = {}) => post('/oauth/mcp/token', { grant_type: 'authorization_code', code,
    client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars', redirect_uri: params.redirect_uri, resource, code_verifier: verifier, ...changes });
  const refresh = token => post('/oauth/mcp/token', { grant_type: 'refresh_token', refresh_token: token, client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars' });
  const introspect = token => post('/oauth/mcp/introspect', { token, resource }, { authorization: 'Bearer resource-secret-for-tests-at-least-32-chars' });
  return { sql, env, issuer, resource, request, post, cookie, bobCookie, params, consent, code, exchange, refresh, introspect };
}

test('discovery and full consent/PKCE flow issue verifiable, audience-bound tokens; refresh rotates and replay revokes', async () => {
  const f = await fixture(); try {
    assert.equal((await fullApp.request(f.issuer + '/.well-known/oauth-authorization-server', {}, f.env)).status, 200);
    const health = await fullApp.request(f.issuer + '/health', {}, f.env);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('content-security-policy'), null);
    const discovery = await (await f.request('/.well-known/oauth-authorization-server')).json();
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
    const jwks = await (await f.request('/.well-known/jwks.json')).json();
    assert.equal(jwks.keys[0].d, undefined);
    const code = await f.code(); const result = await f.exchange(code);
    assert.equal(result.status, 200); assert.equal(result.headers.get('cache-control'), 'no-store');
    const tokens = await result.json();
    const verified = await jwtVerify(tokens.access_token, await importJWK(jwks.keys[0]), { issuer: f.issuer, audience: f.resource, typ: 'at+jwt' });
    assert.equal(verified.payload.sub, 'owner:alice'); assert.equal(verified.payload.exp - verified.payload.iat, 300);
    assert.equal((await f.exchange(code)).status, 400);
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, true);
    const renewed = await (await f.refresh(tokens.refresh_token)).json();
    assert.ok(renewed.refresh_token && renewed.refresh_token !== tokens.refresh_token);
    assert.equal((await f.refresh(tokens.refresh_token)).status, 400);
    assert.equal((await (await f.introspect(renewed.access_token)).json()).active, false);
    assert.equal((await f.refresh(renewed.refresh_token)).status, 400);
  } finally { f.sql.close(); }
});

test('rejects forged callbacks, missing PKCE, changed sessions, CSRF, wrong verifier/resource/client and expired codes', async () => {
  const f = await fixture(); try {
    for (const change of [{ redirect_uri: 'https://evil.example' }, { code_challenge_method: 'plain' }, { scope: 'org:admin.write' }]) {
      assert.equal((await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, ...change }), { headers: { cookie: f.cookie } })).status, 400);
    }
    const nonce = await f.consent();
    assert.equal((await f.post('/oauth/mcp/authorize', { request: nonce, decision: 'allow' }, { cookie: f.bobCookie, origin: f.issuer })).status, 400);
    assert.equal((await f.post('/oauth/mcp/authorize', { request: nonce, decision: 'allow' }, { cookie: f.cookie, origin: 'https://evil.example' })).status, 403);
    const code = await f.code();
    assert.equal((await f.exchange(code, { code_verifier: 'x'.repeat(43) })).status, 400);
    assert.equal((await f.exchange(code, { resource: 'https://other.example/mcp' })).status, 400);
    assert.equal((await f.exchange(code, { client_secret: 'bad' })).status, 401);
    assert.equal((await f.exchange(code)).status, 200);
    const expired = await f.code(); f.sql.exec('UPDATE mcp_oauth_codes SET expires_at = 0');
    assert.equal((await f.exchange(expired)).status, 400);
  } finally { f.sql.close(); }
});

test('consent denial, client revocation, account deactivation and protected introspection', async () => {
  const f = await fixture(); try {
    const nonce = await f.consent();
    const denied = await f.post('/oauth/mcp/authorize', { request: nonce, decision: 'deny' }, { cookie: f.cookie, origin: f.issuer });
    assert.equal(new URL(denied.headers.get('location')).searchParams.get('error'), 'access_denied');
    assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM mcp_oauth_codes').get().n, 0);
    const tokens = await (await f.exchange(await f.code())).json();
    assert.equal((await f.post('/oauth/mcp/introspect', { token: tokens.access_token, resource: f.resource })).status, 401);
    await f.post('/oauth/mcp/revoke', { token: tokens.refresh_token, client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars' });
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, false);
    const other = await (await f.exchange(await f.code())).json();
    f.sql.exec("UPDATE users SET is_active = 0 WHERE id = 'alice'");
    assert.equal((await (await f.introspect(other.access_token)).json()).active, false);
    assert.equal((await f.refresh(other.refresh_token)).status, 400);
  } finally { f.sql.close(); }
});

test('user revocation is session scoped and forged requests cannot revoke connections', async () => {
  const f = await fixture(); try {
    const tokens = await (await f.exchange(await f.code())).json();
    const response = await f.request('/oauth/mcp/connections', { headers: { cookie: f.cookie } });
    const html = await response.text(); const grant = html.match(/name="grant" value="([^"]+)"/)[1]; const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
    assert.equal((await f.post('/oauth/mcp/connections', { grant, csrf }, { cookie: f.bobCookie, origin: f.issuer })).status, 403);
    assert.equal((await f.post('/oauth/mcp/connections', { grant, csrf }, { cookie: f.cookie, origin: f.issuer })).status, 303);
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, false);
  } finally { f.sql.close(); }
});

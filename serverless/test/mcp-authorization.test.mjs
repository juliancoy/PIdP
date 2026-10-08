import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, jwtVerify, importJWK } from 'jose';
import { authorizationConfig, mcpAuthorization as app } from '../src/mcpAuthorization.ts';
import { signJwt, sha256Hex } from '../src/crypto.ts';
import fullApp from '../src/index.ts';

async function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE users(id TEXT PRIMARY KEY, is_active INTEGER); INSERT INTO users VALUES ('alice',1),('bob',1);
    CREATE TABLE website_users(id TEXT, website_id TEXT, is_active INTEGER);`);
  sql.exec(readFileSync(new URL('../migrations/0006_mcp_authorization.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0007_mcp_client_registration.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0008_mcp_login_handoff.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0010_account_identity_links.sql',import.meta.url),'utf8'));
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
      redirectUris: ['https://chatgpt.example/callback'], resources: [resource], scopes: ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write'] } }),
    MCP_OAUTH_RESOURCES_JSON: JSON.stringify({ [resource]: { secretHash: await sha256Hex('resource-secret-for-tests-at-least-32-chars') } }) };
  const cookie = `pidp_session=${await signJwt(env, { sub: 'alice' })}`;
  const bobCookie = `pidp_session=${await signJwt(env, { sub: 'bob' })}`;
  const verifier = 'v'.repeat(43);
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
  const params = { response_type: 'code', client_id: 'chatgpt', redirect_uri: 'https://chatgpt.example/callback',
    resource, scope: 'org:events.read org:events.write org:portal.read org:portal.write', code_challenge: challenge, code_challenge_method: 'S256', state: 'original-state' };
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
    assert.equal(location.searchParams.get('state'), 'original-state');
    assert.equal(location.searchParams.get('iss'), issuer);
    return location.searchParams.get('code');
  }
  const exchange = (code, changes = {}) => post('/oauth/mcp/token', { grant_type: 'authorization_code', code,
    client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars', redirect_uri: params.redirect_uri, resource, code_verifier: verifier, ...changes });
  const refresh = token => post('/oauth/mcp/token', { grant_type: 'refresh_token', refresh_token: token, client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars' });
  const introspect = token => post('/oauth/mcp/introspect', { token, resource }, { authorization: 'Bearer resource-secret-for-tests-at-least-32-chars' });
  return { sql, env, issuer, resource, request, post, cookie, bobCookie, params, consent, code, exchange, refresh, introspect };
}

test('portal login preserves website identity, binds the browser, and completes consent and token exchange', async () => {
  const f = await fixture(); try {
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'MedTech', loginUrl: 'https://portal.example/users/mcp-connect' } });
    f.sql.exec("INSERT INTO website_users VALUES ('member','portal-site',1)");
    const portalCookie = `pidp_session=${await signJwt(f.env, { sub: 'member', actor_type: 'website_user', website_id: 'portal-site', email: 'member@example.test' })}`;
    const start = await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params), { headers: { cookie: f.cookie } });
    assert.equal(start.status, 303);
    const target = new URL(start.headers.get('location'));
    assert.equal(target.origin, f.issuer);
    assert.equal(target.pathname, '/oauth/mcp/browser');
    assert.equal(target.searchParams.has('owner'), false);
    assert.equal((await f.post('/oauth/mcp/handoff', { request: target.searchParams.get('request') },
      { authorization: 'Bearer ' + f.cookie.split('=')[1], origin: 'https://portal.example' })).status, 401);
    const browser = start.headers.get('set-cookie').split(';')[0];
    assert.match(start.headers.get('set-cookie'), /HttpOnly/);
    assert.doesNotMatch(start.headers.get('set-cookie'), /Domain=/i);
    const request = target.searchParams.get('request');
    assert.equal((await f.request('/oauth/mcp/handoff?' + new URLSearchParams({ request }))).status, 401);
    const metadata = await (await f.request('/oauth/mcp/handoff?' + new URLSearchParams({ request }), { headers: { cookie: portalCookie } })).json();
    assert.equal(metadata.account, 'member@example.test');
    assert.equal(metadata.portal, 'MedTech');
    assert.equal((await f.post('/oauth/mcp/handoff', { request }, { cookie: portalCookie, origin: 'https://evil.example' })).status, 403);
    assert.equal((await f.post('/oauth/mcp/handoff', { request }, { cookie: portalCookie })).status, 403);
    const response = await f.post('/oauth/mcp/handoff', { request }, { cookie: portalCookie, origin: 'https://portal.example' });
    assert.equal(response.status, 200);
    const resume = new URL((await response.json()).redirect_url);
    assert.equal((await f.post('/oauth/mcp/handoff', { request }, { cookie: portalCookie, origin: 'https://portal.example' })).status, 400);
    assert.equal((await f.request(resume.pathname + resume.search)).status, 400);
    assert.equal((await f.request(resume.pathname + resume.search, { headers: { cookie: '__Host-pidp_mcp_browser=' + 'z'.repeat(54) } })).status, 400);
    const resumed = await f.request(resume.pathname + resume.search, { headers: { cookie: browser } });
    assert.equal(resumed.status, 303);
    const cookie = resumed.headers.get('set-cookie').split(';')[0];
    assert.ok(cookie.startsWith('__Host-pidp_mcp_session='));
    assert.equal((await (await f.introspect(decodeURIComponent(cookie.split('=')[1]))).json()).active, false);
    assert.equal((await f.request(resume.pathname + resume.search, { headers: { cookie: browser } })).status, 400);
    const consent = await f.request(resumed.headers.get('location'), { headers: { cookie } });
    assert.equal(consent.status, 200);
    assert.equal(consent.headers.get('referrer-policy'), 'same-origin');
    const html = await consent.text(); assert.match(html, /member@example.test/);
    assert.match(html, /Confirm your account and review the requested permissions/);
    assert.match(html, /Permissions requested by/);
    assert.match(html, /Allow access/);assert.match(html, />Deny</);
    assert.equal((html.match(/<form /g)||[]).length,1);
    const nonce = html.match(/name="request" value="([^"]+)"/)[1];
    const allowed = await f.post('/oauth/mcp/authorize', { request: nonce, decision: 'allow' }, { cookie, origin: f.issuer });
    const code = new URL(allowed.headers.get('location')).searchParams.get('code');
    const tokens = await (await f.exchange(code)).json();
    const keys = await (await f.request('/.well-known/jwks.json')).json();
    const verified = await jwtVerify(tokens.access_token, await importJWK(keys.keys[0]), { issuer: f.issuer, audience: f.resource });
    assert.equal(verified.payload.sub, 'website:portal-site:member');
    f.env.ADMIN_USER_IDS='member';
    assert.equal((await(await f.introspect(tokens.access_token)).json()).is_sysadmin,false);
    assert.equal((await f.request('/oauth/mcp/connections', { headers: { cookie } })).status, 200);
    f.sql.exec("UPDATE website_users SET is_active = 0");
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, false);
  } finally { f.sql.close(); }
});

test('portal login rejects expired requests and unconfigured destinations', async () => {
  const f = await fixture(); try {
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'MedTech', loginUrl: 'https://portal.example/users/mcp-connect' } });
    const start = await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params));
    const request = new URL(start.headers.get('location')).searchParams.get('request');
    f.sql.exec('UPDATE mcp_oauth_logins SET expires_at = 0');
    assert.equal((await f.post('/oauth/mcp/handoff', { request }, { cookie: f.cookie, origin: 'https://portal.example' })).status, 400);
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'Bad', loginUrl: 'https://evil.example/users/mcp-connect?next=https://evil.example' } });
    assert.equal((await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params))).status, 503);
  } finally { f.sql.close(); }
});

test('portal login is bounded per browser and account deactivation blocks resume', async () => {
  const f = await fixture(); try {
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'Portal', loginUrl: 'https://portal.example/users/mcp-connect' } });
    const url = '/oauth/mcp/authorize?' + new URLSearchParams(f.params);
    const start = await f.request(url);
    const browser = start.headers.get('set-cookie').split(';')[0];
    for (let i = 1; i < 20; i++) assert.equal((await f.request(url, { headers: { cookie: browser } })).status, 303);
    assert.equal((await f.request(url, { headers: { cookie: browser } })).status, 429);
    const request = new URL(start.headers.get('location')).searchParams.get('request');
    const confirmed = await f.post('/oauth/mcp/handoff', { request }, { cookie: f.cookie, origin: 'https://portal.example' });
    const resume = new URL((await confirmed.json()).redirect_url);
    f.sql.exec("UPDATE users SET is_active = 0 WHERE id = 'alice'");
    assert.equal((await f.request(resume.pathname + resume.search, { headers: { cookie: browser } })).status, 400);
  } finally { f.sql.close(); }
});

test('discovery and full consent/PKCE flow issue verifiable, audience-bound tokens; refresh rotates and replay revokes', async () => {
  const f = await fixture(); try {
    assert.equal((await fullApp.request(f.issuer + '/.well-known/oauth-authorization-server', {}, f.env)).status, 200);
    const health = await fullApp.request(f.issuer + '/health', {}, f.env);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('content-security-policy'), null);
    const discovery = await (await f.request('/.well-known/oauth-authorization-server')).json();
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
    assert.equal(discovery.authorization_response_iss_parameter_supported, true);
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
    const deniedLocation = new URL(denied.headers.get('location'));
    assert.equal(deniedLocation.searchParams.get('error'), 'access_denied');
    assert.equal(deniedLocation.searchParams.get('iss'), f.issuer);
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

test('native public client uses browser consent and PKCE without a distributed secret', async () => {
  const f = await fixture(); try {
    const clients = JSON.parse(f.env.MCP_OAUTH_CLIENTS_JSON);
    clients.chatgpt.tokenEndpointAuthMethod = 'none';
    delete clients.chatgpt.secretHash;
    clients.chatgpt.redirectUris = ['http://127.0.0.1/callback'];
    f.env.MCP_OAUTH_CLIENTS_JSON = JSON.stringify(clients);
    f.params.redirect_uri = 'http://127.0.0.1:49152/callback';
    const cases = JSON.parse(readFileSync(new URL('../../tests/oauth_redirect_cases.json', import.meta.url), 'utf8'));
    for (const { uri, allowed } of cases) {
      const response = await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, redirect_uri: uri }), { headers: { cookie: f.cookie } });
      assert.equal(response.status, allowed ? 200 : 400, uri);
    }
    const code = await f.code();
    const exchange = changes => f.post('/oauth/mcp/token', { grant_type: 'authorization_code', client_id: 'chatgpt', code,
      resource: f.resource, redirect_uri: f.params.redirect_uri, code_verifier: 'v'.repeat(43), ...changes });
    assert.equal((await exchange({ client_secret: '' })).status, 401);
    assert.equal((await exchange({ redirect_uri: 'http://127.0.0.1:54321/callback' })).status, 400);
    assert.equal((await exchange({ code_verifier: 'x'.repeat(43) })).status, 400);
    const response = await exchange({}); assert.equal(response.status, 200);
    const tokens = await response.json();
    const refresh = await f.post('/oauth/mcp/token', { grant_type: 'refresh_token', client_id: 'chatgpt', refresh_token: tokens.refresh_token });
    assert.equal(refresh.status, 200);
    const renewed = await refresh.json();
    await f.post('/oauth/mcp/revoke', { client_id: 'chatgpt', token: renewed.refresh_token });
    assert.equal((await (await f.introspect(renewed.access_token)).json()).active, false);
  } finally { f.sql.close(); }
});

test('dynamic clients require user consent, PKCE and exact callbacks; registration is not account access', async () => {
  const f = await fixture(); try {
    const register = () => f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: '<ChatGPT>', token_endpoint_auth_method: 'none', redirect_uris: ['http://127.0.0.1/callback'] }) });
    assert.equal((await register()).status, 403);
    f.env.MCP_OAUTH_DYNAMIC_REGISTRATION = 'true';
    assert.equal((await (await f.request('/.well-known/oauth-authorization-server')).json()).registration_endpoint, f.issuer + '/oauth/mcp/register');
    const response = await register(); assert.equal(response.status, 201);
    const client = await response.json(); assert.equal(client.client_secret, undefined);
    f.params.client_id = client.client_id; f.params.redirect_uri = 'http://127.0.0.1:54321/callback';
    delete f.params.resource;
    const login = await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params));
    assert.equal(login.status, 303); assert.ok(login.headers.get('location').includes('/app/login'));
    const consent = await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params), { headers: { cookie: f.cookie } });
    assert.match(await consent.text(), /self-reported/);
    const code = await f.code();
    const exchange = changes => f.post('/oauth/mcp/token', { grant_type: 'authorization_code', client_id: client.client_id, code,
      redirect_uri: f.params.redirect_uri, code_verifier: 'v'.repeat(43), ...changes });
    assert.equal((await exchange({ redirect_uri: 'http://127.0.0.1:54321/wrong' })).status, 400);
    assert.equal((await exchange({ code_verifier: 'x'.repeat(43) })).status, 400);
    const issued = await exchange({}); assert.equal(issued.status, 200);
    const tokens = await issued.json();
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, true);
    const stored = JSON.parse(f.sql.prepare('SELECT client_json FROM mcp_oauth_clients WHERE id = ?').get(client.client_id).client_json);
    const secondResource = 'https://other.example/mcp';
    f.env.MCP_OAUTH_RESOURCES_JSON = JSON.stringify({ ...JSON.parse(f.env.MCP_OAUTH_RESOURCES_JSON), [secondResource]: { secretHash: 'a'.repeat(64) } });
    assert.ok(!stored.resources.includes(secondResource));
    const newResourceConsent = await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, resource: secondResource }), { headers: { cookie: f.cookie } });
    assert.equal(newResourceConsent.status, 200);
    assert.match(await newResourceConsent.text(), /other\.example/);
    assert.equal((await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, resource: 'https://unconfigured.example/mcp' }), { headers: { cookie: f.cookie } })).status, 400);
    assert.equal((await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params), { headers: { cookie: f.cookie } })).status, 400);
    f.sql.prepare('UPDATE mcp_oauth_clients SET revoked = 1 WHERE id = ?').run(client.client_id);
    assert.equal((await (await f.introspect(tokens.access_token)).json()).active, false);
    assert.equal((await f.post('/oauth/mcp/token', { client_id: client.client_id, grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status, 401);
  } finally { f.sql.close(); }
});

test('dynamic registration shares callback policy, bounds request size and rate limits anonymous creation', async () => {
  const f = await fixture(); try {
    f.env.MCP_OAUTH_DYNAMIC_REGISTRATION = 'true';
    const cases = JSON.parse(readFileSync(new URL('../../tests/oauth_registration_cases.json', import.meta.url), 'utf8'));
    let i = 0;
    for (const { metadata, status } of cases) {
      const response = await f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': `test-${i++}` }, body: JSON.stringify(metadata) });
      assert.equal(response.status, status, JSON.stringify(metadata));
      if (status === 201) {
        const data = await response.json();
        if (data.client_secret) assert.ok(!f.sql.prepare('SELECT client_json FROM mcp_oauth_clients WHERE id = ?').get(data.client_id).client_json.includes(data.client_secret));
      }
    }
    for (let j = 0; j < 11; j++) {
      const response = await f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': 'rate-test' }, body: '{}' });
      assert.equal(response.status, j === 10 ? 429 : 400);
    }
    assert.equal((await f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: ' '.repeat(17000) })).status, 400);
  } finally { f.sql.close(); }
});

test('dynamically registered confidential clients authenticate using their registered method', async () => {
  for (const method of ['client_secret_basic', 'client_secret_post']) {
    const f = await fixture(); try {
      f.env.MCP_OAUTH_DYNAMIC_REGISTRATION = 'true';
      const r = await f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
        client_name: '<ChatGPT>', token_endpoint_auth_method: method, redirect_uris: [f.params.redirect_uri] }) });
      const client = await r.json(); f.params.client_id = client.client_id;
      const code = await f.code();
      const data = { grant_type: 'authorization_code', client_id: client.client_id, code, redirect_uri: f.params.redirect_uri, resource: f.resource, code_verifier: 'v'.repeat(43) };
      assert.equal((await f.post('/oauth/mcp/token', data)).status, 401);
      const headers = method === 'client_secret_basic' ? { authorization: 'Basic ' + Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64') } : {};
      if (method === 'client_secret_post') data.client_secret = client.client_secret;
      assert.equal((await f.post('/oauth/mcp/token', data, headers)).status, 200);
    } finally { f.sql.close(); }
  }
});


test('separate resources retain distinct credentials, login origins and token audiences', async () => {
  const f = await fixture();
  try {
    const lifetech = 'https://lifetech.fyi/api/org/mcp';
    const code = await f.code();
    f.env.MCP_OAUTH_RESOURCE_CONFIG_JSON = JSON.stringify({ [lifetech]: {
      secretHash: await sha256Hex('lifetech-resource-secret-at-least-32-chars'),
      portal: { name: 'LifeTech', loginUrl: 'https://lifetech.fyi/users/mcp-connect' },
    } });
    const clients = JSON.parse(f.env.MCP_OAUTH_CLIENTS_JSON);
    clients.chatgpt.resources.push(lifetech);
    f.env.MCP_OAUTH_CLIENTS_JSON = JSON.stringify(clients);
    const config = authorizationConfig(f.env);
    assert.ok(config.resources[f.resource]);
    assert.notEqual(config.resources[f.resource].secretHash, config.resources[lifetech].secretHash);
    const start = await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, resource: lifetech }), { headers: { cookie: f.cookie } });
    assert.equal(start.status, 303);
    const login = new URL(start.headers.get('location'));
    assert.equal(login.origin, f.issuer);
    assert.equal(login.pathname, '/oauth/mcp/browser');
    assert.equal(f.sql.prepare('SELECT resource FROM mcp_oauth_logins ORDER BY rowid DESC LIMIT 1').get().resource, lifetech);
    assert.equal((await f.exchange(code, { resource: lifetech })).status, 400);
    const tokens = await (await f.exchange(code)).json();
    const cross = await f.post('/oauth/mcp/introspect', { token: tokens.access_token, resource: lifetech }, { authorization: 'Bearer lifetech-resource-secret-at-least-32-chars' });
    assert.equal((await cross.json()).active, false);
    assert.equal((await f.post('/oauth/mcp/introspect', { token: tokens.access_token, resource: lifetech }, { authorization: 'Bearer resource-secret-for-tests-at-least-32-chars' })).status, 401);
    f.env.MCP_OAUTH_RESOURCE_CONFIG_JSON = JSON.stringify({ [f.resource]: { secretHash: 'a'.repeat(64), portal: { name: 'Other', loginUrl: 'https://other.example/users/mcp-connect' } } });
    assert.throws(() => authorizationConfig(f.env), /not_configured/);
  } finally { f.sql.close(); }
});


test('native grants persist beyond 30 days, upgrade active legacy grants and remain revocable', async () => {
  const f = await fixture();
  const originalNow = Date.now;
  try {
    f.env.MCP_OAUTH_CLIENTS_JSON = JSON.stringify({ chatgpt: { name: '<ChatGPT>', tokenEndpointAuthMethod: 'none',
      redirectUris: ['http://127.0.0.1/callback'], resources: [f.resource], scopes: ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write'] } });
    f.params.redirect_uri = 'http://127.0.0.1:4545/callback';
    const code = await f.code();
    let tokens = await (await f.post('/oauth/mcp/token', { grant_type: 'authorization_code', client_id: 'chatgpt', code,
      resource: f.resource, redirect_uri: f.params.redirect_uri, code_verifier: 'v'.repeat(43) })).json();
    assert.equal(f.sql.prepare('SELECT expires_at FROM mcp_oauth_grants').get().expires_at, 0);
    assert.match(await (await f.request('/oauth/mcp/connections', { headers: { cookie: f.cookie } })).text(), /name="grant"/);
    Date.now = () => originalNow() + 40 * 86400 * 1000;
    const refreshed = await f.post('/oauth/mcp/token', { grant_type: 'refresh_token', client_id: 'chatgpt', refresh_token: tokens.refresh_token });
    assert.equal(refreshed.status, 200);
    tokens = await refreshed.json();
    Date.now = originalNow;
    f.sql.prepare('UPDATE mcp_oauth_grants SET expires_at = ?').run(Math.floor(originalNow() / 1000) + 1000);
    const upgraded = await f.post('/oauth/mcp/token', { grant_type: 'refresh_token', client_id: 'chatgpt', refresh_token: tokens.refresh_token });
    assert.equal(upgraded.status, 200);
    tokens = await upgraded.json();
    assert.equal(f.sql.prepare('SELECT expires_at FROM mcp_oauth_grants').get().expires_at, 0);
    await f.post('/oauth/mcp/revoke', { client_id: 'chatgpt', token: tokens.refresh_token });
    assert.equal((await f.post('/oauth/mcp/token', { grant_type: 'refresh_token', client_id: 'chatgpt', refresh_token: tokens.refresh_token })).status, 400);
  } finally { Date.now = originalNow; f.sql.close(); }
});

test('changing account starts fresh portal SSO and preserves the pending MCP request', async () => {
  const f = await fixture();
  try {
    f.env.PORTAL_SSO_APP_SLUG = 'portal-app';
    f.env.SESSION_COOKIE_DOMAIN = 'id.example';
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'Portal', loginUrl: 'https://portal.example/users/mcp-connect' } });
    const response = await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, prompt: 'login' }), { headers: { cookie: f.cookie } });
    assert.equal(response.status, 303);
    const login = new URL(response.headers.get('location'));
    assert.equal(login.origin + login.pathname, f.issuer + '/oauth/mcp/browser');
    assert.ok(login.searchParams.get('request').startsWith('login_'));
    assert.match(response.headers.get('set-cookie'), /__Host-pidp_mcp_session=;[^,]*Max-Age=0/);
    assert.doesNotMatch(response.headers.get('set-cookie'), /(?:^|, )pidp_session=/);
    const row = f.sql.prepare('SELECT return_path FROM mcp_oauth_logins').get();
    const pending = new URL(row.return_path, f.issuer);
    assert.equal(pending.searchParams.get('prompt'), null);
    assert.equal(pending.searchParams.get('state'), f.params.state);
    assert.equal(pending.searchParams.get('code_challenge'), f.params.code_challenge);
  } finally { f.sql.close(); }
});

test('multi-resource clients can redeem a code without repeating its resource', async () => {
  const f = await fixture();
  try {
    const code = await f.code();
    const other = 'https://other.example/api/org/mcp';
    f.env.MCP_OAUTH_RESOURCE_CONFIG_JSON = JSON.stringify({ [other]: { secretHash: 'a'.repeat(64), portal: { name: 'Other', loginUrl: 'https://other.example/users/mcp-connect' } } });
    const clients = JSON.parse(f.env.MCP_OAUTH_CLIENTS_JSON);
    clients.chatgpt.resources.push(other);
    f.env.MCP_OAUTH_CLIENTS_JSON = JSON.stringify(clients);
    assert.equal((await f.exchange(code, { resource: other })).status, 400);
    const response = await f.post('/oauth/mcp/token', { grant_type: 'authorization_code', code, client_id: 'chatgpt', client_secret: 'client-secret-for-tests-at-least-32-chars', redirect_uri: f.params.redirect_uri, code_verifier: 'v'.repeat(43) });
    assert.equal(response.status, 200);
    const tokens = await response.json();
    assert.equal(JSON.parse(Buffer.from(tokens.access_token.split('.')[1], 'base64url').toString()).aud, f.resource);
    assert.equal((await f.exchange(code)).status, 400);
  } finally { f.sql.close(); }
});

test('two isolated browsers confirm identity then finish OAuth only in the initiating browser', async () => {
  const f = await fixture();
  try {
    f.env.PORTAL_SSO_APP_SLUG = 'members';
    f.env.MCP_OAUTH_PORTALS_JSON = JSON.stringify({ [f.resource]: { name: 'Portal', loginUrl: 'https://portal.example/users/mcp-connect' } });
    const start = await f.request('/oauth/mcp/authorize?' + new URLSearchParams({ ...f.params, prompt: 'login' }));
    const location = new URL(start.headers.get('location')), request = location.searchParams.get('request');
    const browser = start.headers.getSetCookie().find(value => value.startsWith('__Host-pidp_mcp_browser=')).split(';')[0];
    const code = f.sql.prepare('SELECT display FROM mcp_oauth_logins').get().display;
    const primary = { cookie: browser };
    const secondary = { cookie: f.bobCookie, 'x-forwarded-host': 'portal.example' };
    assert.equal((await f.request(location.pathname + location.search, { headers: primary })).status, 200);
    assert.equal((await f.request(location.pathname + location.search, { headers: secondary })).status, 403);
    const statusUrl = '/oauth/mcp/browser/status?' + new URLSearchParams({ request });
    assert.deepEqual(await (await f.request(statusUrl, { headers: primary })).json(), { ready: false });
    const confirmation = await f.request('/oauth/mcp/link?' + new URLSearchParams({ request }), { headers: secondary });
    assert.equal(confirmation.status, 200);
    const html = await confirmation.text();
    assert.ok(!html.includes(code));
    assert.match(html, /Confirm this account/);
    assert.equal((await f.post('/oauth/mcp/link', { request, pairing_code: code }, { ...secondary, origin: 'https://evil.example' })).status, 403);
    assert.equal((await f.post('/oauth/mcp/link', { request, pairing_code: 'BAD-CODE' }, { ...secondary, origin: 'https://portal.example' })).status, 400);
    assert.equal((await f.post('/oauth/mcp/link', { request, pairing_code: code }, { ...secondary, origin: 'https://portal.example' })).status, 200);
    assert.equal((await f.post('/oauth/mcp/link', { request, pairing_code: code }, { ...secondary, origin: 'https://portal.example' })).status, 400);
    const ready = await (await f.request(statusUrl, { headers: primary })).json();
    assert.equal(ready.ready, true);
    const finishArgs = { request };
    assert.equal((await f.post('/oauth/mcp/browser/finish', finishArgs, { ...secondary, origin: f.issuer })).status, 403);
    assert.equal((await f.post('/oauth/mcp/browser/finish', finishArgs, { ...primary, origin: 'https://evil.example' })).status, 403);
    const finish = await f.post('/oauth/mcp/browser/finish', finishArgs, { ...primary, origin: f.issuer });
    assert.equal(finish.status, 303);
    const cookie = finish.headers.get('set-cookie').split(';')[0];
    const consent = await f.request(finish.headers.get('location'), { headers: { cookie } });
    assert.equal(consent.status, 200);
    assert.match(await consent.clone().text(), /bob/);
    const nonce = (await consent.text()).match(/name="request" value="([^"]+)"/)[1];
    const allowed = await f.post('/oauth/mcp/authorize', { request: nonce, decision: 'allow' }, { cookie, origin: f.issuer });
    const authCode = new URL(allowed.headers.get('location')).searchParams.get('code');
    const tokens = await (await f.exchange(authCode)).json();
    const claims = JSON.parse(Buffer.from(tokens.access_token.split('.')[1], 'base64url').toString());
    assert.equal(claims.sub, 'owner:bob');
    assert.equal(claims.aud, f.resource);
    assert.equal((await f.post('/oauth/mcp/browser/finish', finishArgs, { ...primary, origin: f.issuer })).status, 400);
  } finally { f.sql.close(); }
});

test('handoffs expire, cancel, and reject inactive confirmed accounts', async () => {
 const f=await fixture();
 try {
  f.env.MCP_OAUTH_PORTALS_JSON=JSON.stringify({[f.resource]:{name:'Portal',loginUrl:'https://portal.example/users/mcp-connect'}});
  const begin=async()=>{const response=await f.request('/oauth/mcp/authorize?'+new URLSearchParams({...f.params,prompt:'login'}));return{request:new URL(response.headers.get('location')).searchParams.get('request'),cookie:response.headers.getSetCookie().find(c=>c.startsWith('__Host-pidp_mcp_browser=')).split(';')[0]}};
  let pending=await begin();f.sql.exec('UPDATE mcp_oauth_logins SET expires_at=0');
  assert.equal((await f.request('/oauth/mcp/browser/status?'+new URLSearchParams({request:pending.request}),{headers:{cookie:pending.cookie}})).status,400);
  pending=await begin();
  assert.equal((await f.post('/oauth/mcp/browser/cancel',{request:pending.request},{cookie:pending.cookie,origin:f.issuer})).status,200);
  assert.equal((await f.request('/oauth/mcp/link?'+new URLSearchParams({request:pending.request}),{headers:{cookie:f.bobCookie,'x-forwarded-host':'portal.example'}})).status,400);
  pending=await begin();const row=f.sql.prepare('SELECT display FROM mcp_oauth_logins WHERE id=?').get(await sha256Hex(pending.request));
  assert.equal((await f.post('/oauth/mcp/link',{request:pending.request,pairing_code:row.display},{cookie:f.bobCookie,'x-forwarded-host':'portal.example',origin:'https://portal.example'})).status,200);
  f.sql.exec("UPDATE users SET is_active=0 WHERE id='bob'");
  assert.equal((await f.post('/oauth/mcp/browser/finish',{request:pending.request},{cookie:pending.cookie,origin:f.issuer})).status,401);
 }finally{f.sql.close()}
});


test('portal-only DCR and authorization preserve least-privilege scopes', async () => {
  const f = await fixture(); try {
    f.env.MCP_OAUTH_DYNAMIC_REGISTRATION = 'true';
    const metadata = { client_name: '<ChatGPT>', token_endpoint_auth_method: 'none', redirect_uris: [f.params.redirect_uri], scope: 'org:portal.read' };
    const register = scope => f.request('/oauth/mcp/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...metadata, scope }) });
    const response = await register('org:portal.read'); assert.equal(response.status, 201);
    const client = await response.json();
    f.params.client_id = client.client_id; f.params.scope = 'org:portal.read';
    const issued = await f.post('/oauth/mcp/token', { grant_type: 'authorization_code', code: await f.code(), client_id: client.client_id, redirect_uri: f.params.redirect_uri, resource: f.resource, code_verifier: 'v'.repeat(43) });
    assert.equal(issued.status, 200); assert.equal((await issued.json()).scope, 'org:portal.read');
    for (const scope of ['', 'org:unknown']) assert.equal((await register(scope)).status, 400);
    f.params.scope = 'org:events.read';
    assert.equal((await f.request('/oauth/mcp/authorize?' + new URLSearchParams(f.params), { headers: { cookie: f.cookie } })).status, 400);
  } finally { f.sql.close(); }
});

test('explicit system-admin consent preserves primary identity and introspects live authority', async () => {
  const f=await fixture();try{
    f.env.ADMIN_USER_IDS='alice';f.env.MCP_OAUTH_PORTALS_JSON=JSON.stringify({[f.resource]:{name:'Portal',loginUrl:'https://portal.example/users/mcp-connect'}});
    const params=new URLSearchParams({...f.params,account:'system_admin'});
    const absent=await f.request('/oauth/mcp/authorize?'+params);assert.equal(absent.status,303);assert.equal(new URL(absent.headers.get('location')).searchParams.get('owner'),'1');
    assert.equal((await f.request('/oauth/mcp/authorize?'+params,{headers:{cookie:f.bobCookie}})).status,403);
    f.sql.exec("INSERT INTO website_users VALUES ('alice','site',1)");
    const member=`pidp_session=${await signJwt(f.env,{sub:'alice',actor_type:'website_user',website_id:'site',is_sysadmin:true})}`;
    assert.equal((await f.request('/oauth/mcp/authorize?'+params,{headers:{cookie:member}})).status,403);
    const consent=await f.request('/oauth/mcp/authorize?'+params,{headers:{cookie:f.cookie}});assert.equal(consent.status,200);const html=await consent.text();assert.match(html,/name="account" value="system_admin"/);
    const nonce=html.match(/name="request" value="([^"]+)"/)[1];
    assert.equal((await f.post('/oauth/mcp/authorize',{request:nonce,decision:'allow',account:'system_admin'},{cookie:member,origin:f.issuer})).status,403);
    const approved=await f.post('/oauth/mcp/authorize',{request:nonce,decision:'allow',account:'system_admin'},{cookie:f.cookie,origin:f.issuer});assert.equal(approved.status,303);
    const code=new URL(approved.headers.get('location')).searchParams.get('code');const tokens=await(await f.exchange(code)).json();
    const status=await(await f.introspect(tokens.access_token)).json();assert.equal(status.active,true);assert.equal(status.sub,'owner:alice');assert.equal(status.is_sysadmin,true);
    f.env.ADMIN_USER_IDS='';assert.equal((await(await f.introspect(tokens.access_token)).json()).is_sysadmin,false);
  }finally{f.sql.close()}
});

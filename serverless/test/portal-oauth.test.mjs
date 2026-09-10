import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { Hono } from 'hono';

const directory = await mkdtemp(`${tmpdir()}/portal-oauth-`);
await build({ entryPoints: [new URL('../src/oauth.ts', import.meta.url).pathname], outfile: `${directory}/oauth.mjs`, bundle: true, platform: 'node', format: 'esm' });
const { oauthLogin, oauthCallback } = await import(pathToFileURL(`${directory}/oauth.mjs`).href);
await rm(directory, { recursive: true });
const portal = 'https://medtech.social';
const forwarded = { 'x-forwarded-host': 'medtech.social', 'x-forwarded-proto': 'https' };

function fixture() {
  let verifier, consumed = false;
  const DB = { prepare(sql) {
    let values;
    return {
      bind(...args) { values = args; return this; },
      async all() { return { results: [] }; },
      async first() {
        if (sql.includes('FROM oauth_states')) return consumed ? null : { code_verifier: verifier };
        return { id: 'fixture-user', identity_data: '{}' };
      },
      async run() {
        if (sql.startsWith('INSERT INTO oauth_states')) verifier = values[4];
        if (sql.startsWith('UPDATE oauth_states')) { const changes = consumed ? 0 : 1; consumed = true; return { meta: { changes } }; }
        return { meta: { changes: 1 } };
      },
    };
  } };
  const env = { DB, SECRET_KEY: 'local-test-key', PORTAL_AUTH_ORIGINS: portal, SESSION_COOKIE_DOMAIN: 'codecollective.us',
    FRONTEND_REDIRECT_URL: 'https://codecollective.us/p/auth/callback',
    GOOGLE_CLIENT_ID: 'test-google', GOOGLE_CLIENT_SECRET: 'test-secret', GOOGLE_REDIRECT_URI: 'https://id.codecollective.us/auth/google/callback',
    GITHUB_CLIENT_ID: 'test-github', GITHUB_CLIENT_SECRET: 'test-secret', GITHUB_REDIRECT_URI: 'https://id.codecollective.us/auth/github/callback' };
  const app = new Hono();
  app.get('/auth/:provider/login', oauthLogin);
  app.get('/auth/:provider/callback', oauthCallback);
  app.onError((error, c) => c.json({ error: error.message }, error.status || 400));
  const request = (url, headers = {}) => app.request(url, { headers }, env);
  async function start(provider = 'google', headers = forwarded) {
    const response = await request(`https://pidp.example/auth/${provider}/login?owner=1&next=${encodeURIComponent(`${portal}/p/auth/callback?next=/community`)}`, headers);
    const authorize = new URL(response.headers.get('location'));
    return { state: authorize.searchParams.get('state'), cookie: response.headers.getSetCookie()[0].split(';')[0], authorize };
  }
  return { request, start };
}

for (const provider of ['google', 'github']) test(`${provider} returns to the initiating portal before issuing a session`, async t => {
  const { request, start } = fixture();
  const { state, cookie, authorize } = await start(provider);
  assert.equal(authorize.searchParams.get('redirect_uri'), `https://id.codecollective.us/auth/${provider}/callback`);
  const callback = `https://id.codecollective.us/auth/${provider}/callback?code=one-use-provider-code&state=${encodeURIComponent(state)}`;
  const relay = await request(callback, { cookie: 'pidp_oauth_state=unrelated-other-tab' });
  assert.equal(relay.status, 303);
  const location = new URL(relay.headers.get('location'));
  assert.equal(location.origin, portal);
  assert.equal(location.pathname, `/pidp/auth/${provider}/callback`);
  assert.equal(location.searchParams.has('token'), false);
  assert.equal(relay.headers.get('referrer-policy'), 'no-referrer');
  const exchanges = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (String(url).includes('/token') || String(url).includes('/access_token')) {
      exchanges.push(options.body);
      return Response.json({ access_token: 'provider-fixture-token' });
    }
    return Response.json({ sub: 'google-user', id: 'github-user', email: 'fixture@example.test', name: 'Fixture User' });
  });
  const upstream = `https://pidp.example/auth/${provider}/callback${location.search}`;
  assert.equal((await request(upstream, forwarded)).status, 400);
  assert.equal((await request(upstream, { ...forwarded, cookie: 'pidp_oauth_state=wrong' })).status, 400);
  const response = await request(upstream, { ...forwarded, cookie });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), `${portal}/p/auth/callback?next=/community`);
  assert.ok(response.headers.getSetCookie().some(value => value.startsWith('pidp_session=') && value.includes('HttpOnly') && value.includes('Secure')));
  assert.equal(exchanges.length, 1);
  assert.equal(exchanges[0].get('redirect_uri'), authorize.searchParams.get('redirect_uri'));
  assert.ok(exchanges[0].get('code_verifier'));
  assert.equal((await request(upstream, { ...forwarded, cookie })).status, 400);
});

test('unknown hosts cannot select a portal and tampered state cannot redirect', async () => {
  const { request, start } = fixture();
  const unknown = await start('google', { ...forwarded, 'x-forwarded-host': 'evil.example' });
  assert.equal(JSON.parse(Buffer.from(unknown.state.split('.')[0], 'base64url').toString()).portal_origin, undefined);
  const { state } = await start();
  const bad = `${state.slice(0, -3)}bad`;
  const response = await request(`https://id.codecollective.us/auth/google/callback?code=test&state=${encodeURIComponent(bad)}`);
  assert.equal(response.status, 400);
  assert.equal(response.headers.has('location'), false);
});

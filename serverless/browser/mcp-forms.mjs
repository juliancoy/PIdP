import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { chromium } from '@playwright/test';
import { generateKeyPair, exportJWK } from 'jose';
import { mcpAuthorization } from '../src/mcpAuthorization.ts';
import { sha256Hex, signJwt } from '../src/crypto.ts';

test('real browser consent and revocation keep same-origin CSRF protection and omit cross-site referrers', async () => {
  const sql = new DatabaseSync(':memory:');
  sql.exec("CREATE TABLE users(id TEXT, is_active INTEGER); INSERT INTO users VALUES ('alice',1)");
  sql.exec(readFileSync(new URL('../migrations/0006_mcp_authorization.sql', import.meta.url), 'utf8'));
  const db = { prepare(query) { const stmt = sql.prepare(query); return { bind(...params) { return {
    async first() { return stmt.get(...params) ?? null; },
    async all() { return { results: stmt.all(...params) }; },
    async run() { return { meta: stmt.run(...params) }; },
  }; } }; } };
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const issuer = 'https://id.example', resource = 'https://medtech.social/api/org/mcp';
  const scopes = ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write'];
  let callbackReferrer;
  const callbackServer = createServer((request, response) => {
    callbackReferrer = request.headers.referer;
    response.end('Connected');
  });
  await new Promise(resolve => callbackServer.listen(0, '127.0.0.1', resolve));
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  const env = { DB: db, SECRET_KEY: 'browser-test-session-key', MCP_OAUTH_ISSUER: issuer,
    MCP_OAUTH_PRIVATE_JWK: JSON.stringify({ ...await exportJWK(privateKey), kid: 'test' }),
    MCP_OAUTH_CLIENTS_JSON: JSON.stringify({ client: { name: 'Codex', dynamic: true, tokenEndpointAuthMethod: 'none',
      redirectUris: [callback], resources: [resource], scopes } }),
    MCP_OAUTH_RESOURCES_JSON: JSON.stringify({ [resource]: { secretHash: await sha256Hex('resource-secret-for-browser-tests-32-chars') } }) };
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    await context.addCookies([{ name: 'pidp_session', value: await signJwt(env, { sub: 'alice', email: 'member@example.com' }), url: issuer, httpOnly: true, secure: true, sameSite: 'Lax' }]);
    const page = await context.newPage();
    const browserErrors = [];
    page.on('requestfailed', request => browserErrors.push(`${request.url()}: ${request.failure()?.errorText}`));
    page.on('console', message => { if (message.type() === 'error') browserErrors.push(message.text()); });
    const postOrigins = [];
    await context.route(issuer + '/**', async route => {
      const request = route.request();
      if (request.method() === 'POST') postOrigins.push(request.headers().origin);
      const response = await mcpAuthorization.request(request.url(), {
        method: request.method(), headers: request.headers(), body: request.postDataBuffer() || undefined,
      }, env);
      await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() });
    });
    const verifier = 'v'.repeat(43);
    const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
    await page.goto(issuer + '/oauth/mcp/authorize?' + new URLSearchParams({ response_type: 'code', client_id: 'client',
      redirect_uri: callback, resource, scope: scopes.join(' '), code_challenge_method: 'S256', code_challenge: challenge, state: 'state' }));
    await page.getByRole('heading', { name: 'Connect Codex to MedTech' }).waitFor();
    await page.waitForFunction(() => document.querySelector('.brand img')?.naturalWidth > 0);
    assert.equal(await page.locator('.allow').evaluate(button => getComputedStyle(button).backgroundColor), 'rgb(8, 124, 137)');
    for (const viewport of [{ width: 1440, height: 1050 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.screenshot({ path: `/tmp/pidp-medtech-consent-${viewport.width}.png`, fullPage: true });
    }
    await page.getByText('Connection details', { exact: true }).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.getByRole('button', { name: 'Allow access' }).click();
    await page.waitForURL(callback + '**', { timeout: 5000 }).catch(() => {
      assert.fail(JSON.stringify({ url: page.url(), postOrigins, browserErrors }));
    });
    assert.equal(callbackReferrer, undefined);
    const code = new URL(page.url()).searchParams.get('code');
    assert.ok(code);
    const exchange = await mcpAuthorization.request(issuer + '/oauth/mcp/token', { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'client',
        code, redirect_uri: callback, resource, code_verifier: verifier }) }, env);
    assert.equal(exchange.status, 200);
    await page.goto(issuer + '/oauth/mcp/connections');
    const revoked = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/oauth/mcp/connections'));
    await page.getByRole('button', { name: 'Revoke access' }).click();
    assert.equal((await revoked).status(), 303);
    // Playwright routes intercept the initial request, not every redirect in its chain.
    const connections = await context.newPage();
    await connections.goto(issuer + '/oauth/mcp/connections');
    await connections.getByText('No active connections.').waitFor();
    assert.deepEqual(postOrigins, [issuer, issuer]);
    assert.equal(sql.prepare('SELECT revoked FROM mcp_oauth_grants').get().revoked, 1);
  } finally { await browser.close(); callbackServer.closeAllConnections(); await new Promise(resolve => callbackServer.close(resolve)); sql.close(); }
});

import { Hono, type Context } from 'hono';
import { getCookie } from 'hono/cookie';
import { importJWK, SignJWT, jwtVerify, type JWK } from 'jose';
import { randomToken, sha256Hex, verifyJwt } from './crypto';
import type { Env } from './types';

const scopes = ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write'];
const now = () => Math.floor(Date.now() / 1000);
type Client = { name: string; redirectUris: string[]; resources: string[]; scopes: string[]; secretHash: string };
type Config = { issuer: string; key: JWK; keys: JWK[]; clients: Record<string, Client>; resources: Record<string, { secretHash: string }> };
type Grant = { id: string; subject: string; client_id: string; resource: string; scope: string; expires_at: number; revoked: number };
type Pending = { id: string; session_hash: string; subject: string; client_id: string; redirect_uri: string; resource: string; scope: string; challenge: string; state: string; expires_at: number };
class OAuthError extends Error {
  constructor(public code: string, public status: 400 | 401 | 403 | 429 | 503 = 400) { super(code); }
}
function https(value: string) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash) throw new Error();
  return value;
}
export function authorizationConfig(env: Env): Config {
  try {
    const issuer = https(env.MCP_OAUTH_ISSUER!);
    if (new URL(issuer).origin !== issuer) throw new Error();
    const key = JSON.parse(env.MCP_OAUTH_PRIVATE_JWK!);
    if (key.kty !== 'EC' || key.crv !== 'P-256' || !key.d || !key.x || !key.y || !key.kid) throw new Error();
    const publicKey = { kty: key.kty, crv: key.crv, x: key.x, y: key.y, kid: key.kid, alg: 'ES256', use: 'sig' };
    const old = JSON.parse(env.MCP_OAUTH_PUBLIC_JWKS || '{"keys":[]}').keys;
    if (!Array.isArray(old) || old.some((k: JWK) => k.d || k.kty !== 'EC' || k.crv !== 'P-256' || !k.x || !k.y || !k.kid)) throw new Error();
    const clients = JSON.parse(env.MCP_OAUTH_CLIENTS_JSON!);
    const resources = JSON.parse(env.MCP_OAUTH_RESOURCES_JSON!);
    if (!Object.keys(clients).length || !Object.keys(resources).length) throw new Error();
    for (const [url, resource] of Object.entries(resources) as [string, { secretHash: string }][]) {
      https(url); if (!/^[a-f0-9]{64}$/.test(resource.secretHash)) throw new Error();
    }
    for (const client of Object.values(clients) as Client[]) {
      if (!client.name || !/^[a-f0-9]{64}$/.test(client.secretHash) || !client.redirectUris?.length || !client.resources?.length || !client.scopes?.length) throw new Error();
      client.redirectUris.forEach(https);
      if (client.resources.some(r => !Object.hasOwn(resources, r)) || client.scopes.some(s => !scopes.includes(s))) throw new Error();
    }
    return { issuer, key, keys: [publicKey, ...old.filter((k: JWK) => k.kid !== key.kid).map((k: JWK) =>
      ({ kty: k.kty, crv: k.crv, x: k.x, y: k.y, kid: k.kid, alg: 'ES256', use: 'sig' }))], clients, resources };
  } catch { throw new OAuthError('authorization_server_not_configured', 503); }
}
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
async function form(c: Context<{ Bindings: Env }>) {
  if (!c.req.header('content-type')?.startsWith('application/x-www-form-urlencoded')) throw new OAuthError('invalid_request');
  // Read incrementally rather than trusting Content-Length.
  const reader = c.req.raw.body?.getReader(); let size = 0; const chunks: Uint8Array[] = [];
  if (reader) while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length;
    if (size > 16384) { await reader.cancel(); throw new OAuthError('invalid_request'); } chunks.push(value); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const params = new URLSearchParams(new TextDecoder().decode(bytes));
  for (const k of params.keys()) if (params.getAll(k).length > 1) throw new OAuthError('invalid_request');
  return params;
}
async function activeSubject(env: Env, subject: string) {
  const [actor, site, id] = subject.split(':');
  if (actor === 'owner' && site && !id) return Boolean(await env.DB.prepare('SELECT id FROM users WHERE id = ? AND is_active = 1').bind(site).first());
  if (actor === 'website' && site && id) return Boolean(await env.DB.prepare('SELECT id FROM website_users WHERE website_id = ? AND id = ? AND is_active = 1').bind(site, id).first());
  return false;
}
async function session(c: Context<{ Bindings: Env }>) {
  const token = getCookie(c, 'pidp_session');
  if (!token) return null;
  try {
    const payload = await verifyJwt(c.env, token);
    const subject = payload.actor_type === 'website_user' ? `website:${payload.website_id}:${payload.sub}` : `owner:${payload.sub}`;
    if (!await activeSubject(c.env, subject)) return null;
    return { subject, display: String(payload.email || payload.sub), hash: await sha256Hex(token) };
  } catch { return null; }
}
async function authenticateClient(c: Context<{ Bindings: Env }>, p: URLSearchParams, config: Config) {
  let id = p.get('client_id') || '', secret = p.get('client_secret') || '';
  const auth = c.req.header('authorization');
  if (auth) {
    if (!auth.startsWith('Basic ') || secret) throw new OAuthError('invalid_client', 401);
    try { const value = atob(auth.slice(6)); const split = value.indexOf(':');
      const basicId = decodeURIComponent(value.slice(0, split));
      if (split < 0 || (id && id !== basicId)) throw new Error();
      id = basicId; secret = decodeURIComponent(value.slice(split + 1));
    } catch { throw new OAuthError('invalid_client', 401); }
  }
  const client = Object.hasOwn(config.clients, id) && config.clients[id];
  if (!client || secret.length < 32 || await sha256Hex(secret) !== client.secretHash) throw new OAuthError('invalid_client', 401);
  return { id, client };
}
function validateGrant(config: Config, grant: Grant) {
  const client = Object.hasOwn(config.clients, grant.client_id) && config.clients[grant.client_id];
  return !grant.revoked && grant.expires_at > now() && client && client.resources.includes(grant.resource)
    && grant.scope.split(' ').every(s => client.scopes.includes(s));
}
async function tokens(env: Env, config: Config, grant: Grant) {
  const issued = now();
  const access = await new SignJWT({ scope: grant.scope, client_id: grant.client_id, grant_id: grant.id })
    .setProtectedHeader({ alg: 'ES256', kid: config.key.kid, typ: 'at+jwt' })
    .setIssuer(config.issuer).setAudience(grant.resource).setSubject(grant.subject)
    .setIssuedAt(issued).setExpirationTime(issued + 300).setJti(crypto.randomUUID())
    .sign(await importJWK(config.key, 'ES256'));
  const refresh = randomToken('mcp_refresh_');
  await env.DB.prepare('INSERT INTO mcp_oauth_refresh (hash, grant_id) VALUES (?, ?)').bind(await sha256Hex(refresh), grant.id).run();
  return { access_token: access, token_type: 'Bearer', expires_in: 300, refresh_token: refresh, scope: grant.scope };
}
export const mcpAuthorization = new Hono<{ Bindings: Env }>();
mcpAuthorization.use('*', async (c, next) => {
  if (!c.req.path.startsWith('/oauth/mcp/') && !['/.well-known/oauth-authorization-server', '/.well-known/jwks.json'].includes(c.req.path)) return next();
  c.header('Cache-Control', 'no-store'); c.header('Pragma', 'no-cache');
  c.header('Referrer-Policy', 'no-referrer'); c.header('X-Content-Type-Options', 'nosniff');
  c.header('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  await next();
});
mcpAuthorization.onError((err, c) => c.json({ error: err instanceof OAuthError ? err.code : 'server_error' }, err instanceof OAuthError ? err.status : 503));
mcpAuthorization.get('/.well-known/oauth-authorization-server', c => {
  const cfg = authorizationConfig(c.env); const base = `${cfg.issuer}/oauth/mcp`;
  return c.json({ issuer: cfg.issuer, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`,
    revocation_endpoint: `${base}/revoke`, introspection_endpoint: `${base}/introspect`, jwks_uri: `${cfg.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'], scopes_supported: scopes,
    authorization_response_iss_parameter_supported: true,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'] });
});
mcpAuthorization.get('/.well-known/jwks.json', c => c.json({ keys: authorizationConfig(c.env).keys }));
mcpAuthorization.get('/oauth/mcp/authorize', async c => {
  const cfg = authorizationConfig(c.env); const u = new URL(c.req.url); const p = u.searchParams;
  if (u.origin !== cfg.issuer || u.search.length > 8192) throw new OAuthError('invalid_request');
  for (const k of p.keys()) if (p.getAll(k).length > 1) throw new OAuthError('invalid_request');
  const id = p.get('client_id') || ''; const client = Object.hasOwn(cfg.clients, id) && cfg.clients[id];
  const redirect = p.get('redirect_uri') || ''; const resource = p.get('resource') || '';
  if (!client || !client.redirectUris.includes(redirect) || !client.resources.includes(resource)) throw new OAuthError('invalid_request');
  const requested = [...new Set((p.get('scope') || '').split(' ').filter(Boolean))];
  if (!requested.includes(scopes[0]) || requested.some(s => !client.scopes.includes(s))) throw new OAuthError('invalid_scope');
  const challenge = p.get('code_challenge') || '';
  if (p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new OAuthError('invalid_request');
  const actor = await session(c);
  if (!actor) return c.redirect(`${cfg.issuer}/app/login?owner=1&next=${encodeURIComponent(u.pathname + u.search)}`, 303);
  // Bound persisted pending requests per session; expired records are cheap to remove.
  await c.env.DB.prepare('DELETE FROM mcp_oauth_requests WHERE expires_at < ?').bind(now()).run();
  const count = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM mcp_oauth_requests WHERE session_hash = ?').bind(actor.hash).first<{ n: number }>();
  if ((count?.n || 0) >= 20) throw new OAuthError('too_many_requests', 429);
  const nonce = randomToken('consent_');
  await c.env.DB.prepare('INSERT INTO mcp_oauth_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256Hex(nonce), actor.hash, actor.subject, id, redirect, resource, requested.join(' '), challenge, p.get('state') || '', now() + 600).run();
  const permissionItems = [
    requested.includes('org:events.read') ? '<li>Read events in organizations you manage.</li>' : '',
    requested.includes('org:events.write') ? '<li>Change events and invite collaborators in organizations you manage.</li>' : '',
    requested.includes('org:portal.read') ? '<li>Read portal setup and homepage settings for organizations you manage.</li>' : '',
    requested.includes('org:portal.write') ? '<li>Change portal setup, homepage settings, and custom-domain requests for organizations you manage.</li>' : '',
  ].join('');
  return c.html(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize OrgPortal access · PIdP</title><main><h1>Allow ${escape(client.name)} to access OrgPortal?</h1><p>Account: ${escape(actor.display)}</p><p>Service: ${escape(resource)}</p><ul>${permissionItems}</ul><p>Your organization permissions still apply. You can revoke this connection in PIdP.</p><form method="post" action="/oauth/mcp/authorize"><input type="hidden" name="request" value="${nonce}"><button name="decision" value="allow">Allow access</button> <button name="decision" value="deny">Deny</button></form></main></html>`);
});
mcpAuthorization.post('/oauth/mcp/authorize', async c => {
  const cfg = authorizationConfig(c.env);
  if (c.req.header('origin') !== cfg.issuer) throw new OAuthError('invalid_request', 403);
  const actor = await session(c); if (!actor) throw new OAuthError('login_required', 401);
  const p = await form(c); if (!['allow', 'deny'].includes(p.get('decision') || '')) throw new OAuthError('invalid_request');
  const row = await c.env.DB.prepare('DELETE FROM mcp_oauth_requests WHERE id = ? AND session_hash = ? AND subject = ? AND expires_at >= ? RETURNING *')
    .bind(await sha256Hex(p.get('request') || ''), actor.hash, actor.subject, now()).first<Pending>();
  if (!row) throw new OAuthError('invalid_request');
  const client = Object.hasOwn(cfg.clients, row.client_id) && cfg.clients[row.client_id];
  if (!client || !client.redirectUris.includes(row.redirect_uri) || !client.resources.includes(row.resource) || row.scope.split(' ').some(s => !client.scopes.includes(s))) throw new OAuthError('invalid_request');
  const redirect = new URL(row.redirect_uri); redirect.searchParams.set('state', row.state);
  if (p.get('decision') === 'deny') redirect.searchParams.set('error', 'access_denied');
  redirect.searchParams.set('iss', cfg.issuer);
  if (p.get('decision') !== 'deny') {
    const code = randomToken('mcp_code_');
    await c.env.DB.prepare('INSERT INTO mcp_oauth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(await sha256Hex(code), row.subject, row.client_id, row.redirect_uri, row.resource, row.scope, row.challenge, now() + 120).run();
    redirect.searchParams.set('code', code);
  }
  return c.redirect(redirect.toString(), 303);
});
mcpAuthorization.post('/oauth/mcp/token', async c => {
  const cfg = authorizationConfig(c.env); const p = await form(c); const { id, client } = await authenticateClient(c, p, cfg);
  if (p.get('grant_type') === 'authorization_code') {
    const verifier = p.get('code_verifier') || '';
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new OAuthError('invalid_grant');
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const challenge = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const row = await c.env.DB.prepare('DELETE FROM mcp_oauth_codes WHERE hash = ? AND client_id = ? AND redirect_uri = ? AND resource = ? AND challenge = ? AND expires_at >= ? RETURNING *')
      .bind(await sha256Hex(p.get('code') || ''), id, p.get('redirect_uri') || '', p.get('resource') || '', challenge, now()).first<Pending>();
    if (!row || !client.resources.includes(row.resource) || row.scope.split(' ').some(s => !client.scopes.includes(s)) || !await activeSubject(c.env, row.subject)) throw new OAuthError('invalid_grant');
    const grant: Grant = { id: crypto.randomUUID(), subject: row.subject, client_id: id, resource: row.resource, scope: row.scope, expires_at: now() + 2592000, revoked: 0 };
    await c.env.DB.prepare('INSERT INTO mcp_oauth_grants VALUES (?, ?, ?, ?, ?, ?, 0)').bind(grant.id, grant.subject, id, grant.resource, grant.scope, grant.expires_at).run();
    return c.json(await tokens(c.env, cfg, grant));
  }
  if (p.get('grant_type') !== 'refresh_token') throw new OAuthError('unsupported_grant_type');
  const hash = await sha256Hex(p.get('refresh_token') || '');
  const grant = await c.env.DB.prepare('SELECT g.*, r.used FROM mcp_oauth_refresh r JOIN mcp_oauth_grants g ON g.id = r.grant_id WHERE r.hash = ? AND g.client_id = ?').bind(hash, id).first<Grant & { used: number }>();
  if (!grant || !validateGrant(cfg, grant) || !await activeSubject(c.env, grant.subject)) throw new OAuthError('invalid_grant');
  if ((p.has('resource') && p.get('resource') !== grant.resource) || (p.has('scope') && p.get('scope') !== grant.scope)) throw new OAuthError('invalid_scope');
  const claimed = await c.env.DB.prepare('UPDATE mcp_oauth_refresh SET used = 1 WHERE hash = ? AND used = 0 RETURNING hash').bind(hash).first();
  if (!claimed) { await c.env.DB.prepare('UPDATE mcp_oauth_grants SET revoked = 1 WHERE id = ?').bind(grant.id).run(); throw new OAuthError('invalid_grant'); }
  return c.json(await tokens(c.env, cfg, grant));
});
mcpAuthorization.post('/oauth/mcp/introspect', async c => {
  const cfg = authorizationConfig(c.env); const p = await form(c); const resource = p.get('resource') || '';
  const binding = Object.hasOwn(cfg.resources, resource) && cfg.resources[resource];
  const secret = /^Bearer (\S+)$/.exec(c.req.header('authorization') || '')?.[1];
  if (!binding || !secret || secret.length < 32 || await sha256Hex(secret) !== binding.secretHash) throw new OAuthError('invalid_client', 401);
  let payload;
  try { const verified = await jwtVerify(p.get('token') || '', async header => {
    const key = cfg.keys.find(k => k.kid === header.kid); if (!key) throw new Error(); return await importJWK(key, 'ES256');
  }, { issuer: cfg.issuer, audience: resource, algorithms: ['ES256'], typ: 'at+jwt', requiredClaims: ['sub', 'exp', 'iat', 'jti'] }); payload = verified.payload;
  } catch { return c.json({ active: false }); }
  const grant = await c.env.DB.prepare('SELECT * FROM mcp_oauth_grants WHERE id = ?').bind(payload.grant_id).first<Grant>();
  if (!grant || !validateGrant(cfg, grant) || grant.resource !== resource || grant.subject !== payload.sub || grant.scope !== payload.scope || !await activeSubject(c.env, grant.subject)) return c.json({ active: false });
  return c.json({ active: true, sub: payload.sub, iss: cfg.issuer, aud: resource, scope: payload.scope, exp: payload.exp });
});
mcpAuthorization.post('/oauth/mcp/revoke', async c => {
  const cfg = authorizationConfig(c.env); const p = await form(c); const { id } = await authenticateClient(c, p, cfg);
  await c.env.DB.prepare('UPDATE mcp_oauth_grants SET revoked = 1 WHERE client_id = ? AND id IN (SELECT grant_id FROM mcp_oauth_refresh WHERE hash = ?)').bind(id, await sha256Hex(p.get('token') || '')).run();
  return c.body(null, 200);
});
// Account-controlled revocation uses the existing session and same-origin POST.
mcpAuthorization.get('/oauth/mcp/connections', async c => {
  const cfg = authorizationConfig(c.env); const actor = await session(c); if (!actor) return c.redirect(`${cfg.issuer}/app/login?owner=1&next=/oauth/mcp/connections`, 303);
  const rows = await c.env.DB.prepare('SELECT * FROM mcp_oauth_grants WHERE subject = ? AND revoked = 0 AND expires_at > ? ORDER BY expires_at DESC LIMIT 100').bind(actor.subject, now()).all<Grant>();
  const csrf = await sha256Hex(`${actor.hash}:mcp-revoke`);
  return c.html(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Connected apps · PIdP</title><main><h1>Connected event apps</h1>${rows.results.map(g => `<form method="post"><p>${escape(g.client_id)} — ${escape(g.resource)} (${escape(g.scope)})</p><input type="hidden" name="grant" value="${escape(g.id)}"><input type="hidden" name="csrf" value="${csrf}"><button>Revoke access</button></form>`).join('') || '<p>No active connections.</p>'}</main></html>`);
});
mcpAuthorization.post('/oauth/mcp/connections', async c => {
  const cfg = authorizationConfig(c.env); const actor = await session(c);
  if (!actor || c.req.header('origin') !== cfg.issuer) throw new OAuthError('invalid_request', 403);
  const p = await form(c); if (p.get('csrf') !== await sha256Hex(`${actor.hash}:mcp-revoke`)) throw new OAuthError('invalid_request', 403);
  await c.env.DB.prepare('UPDATE mcp_oauth_grants SET revoked = 1 WHERE id = ? AND subject = ?').bind(p.get('grant'), actor.subject).run();
  return c.redirect('/oauth/mcp/connections', 303);
});

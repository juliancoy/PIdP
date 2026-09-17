import { Hono, type Context } from 'hono';
import { getCookie } from 'hono/cookie';
import { importJWK, SignJWT, jwtVerify, type JWK } from 'jose';
import { randomToken, sha256Hex, verifyJwt } from './crypto';
import type { Env } from './types';

const scopes = ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write'];
const now = () => Math.floor(Date.now() / 1000);
type Client = { name: string; redirectUris: string[]; resources: string[]; scopes: string[]; secretHash?: string; tokenEndpointAuthMethod?: 'none' | 'client_secret_basic' | 'client_secret_post'; dynamic?: boolean };
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
function loopback(value: string) {
  const u = new URL(value);
  return u.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(u.hostname)
    && !u.username && !u.password && !u.hash && !u.search;
}
function redirectAllowed(client: Client, value: string) {
  try {
    const actual = new URL(value);
    return client.redirectUris.some(registered => {
      if (registered === value) return true;
      if (client.tokenEndpointAuthMethod !== 'none' || !loopback(registered) || !loopback(value)) return false;
      const expected = new URL(registered);
      return actual.hostname === expected.hostname && actual.pathname === expected.pathname;
    });
  } catch { return false; }
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
      if (!client.name || !client.redirectUris?.length || !client.resources?.length || !client.scopes?.length) throw new Error();
      if (client.tokenEndpointAuthMethod === 'none') {
        if (client.secretHash !== undefined || !client.redirectUris.every(loopback)) throw new Error();
      } else {
        if (client.tokenEndpointAuthMethod !== undefined || !/^[a-f0-9]{64}$/.test(client.secretHash || '')) throw new Error();
        client.redirectUris.forEach(https);
      }
      if (client.resources.some(r => !Object.hasOwn(resources, r)) || client.scopes.some(s => !scopes.includes(s))) throw new Error();
    }
    return { issuer, key, keys: [publicKey, ...old.filter((k: JWK) => k.kid !== key.kid).map((k: JWK) =>
      ({ kty: k.kty, crv: k.crv, x: k.x, y: k.y, kid: k.kid, alg: 'ES256', use: 'sig' }))], clients, resources };
  } catch { throw new OAuthError('authorization_server_not_configured', 503); }
}
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
async function form(c: Context<{ Bindings: Env }>) {
  if (!c.req.header('content-type')?.startsWith('application/x-www-form-urlencoded')) throw new OAuthError('invalid_request');
  const params = new URLSearchParams(await boundedBody(c.req.raw));
  for (const k of params.keys()) if (params.getAll(k).length > 1) throw new OAuthError('invalid_request');
  return params;
}
async function boundedBody(request: Request) {
  // Read incrementally rather than trusting Content-Length.
  const reader = request.body?.getReader(); let size = 0; const chunks: Uint8Array[] = [];
  if (reader) while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length;
    if (size > 16384) { await reader.cancel(); throw new OAuthError('invalid_request'); } chunks.push(value); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder().decode(bytes);
}
async function getClient(env: Env, cfg: Config, id: string): Promise<Client | undefined> {
  if (Object.hasOwn(cfg.clients, id)) return cfg.clients[id];
  if (env.MCP_OAUTH_DYNAMIC_REGISTRATION !== 'true' || !/^mcp_dynamic_[A-Za-z0-9_-]{20,100}$/.test(id)) return undefined;
  const row = await env.DB.prepare('SELECT client_json FROM mcp_oauth_clients WHERE id = ? AND revoked = 0').bind(id).first<{ client_json: string }>();
  if (!row) return undefined;
  const client: Client = JSON.parse(row.client_json);
  return { ...client, dynamic: true, resources: client.resources.filter(r => Object.hasOwn(cfg.resources, r)) };
}
async function registrationLimit(env: Env, ip: string) {
  const window = Math.floor(now() / 3600);
  await env.DB.prepare('DELETE FROM mcp_oauth_registration_limits WHERE window_start < ?').bind(window - 1).run();
  for (const [id, limit] of [[await sha256Hex(ip), 10], ['global', 100]] as const) {
    const row = await env.DB.prepare(`INSERT INTO mcp_oauth_registration_limits (id, window_start, requests)
      VALUES (?, ?, 1) ON CONFLICT(id) DO UPDATE SET window_start = excluded.window_start,
      requests = CASE WHEN mcp_oauth_registration_limits.window_start = excluded.window_start THEN mcp_oauth_registration_limits.requests + 1 ELSE 1 END
      WHERE mcp_oauth_registration_limits.window_start != excluded.window_start OR mcp_oauth_registration_limits.requests < ? RETURNING id`)
      .bind(id, window, limit).first();
    if (!row) throw new OAuthError('too_many_requests', 429);
  }
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
  const client = await getClient(c.env, config, id);
  if (!client) throw new OAuthError('invalid_client', 401);
  if (client.tokenEndpointAuthMethod === 'none') {
    if (auth || p.has('client_secret')) throw new OAuthError('invalid_client', 401);
  } else if ((client.tokenEndpointAuthMethod === 'client_secret_basic' && !auth)
      || (client.tokenEndpointAuthMethod === 'client_secret_post' && auth)
      || secret.length < 32 || await sha256Hex(secret) !== client.secretHash) throw new OAuthError('invalid_client', 401);
  return { id, client };
}
async function validateGrant(env: Env, config: Config, grant: Grant) {
  const client = await getClient(env, config, grant.client_id);
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
    ...(c.env.MCP_OAUTH_DYNAMIC_REGISTRATION === 'true' ? { registration_endpoint: `${base}/register` } : {}),
    revocation_endpoint: `${base}/revoke`, introspection_endpoint: `${base}/introspect`, jwks_uri: `${cfg.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'], scopes_supported: scopes,
    authorization_response_iss_parameter_supported: true,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'] });
});
mcpAuthorization.post('/oauth/mcp/register', async c => {
  const cfg = authorizationConfig(c.env);
  if (c.env.MCP_OAUTH_DYNAMIC_REGISTRATION !== 'true') throw new OAuthError('registration_not_supported', 403);
  await registrationLimit(c.env, c.req.header('cf-connecting-ip') || 'unknown');
  if (!c.req.header('content-type')?.startsWith('application/json')) throw new OAuthError('invalid_client_metadata');
  let p: Record<string, unknown>;
  try { p = JSON.parse(await boundedBody(c.req.raw)); }
  catch { throw new OAuthError('invalid_client_metadata'); }
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new OAuthError('invalid_client_metadata');
  const method = p.token_endpoint_auth_method ?? 'client_secret_basic';
  if (typeof method !== 'string' || !['none', 'client_secret_basic', 'client_secret_post'].includes(method)) throw new OAuthError('invalid_client_metadata');
  const redirects = p.redirect_uris;
  if (!Array.isArray(redirects) || !redirects.length || redirects.length > 5 || redirects.some(uri => {
    if (typeof uri !== 'string' || uri.length > 2000 || uri.includes('*')) return true;
    try { if (method === 'none' && loopback(uri)) return false; https(uri); return false; } catch { return true; }
  })) throw new OAuthError('invalid_redirect_uri');
  for (const [field, allowed] of [['grant_types', ['authorization_code', 'refresh_token']], ['response_types', ['code']]] as const) {
    const value = p[field];
    if (value !== undefined && (!Array.isArray(value) || !value.length || value.some(v => !(allowed as readonly unknown[]).includes(v)))) throw new OAuthError('invalid_client_metadata');
  }
  if (Array.isArray(p.grant_types) && !p.grant_types.includes('authorization_code')) throw new OAuthError('invalid_client_metadata');
  const name = p.client_name ?? 'MCP client';
  if (typeof name !== 'string' || !name.trim() || name.length > 120 || /[\x00-\x1f\x7f]/.test(name)) throw new OAuthError('invalid_client_metadata');
  if (p.scope !== undefined && (typeof p.scope !== 'string' || p.scope.length > 1000)) throw new OAuthError('invalid_client_metadata');
  const requested = p.scope === undefined ? scopes : [...new Set((p.scope as string).split(' ').filter(Boolean))];
  if (!requested.includes(scopes[0]) || requested.some(s => !scopes.includes(s))) throw new OAuthError('invalid_client_metadata');
  const id = randomToken('mcp_dynamic_');
  const secret = method === 'none' ? undefined : randomToken('mcp_client_');
  const client: Client = { name: name.trim(), redirectUris: [...new Set(redirects)], resources: Object.keys(cfg.resources), scopes: requested,
    tokenEndpointAuthMethod: method as Client['tokenEndpointAuthMethod'], ...(secret ? { secretHash: await sha256Hex(secret) } : {}), dynamic: true };
  const inserted = await c.env.DB.prepare(`INSERT INTO mcp_oauth_clients (id, client_json, created_at)
    SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM mcp_oauth_clients) < 10000 RETURNING id`).bind(id, JSON.stringify(client), now()).first();
  if (!inserted) throw new OAuthError('too_many_requests', 429);
  return c.json({ client_id: id, client_id_issued_at: now(), client_name: client.name, redirect_uris: client.redirectUris,
    token_endpoint_auth_method: method, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope: requested.join(' '),
    ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}) }, 201);
});
mcpAuthorization.get('/.well-known/jwks.json', c => c.json({ keys: authorizationConfig(c.env).keys }));
mcpAuthorization.get('/oauth/mcp/authorize', async c => {
  const cfg = authorizationConfig(c.env); const u = new URL(c.req.url); const p = u.searchParams;
  if (u.origin !== cfg.issuer || u.search.length > 8192) throw new OAuthError('invalid_request');
  for (const k of p.keys()) if (p.getAll(k).length > 1) throw new OAuthError('invalid_request');
  const id = p.get('client_id') || ''; const client = await getClient(c.env, cfg, id);
  const redirect = p.get('redirect_uri') || '';
  const resource = p.get('resource') ?? (client?.resources.length === 1 ? client.resources[0] : '');
  if (!client || !redirectAllowed(client, redirect) || !client.resources.includes(resource)) throw new OAuthError('invalid_request');
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
    requested.includes('org:events.write') ? '<li>Change events, upload event photos, and invite collaborators in organizations you manage.</li>' : '',
    requested.includes('org:portal.read') ? '<li>Read portal setup and homepage settings for organizations you manage.</li>' : '',
    requested.includes('org:portal.write') ? '<li>Change portal setup, homepage settings, and custom-domain requests for organizations you manage.</li>' : '',
  ].join('');
  return c.html(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize OrgPortal access · PIdP</title><main><h1>Allow ${escape(client.name)} to access OrgPortal?</h1>${client.dynamic ? `<p>This client name is self-reported, not verified by PIdP.</p><p>Callback: ${escape(redirect)}</p>` : ''}<p>Account: ${escape(actor.display)}</p><p>Service: ${escape(resource)}</p><ul>${permissionItems}</ul><p>Your organization permissions still apply. You can revoke this connection in PIdP.</p><form method="post" action="/oauth/mcp/authorize"><input type="hidden" name="request" value="${nonce}"><button name="decision" value="allow">Allow access</button> <button name="decision" value="deny">Deny</button></form></main></html>`);
});
mcpAuthorization.post('/oauth/mcp/authorize', async c => {
  const cfg = authorizationConfig(c.env);
  if (c.req.header('origin') !== cfg.issuer) throw new OAuthError('invalid_request', 403);
  const actor = await session(c); if (!actor) throw new OAuthError('login_required', 401);
  const p = await form(c); if (!['allow', 'deny'].includes(p.get('decision') || '')) throw new OAuthError('invalid_request');
  const row = await c.env.DB.prepare('DELETE FROM mcp_oauth_requests WHERE id = ? AND session_hash = ? AND subject = ? AND expires_at >= ? RETURNING *')
    .bind(await sha256Hex(p.get('request') || ''), actor.hash, actor.subject, now()).first<Pending>();
  if (!row) throw new OAuthError('invalid_request');
  const client = await getClient(c.env, cfg, row.client_id);
  if (!client || !redirectAllowed(client, row.redirect_uri) || !client.resources.includes(row.resource) || row.scope.split(' ').some(s => !client.scopes.includes(s))) throw new OAuthError('invalid_request');
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
      .bind(await sha256Hex(p.get('code') || ''), id, p.get('redirect_uri') || '', p.get('resource') ?? (client.resources.length === 1 ? client.resources[0] : ''), challenge, now()).first<Pending>();
    if (!row || !client.resources.includes(row.resource) || row.scope.split(' ').some(s => !client.scopes.includes(s)) || !await activeSubject(c.env, row.subject)) throw new OAuthError('invalid_grant');
    const grant: Grant = { id: crypto.randomUUID(), subject: row.subject, client_id: id, resource: row.resource, scope: row.scope, expires_at: now() + 2592000, revoked: 0 };
    await c.env.DB.prepare('INSERT INTO mcp_oauth_grants VALUES (?, ?, ?, ?, ?, ?, 0)').bind(grant.id, grant.subject, id, grant.resource, grant.scope, grant.expires_at).run();
    return c.json(await tokens(c.env, cfg, grant));
  }
  if (p.get('grant_type') !== 'refresh_token') throw new OAuthError('unsupported_grant_type');
  const hash = await sha256Hex(p.get('refresh_token') || '');
  const grant = await c.env.DB.prepare('SELECT g.*, r.used FROM mcp_oauth_refresh r JOIN mcp_oauth_grants g ON g.id = r.grant_id WHERE r.hash = ? AND g.client_id = ?').bind(hash, id).first<Grant & { used: number }>();
  if (!grant || !await validateGrant(c.env, cfg, grant) || !await activeSubject(c.env, grant.subject)) throw new OAuthError('invalid_grant');
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
  if (!grant || !await validateGrant(c.env, cfg, grant) || grant.resource !== resource || grant.subject !== payload.sub || grant.scope !== payload.scope || !await activeSubject(c.env, grant.subject)) return c.json({ active: false });
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

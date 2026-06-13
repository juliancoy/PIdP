import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { Env, SocialProfile, WebsiteRow, WebsiteSchemaField } from "./types";
import { first, nowIso, parseJson, websiteBySlug } from "./db";
import { fail } from "./http";
import { sha256Hex, signJwt } from "./crypto";
import { SYSTEM_SCHEMA_FIELDS, normalizeHost, normalizeSlug, schemaWithSystemFields, validateIdentityData } from "./normalize";

type Provider = "google" | "github";

interface OAuthState {
  provider: Provider;
  nonce: string;
  app_slug?: string;
  force_owner?: boolean;
  next?: string;
  exp: number;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const COOKIE_NAME = "pidp_oauth_state";
const SESSION_COOKIE = "pidp_session";

function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function hmac(env: Env, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

async function encodeState(env: Env, state: OAuthState): Promise<string> {
  const body = base64Url(enc.encode(JSON.stringify(state)));
  return `${body}.${await hmac(env, body)}`;
}

async function decodeState(env: Env, value: string | undefined): Promise<OAuthState> {
  if (!value) fail(400, "OAuth sign-in session expired. Please try again.");
  const [body, sig] = value.split(".");
  if (!body || !sig || (await hmac(env, body)) !== sig) fail(400, "OAuth sign-in session expired. Please try again.");
  const state = JSON.parse(dec.decode(fromBase64Url(body))) as OAuthState;
  if (!state.exp || state.exp < Math.floor(Date.now() / 1000)) fail(400, "OAuth sign-in session expired. Please try again.");
  return state;
}

async function storeOAuthState(env: Env, state: OAuthState, stateValue: string): Promise<{ codeChallenge: string }> {
  const codeVerifier = generatePkceVerifier();
  const codeChallenge = await pkceChallenge(codeVerifier);
  await env.DB.prepare("DELETE FROM oauth_states WHERE expires_at < ? OR consumed_at IS NOT NULL").bind(Math.floor(Date.now() / 1000)).run();
  await env.DB.prepare(
    "INSERT INTO oauth_states (id, provider, nonce_hash, state_hash, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), state.provider, await sha256Hex(state.nonce), await sha256Hex(stateValue), codeVerifier, state.exp).run();
  return { codeChallenge };
}

async function consumeOAuthState(env: Env, state: OAuthState, stateValue: string): Promise<string> {
  const row = await env.DB.prepare(
    "SELECT code_verifier FROM oauth_states WHERE provider = ? AND nonce_hash = ? AND state_hash = ? AND consumed_at IS NULL AND expires_at >= ?",
  ).bind(state.provider, await sha256Hex(state.nonce), await sha256Hex(stateValue), Math.floor(Date.now() / 1000)).first<{ code_verifier: string | null }>();
  const result = await env.DB.prepare(
    "UPDATE oauth_states SET consumed_at = ? WHERE provider = ? AND nonce_hash = ? AND state_hash = ? AND consumed_at IS NULL AND expires_at >= ?",
  ).bind(nowIso(), state.provider, await sha256Hex(state.nonce), await sha256Hex(stateValue), Math.floor(Date.now() / 1000)).run();
  if (!result.meta?.changes) fail(400, `${state.provider} sign-in session expired. Please try again.`);
  if (!row?.code_verifier) fail(400, `${state.provider} sign-in session expired. Please try again.`);
  return row.code_verifier;
}

function truthy(value: string | undefined): boolean {
  return ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function providerConfig(env: Env, provider: string) {
  if (provider === "google") {
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) fail(400, "Provider not enabled");
    return {
      provider: "google" as const,
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      redirectUri: env.GOOGLE_REDIRECT_URI,
      authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      scope: "openid email profile",
    };
  }
  if (provider === "github") {
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) fail(400, "Provider not enabled");
    return {
      provider: "github" as const,
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      redirectUri: env.GITHUB_REDIRECT_URI,
      authorizeUrl: "https://github.com/login/oauth/authorize",
      tokenUrl: "https://github.com/login/oauth/access_token",
      scope: "read:user user:email",
    };
  }
  fail(400, "Unsupported provider");
}

function requestBase(c: Context<{ Bindings: Env }>): string {
  const configured = c.env.PUBLIC_BASE_URL?.trim().replace(/\/+$/g, "");
  if (configured) return configured;
  const url = new URL(c.req.url);
  return `${url.protocol}//${url.host}`;
}

function callbackUri(c: Context<{ Bindings: Env }>, provider: Provider, configured?: string): string {
  return configured || `${requestBase(c)}/auth/${provider}/callback`;
}

function originOf(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return null;
  }
}

function redirectLocationForSession(env: Env, target: string | undefined, token: string): string {
  const resolved = target || env.FRONTEND_REDIRECT_URL || "/";
  if (!allowedNativeRedirect(env, resolved)) return resolved;
  const separator = resolved.includes("#") ? "&" : "#";
  return `${resolved}${separator}${new URLSearchParams({ token, token_type: "bearer" }).toString()}`;
}

function setLoginSession(c: Context<{ Bindings: Env }>, token: string) {
  const domain = String(c.env.SESSION_COOKIE_DOMAIN || "").trim().replace(/^Domain=/i, "").replace(/;.*$/g, "");
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    ...(domain ? { domain } : {}),
    maxAge: Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "525600") * 60,
  });
}

function allowedNativeRedirect(env: Env, target: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return false;
  }
  const scheme = parsed.protocol.replace(/:$/g, "").toLowerCase();
  if (!scheme || scheme === "http" || scheme === "https") return false;
  const allowed = (env.NATIVE_REDIRECT_SCHEMES || "")
    .split(",")
    .map((item) => item.trim().toLowerCase().replace(/:$/g, ""))
    .filter(Boolean);
  return allowed.includes(scheme);
}

function resolveRedirectTarget(env: Env, rawTarget: string | undefined, website: WebsiteRow | null): string | undefined {
  const target = String(rawTarget || "").trim();
  if (!target) return env.FRONTEND_REDIRECT_URL || "/";
  if (target.startsWith("/")) return target;
  if (allowedNativeRedirect(env, target)) return target;
  const targetOrigin = originOf(target);
  if (!targetOrigin) return env.FRONTEND_REDIRECT_URL || "/";
  const frontendOrigin = originOf(env.FRONTEND_REDIRECT_URL);
  if (frontendOrigin && targetOrigin === frontendOrigin) return target;
  if (website) {
    const allowed = parseJson<string[]>(website.allowed_redirect_origins, []);
    if (allowed.includes(targetOrigin)) return target;
  }
  return env.FRONTEND_REDIRECT_URL || "/";
}

function socialIdentityPayload(profile: SocialProfile, schemaFields: Record<string, WebsiteSchemaField>): Record<string, unknown> {
  const raw = profile.raw || {};
  const firstName = String(raw.given_name || raw.first_name || "").trim();
  const lastName = String(raw.family_name || raw.last_name || "").trim();
  const displayName = profile.full_name || profile.email.split("@")[0];
  const payload: Record<string, unknown> = {};
  if ("display_name" in schemaFields) payload.display_name = displayName;
  if ("first_name" in schemaFields && firstName) payload.first_name = firstName;
  if ("last_name" in schemaFields && lastName) payload.last_name = lastName;
  if ("avatar_url" in schemaFields && profile.avatar_url) payload.avatar_url = profile.avatar_url;
  for (const [fieldName, definition] of Object.entries(schemaFields)) {
    if (!definition.required || fieldName in payload) continue;
    if (definition.type === "number") payload[fieldName] = 0;
    else if (definition.type === "boolean") payload[fieldName] = false;
    else if (definition.type === "array") payload[fieldName] = [];
    else if (definition.type === "object") payload[fieldName] = {};
    else payload[fieldName] = "";
  }
  return validateIdentityData(payload, schemaFields);
}

function socialRawWithoutAvatar(profile: SocialProfile): Record<string, unknown> {
  const raw = { ...(profile.raw || {}) };
  delete raw.picture;
  delete raw.avatar_url;
  return raw;
}

function imageExtension(contentType: string): string {
  const normalized = contentType.toLowerCase().split(";")[0].trim();
  if (normalized === "image/jpeg" || normalized === "image/jpg") return "jpg";
  if (normalized === "image/webp") return "webp";
  if (normalized === "image/gif") return "gif";
  return "png";
}

async function storeSocialAvatar(env: Env, userId: string, provider: Provider, avatarUrl: string | null, publicOrigin: string): Promise<Record<string, unknown>> {
  if (!avatarUrl) return {};
  if (!env.AVATARS) {
    return {
      avatar_url: avatarUrl,
      avatar_source: `${provider}-external`,
    };
  }

  try {
    const resp = await fetch(avatarUrl);
    if (!resp.ok || !resp.body) throw new Error(`avatar fetch failed (${resp.status})`);
    const contentType = resp.headers.get("content-type") || "image/png";
    const objectKey = `avatars/${userId}/${crypto.randomUUID()}.${imageExtension(contentType)}`;
    await env.AVATARS.put(objectKey, resp.body, {
      httpMetadata: { contentType },
    });
    const publicBase = (env.PUBLIC_R2_BASE_URL || publicOrigin).replace(/\/+$/g, "");
    return {
      avatar_url: `${publicBase}/${objectKey}`,
      avatar_object_key: objectKey,
      avatar_source: provider,
    };
  } catch (error) {
    console.error("OAuth avatar storage failed", { provider, userId, error });
    return {
      avatar_url: avatarUrl,
      avatar_source: `${provider}-external`,
    };
  }
}

async function findWebsiteFromHost(env: Env, host: string | null): Promise<WebsiteRow | null> {
  if (!host) return null;
  const rows = await env.DB.prepare("SELECT * FROM websites ORDER BY created_at").all<WebsiteRow>();
  for (const website of rows.results || []) {
    if (parseJson<string[]>(website.login_hosts, []).includes(host)) return website;
  }
  return null;
}

function generatePkceVerifier(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function pkceChallenge(codeVerifier: string): Promise<string> {
  return base64Url(await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier)));
}

async function exchangeCode(env: Env, provider: Provider, code: string, redirectUri: string, codeVerifier: string): Promise<string> {
  const cfg = providerConfig(env, provider);
  const body = tokenExchangeBody(cfg.clientId, cfg.clientSecret, code, redirectUri, codeVerifier);
  const resp = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await resp.json<Record<string, unknown>>();
  const accessToken = String(data.access_token || "");
  if (!resp.ok || !accessToken) fail(400, `${provider} sign-in failed. Please try again.`);
  return accessToken;
}

function tokenExchangeBody(clientId: string, clientSecret: string, code: string, redirectUri: string, codeVerifier: string): URLSearchParams {
  return new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: codeVerifier,
  });
}

async function fetchSocialProfile(provider: Provider, accessToken: string): Promise<SocialProfile> {
  if (provider === "google") {
    const resp = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const userinfo = await resp.json<Record<string, unknown>>();
    const email = String(userinfo.email || "").trim().toLowerCase();
    if (!email) fail(400, "Provider did not return an email");
    return {
      email,
      full_name: userinfo.name ? String(userinfo.name) : null,
      provider_account_id: String(userinfo.sub || ""),
      avatar_url: userinfo.picture ? String(userinfo.picture) : null,
      raw: userinfo,
    };
  }

  const profileResp = await fetch("https://api.github.com/user", {
    headers: { authorization: `Bearer ${accessToken}`, accept: "application/vnd.github+json", "user-agent": "pidp-serverless" },
  });
  const profile = await profileResp.json<Record<string, unknown>>();
  let email = profile.email ? String(profile.email) : "";
  if (!email) {
    const emailsResp = await fetch("https://api.github.com/user/emails", {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/vnd.github+json", "user-agent": "pidp-serverless" },
    });
    const emails = await emailsResp.json<Array<Record<string, unknown>>>();
    const primary = Array.isArray(emails) ? emails.find((item) => item.primary) || emails[0] : null;
    email = primary?.email ? String(primary.email) : "";
  }
  email = email.trim().toLowerCase();
  if (!email) fail(400, "Provider did not return an email");
  return {
    email,
    full_name: profile.name ? String(profile.name) : profile.login ? String(profile.login) : null,
    provider_account_id: String(profile.id || ""),
    avatar_url: profile.avatar_url ? String(profile.avatar_url) : null,
    raw: profile,
  };
}

export async function oauthLogin(c: Context<{ Bindings: Env }>): Promise<Response> {
  const cfg = providerConfig(c.env, String(c.req.param("provider") || ""));
  const url = new URL(c.req.url);
  const appSlug = truthy(url.searchParams.get("owner") || undefined) ? "" : (url.searchParams.get("app") || "").trim();
  const state: OAuthState = {
    provider: cfg.provider,
    nonce: crypto.randomUUID(),
    app_slug: appSlug || undefined,
    force_owner: truthy(url.searchParams.get("owner") || undefined),
    next: url.searchParams.get("next") || undefined,
    exp: Math.floor(Date.now() / 1000) + 20 * 60,
  };
  const stateValue = await encodeState(c.env, state);
  const { codeChallenge } = await storeOAuthState(c.env, state, stateValue);
  setCookie(c, COOKIE_NAME, stateValue, { httpOnly: true, secure: true, sameSite: "Lax", path: "/", maxAge: 20 * 60 });

  const authorize = new URL(cfg.authorizeUrl);
  authorize.searchParams.set("client_id", cfg.clientId);
  authorize.searchParams.set("redirect_uri", callbackUri(c, cfg.provider, cfg.redirectUri));
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", cfg.scope);
  authorize.searchParams.set("state", stateValue);
  authorize.searchParams.set("code_challenge", codeChallenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  if (cfg.provider === "google") authorize.searchParams.set("access_type", "online");
  return c.redirect(authorize.toString(), 303);
}

export async function oauthCallback(c: Context<{ Bindings: Env }>): Promise<Response> {
  const provider = String(c.req.param("provider") || "") as Provider;
  const cfg = providerConfig(c.env, provider);
  const url = new URL(c.req.url);
  if (url.searchParams.get("error")) fail(400, `${provider} sign-in failed. Please try again.`);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state") || "";
  const cookieState = getCookie(c, COOKIE_NAME);
  deleteCookie(c, COOKIE_NAME, { path: "/" });
  if (!code || !returnedState) fail(400, `${provider} sign-in session expired. Please try again.`);
  if (cookieState && returnedState !== cookieState) fail(400, `${provider} sign-in session expired. Please try again.`);
  const state = await decodeState(c.env, cookieState || returnedState);
  if (state.provider !== provider) fail(400, `${provider} sign-in session expired. Please try again.`);
  const codeVerifier = await consumeOAuthState(c.env, state, returnedState);

  const accessToken = await exchangeCode(c.env, cfg.provider, code, callbackUri(c, cfg.provider, cfg.redirectUri), codeVerifier);
  const profile = await fetchSocialProfile(cfg.provider, accessToken);
  if (!profile.provider_account_id) fail(400, "Provider did not return an account id");

  let loginWebsite: WebsiteRow | null = null;
  if (state.app_slug) loginWebsite = await websiteBySlug(c.env.DB, normalizeSlug(state.app_slug));
  if (!loginWebsite && !state.force_owner) {
    loginWebsite = await findWebsiteFromHost(c.env, normalizeHost(new URL(c.req.url).host));
  }

  if (loginWebsite) {
    let websiteUser = await first<{ id: string; identity_data: string }>(c.env.DB.prepare(
      "SELECT * FROM website_users WHERE website_id = ? AND provider = ? AND provider_account_id = ?",
    ).bind(loginWebsite.id, provider, profile.provider_account_id));
    if (!websiteUser) {
      websiteUser = await first<{ id: string; identity_data: string }>(c.env.DB.prepare("SELECT * FROM website_users WHERE website_id = ? AND lower(email) = lower(?)").bind(loginWebsite.id, profile.email));
    }
    const schema = schemaWithSystemFields(parseJson<Record<string, WebsiteSchemaField>>(loginWebsite.user_schema, SYSTEM_SCHEMA_FIELDS));
    const identity = socialIdentityPayload(profile, schema);
    const id = websiteUser?.id || crypto.randomUUID();
    const existingIdentity = websiteUser ? parseJson<Record<string, unknown>>(websiteUser.identity_data, {}) : {};
    const existingAvatarUrl = typeof existingIdentity.avatar_url === "string" ? existingIdentity.avatar_url : "";
    const existingAvatarKey = typeof existingIdentity.avatar_object_key === "string" ? existingIdentity.avatar_object_key : "";
    if ("avatar_url" in schema) {
      if (existingAvatarKey) {
        identity.avatar_object_key = existingAvatarKey;
        if (existingAvatarUrl) identity.avatar_url = existingAvatarUrl;
      } else if (profile.avatar_url) {
        Object.assign(identity, await storeSocialAvatar(c.env, id, provider, profile.avatar_url, requestBase(c)));
      } else if (existingAvatarUrl) {
        identity.avatar_url = existingAvatarUrl;
      }
    }
    if (websiteUser) {
      await c.env.DB.prepare(
        "UPDATE website_users SET email = ?, full_name = ?, provider = ?, provider_account_id = ?, identity_data = ?, is_active = 1 WHERE id = ?",
      ).bind(profile.email, profile.full_name, provider, profile.provider_account_id, JSON.stringify(identity), id).run();
    } else {
      await c.env.DB.prepare(
        "INSERT INTO website_users (id, website_id, email, full_name, provider, provider_account_id, identity_data, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
      ).bind(id, loginWebsite.id, profile.email, profile.full_name, provider, profile.provider_account_id, JSON.stringify(identity), nowIso()).run();
    }
    const token = await signJwt(c.env, { sub: id, email: profile.email, actor_type: "website_user", website_id: loginWebsite.id });
    setLoginSession(c, token);
    return c.redirect(redirectLocationForSession(c.env, resolveRedirectTarget(c.env, state.next, loginWebsite), token), 303);
  }

  let user = await first<{ id: string; identity_data: string }>(c.env.DB.prepare("SELECT * FROM users WHERE provider = ? AND provider_account_id = ?").bind(provider, profile.provider_account_id));
  if (!user) user = await first<{ id: string; identity_data: string }>(c.env.DB.prepare("SELECT * FROM users WHERE lower(email) = lower(?)").bind(profile.email));
  const id = user?.id || crypto.randomUUID();
  const existingIdentity = user ? parseJson<Record<string, unknown>>(user.identity_data, {}) : {};
  const existingAvatarUrl = typeof existingIdentity.avatar_url === "string" ? existingIdentity.avatar_url : "";
  const existingAvatarKey = typeof existingIdentity.avatar_object_key === "string" ? existingIdentity.avatar_object_key : "";
  const identity = { ...existingIdentity, ...socialRawWithoutAvatar(profile) };
  if (existingAvatarKey) {
    identity.avatar_object_key = existingAvatarKey;
    if (existingAvatarUrl) identity.avatar_url = existingAvatarUrl;
  } else if (profile.avatar_url) {
    Object.assign(identity, await storeSocialAvatar(c.env, id, provider, profile.avatar_url, requestBase(c)));
  } else if (existingAvatarUrl) {
    identity.avatar_url = existingAvatarUrl;
  }
  if (user) {
    await c.env.DB.prepare("UPDATE users SET email = ?, full_name = ?, provider = ?, provider_account_id = ?, identity_data = ? WHERE id = ?")
      .bind(profile.email, profile.full_name, provider, profile.provider_account_id, JSON.stringify(identity), id).run();
  } else {
    await c.env.DB.prepare(
      "INSERT INTO users (id, email, full_name, provider, provider_account_id, identity_data, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
    ).bind(id, profile.email, profile.full_name, provider, profile.provider_account_id, JSON.stringify(identity), nowIso()).run();
  }
  const token = await signJwt(c.env, { sub: id, email: profile.email });
  setLoginSession(c, token);
  return c.redirect(redirectLocationForSession(c.env, resolveRedirectTarget(c.env, state.next, null), token), 303);
}

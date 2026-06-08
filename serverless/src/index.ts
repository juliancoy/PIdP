import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Env, UserApiTokenRow, UserRow, WebsiteRow, WebsiteSchemaField, WebsiteUserRow } from "./types";
import { all, apiTokenById, countWhere, first, normalizeScope, nowIso, parseJson, userByEmail, userById, websiteById, websiteBySlug, websiteUserByEmail, websiteUserById } from "./db";
import { bearerToken, fail, formCredentials, jsonError, readJson } from "./http";
import { hashPassword, randomToken, sha256Hex, signJwt, verifyJwt, verifyPassword } from "./crypto";
import { DEFAULT_MAX_USERS_PER_WEBSITE, MAX_WEBSITES_PER_OWNER, PROFILE_LINK_FIELDS, SYSTEM_SCHEMA_FIELDS, normalizeBranding, normalizeHostList, normalizeOriginList, normalizeSlug, normalizeWebsiteSchema, schemaWithSystemFields, validateIdentityData } from "./normalize";
import { oauthCallback, oauthLogin } from "./oauth";
import { renderProfilePage, renderProfileQrSvg } from "./profilePage";

const app = new Hono<{ Bindings: Env }>();

const TOKEN_SCOPE_GRANTS: Record<string, string[]> = {
  service: ["service:*"],
  org_portal: ["org:profile.read", "org:profile.write", "org:events.attend", "org:chat.use"],
  org_mcp: ["org:mcp.use", "org:profile.read", "org:events.read"],
  org_admin: ["org:*", "org:admin.read", "org:admin.write", "org:mcp.use"],
};
const SESSION_COOKIE = "pidp_session";

app.use("*", async (c, next) => {
  const allowed = (c.env.ALLOWED_ORIGINS || "").split(",").map((item) => item.trim()).filter(Boolean);
  if (!allowed.length) return next();
  return cors({ origin: allowed, credentials: true, allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] })(c, next);
});

app.onError((error, c) => jsonError(c, error));

function json<T>(value: T): string {
  return JSON.stringify(value);
}

function absoluteUrl(c: { req: { url: string } }, path: string): string {
  return new URL(path, c.req.url).toString();
}

function svgAttachment(svg: string, filename: string): Response {
  return new Response(svg, {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "content-disposition": `attachment; filename="${filename.replace(/[^a-zA-Z0-9._-]/g, "-")}"`,
      "cache-control": "no-store",
    },
  });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char] || char);
}

function cookieValue(c: { req: { header(name: string): string | undefined } }, name: string): string | null {
  const raw = c.req.header("Cookie") || "";
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function setSessionCookie(headers: Headers, token: string, maxAgeSeconds: number) {
  headers.append(
    "set-cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`,
  );
}

function clearSessionCookie(headers: Headers) {
  headers.append("set-cookie", `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

function redirectWithToken(next: string, token: string, headers = new Headers()): Response {
  const fallback = "/";
  let target = next || fallback;
  try {
    target = new URL(target).toString();
  } catch {
    target = target.startsWith("/") ? target : fallback;
  }
  const separator = target.includes("#") ? "&" : "#";
  headers.set("location", `${target}${separator}token=${encodeURIComponent(token)}`);
  return new Response(null, { status: 303, headers });
}

function renderAppLoginPage(params: { appName: string; appSlug: string; next: string; error?: string; ownerMode: boolean }) {
  const appField = params.appSlug ? `<input type="hidden" name="app" value="${escapeHtml(params.appSlug)}">` : "";
  const ownerField = params.ownerMode ? `<input type="hidden" name="owner" value="1">` : "";
  const error = params.error ? `<p class="error">${escapeHtml(params.error)}</p>` : "";
  const title = params.ownerMode ? `${params.appName} Owner Login` : `${params.appName} Login`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #111827; }
    main { width: min(100% - 32px, 420px); background: #fff; border: 1px solid #d7dce3; border-radius: 8px; padding: 24px; box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
    h1 { font-size: 1.4rem; margin: 0 0 16px; }
    label { display: grid; gap: 6px; font-size: 0.92rem; margin: 12px 0; }
    input { font: inherit; padding: 10px 12px; border: 1px solid #bcc4d0; border-radius: 6px; }
    button { width: 100%; margin-top: 12px; padding: 10px 12px; border: 0; border-radius: 6px; background: #111827; color: #fff; font: inherit; cursor: pointer; }
    .error { color: #b42318; background: #fff1f0; border: 1px solid #ffccc7; padding: 10px 12px; border-radius: 6px; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(title)}</h1>
    ${error}
    <form method="post" action="/app/login">
      ${appField}
      ${ownerField}
      <input type="hidden" name="next" value="${escapeHtml(params.next)}">
      <label>Email <input name="email" type="email" autocomplete="email" required></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Log in</button>
    </form>
  </main>
</body>
</html>`;
}

function isSysadmin(env: Env, user: UserRow): boolean {
  const adminIds = (env.ADMIN_USER_IDS || "").split(",").map((item) => item.trim()).filter(Boolean);
  const adminEmails = (env.ADMIN_EMAILS || "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  const identity = parseJson<Record<string, unknown>>(user.identity_data, {});
  const roles = Array.isArray(identity.roles) ? identity.roles.map((item) => String(item).trim().toLowerCase()) : [];
  return adminIds.includes(user.id) || adminEmails.includes(user.email.toLowerCase()) || identity.is_sysadmin === true || roles.includes("sysadmin") || roles.includes("admin");
}

function userPublic(env: Env, user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    full_name: user.full_name,
    provider: user.provider,
    identity_data: parseJson(user.identity_data, {}),
    is_sysadmin: isSysadmin(env, user),
    is_active: Boolean(user.is_active),
    created_at: user.created_at,
  };
}

function websitePublic(row: WebsiteRow) {
  return {
    id: row.id,
    owner_id: row.owner_id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    login_hosts: parseJson<string[]>(row.login_hosts, []),
    allowed_redirect_origins: parseJson<string[]>(row.allowed_redirect_origins, []),
    branding: parseJson<Record<string, unknown>>(row.branding, {}),
    user_schema: schemaWithSystemFields(parseJson<Record<string, WebsiteSchemaField>>(row.user_schema, {})),
    max_users: row.max_users,
    created_at: row.created_at,
  };
}

function websiteUserPublic(row: WebsiteUserRow) {
  return {
    id: row.id,
    website_id: row.website_id,
    email: row.email,
    full_name: row.full_name,
    provider: row.provider,
    identity_data: parseJson(row.identity_data, {}),
    is_active: Boolean(row.is_active),
    created_at: row.created_at,
  };
}

function apiTokenPublic(row: UserApiTokenRow) {
  return {
    id: row.id,
    name: row.name,
    scope: row.scope,
    scope_grants: TOKEN_SCOPE_GRANTS[row.scope] || [],
    is_active: Boolean(row.is_active),
    created_at: row.created_at,
    last_used_at: row.last_used_at,
  };
}

async function currentOwner(env: Env, token: string): Promise<UserRow> {
  if (token.startsWith("pidp_pat_")) {
    const owner = await ownerFromPat(env, token);
    return owner.user;
  }
  const payload = await verifyJwt(env, token);
  if (payload.actor_type === "website_user") fail(403, "Website user tokens cannot manage websites");
  const user = await userById(env.DB, payload.sub);
  if (!user) fail(404, "User not found");
  return user;
}

async function currentOwnerForTokenAdmin(env: Env, token: string): Promise<UserRow> {
  if (!token.startsWith("pidp_pat_")) return currentOwner(env, token);
  const { user, tokenRow } = await ownerFromPat(env, token);
  if (tokenRow.scope !== "org_admin") fail(403, "PAT scope does not permit token administration");
  return user;
}

async function currentWebsiteUser(env: Env, token: string): Promise<WebsiteUserRow> {
  const payload = await verifyJwt(env, token);
  if (payload.actor_type !== "website_user" || !payload.website_id) fail(403, "Token is not a website user token");
  const user = await websiteUserById(env.DB, payload.website_id, payload.sub);
  if (!user) fail(404, "Website user not found");
  return user;
}

async function ownerFromPat(env: Env, rawToken: string): Promise<{ user: UserRow; tokenRow: UserApiTokenRow }> {
  const tokenHash = await sha256Hex(rawToken);
  const tokenRow = await first<UserApiTokenRow>(
    env.DB.prepare("SELECT * FROM user_api_tokens WHERE token_hash = ? AND is_active = 1").bind(tokenHash),
  );
  if (!tokenRow) fail(401, "Invalid API token");
  await env.DB.prepare("UPDATE user_api_tokens SET last_used_at = ? WHERE id = ?").bind(nowIso(), tokenRow.id).run();
  const user = await userById(env.DB, tokenRow.owner_id);
  if (!user) fail(401, "Invalid API token");
  return { user, tokenRow };
}

async function ownedWebsite(env: Env, ownerId: string, websiteId: string): Promise<WebsiteRow> {
  const website = await first<WebsiteRow>(env.DB.prepare("SELECT * FROM websites WHERE id = ? AND owner_id = ?").bind(websiteId, ownerId));
  if (!website) fail(404, "Website not found");
  return website;
}

async function createOwnerToken(env: Env, user: UserRow): Promise<string> {
  return signJwt(env, { sub: user.id, email: user.email, is_sysadmin: isSysadmin(env, user) });
}

async function createWebsiteUserToken(env: Env, websiteUser: WebsiteUserRow): Promise<string> {
  return signJwt(env, { sub: websiteUser.id, email: websiteUser.email, actor_type: "website_user", website_id: websiteUser.website_id });
}

async function issueApiToken(env: Env, ownerId: string, name: string, scopeRaw: unknown) {
  const scope = normalizeScope(scopeRaw);
  const existing = await first<UserApiTokenRow>(env.DB.prepare("SELECT * FROM user_api_tokens WHERE owner_id = ? AND name = ?").bind(ownerId, name));
  if (existing?.is_active) fail(409, "Active API token with this name already exists");
  const raw = randomToken("pidp_pat_");
  const tokenHash = await sha256Hex(raw);
  const id = crypto.randomUUID();
  if (existing) {
    await env.DB.prepare("UPDATE user_api_tokens SET token_hash = ?, scope = ?, is_active = 1, last_used_at = NULL WHERE id = ?").bind(tokenHash, scope, existing.id).run();
    return { token: raw, row: { ...existing, token_hash: tokenHash, scope, is_active: 1, last_used_at: null } };
  }
  const createdAt = nowIso();
  await env.DB.prepare(
    "INSERT INTO user_api_tokens (id, owner_id, name, token_hash, scope, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
  ).bind(id, ownerId, name, tokenHash, scope, createdAt).run();
  return { token: raw, row: { id, owner_id: ownerId, name, token_hash: tokenHash, scope, is_active: 1, last_used_at: null, created_at: createdAt } };
}

async function createWebsiteFromPayload(env: Env, owner: UserRow, payload: Record<string, unknown>, conflictStatus: number) {
  const count = await countWhere(env.DB, "SELECT count(*) AS n FROM websites WHERE owner_id = ?", owner.id);
  if (count >= MAX_WEBSITES_PER_OWNER) fail(conflictStatus, `Each account may only create ${MAX_WEBSITES_PER_OWNER} websites`);
  const name = String(payload.name || "").trim();
  if (!name) fail(422, "name is required");
  const slug = normalizeSlug(String(payload.slug || name));
  if (await websiteBySlug(env.DB, slug)) fail(409, "Website slug already exists");
  const id = crypto.randomUUID();
  const createdAt = nowIso();
  const row: WebsiteRow = {
    id,
    owner_id: owner.id,
    name,
    slug,
    description: payload.description ? String(payload.description) : null,
    login_hosts: json(normalizeHostList(payload.login_hosts)),
    allowed_redirect_origins: json(normalizeOriginList(payload.allowed_redirect_origins)),
    branding: json(normalizeBranding({})),
    user_schema: json(SYSTEM_SCHEMA_FIELDS),
    max_users: DEFAULT_MAX_USERS_PER_WEBSITE,
    created_at: createdAt,
  };
  await env.DB.prepare(
    "INSERT INTO websites (id, owner_id, name, slug, description, login_hosts, allowed_redirect_origins, branding, user_schema, max_users, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(row.id, row.owner_id, row.name, row.slug, row.description, row.login_hosts, row.allowed_redirect_origins, row.branding, row.user_schema, row.max_users, row.created_at).run();
  return row;
}

app.get("/health", (c) => c.json({ status: "ok" }));

app.get("/.well-known/jwks.json", (c) => c.json({ keys: [] }));

app.get("/configuration", (c) => {
  const url = new URL(c.req.url);
  return c.json({
    base_addr: `${url.protocol}//${url.host}/`,
    google_client_id: c.env.GOOGLE_CLIENT_ID || null,
    google_redirect_uri: c.env.GOOGLE_REDIRECT_URI || `${url.protocol}//${url.host}/auth/google/callback`,
    github_client_id: c.env.GITHUB_CLIENT_ID || null,
    github_redirect_uri: c.env.GITHUB_REDIRECT_URI || `${url.protocol}//${url.host}/auth/github/callback`,
    frontend_redirect_url: c.env.FRONTEND_REDIRECT_URL || null,
    minio_endpoint: null,
    minio_bucket: null,
    minio_public_base_url: c.env.PUBLIC_R2_BASE_URL || "",
  });
});

app.get("/avatars/*", async (c) => {
  if (!c.env.AVATARS) fail(404, "Avatar storage is not configured");
  const objectKey = c.req.path.replace(/^\/+/, "");
  if (!objectKey.startsWith("avatars/")) fail(404, "Avatar not found");
  const object = await c.env.AVATARS.get(objectKey);
  if (!object) fail(404, "Avatar not found");
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("cache-control", "public, max-age=31536000, immutable");
  return new Response(object.body, { headers });
});

app.post("/auth/register", async (c) => {
  const payload = await readJson<Record<string, unknown>>(c);
  const email = String(payload.email || "").trim().toLowerCase();
  const password = String(payload.password || "");
  if (!email || !password) fail(422, "email and password are required");
  if (await userByEmail(c.env.DB, email)) fail(409, "Account already exists. Please log in.");
  const id = crypto.randomUUID();
  const createdAt = nowIso();
  const hashedPassword = await hashPassword(password);
  await c.env.DB.prepare(
    "INSERT INTO users (id, email, hashed_password, full_name, identity_data, is_active, created_at) VALUES (?, ?, ?, ?, '{}', 1, ?)",
  ).bind(id, email, hashedPassword, payload.full_name ? String(payload.full_name) : null, createdAt).run();
  const user = await userById(c.env.DB, id);
  return c.json(userPublic(c.env, user!));
});

app.post("/auth/token", async (c) => {
  const { username, password } = await formCredentials(c);
  const user = await userByEmail(c.env.DB, username);
  if (!user || !(await verifyPassword(password, user.hashed_password))) fail(401, "Invalid credentials");
  return c.json({ access_token: await createOwnerToken(c.env, user), token_type: "bearer" });
});

app.get("/app/login", async (c) => {
  const url = new URL(c.req.url);
  const appParam = url.searchParams.get("app") || "";
  const appSlug = appParam ? normalizeSlug(appParam) : "";
  const appName = c.env.APP_NAME || "PIdP";
  const ownerMode = Boolean(url.searchParams.get("owner"));
  const next = url.searchParams.get("next") || c.env.FRONTEND_REDIRECT_URL || "/";
  if (url.searchParams.get("auto") && (c.env.GOOGLE_CLIENT_ID || c.env.GITHUB_CLIENT_ID)) {
    const provider = c.env.GOOGLE_CLIENT_ID ? "google" : "github";
    const redirect = new URL(`/auth/${provider}/login`, url.origin);
    redirect.searchParams.set("next", next);
    if (ownerMode) redirect.searchParams.set("owner", "1");
    else if (appSlug) redirect.searchParams.set("app", appSlug);
    return c.redirect(redirect.toString(), 303);
  }
  return c.html(renderAppLoginPage({ appName, appSlug, next, ownerMode }));
});

app.get("/app/login/", (c) => {
  const url = new URL(c.req.url);
  url.pathname = "/app/login";
  return c.redirect(url.toString(), 301);
});

app.post("/app/login", async (c) => {
  const form = await c.req.parseBody();
  const email = String(form.email || "").trim().toLowerCase();
  const password = String(form.password || "");
  const appParam = String(form.app || "");
  const appSlug = appParam ? normalizeSlug(appParam) : "";
  const appName = c.env.APP_NAME || "PIdP";
  const ownerMode = Boolean(form.owner);
  const next = String(form.next || c.env.FRONTEND_REDIRECT_URL || "/");
  if (!email || !password) {
    return c.html(renderAppLoginPage({ appName, appSlug, next, ownerMode, error: "Email and password are required." }), 422);
  }

  if (!ownerMode && appSlug) {
    const website = await websiteBySlug(c.env.DB, appSlug);
    if (website) {
      const websiteUser = await websiteUserByEmail(c.env.DB, website.id, email);
      if (!websiteUser || !(await verifyPassword(password, websiteUser.hashed_password))) {
        return c.html(renderAppLoginPage({ appName, appSlug, next, ownerMode, error: "Invalid credentials." }), 401);
      }
      if (!websiteUser.is_active) {
        return c.html(renderAppLoginPage({ appName, appSlug, next, ownerMode, error: "This account is inactive." }), 403);
      }
      const token = await createWebsiteUserToken(c.env, websiteUser);
      const headers = new Headers();
      setSessionCookie(headers, token, Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "60") * 60);
      return redirectWithToken(next, token, headers);
    }
  }

  const user = await userByEmail(c.env.DB, email);
  if (!user || !(await verifyPassword(password, user.hashed_password))) {
    return c.html(renderAppLoginPage({ appName, appSlug, next, ownerMode, error: "Invalid credentials." }), 401);
  }
  const token = await createOwnerToken(c.env, user);
  const headers = new Headers();
  setSessionCookie(headers, token, Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "60") * 60);
  return redirectWithToken(next, token, headers);
});

app.get("/auth/me", async (c) => {
  const token = bearerToken(c);
  const payload = await verifyJwt(c.env, token);
  if (payload.actor_type === "website_user") {
    const websiteUser = await currentWebsiteUser(c.env, token);
    return c.json(userPublic(c.env, {
      id: websiteUser.id,
      email: websiteUser.email,
      hashed_password: websiteUser.hashed_password,
      full_name: websiteUser.full_name,
      provider: websiteUser.provider,
      provider_account_id: websiteUser.provider_account_id,
      identity_data: websiteUser.identity_data,
      is_active: websiteUser.is_active,
      created_at: websiteUser.created_at,
    }));
  }
  const user = await currentOwner(c.env, token);
  return c.json(userPublic(c.env, user));
});

app.put("/auth/me", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const payload = await readJson<Record<string, unknown>>(c);
  const identity = parseJson<Record<string, unknown>>(owner.identity_data, {});
  const fullName = "full_name" in payload ? String(payload.full_name || "") : owner.full_name;
  delete payload.full_name;
  Object.assign(identity, payload);
  await c.env.DB.prepare("UPDATE users SET full_name = ?, identity_data = ? WHERE id = ?").bind(fullName || null, json(identity), owner.id).run();
  return c.json(userPublic(c.env, (await userById(c.env.DB, owner.id))!));
});

app.post("/auth/session/exchange", async (c) => {
  const token = bearerToken(c);
  const payload = await verifyJwt(c.env, token);
  const rotated = payload.actor_type === "website_user"
    ? await createWebsiteUserToken(c.env, await currentWebsiteUser(c.env, token))
    : await createOwnerToken(c.env, await currentOwner(c.env, token));
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  setSessionCookie(headers, rotated, Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "60") * 60);
  return new Response(JSON.stringify({ access_token: rotated, token_type: "bearer" }), { status: 200, headers });
});

app.post("/auth/session/login", async (c) => {
  const { username, password } = await formCredentials(c);
  const user = await userByEmail(c.env.DB, username);
  if (!user || !(await verifyPassword(password, user.hashed_password))) fail(401, "Invalid credentials");
  const token = await createOwnerToken(c.env, user);
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  setSessionCookie(headers, token, Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "60") * 60);
  return new Response(JSON.stringify({ access_token: token, token_type: "bearer" }), { status: 200, headers });
});

app.post("/auth/session/logout", (c) => {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  clearSessionCookie(headers);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
});

app.get("/auth/session-token", async (c) => {
  const token = cookieValue(c, SESSION_COOKIE);
  if (!token) fail(401, "No active session");
  await verifyJwt(c.env, token);
  return c.json({ access_token: token, token_type: "bearer" });
});

app.post("/auth/smoke-token", async (c) => {
  const configuredSecret = String(c.env.SMOKE_TEST_SECRET || "");
  if (!configuredSecret) fail(404, "Smoke token endpoint is not configured");
  const payload = await readJson<Record<string, unknown>>(c);
  const suppliedSecret = String(payload.secret || "");
  if (!suppliedSecret || suppliedSecret !== configuredSecret) fail(403, "Smoke token secret is invalid");
  const email = String(payload.email || "").trim().toLowerCase();
  if (!email) fail(422, "email is required");
  const user = await userByEmail(c.env.DB, email);
  if (!user || !user.is_active) fail(404, "Smoke user not found");
  const token = await createOwnerToken(c.env, user);
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  setSessionCookie(headers, token, Number(c.env.ACCESS_TOKEN_EXPIRE_MINUTES || "60") * 60);
  return new Response(JSON.stringify({ access_token: token, token_type: "bearer" }), { status: 200, headers });
});

app.post("/auth/tokens", async (c) => {
  const owner = await currentOwnerForTokenAdmin(c.env, bearerToken(c));
  const payload = await readJson<Record<string, unknown>>(c);
  const name = String(payload.name || "").trim();
  if (!name) fail(422, "Token name is required");
  const issued = await issueApiToken(c.env, owner.id, name, payload.scope);
  return c.json({ token: issued.token, token_id: issued.row.id, name: issued.row.name, scope: issued.row.scope, scope_grants: TOKEN_SCOPE_GRANTS[issued.row.scope] || [] });
});

app.get("/auth/tokens", async (c) => {
  const owner = await currentOwnerForTokenAdmin(c.env, bearerToken(c));
  const rows = await all<UserApiTokenRow>(c.env.DB.prepare("SELECT * FROM user_api_tokens WHERE owner_id = ? ORDER BY created_at DESC").bind(owner.id));
  return c.json(rows.map(apiTokenPublic));
});

app.patch("/auth/tokens/:tokenId", async (c) => {
  const owner = await currentOwnerForTokenAdmin(c.env, bearerToken(c));
  const payload = await readJson<Record<string, unknown>>(c);
  const name = String(payload.name || "").trim();
  if (!name) fail(422, "Token name is required");
  const row = await apiTokenById(c.env.DB, owner.id, c.req.param("tokenId"));
  if (!row) fail(404, "API token not found");
  await c.env.DB.prepare("UPDATE user_api_tokens SET name = ? WHERE id = ?").bind(name, row.id).run();
  return c.json(apiTokenPublic({ ...row, name }));
});

app.delete("/auth/tokens/:tokenId", async (c) => {
  const owner = await currentOwnerForTokenAdmin(c.env, bearerToken(c));
  const row = await apiTokenById(c.env.DB, owner.id, c.req.param("tokenId"));
  if (!row) fail(404, "API token not found");
  await c.env.DB.prepare("UPDATE user_api_tokens SET is_active = 0 WHERE id = ?").bind(row.id).run();
  return c.json({ revoked: true, token_id: row.id });
});

app.post("/auth/tokens/:tokenId/cycle", async (c) => {
  const owner = await currentOwnerForTokenAdmin(c.env, bearerToken(c));
  const row = await apiTokenById(c.env.DB, owner.id, c.req.param("tokenId"));
  if (!row) fail(404, "API token not found");
  const raw = randomToken("pidp_pat_");
  await c.env.DB.prepare("UPDATE user_api_tokens SET token_hash = ?, is_active = 1, last_used_at = NULL WHERE id = ?").bind(await sha256Hex(raw), row.id).run();
  return c.json({ token: raw, token_id: row.id, name: row.name, scope: row.scope, scope_grants: TOKEN_SCOPE_GRANTS[row.scope] || [] });
});

app.get("/service/me", async (c) => {
  return c.json(userPublic(c.env, await currentOwner(c.env, bearerToken(c))));
});

app.get("/service/token-info", async (c) => {
  const token = bearerToken(c);
  if (token.startsWith("pidp_pat_")) {
    const { user, tokenRow } = await ownerFromPat(c.env, token);
    return c.json({ token_kind: "pat", actor_type: "owner", scope: tokenRow.scope, scope_grants: TOKEN_SCOPE_GRANTS[tokenRow.scope] || [], owner: userPublic(c.env, user) });
  }
  const payload = await verifyJwt(c.env, token);
  if (payload.actor_type === "website_user") {
    const user = await currentWebsiteUser(c.env, token);
    return c.json({ token_kind: "jwt", actor_type: "website_user", scope: "session", scope_grants: ["session:*"], owner: websiteUserPublic(user) });
  }
  const user = await currentOwner(c.env, token);
  return c.json({ token_kind: "jwt", actor_type: "owner", scope: "session", scope_grants: ["session:*"], owner: userPublic(c.env, user) });
});

app.get("/service/websites", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const rows = await all<WebsiteRow>(c.env.DB.prepare("SELECT * FROM websites WHERE owner_id = ? ORDER BY created_at").bind(owner.id));
  return c.json(rows.map(websitePublic));
});

app.post("/service/websites", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const row = await createWebsiteFromPayload(c.env, owner, await readJson(c), 409);
  return c.json(websitePublic(row));
});

app.get("/auth/users", async (c) => {
  await currentOwner(c.env, bearerToken(c));
  const email = c.req.query("email") || "";
  const rows = await all<UserRow>(c.env.DB.prepare("SELECT * FROM users WHERE lower(email) LIKE lower(?)").bind(email));
  return c.json(rows.map((row) => userPublic(c.env, row)));
});

app.get("/auth/public/users", async (c) => {
  const ids = (c.req.query("ids") || "").split(",").map((item) => item.trim()).filter(Boolean);
  if (!ids.length) return c.json([]);
  const placeholders = ids.map(() => "?").join(",");
  const rows = await all<UserRow>(c.env.DB.prepare(`SELECT * FROM users WHERE id IN (${placeholders})`).bind(...ids));
  return c.json(rows.map((user) => {
    const identity = parseJson<Record<string, unknown>>(user.identity_data, {});
    const publicProfile: Record<string, unknown> = {
      id: user.id,
      full_name: user.full_name,
      display_name: identity.display_name || null,
      avatar_url: identity.avatar_url || null,
    };
    for (const field of PROFILE_LINK_FIELDS) {
      publicProfile[field] = identity[field] ?? (field === "website_urls" ? [] : null);
    }
    return publicProfile;
  }));
});

app.get("/u/:userId", async (c) => {
  const user = await userById(c.env.DB, c.req.param("userId"));
  if (!user || !user.is_active) fail(404, "User not found");
  const profilePath = `/u/${encodeURIComponent(user.id)}`;
  const profileUrl = absoluteUrl(c, profilePath);
  return c.html(renderProfilePage({
    id: user.id,
    email: user.email,
    fullName: user.full_name,
    identity: parseJson<Record<string, unknown>>(user.identity_data, {}),
    profileUrl,
    qrSvg: await renderProfileQrSvg(profileUrl),
    qrDownloadUrl: `${profilePath}/qr.svg`,
  }));
});

app.get("/u/:userId/qr.svg", async (c) => {
  const user = await userById(c.env.DB, c.req.param("userId"));
  if (!user || !user.is_active) fail(404, "User not found");
  return svgAttachment(await renderProfileQrSvg(absoluteUrl(c, `/u/${encodeURIComponent(user.id)}`)), `pidp-${user.id}-qr.svg`);
});

app.get("/users/:userId", async (c) => {
  const userId = c.req.param("userId");
  return c.redirect(`/u/${encodeURIComponent(userId)}`, 308);
});

app.get("/sites/:websiteSlug/users/:websiteUserId/profile", async (c) => {
  const website = await websiteBySlug(c.env.DB, normalizeSlug(c.req.param("websiteSlug")));
  if (!website) fail(404, "Website not found");
  const websiteUser = await websiteUserById(c.env.DB, website.id, c.req.param("websiteUserId"));
  if (!websiteUser || !websiteUser.is_active) fail(404, "Website user not found");
  const profilePath = `/sites/${encodeURIComponent(website.slug)}/users/${encodeURIComponent(websiteUser.id)}/profile`;
  const profileUrl = absoluteUrl(c, profilePath);
  return c.html(renderProfilePage({
    id: websiteUser.id,
    email: websiteUser.email,
    fullName: websiteUser.full_name,
    identity: parseJson<Record<string, unknown>>(websiteUser.identity_data, {}),
    schema: schemaWithSystemFields(parseJson<Record<string, WebsiteSchemaField>>(website.user_schema, SYSTEM_SCHEMA_FIELDS)),
    titleSuffix: website.name,
    profileUrl,
    qrSvg: await renderProfileQrSvg(profileUrl),
    qrDownloadUrl: `${profilePath}/qr.svg`,
  }));
});

app.get("/sites/:websiteSlug/users/:websiteUserId/profile/qr.svg", async (c) => {
  const website = await websiteBySlug(c.env.DB, normalizeSlug(c.req.param("websiteSlug")));
  if (!website) fail(404, "Website not found");
  const websiteUser = await websiteUserById(c.env.DB, website.id, c.req.param("websiteUserId"));
  if (!websiteUser || !websiteUser.is_active) fail(404, "Website user not found");
  const profilePath = `/sites/${encodeURIComponent(website.slug)}/users/${encodeURIComponent(websiteUser.id)}/profile`;
  return svgAttachment(await renderProfileQrSvg(absoluteUrl(c, profilePath)), `pidp-${website.slug}-${websiteUser.id}-qr.svg`);
});

app.post("/auth/avatar/upload-url", async (c) => {
  if (!c.env.AVATARS) fail(503, "R2 avatar bucket not configured");
  const payload = await verifyJwt(c.env, bearerToken(c));
  const objectKey = `avatars/${payload.sub}/${crypto.randomUUID()}.png`;
  const publicBase = (c.env.PUBLIC_R2_BASE_URL || new URL(c.req.url).origin).replace(/\/+$/g, "");
  return c.json({
    upload_url: `/auth/avatar/upload/${objectKey}`,
    public_url: `${publicBase}/${objectKey}`,
    object_key: objectKey,
  });
});

app.put("/auth/avatar/upload/*", async (c) => {
  if (!c.env.AVATARS) fail(503, "R2 avatar bucket not configured");
  await verifyJwt(c.env, bearerToken(c));
  const objectKey = c.req.path.replace("/auth/avatar/upload/", "");
  if (!objectKey.startsWith("avatars/")) fail(422, "Invalid avatar object key");
  await c.env.AVATARS.put(objectKey, c.req.raw.body, { httpMetadata: { contentType: c.req.header("content-type") || "image/png" } });
  return c.json({ object_key: objectKey });
});

app.post("/profile/avatar", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const payload = await readJson<Record<string, unknown>>(c);
  const avatarUrl = String(payload.avatar_url || "").trim();
  const objectKey = String(payload.object_key || "").trim();
  if (!avatarUrl || !objectKey) fail(422, "avatar_url and object_key are required");
  const identity = parseJson<Record<string, unknown>>(owner.identity_data, {});
  identity.avatar_url = avatarUrl;
  identity.avatar_object_key = objectKey;
  identity.avatar_source = "uploaded";
  await c.env.DB.prepare("UPDATE users SET identity_data = ? WHERE id = ?").bind(json(identity), owner.id).run();
  return c.json({ avatar_url: avatarUrl, avatar_object_key: objectKey });
});

app.post("/websites", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const row = await createWebsiteFromPayload(c.env, owner, await readJson(c), 403);
  return c.json(websitePublic(row));
});

app.get("/websites", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const rows = await all<WebsiteRow>(c.env.DB.prepare("SELECT * FROM websites WHERE owner_id = ? ORDER BY created_at").bind(owner.id));
  return c.json(rows.map(websitePublic));
});

app.get("/websites/:websiteId", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  return c.json(websitePublic(await ownedWebsite(c.env, owner.id, c.req.param("websiteId"))));
});

app.put("/websites/:websiteId/schema", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  const payload = await readJson<{ fields?: Record<string, WebsiteSchemaField> }>(c);
  const schema = normalizeWebsiteSchema(payload.fields || {});
  await c.env.DB.prepare("UPDATE websites SET user_schema = ? WHERE id = ?").bind(json(schema), website.id).run();
  return c.json(websitePublic((await websiteById(c.env.DB, website.id))!));
});

app.put("/websites/:websiteId/auth-config", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  const payload = await readJson<Record<string, unknown>>(c);
  await c.env.DB.prepare("UPDATE websites SET login_hosts = ?, allowed_redirect_origins = ? WHERE id = ?")
    .bind(json(normalizeHostList(payload.login_hosts)), json(normalizeOriginList(payload.allowed_redirect_origins)), website.id).run();
  return c.json(websitePublic((await websiteById(c.env.DB, website.id))!));
});

app.put("/websites/:websiteId/branding", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  await c.env.DB.prepare("UPDATE websites SET branding = ? WHERE id = ?").bind(json(normalizeBranding(await readJson(c))), website.id).run();
  return c.json(websitePublic((await websiteById(c.env.DB, website.id))!));
});

app.get("/websites/:websiteId/users", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  const rows = await all<WebsiteUserRow>(c.env.DB.prepare("SELECT * FROM website_users WHERE website_id = ? ORDER BY created_at").bind(website.id));
  return c.json(rows.map(websiteUserPublic));
});

app.post("/websites/:websiteId/users", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  const payload = await readJson<Record<string, unknown>>(c);
  const count = await countWhere(c.env.DB, "SELECT count(*) AS n FROM website_users WHERE website_id = ?", website.id);
  if (count >= website.max_users) fail(403, `Website user limit reached (${website.max_users})`);
  const email = String(payload.email || "").trim().toLowerCase();
  if (!email || !payload.password) fail(422, "email and password are required");
  if (await websiteUserByEmail(c.env.DB, website.id, email)) fail(409, "Website user already exists");
  const schema = schemaWithSystemFields(parseJson<Record<string, WebsiteSchemaField>>(website.user_schema, SYSTEM_SCHEMA_FIELDS));
  const identityData = validateIdentityData(payload.identity_data, schema);
  const id = crypto.randomUUID();
  const createdAt = nowIso();
  await c.env.DB.prepare(
    "INSERT INTO website_users (id, website_id, email, hashed_password, full_name, identity_data, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
  ).bind(id, website.id, email, await hashPassword(String(payload.password)), payload.full_name ? String(payload.full_name) : null, json(identityData), createdAt).run();
  return c.json(websiteUserPublic((await websiteUserById(c.env.DB, website.id, id))!));
});

app.put("/websites/:websiteId/users/:websiteUserId", async (c) => {
  const owner = await currentOwner(c.env, bearerToken(c));
  const website = await ownedWebsite(c.env, owner.id, c.req.param("websiteId"));
  const websiteUser = await websiteUserById(c.env.DB, website.id, c.req.param("websiteUserId"));
  if (!websiteUser) fail(404, "Website user not found");
  const payload = await readJson<Record<string, unknown>>(c);
  const fullName = "full_name" in payload ? String(payload.full_name || "") : websiteUser.full_name;
  const isActive = "is_active" in payload ? (payload.is_active ? 1 : 0) : websiteUser.is_active;
  const identityData = "identity_data" in payload
    ? validateIdentityData(payload.identity_data, schemaWithSystemFields(parseJson<Record<string, WebsiteSchemaField>>(website.user_schema, SYSTEM_SCHEMA_FIELDS)))
    : parseJson<Record<string, unknown>>(websiteUser.identity_data, {});
  await c.env.DB.prepare("UPDATE website_users SET full_name = ?, is_active = ?, identity_data = ? WHERE id = ?")
    .bind(fullName || null, isActive, json(identityData), websiteUser.id).run();
  return c.json(websiteUserPublic((await websiteUserById(c.env.DB, website.id, websiteUser.id))!));
});

app.post("/websites/:websiteSlug/auth/register", async (c) => {
  const website = await websiteBySlug(c.env.DB, normalizeSlug(c.req.param("websiteSlug")));
  if (!website) fail(404, "Website not found");
  const payload = await readJson<Record<string, unknown>>(c);
  const count = await countWhere(c.env.DB, "SELECT count(*) AS n FROM website_users WHERE website_id = ?", website.id);
  if (count >= website.max_users) fail(403, `Website user limit reached (${website.max_users})`);
  const email = String(payload.email || "").trim().toLowerCase();
  if (!email || !payload.password) fail(422, "email and password are required");
  if (await websiteUserByEmail(c.env.DB, website.id, email)) fail(409, "Website user already exists");
  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    "INSERT INTO website_users (id, website_id, email, hashed_password, full_name, identity_data, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
  ).bind(id, website.id, email, await hashPassword(String(payload.password)), payload.full_name ? String(payload.full_name) : null, json(validateIdentityData(payload.identity_data, schemaWithSystemFields(parseJson(website.user_schema, SYSTEM_SCHEMA_FIELDS)))), nowIso()).run();
  return c.json(websiteUserPublic((await websiteUserById(c.env.DB, website.id, id))!));
});

app.post("/websites/:websiteSlug/auth/token", async (c) => {
  const website = await websiteBySlug(c.env.DB, normalizeSlug(c.req.param("websiteSlug")));
  if (!website) fail(404, "Website not found");
  const payload = await readJson<Record<string, unknown>>(c);
  const websiteUser = await websiteUserByEmail(c.env.DB, website.id, String(payload.email || "").trim().toLowerCase());
  if (!websiteUser || !(await verifyPassword(String(payload.password || ""), websiteUser.hashed_password))) fail(401, "Invalid credentials");
  if (!websiteUser.is_active) fail(403, "Website user is inactive");
  return c.json({ access_token: await createWebsiteUserToken(c.env, websiteUser), token_type: "bearer" });
});

app.get("/websites/:websiteSlug/auth/me", async (c) => {
  const website = await websiteBySlug(c.env.DB, normalizeSlug(c.req.param("websiteSlug")));
  if (!website) fail(404, "Website not found");
  const payload = await verifyJwt(c.env, bearerToken(c));
  if (payload.actor_type !== "website_user" || payload.website_id !== website.id) fail(403, "Token does not belong to this website");
  const user = await websiteUserById(c.env.DB, website.id, payload.sub);
  if (!user) fail(404, "Website user not found");
  return c.json(websiteUserPublic(user));
});

app.get("/auth/:provider/login", oauthLogin);

app.get("/auth/:provider/callback", oauthCallback);

export default app;

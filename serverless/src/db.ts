import type { ApiTokenScope, UserApiTokenRow, UserRow, WebsiteRow, WebsiteUserRow } from "./types";

export function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

export async function first<T>(stmt: D1PreparedStatement): Promise<T | null> {
  return await stmt.first<T>();
}

export async function all<T>(stmt: D1PreparedStatement): Promise<T[]> {
  const result = await stmt.all<T>();
  return result.results || [];
}

export async function userById(db: D1Database, id: string): Promise<UserRow | null> {
  return first<UserRow>(db.prepare("SELECT * FROM users WHERE id = ?").bind(id));
}

export async function userByEmail(db: D1Database, email: string): Promise<UserRow | null> {
  return first<UserRow>(db.prepare("SELECT * FROM users WHERE lower(email) = lower(?)").bind(email));
}

export async function websiteById(db: D1Database, id: string): Promise<WebsiteRow | null> {
  return first<WebsiteRow>(db.prepare("SELECT * FROM websites WHERE id = ?").bind(id));
}

export async function websiteBySlug(db: D1Database, slug: string): Promise<WebsiteRow | null> {
  return first<WebsiteRow>(db.prepare("SELECT * FROM websites WHERE slug = ?").bind(slug));
}

export async function ownedWebsite(db: D1Database, ownerId: string, websiteId: string): Promise<WebsiteRow | null> {
  return first<WebsiteRow>(db.prepare("SELECT * FROM websites WHERE id = ? AND owner_id = ?").bind(websiteId, ownerId));
}

export async function countWhere(db: D1Database, sql: string, ...params: unknown[]): Promise<number> {
  const row = await first<{ n: number }>(db.prepare(sql).bind(...params));
  return Number(row?.n || 0);
}

export async function apiTokenById(db: D1Database, ownerId: string, id: string): Promise<UserApiTokenRow | null> {
  return first<UserApiTokenRow>(db.prepare("SELECT * FROM user_api_tokens WHERE id = ? AND owner_id = ?").bind(id, ownerId));
}

export async function activeApiTokenByHash(db: D1Database, tokenHash: string): Promise<(UserApiTokenRow & { owner_email: string }) | null> {
  return first<UserApiTokenRow & { owner_email: string }>(
    db.prepare(
      "SELECT t.*, u.email AS owner_email FROM user_api_tokens t JOIN users u ON u.id = t.owner_id WHERE t.token_hash = ? AND t.is_active = 1",
    ).bind(tokenHash),
  );
}

export async function websiteUserByEmail(db: D1Database, websiteId: string, email: string): Promise<WebsiteUserRow | null> {
  return first<WebsiteUserRow>(db.prepare("SELECT * FROM website_users WHERE website_id = ? AND lower(email) = lower(?)").bind(websiteId, email));
}

export async function websiteUserById(db: D1Database, websiteId: string, id: string): Promise<WebsiteUserRow | null> {
  return first<WebsiteUserRow>(db.prepare("SELECT * FROM website_users WHERE website_id = ? AND id = ?").bind(websiteId, id));
}

export function normalizeScope(scope: unknown): ApiTokenScope {
  const value = String(scope || "service").trim().toLowerCase();
  if (["service", "org_portal", "org_mcp", "org_admin"].includes(value)) return value as ApiTokenScope;
  return "service";
}

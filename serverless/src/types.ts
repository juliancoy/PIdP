export type ApiTokenScope = "service" | "org_portal" | "org_mcp" | "org_admin";
export type ActorType = "owner" | "website_user";

export interface Env {
  MCP_OAUTH_ISSUER?: string;
  MCP_OAUTH_PRIVATE_JWK?: string;
  MCP_OAUTH_PUBLIC_JWKS?: string;
  MCP_OAUTH_CLIENTS_JSON?: string;
  MCP_OAUTH_RESOURCES_JSON?: string;
  DB: D1Database;
  CF_VERSION_METADATA?: { id: string };
  AVATARS?: R2Bucket;
  APP_NAME?: string;
  ENV?: string;
  SECRET_KEY: string;
  ACCESS_TOKEN_EXPIRE_MINUTES?: string;
  SESSION_COOKIE_DOMAIN?: string;
  PORTAL_AUTH_ORIGINS?: string;
  ALLOWED_ORIGINS?: string;
  ADMIN_EMAILS?: string;
  ADMIN_USER_IDS?: string;
  SMOKE_TEST_SECRET?: string;
  PUBLIC_R2_BASE_URL?: string;
  PUBLIC_BASE_URL?: string;
  FRONTEND_REDIRECT_URL?: string;
  NATIVE_REDIRECT_SCHEMES?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GOOGLE_REDIRECT_URI?: string;
  GOOGLE_CALENDAR_REDIRECT_URI?: string;
  MICROSOFT_CLIENT_ID?: string;
  MICROSOFT_CLIENT_SECRET?: string;
  MICROSOFT_REDIRECT_URI?: string;
  MICROSOFT_CALENDAR_REDIRECT_URI?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_REDIRECT_URI?: string;
}

export interface UserRow {
  id: string;
  email: string;
  hashed_password: string | null;
  full_name: string | null;
  provider: string | null;
  provider_account_id: string | null;
  identity_data: string;
  is_active: number;
  created_at: string;
}

export interface WebsiteRow {
  id: string;
  owner_id: string;
  name: string;
  slug: string;
  description: string | null;
  login_hosts: string;
  allowed_redirect_origins: string;
  branding: string;
  user_schema: string;
  max_users: number;
  created_at: string;
}

export interface WebsiteUserRow {
  id: string;
  website_id: string;
  email: string;
  hashed_password: string | null;
  full_name: string | null;
  provider: string | null;
  provider_account_id: string | null;
  identity_data: string;
  is_active: number;
  created_at: string;
}

export interface UserApiTokenRow {
  id: string;
  owner_id: string;
  name: string;
  token_hash: string;
  scope: ApiTokenScope;
  is_active: number;
  last_used_at: string | null;
  created_at: string;
}

export interface JwtPayload {
  sub: string;
  email?: string;
  exp: number;
  actor_type?: ActorType;
  website_id?: string;
  is_sysadmin?: boolean;
}

export interface WebsiteSchemaField {
  type?: "string" | "number" | "boolean" | "array" | "object";
  required?: boolean;
  label?: string | null;
  description?: string | null;
  system?: boolean;
}

export interface SocialProfile {
  email: string;
  full_name: string | null;
  provider_account_id: string;
  avatar_url: string | null;
  raw: Record<string, unknown>;
}

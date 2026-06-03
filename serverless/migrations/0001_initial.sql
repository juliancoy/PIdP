PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  hashed_password TEXT,
  full_name TEXT,
  provider TEXT,
  provider_account_id TEXT,
  identity_data TEXT NOT NULL DEFAULT '{}',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_account ON users(provider, provider_account_id);

CREATE TABLE IF NOT EXISTS websites (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT,
  login_hosts TEXT NOT NULL DEFAULT '[]',
  allowed_redirect_origins TEXT NOT NULL DEFAULT '[]',
  branding TEXT NOT NULL DEFAULT '{}',
  user_schema TEXT NOT NULL DEFAULT '{}',
  max_users INTEGER NOT NULL DEFAULT 10,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_websites_owner_id ON websites(owner_id);
CREATE INDEX IF NOT EXISTS idx_websites_slug ON websites(slug);

CREATE TABLE IF NOT EXISTS website_users (
  id TEXT PRIMARY KEY,
  website_id TEXT NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  hashed_password TEXT,
  full_name TEXT,
  provider TEXT,
  provider_account_id TEXT,
  identity_data TEXT NOT NULL DEFAULT '{}',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (website_id, email),
  UNIQUE (website_id, provider, provider_account_id)
);

CREATE INDEX IF NOT EXISTS idx_website_users_website_id ON website_users(website_id);
CREATE INDEX IF NOT EXISTS idx_website_users_email ON website_users(email);

CREATE TABLE IF NOT EXISTS user_api_tokens (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL DEFAULT 'service',
  is_active INTEGER NOT NULL DEFAULT 1,
  last_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (owner_id, name)
);

CREATE INDEX IF NOT EXISTS idx_user_api_tokens_owner_id ON user_api_tokens(owner_id);
CREATE INDEX IF NOT EXISTS idx_user_api_tokens_token_hash ON user_api_tokens(token_hash);

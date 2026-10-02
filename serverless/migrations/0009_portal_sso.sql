CREATE TABLE IF NOT EXISTS portal_sso_requests (
 id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, origin TEXT NOT NULL,
 next TEXT NOT NULL, website_id TEXT NOT NULL, app TEXT NOT NULL,
 subject TEXT, code_hash TEXT, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_sso_expiry ON portal_sso_requests(expires_at);
CREATE TABLE IF NOT EXISTS portal_sso_limits (
 ip_hash TEXT PRIMARY KEY, window_start INTEGER NOT NULL, requests INTEGER NOT NULL
);

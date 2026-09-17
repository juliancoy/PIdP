CREATE TABLE mcp_oauth_logins (
  id TEXT PRIMARY KEY,
  browser_hash TEXT NOT NULL,
  resource TEXT NOT NULL,
  return_path TEXT NOT NULL,
  subject TEXT,
  display TEXT,
  code_hash TEXT UNIQUE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX mcp_oauth_logins_expiry ON mcp_oauth_logins(expires_at);
CREATE INDEX mcp_oauth_logins_browser ON mcp_oauth_logins(browser_hash);

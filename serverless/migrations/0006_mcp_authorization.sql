CREATE TABLE mcp_oauth_requests (
  id TEXT PRIMARY KEY, session_hash TEXT NOT NULL, subject TEXT NOT NULL,
  client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, resource TEXT NOT NULL,
  scope TEXT NOT NULL, challenge TEXT NOT NULL, state TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE mcp_oauth_codes (
  hash TEXT PRIMARY KEY, subject TEXT NOT NULL, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL,
  challenge TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE mcp_oauth_grants (
  id TEXT PRIMARY KEY, subject TEXT NOT NULL, client_id TEXT NOT NULL,
  resource TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE mcp_oauth_refresh (
  hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES mcp_oauth_grants(id),
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX mcp_oauth_grants_subject ON mcp_oauth_grants(subject);
CREATE INDEX mcp_oauth_requests_expiry ON mcp_oauth_requests(expires_at);
CREATE INDEX mcp_oauth_codes_expiry ON mcp_oauth_codes(expires_at);

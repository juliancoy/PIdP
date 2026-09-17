CREATE TABLE mcp_oauth_clients (
  id TEXT PRIMARY KEY,
  client_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE mcp_oauth_registration_limits (
  id TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  requests INTEGER NOT NULL
);
CREATE INDEX mcp_oauth_registration_limits_window ON mcp_oauth_registration_limits(window_start);

CREATE TABLE IF NOT EXISTS oauth_states (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  state_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_provider_nonce ON oauth_states(provider, nonce_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

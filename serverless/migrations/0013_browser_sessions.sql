-- Remembered browser sessions: 30-day inactivity, 90-day absolute limit.
-- Store only a hash of the random session identifier. Account deletion cascades.
CREATE TABLE browser_sessions (
  id_hash TEXT PRIMARY KEY,
  owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  website_user_id TEXT REFERENCES website_users(id) ON DELETE CASCADE,
  website_id TEXT REFERENCES websites(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  CHECK ((owner_id IS NOT NULL AND website_user_id IS NULL AND website_id IS NULL)
      OR (owner_id IS NULL AND website_user_id IS NOT NULL AND website_id IS NOT NULL))
);
CREATE INDEX browser_sessions_expiry ON browser_sessions(expires_at);
-- Carry the original authentication time across a one-use tenant handoff.
ALTER TABLE portal_sso_requests ADD COLUMN auth_time INTEGER;

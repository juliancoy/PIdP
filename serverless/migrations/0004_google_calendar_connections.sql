CREATE TABLE IF NOT EXISTS google_calendar_connections (
  owner_user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  google_user_id TEXT NOT NULL,
  google_email TEXT,
  calendar_id TEXT NOT NULL DEFAULT 'primary',
  refresh_token_encrypted TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  sync_busy INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_google_calendar_connections_google_user_id
  ON google_calendar_connections(google_user_id);

CREATE TABLE IF NOT EXISTS google_calendar_service_links (
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  external_service_id TEXT NOT NULL,
  calendar_id TEXT NOT NULL DEFAULT 'primary',
  google_event_id TEXT NOT NULL,
  summary TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (owner_user_id, external_service_id)
);

CREATE TABLE IF NOT EXISTS microsoft_calendar_connections (
  owner_user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  microsoft_user_id TEXT NOT NULL,
  microsoft_email TEXT,
  calendar_id TEXT NOT NULL DEFAULT 'primary',
  refresh_token_encrypted TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_microsoft_calendar_connections_microsoft_user_id
  ON microsoft_calendar_connections(microsoft_user_id);

CREATE TABLE IF NOT EXISTS microsoft_calendar_event_links (
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  external_event_id TEXT NOT NULL,
  calendar_id TEXT NOT NULL DEFAULT 'primary',
  microsoft_event_id TEXT NOT NULL,
  summary TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (owner_user_id, external_event_id)
);

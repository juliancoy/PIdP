-- Ephemeral PKCE handoff metadata; removed on consumption or after ten minutes.
CREATE TABLE portal_desktop_requests (
 id TEXT PRIMARY KEY,
 redirect_uri TEXT NOT NULL,
 challenge TEXT NOT NULL,
 state TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX portal_desktop_requests_expiry ON portal_desktop_requests(expires_at);

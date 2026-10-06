CREATE TABLE account_identity_links (
 subject TEXT PRIMARY KEY,
 canonical_user_id TEXT NOT NULL REFERENCES users(id),
 website_id TEXT NOT NULL REFERENCES websites(id),
 website_user_id TEXT NOT NULL REFERENCES website_users(id),
 linked_at TEXT NOT NULL,
 UNIQUE(website_id,website_user_id)
);
CREATE INDEX account_identity_links_person ON account_identity_links(canonical_user_id);
CREATE TABLE account_identity_link_previews (
 id TEXT PRIMARY KEY,
 canonical_user_id TEXT NOT NULL REFERENCES users(id),
 subject TEXT NOT NULL,
 website_id TEXT NOT NULL REFERENCES websites(id),
 website_user_id TEXT NOT NULL REFERENCES website_users(id),
 proof_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 applied_at TEXT
);
CREATE TABLE account_identity_link_requests (
 id TEXT PRIMARY KEY,
 canonical_user_id TEXT NOT NULL REFERENCES users(id),
 website_id TEXT NOT NULL REFERENCES websites(id),
 browser_hash TEXT NOT NULL UNIQUE,
 primary_proof_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 subject TEXT,
 used_at TEXT
);

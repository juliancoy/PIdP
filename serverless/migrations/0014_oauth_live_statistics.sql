-- Anonymous daily stage counters, retained for 30 days. No account or client identifiers.
CREATE TABLE oauth_live_statistics (
 day TEXT NOT NULL,stage TEXT NOT NULL,outcome TEXT NOT NULL,
 requests INTEGER NOT NULL,total_ms INTEGER NOT NULL,max_ms INTEGER NOT NULL,
 PRIMARY KEY(day,stage,outcome)
);

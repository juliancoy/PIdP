-- Split UUID collisions between users.id and website_users.id.
-- Safe to run repeatedly; only rows with direct collisions are updated.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

WITH collisions AS (
  SELECT w.id
  FROM website_users w
  JOIN users u ON u.id = w.id
)
UPDATE website_users w
SET id = gen_random_uuid()
FROM collisions c
WHERE w.id = c.id;

-- Verify no remaining collisions.
SELECT COUNT(*) AS remaining_collisions
FROM website_users w
JOIN users u ON w.id = u.id;

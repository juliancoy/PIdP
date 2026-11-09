-- Fail closed on pre-existing collisions; never merge identities by email.
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_normalized ON users(lower(trim(email)));
CREATE UNIQUE INDEX IF NOT EXISTS uq_website_users_email_normalized ON website_users(website_id,lower(trim(email)));

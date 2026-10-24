-- DRAFT for separate review and authorization; not an automatic release migration.
-- Legacy subjects remain aliases.
-- An email-only collision must never establish account ownership.
-- Execute only through the atomic D1 batch helper; ?1 is the configured app slug.
SELECT CASE WHEN (SELECT count(*) FROM websites WHERE slug=?1)<>1
 OR EXISTS (SELECT lower(m.email) FROM website_users m JOIN websites w ON w.id=m.website_id
 WHERE w.slug=?1 GROUP BY lower(m.email) HAVING count(*)>1)
 OR EXISTS (SELECT lower(email) FROM users GROUP BY lower(email) HAVING count(*)>1)
 THEN json('Missing application or ambiguous email') ELSE 1 END;

SELECT CASE WHEN EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 LEFT JOIN account_identity_links l ON l.website_user_id=m.id AND l.website_id=m.website_id
 LEFT JOIN users u ON lower(u.email)=lower(m.email)
 WHERE w.slug=?1 AND l.subject IS NULL AND u.id IS NOT NULL
 AND NOT COALESCE(m.provider IS NOT NULL AND m.provider_account_id IS NOT NULL
   AND m.provider_account_id<>'' AND u.provider=m.provider AND u.provider_account_id=m.provider_account_id,0)
) OR EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 JOIN users u ON u.id=m.id WHERE w.slug=?1 AND lower(u.email)<>lower(m.email)
) THEN json('Unverified legacy account collision') ELSE 1 END;

INSERT INTO users(id,email,hashed_password,full_name,provider,provider_account_id,identity_data,is_active,created_at)
SELECT m.id,m.email,m.hashed_password,m.full_name,m.provider,m.provider_account_id,m.identity_data,m.is_active,m.created_at
FROM website_users m JOIN websites w ON w.id=m.website_id
WHERE w.slug=?1
 AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id AND l.website_id=m.website_id)
 AND NOT EXISTS(SELECT 1 FROM users u WHERE lower(u.email)=lower(m.email));

INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
SELECT 'website:'||m.website_id||':'||m.id,u.id,m.website_id,m.id,strftime('%Y-%m-%dT%H:%M:%fZ','now')
FROM website_users m JOIN websites w ON w.id=m.website_id
JOIN users u ON u.id=m.id OR (u.provider=m.provider AND u.provider_account_id=m.provider_account_id
 AND m.provider_account_id IS NOT NULL AND m.provider_account_id<>'' AND lower(u.email)=lower(m.email))
WHERE w.slug=?1
 AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id AND l.website_id=m.website_id);

SELECT CASE WHEN EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 LEFT JOIN account_identity_links l ON l.website_user_id=m.id AND l.website_id=m.website_id
 LEFT JOIN users u ON u.id=l.canonical_user_id
 WHERE w.slug=?1 AND (u.id IS NULL OR
 m.is_active<>u.is_active)
) THEN json('Legacy credential migration incomplete or conflicting') ELSE 1 END;

-- Existing primary credentials remain authoritative. Never add a member password
-- to an existing primary account; new accounts already received their password.
UPDATE website_users SET hashed_password=NULL WHERE website_id IN (SELECT id FROM websites WHERE slug=?1);

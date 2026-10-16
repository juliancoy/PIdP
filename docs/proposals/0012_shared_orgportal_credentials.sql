-- DRAFT for separate review and authorization; not an automatic release migration.
-- Legacy subjects remain aliases.
-- An email-only collision must never establish account ownership.
SELECT CASE WHEN EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 LEFT JOIN account_identity_links l ON l.website_user_id=m.id AND l.website_id=m.website_id
 LEFT JOIN users u ON lower(u.email)=lower(m.email)
 WHERE w.slug='code-collective' AND l.subject IS NULL AND u.id IS NOT NULL
 AND NOT COALESCE(m.provider IS NOT NULL AND m.provider_account_id IS NOT NULL
   AND m.provider_account_id<>'' AND u.provider=m.provider AND u.provider_account_id=m.provider_account_id,0)
) OR EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 JOIN users u ON u.id=m.id WHERE w.slug='code-collective' AND lower(u.email)<>lower(m.email)
) THEN json('Unverified legacy account collision') ELSE 1 END;

INSERT INTO users(id,email,hashed_password,full_name,provider,provider_account_id,identity_data,is_active,created_at)
SELECT m.id,m.email,m.hashed_password,m.full_name,m.provider,m.provider_account_id,m.identity_data,m.is_active,m.created_at
FROM website_users m JOIN websites w ON w.id=m.website_id
WHERE w.slug='code-collective'
 AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id AND l.website_id=m.website_id)
 AND NOT EXISTS(SELECT 1 FROM users u WHERE lower(u.email)=lower(m.email));

INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
SELECT 'website:'||m.website_id||':'||m.id,u.id,m.website_id,m.id,strftime('%Y-%m-%dT%H:%M:%fZ','now')
FROM website_users m JOIN websites w ON w.id=m.website_id
JOIN users u ON u.id=m.id OR (u.provider=m.provider AND u.provider_account_id=m.provider_account_id
 AND m.provider_account_id IS NOT NULL AND m.provider_account_id<>'' AND lower(u.email)=lower(m.email))
WHERE w.slug='code-collective'
 AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id AND l.website_id=m.website_id);

SELECT CASE WHEN EXISTS (
 SELECT 1 FROM website_users m JOIN websites w ON w.id=m.website_id
 LEFT JOIN account_identity_links l ON l.website_user_id=m.id AND l.website_id=m.website_id
 LEFT JOIN users u ON u.id=l.canonical_user_id
 WHERE w.slug='code-collective' AND (u.id IS NULL OR
 (m.hashed_password IS NOT NULL AND u.hashed_password IS NOT NULL AND m.hashed_password<>u.hashed_password))
) THEN json('Legacy credential migration incomplete or conflicting') ELSE 1 END;

UPDATE users SET hashed_password=COALESCE(hashed_password,(
 SELECT m.hashed_password FROM website_users m JOIN account_identity_links l ON l.website_user_id=m.id AND l.website_id=m.website_id
 JOIN websites w ON w.id=m.website_id WHERE w.slug='code-collective' AND l.canonical_user_id=users.id AND m.hashed_password IS NOT NULL LIMIT 1
)) WHERE id IN (SELECT l.canonical_user_id FROM account_identity_links l JOIN websites w ON w.id=l.website_id WHERE w.slug='code-collective');

UPDATE website_users SET hashed_password=NULL WHERE website_id IN (SELECT id FROM websites WHERE slug='code-collective');

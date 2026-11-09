import type { Env } from './types';

export async function portalDirectoryAliases(env: Env, ownerId: string) {
 const site = await env.DB.prepare('SELECT id,owner_id FROM websites WHERE slug=?').bind(env.PORTAL_SSO_APP_SLUG || 'orgportal').first<{id:string;owner_id:string}>();
 if (!site || site.owner_id !== ownerId) throw new Error('Portal owner required');
 const rows=await env.DB.prepare(`SELECT l.website_user_id AS account_id,l.canonical_user_id
  FROM account_identity_links l JOIN users u ON u.id=l.canonical_user_id
  JOIN website_users m ON m.id=l.website_user_id AND m.website_id=l.website_id
  WHERE l.website_id=? ORDER BY l.website_user_id`).bind(site.id).all<{account_id:string;canonical_user_id:string}>();
 return (rows.results || []).map(row=>({account_id:row.account_id,canonical_user_id:row.canonical_user_id}));
}

/** Fresh verified Google subject is proof; an email match on its own is never a link. */
export async function linkVerifiedPortalProvider(env:Env,provider:string,profile:{email:string;provider_account_id:string;raw:Record<string,unknown>}) {
 if(provider!=='google'||profile.raw.email_verified!==true||!profile.provider_account_id||!profile.email.trim())return;
 await env.DB.prepare(`INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
  SELECT 'website:'||m.website_id||':'||m.id,u.id,m.website_id,m.id,?
  FROM website_users m JOIN websites w ON w.id=m.website_id
  JOIN users u ON u.provider=m.provider AND u.provider_account_id=m.provider_account_id
    AND lower(trim(u.email))=lower(trim(m.email))
  WHERE w.slug=? AND m.provider='google' AND m.provider_account_id=? AND lower(trim(m.email))=?
    AND m.is_active=1 AND u.is_active=1
    AND (SELECT count(*) FROM users p WHERE p.provider='google' AND p.provider_account_id=m.provider_account_id)=1
    AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id)
  ON CONFLICT(subject) DO NOTHING`).bind(new Date().toISOString(),env.PORTAL_SSO_APP_SLUG||'orgportal',profile.provider_account_id,profile.email.trim().toLowerCase()).run();
}

/** Basic portal identity only; contact details and unrelated tenants stay private. */
export async function portalDirectoryPeople(env:Env,ownerId:string) {
 const rows=await env.DB.prepare(`SELECT m.id user_id,m.full_name user_name FROM website_users m
  JOIN websites w ON w.id=m.website_id WHERE w.slug=? AND w.owner_id=? AND m.is_active=1 ORDER BY m.id`)
  .bind(env.PORTAL_SSO_APP_SLUG||'orgportal',ownerId).all<{user_id:string;user_name:string|null}>();
 return (rows.results||[]).map(row=>({user_id:row.user_id,user_name:row.user_name?.trim()&&!row.user_name.includes('@')?row.user_name.trim():'Portal member'}));
}

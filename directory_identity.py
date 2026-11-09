"""Canonical portal aliases; no email-only account linking or credential migration."""
from datetime import datetime, timezone
from sqlalchemy import select, text
from models import User, Website, WebsiteUser, AccountIdentityLink

async def portal_directory_aliases(session, owner_id, app_slug):
    site = (await session.execute(select(Website).where(Website.slug == app_slug))).scalar_one_or_none()
    if not site or site.owner_id != owner_id:
        raise PermissionError('Portal owner required')
    rows = (await session.execute(select(AccountIdentityLink.website_user_id, AccountIdentityLink.canonical_user_id)
        .join(User, User.id == AccountIdentityLink.canonical_user_id)
        .join(WebsiteUser, (WebsiteUser.id == AccountIdentityLink.website_user_id) & (WebsiteUser.website_id == AccountIdentityLink.website_id))
        .where(AccountIdentityLink.website_id == site.id))).all()
    return [dict(account_id=str(account), canonical_user_id=str(person)) for account, person in rows]

async def link_verified_portal_provider(session, provider, profile, app_slug):
    if provider != 'google' or (profile.get('raw') or {}).get('email_verified') is not True or not profile.get('provider_account_id') or not profile.get('email'):
        return
    await session.execute(text("""INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
      SELECT 'website:'||CAST(m.website_id AS TEXT)||':'||CAST(m.id AS TEXT),u.id,m.website_id,m.id,:at
      FROM website_users m JOIN websites w ON w.id=m.website_id
      JOIN users u ON u.provider=m.provider AND u.provider_account_id=m.provider_account_id
        AND lower(trim(u.email))=lower(trim(m.email))
      WHERE w.slug=:app AND m.provider='google' AND m.provider_account_id=:provider_id AND lower(trim(m.email))=:email
        AND m.is_active=true AND u.is_active=true
        AND (SELECT count(*) FROM users p WHERE p.provider='google' AND p.provider_account_id=m.provider_account_id)=1
        AND NOT EXISTS(SELECT 1 FROM account_identity_links l WHERE l.website_user_id=m.id)
      ON CONFLICT(subject) DO NOTHING"""), dict(at=datetime.now(timezone.utc).isoformat(), app=app_slug,
        provider_id=str(profile['provider_account_id']), email=profile['email'].strip().lower()))

async def portal_directory_people(session, owner_id, app_slug):
    """Basic active portal names only, scoped to its owner; no private contacts."""
    rows = (await session.execute(text("""SELECT m.id user_id,m.full_name user_name
        FROM website_users m JOIN websites w ON w.id=m.website_id
        WHERE w.slug=:app AND w.owner_id=:owner AND m.is_active=true ORDER BY m.id"""),
        dict(app=app_slug, owner=owner_id))).all()
    return [dict(user_id=str(account), user_name=name.strip() if name and name.strip() and '@' not in name else 'Portal member') for account, name in rows]

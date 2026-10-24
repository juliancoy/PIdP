"""Consolidate the shared portal credentials; default is a read-only preview."""
import argparse
import asyncio
from datetime import datetime, timezone
from sqlalchemy import select, func, text
from db import SessionLocal
from config import settings
from models import User, Website, WebsiteUser, AccountIdentityLink

async def migrate(apply=False, app_slug=None, writes_paused=False, backup_verified=False):
    if apply and not (writes_paused and backup_verified):
        raise RuntimeError("Pause identity writes and verify the pre-migration backup first")
    app_slug = app_slug or settings.portal_sso_app_slug
    if not app_slug or app_slug != settings.portal_sso_app_slug:
        raise RuntimeError("Target must match configured PORTAL_SSO_APP_SLUG")
    if settings.portal_shared_identity:
        raise RuntimeError("Run before enabling shared identity, with identity writes paused")
    async with SessionLocal() as session:
        async with session.begin():
            if apply:
                # Prevent registrations, password changes and link changes during planning/apply.
                await session.execute(text('LOCK TABLE websites, users, website_users, account_identity_links IN SHARE ROW EXCLUSIVE MODE'))
            website = (await session.execute(select(Website).where(Website.slug == app_slug))).scalar_one_or_none()
            if not website:
                raise RuntimeError('Configured portal application does not exist')
            members = (await session.execute(select(WebsiteUser).where(WebsiteUser.website_id == website.id))).scalars().all()
            created = linked = retained_primary_passwords = 0
            emails = [member.email.lower() for member in members]
            if len(emails) != len(set(emails)):
                raise RuntimeError("Case-insensitive duplicate member emails require resolution")
            duplicate = (await session.execute(select(func.lower(User.email)).group_by(func.lower(User.email)).having(func.count() > 1))).first()
            if duplicate:
                raise RuntimeError("Case-insensitive duplicate primary emails require resolution")
            plan = []
            for member in members:
                link = (await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.website_id == website.id, AccountIdentityLink.website_user_id == member.id))).scalar_one_or_none()
                person = await session.get(User, link.canonical_user_id) if link else (await session.execute(select(User).where(func.lower(User.email) == member.email.lower()))).scalar_one_or_none()
                if link and not person:
                    raise RuntimeError("Identity link refers to a missing primary account")
                if person and person.is_active != member.is_active:
                    raise RuntimeError("Account active states differ; resolve before migration")
                if person and not link and not (member.provider and member.provider_account_id and person.provider == member.provider and person.provider_account_id == member.provider_account_id):
                    raise RuntimeError('Unverified legacy account collision; authenticate both accounts before migration')
                if not person:
                    if await session.get(User, member.id):
                        raise RuntimeError('Legacy account ID collision')
                    person = User(id=member.id, email=member.email, hashed_password=member.hashed_password, full_name=member.full_name, provider=member.provider, provider_account_id=member.provider_account_id, identity_data=member.identity_data, is_active=member.is_active, created_at=member.created_at)
                    created += 1
                if member.hashed_password and person.hashed_password and member.hashed_password != person.hashed_password:
                    retained_primary_passwords += 1
                if not link:
                    linked += 1
                plan.append((member, person, link))
            if apply:
                for member, person, link in plan:
                    session.add(person)
                    await session.flush()
                    if not link:
                        session.add(AccountIdentityLink(subject=f'website:{member.website_id}:{member.id}', canonical_user_id=person.id, website_id=member.website_id, website_user_id=member.id, linked_at=datetime.now(timezone.utc).isoformat()))
                    member.hashed_password = None
            return {'app': app_slug, 'retained_primary_passwords': retained_primary_passwords, 'accounts': len(members), 'created': created, 'linked': linked, 'applied': apply}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--app', required=True, help='Must match configured PORTAL_SSO_APP_SLUG')
    parser.add_argument("--writes-paused", action="store_true")
    parser.add_argument("--backup-verified", action="store_true")
    args = parser.parse_args()
    print(asyncio.run(migrate(args.apply, args.app, args.writes_paused, args.backup_verified)))

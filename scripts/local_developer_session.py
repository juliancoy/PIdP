"""Mint a synthetic member session for the host-side local-login helper only.

Run through local-login, which verifies the identity/database Docker containers.
No HTTP route or production authentication shortcut is installed.
"""
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import settings
from db import SessionLocal, engine
from models import User, Website, WebsiteUser
from security import create_access_token
from sqlalchemy import select


async def main():
    if os.environ.get('ORGPORTAL_LOCAL_DEVELOPER_SESSION') != '1':
        raise RuntimeError('Use the host-side local-login command.')
    if urlsplit(settings.public_base_url or '').hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise RuntimeError('Developer sessions require a loopback identity deployment.')
    try:
        async with SessionLocal() as session:
            if '--admin' in sys.argv:
                owner_id = uuid5(NAMESPACE_URL, 'orgportal:local-developer-admin')
                if str(owner_id) not in settings.admin_user_ids_list:
                    raise RuntimeError('The synthetic local administrator must be explicitly allowlisted.')
                email = 'administrator@local.orgportal.example.com'
                owner = await session.get(User, owner_id)
                collision = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
                if collision is not None and collision.id != owner_id:
                    raise RuntimeError('The reserved local administrator identity is already in use.')
                if owner is None:
                    owner = User(id=owner_id, email=email, full_name='Local Administrator',
                                 identity_data={'local_developer': True}, is_active=True)
                    session.add(owner)
                    await session.commit()
                if owner.email != email or not owner.is_active:
                    raise RuntimeError('The reserved local administrator account is disabled or conflicts.')
                settings.access_token_expire_minutes = min(settings.access_token_expire_minutes, 480)
                token = create_access_token(str(owner.id), owner.email, {'is_sysadmin': True})
                print(json.dumps({'token': token, 'member_id': str(owner.id), 'email': email,
                                  'admin': True, 'max_age': settings.access_token_expire_minutes * 60}))
                return
            website = (await session.execute(select(Website).where(
                Website.slug == settings.portal_sso_app_slug))).scalar_one_or_none()
            if website is None:
                raise RuntimeError('Start the local deployment to register its portal first.')
            member_id = uuid5(NAMESPACE_URL, f'orgportal:local-developer:{website.id}')
            email = 'developer@local.orgportal.example.com'
            member = await session.get(WebsiteUser, member_id)
            if member is not None and member.email == 'developer@orgportal.local.invalid':
                member.email = email
                await session.commit()
            member = (await session.execute(select(WebsiteUser).where(
                WebsiteUser.website_id == website.id, WebsiteUser.email == email))).scalar_one_or_none()
            if member is not None and member.id != member_id:
                raise RuntimeError('The reserved local fixture identity conflicts with an existing account.')
            if member is None:
                member = WebsiteUser(id=member_id, website_id=website.id, email=email,
                    full_name='Local Developer', identity_data={'local_developer': True}, is_active=True)
                session.add(member)
                await session.commit()
            if not member.is_active:
                raise RuntimeError('The local developer account is disabled.')
            settings.access_token_expire_minutes = min(settings.access_token_expire_minutes, 480)
            token = create_access_token(str(member.id), member.email, {
                'actor_type': 'website_user', 'website_id': str(website.id)})
            # Captured by the host helper. Never print this subprocess output to a terminal.
            print(json.dumps({'token': token, 'member_id': str(member.id), 'email': email,
                              'max_age': settings.access_token_expire_minutes * 60}))
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())

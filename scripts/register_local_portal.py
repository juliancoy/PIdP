"""Register the configured portal in local PIdP and its synthetic administrator."""
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import settings
from db import SessionLocal, engine
from models import User, Website
from sqlalchemy import select, text
from local_admin import provision_local_admin


async def register():
    origin = urlsplit(settings.public_base_url or '')
    if origin.hostname not in {'localhost', 'id.localhost', '127.0.0.1', '::1', '192.168.50.141'}:
        raise RuntimeError('Local portal registration requires the configured local machine address.')
    slug = settings.portal_sso_app_slug
    if not slug:
        raise RuntimeError('PORTAL_SSO_APP_SLUG is required.')
    async with SessionLocal() as session:
        # Serialize registration and the one-time application rename.
        await session.execute(text("SELECT pg_advisory_xact_lock(736410229)"))
        website = (await session.execute(select(Website).where(Website.slug == slug))).scalar_one_or_none()
        if slug == 'orgportal':
            previous = (await session.execute(select(Website).where(
                Website.slug == 'code-collective'))).scalar_one_or_none()
            if website is not None and previous is not None:
                raise RuntimeError('Conflicting OrgPortal registrations require review before startup.')
            if website is None and previous is not None:
                website = previous
                website.slug = 'orgportal'
                website.name = 'OrgPortal'
                website.description = 'One OrgPortal account for all groups.'
                await session.commit()
        if website is None:
            owner_id = uuid5(NAMESPACE_URL, 'orgportal:local-registration-owner')
            if await session.get(User, owner_id) is None:
                session.add(User(id=owner_id, email='registration@orgportal.local.invalid',
                    full_name='Local application registration', is_active=False))
                await session.flush()
            session.add(Website(owner_id=owner_id, slug=slug, name='Local OrgPortal',
                login_hosts=[origin.netloc], allowed_redirect_origins=[f'{origin.scheme}://{origin.netloc}']))
            await session.commit()
            print(f'Registered local portal application: {slug}')
        else:
            website.login_hosts = list(dict.fromkeys([*(website.login_hosts or []), origin.netloc]))
            website.allowed_redirect_origins = list(dict.fromkeys([*(website.allowed_redirect_origins or []), f'{origin.scheme}://{origin.netloc}']))
            await session.commit()
            print(f'Local portal application updated: {slug}')
        if origin.hostname in {'localhost', 'id.localhost', '127.0.0.1', '::1'}:
            admin = await provision_local_admin(session)
            print(f'Local administrator provisioned: {admin.email}')


async def main():
    try:
        await register()
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())

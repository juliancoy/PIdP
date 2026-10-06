"""Register the configured portal in local PIdP without granting account access."""
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


async def register():
    origin = urlsplit(settings.public_base_url or '')
    if origin.hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise RuntimeError('Local portal registration requires a loopback PUBLIC_BASE_URL.')
    slug = settings.portal_sso_app_slug
    if not slug:
        raise RuntimeError('PORTAL_SSO_APP_SLUG is required.')
    async with SessionLocal() as session:
        # Serialize repeat startup calls; never change an existing registration.
        await session.execute(text("SELECT pg_advisory_xact_lock(736410229)"))
        website = (await session.execute(select(Website).where(Website.slug == slug))).scalar_one_or_none()
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
            print(f'Local portal application already registered: {slug}')


async def main():
    try:
        await register()
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())

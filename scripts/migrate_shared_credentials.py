"""Consolidate the shared portal credentials; default is a read-only preview."""
import argparse
import asyncio
from sqlalchemy import select
from db import SessionLocal
from models import User, Website, WebsiteUser, AccountIdentityLink

async def migrate(apply=False):
    async with SessionLocal() as session:
        async with session.begin():
            website = (await session.execute(select(Website).where(Website.slug == 'code-collective'))).scalar_one_or_none()
            if not website:
                return {'accounts': 0, 'created': 0, 'linked': 0, 'applied': apply}
            members = (await session.execute(select(WebsiteUser).where(WebsiteUser.website_id == website.id))).scalars().all()
            created = linked = 0
            plan = []
            for member in members:
                link = (await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.website_id == website.id, AccountIdentityLink.website_user_id == member.id))).scalar_one_or_none()
                person = await session.get(User, link.canonical_user_id) if link else (await session.execute(select(User).where(User.email == member.email))).scalar_one_or_none()
                if person and not link and not (member.provider and member.provider_account_id and person.provider == member.provider and person.provider_account_id == member.provider_account_id):
                    raise RuntimeError('Unverified legacy account collision; authenticate both accounts before migration')
                if not person:
                    if await session.get(User, member.id):
                        raise RuntimeError('Legacy account ID collision')
                    person = User(id=member.id, email=member.email, hashed_password=member.hashed_password, full_name=member.full_name, provider=member.provider, provider_account_id=member.provider_account_id, identity_data=member.identity_data, is_active=member.is_active, created_at=member.created_at)
                    created += 1
                if member.hashed_password and person.hashed_password and member.hashed_password != person.hashed_password:
                    raise RuntimeError('Conflicting passwords; choose credentials after proving ownership')
                if not link:
                    linked += 1
                plan.append((member, person, link))
            if apply:
                for member, person, link in plan:
                    session.add(person)
                    if not person.hashed_password:
                        person.hashed_password = member.hashed_password
                    await session.flush()
                    if not link:
                        session.add(AccountIdentityLink(subject=f'website:{member.website_id}:{member.id}', canonical_user_id=person.id, website_id=member.website_id, website_user_id=member.id))
                    member.hashed_password = None
            return {'accounts': len(members), 'created': created, 'linked': linked, 'applied': apply}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    print(asyncio.run(migrate(parser.parse_args().apply)))

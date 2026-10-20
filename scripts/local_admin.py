"""Provision the reserved administrator in a loopback development deployment."""
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5
from sqlalchemy import select
from config import settings
from models import User


async def provision_local_admin(session):
    if settings.env != 'dev' or urlsplit(settings.public_base_url or '').hostname not in {'localhost', '127.0.0.1', '::1'}:
        raise RuntimeError('Administrator provisioning requires a local development deployment.')
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
    return owner

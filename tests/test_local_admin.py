import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import NAMESPACE_URL, uuid5

os.environ.setdefault('SECRET_KEY', 'local-admin-test-secret')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import local_admin


class LocalAdminTests(unittest.IsolatedAsyncioTestCase):
    async def test_remote_or_unallowlisted_setup_never_reads_database(self):
        session = SimpleNamespace(get=AsyncMock())
        for base, ids, env in [('https://orgportal.cc/pidp', 'reserved', 'dev'),
                               ('https://localhost:8443/pidp', '', 'dev'),
                               ('https://localhost:8443/pidp', 'reserved', 'production')]:
            with patch.multiple(local_admin.settings, public_base_url=base, admin_user_ids=ids, env=env):
                with self.assertRaises(RuntimeError):
                    await local_admin.provision_local_admin(session)
        session.get.assert_not_called()

    async def test_existing_admin_is_idempotent_and_disabled_account_is_not_reenabled(self):
        identity = uuid5(NAMESPACE_URL, 'orgportal:local-developer-admin')
        owner = SimpleNamespace(id=identity, email='administrator@local.orgportal.example.com', is_active=True)
        session = SimpleNamespace(get=AsyncMock(return_value=owner), execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: owner)), commit=AsyncMock())
        with patch.multiple(local_admin.settings, public_base_url='https://localhost:8443/pidp',
                            admin_user_ids=str(identity), env='dev'):
            self.assertIs(await local_admin.provision_local_admin(session), owner)
            self.assertIs(await local_admin.provision_local_admin(session), owner)
            session.commit.assert_not_called()
            owner.is_active = False
            with self.assertRaises(RuntimeError):
                await local_admin.provision_local_admin(session)

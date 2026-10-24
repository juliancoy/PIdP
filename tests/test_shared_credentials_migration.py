"""Real PostgreSQL migration checks, confined to a disposable test database/schema."""
import os
os.environ.setdefault('SECRET_KEY', 'migration-test-secret')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')
import unittest
from uuid import uuid4
from urllib.parse import urlsplit
from unittest.mock import patch
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from models import Base, User, Website, WebsiteUser, AccountIdentityLink
from scripts import migrate_shared_credentials as migration

@unittest.skipUnless(os.environ.get('PIDP_OAUTH_TEST_DATABASE_URL'), 'Requires isolated oauth_test PostgreSQL database')
class SharedCredentialsMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_preview_apply_idempotence_and_transaction_rollback(self):
        database = os.environ['PIDP_OAUTH_TEST_DATABASE_URL']
        url = urlsplit(database)
        self.assertIn(url.hostname, ('127.0.0.1', 'localhost'))
        self.assertEqual(url.path, '/oauth_test')
        schema = 'migration_' + uuid4().hex
        engine = create_async_engine(database, connect_args={'server_settings': {'search_path': schema}})
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        tables = [User.__table__, Website.__table__, WebsiteUser.__table__, AccountIdentityLink.__table__]
        owner, site, member, old = [uuid4() for _ in range(4)]
        try:
            async with engine.begin() as conn:
                await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
                await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=tables))
            async with sessions.begin() as session:
                session.add(User(id=owner, email='Primary@test', hashed_password='primary-hash'))
                await session.flush()
                session.add(Website(id=site, owner_id=owner, slug='orgportal', name='Portal'))
                await session.flush()
                session.add_all([WebsiteUser(id=member, website_id=site, email='new@test', hashed_password='new-hash'),
                    WebsiteUser(id=old, website_id=site, email='primary@test', hashed_password='other-salted-hash')])
                await session.flush()
                session.add(AccountIdentityLink(subject=f'website:{site}:{old}', canonical_user_id=owner,
                    website_id=site, website_user_id=old, linked_at='now'))
            with patch.object(migration, 'SessionLocal', sessions), patch.multiple(migration.settings,
                    portal_sso_app_slug='orgportal', portal_shared_identity=False):
                preview = await migration.migrate(app_slug='orgportal')
                self.assertEqual(preview['created'], 1)
                async with sessions() as session:
                    self.assertIsNone(await session.get(User, member))
                with self.assertRaises(RuntimeError):
                    await migration.migrate(True, 'orgportal')
                # Force a failure after the first member's writes have been flushed.
                async with sessions.begin() as session:
                    await session.execute(text(f"ALTER TABLE account_identity_links ADD CONSTRAINT reject_new CHECK (website_user_id <> '{member}')"))
                with self.assertRaises(Exception):
                    await migration.migrate(True, 'orgportal', True, True)
                async with sessions() as session:
                    self.assertIsNone(await session.get(User, member))
                    self.assertEqual((await session.get(WebsiteUser, member)).hashed_password, 'new-hash')
                async with sessions.begin() as session:
                    await session.execute(text('ALTER TABLE account_identity_links DROP CONSTRAINT reject_new'))
                result = await migration.migrate(True, 'orgportal', True, True)
                self.assertEqual(result['created'], 1)
                self.assertEqual((await migration.migrate(True, 'orgportal', True, True))['created'], 0)
                async with sessions() as session:
                    self.assertEqual((await session.get(User, member)).hashed_password, 'new-hash')
                    self.assertEqual((await session.get(User, owner)).hashed_password, 'primary-hash')
                    self.assertIsNone((await session.get(WebsiteUser, old)).hashed_password)
                    link = await session.get(AccountIdentityLink, f'website:{site}:{member}')
                    self.assertTrue(link.linked_at)
                    self.assertEqual(link.canonical_user_id, member)
        finally:
            async with engine.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            await engine.dispose()

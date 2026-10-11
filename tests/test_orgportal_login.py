import asyncio
import os
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

os.environ.setdefault('SECRET_KEY', 'local-migration-test')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')

from sqlalchemy import create_engine, text
from scripts import migrate_orgportal_login as migration


class OrgPortalLoginMigrationTests(unittest.TestCase):
    def test_rename_keeps_existing_accounts_and_is_idempotent(self):
        database = create_engine('sqlite://')
        try:
            with database.begin() as connection:
                connection.exec_driver_sql('CREATE TABLE websites(id TEXT PRIMARY KEY, slug TEXT UNIQUE, name TEXT, description TEXT)')
                connection.exec_driver_sql('CREATE TABLE website_users(id TEXT PRIMARY KEY, website_id TEXT REFERENCES websites(id))')
                connection.exec_driver_sql("INSERT INTO websites VALUES('shared-id','code-collective','Code Collective','')")
                connection.exec_driver_sql("INSERT INTO website_users VALUES('member-id','shared-id')")

            class LocalEngine:
                dispose = AsyncMock()

                @asynccontextmanager
                async def begin(self):
                    with database.begin() as connection:
                        class Adapter:
                            async def execute(self, statement):
                                return connection.execute(statement)
                        yield Adapter()

            with patch.object(migration, 'engine', LocalEngine()):
                asyncio.run(migration.main())
                asyncio.run(migration.main())
            with database.connect() as connection:
                self.assertEqual(connection.execute(text('SELECT id, slug, name FROM websites')).all(),
                                 [('shared-id', 'orgportal', 'OrgPortal')])
                self.assertEqual(connection.execute(text('SELECT id, website_id FROM website_users')).all(),
                                 [('member-id', 'shared-id')])
        finally:
            database.dispose()

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


class AdministratorLoginBrandingTests(unittest.IsolatedAsyncioTestCase):
    async def test_orgportal_owner_login_preserves_brand_and_authentication_lane(self):
        import main
        from starlette.requests import Request
        request = Request({'type':'http','method':'GET','path':'/app/login','query_string':b'owner=1','headers':[(b'host',b'orgportal.cc')],'scheme':'https','server':('orgportal.cc',443)})
        with patch.object(main, '_render_template', return_value='rendered') as render:
            await main.frontend_app_login(request, AsyncMock())
        context = render.call_args.args[2]
        self.assertEqual(context['page_title'], 'Sign in to OrgPortal')
        self.assertEqual(context['login_app_name'], 'OrgPortal')
        self.assertTrue(context['login_force_owner'])
        self.assertEqual(context['login_app_slug'], '')
        self.assertEqual(context['login_branding']['logo_url'], 'https://orgportal.cc/orgportal.svg')

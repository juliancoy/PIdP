import os
os.environ.setdefault('SECRET_KEY', 'retention-test-secret')
os.environ.setdefault('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')
import unittest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import mcp_authorization
from models import Base
from retention import run_retention

class RetentionTest(unittest.IsolatedAsyncioTestCase):
    async def test_cutoff_and_batch(self):
        engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        async with engine.begin() as connection:
            # Only the retention tables are needed; the production identity schema
            # contains PostgreSQL JSONB columns that SQLite cannot compile.
            tables = [Base.metadata.tables[name] for name in (
                'mcp_oauth_requests', 'mcp_oauth_codes', 'mcp_oauth_logins',
                'portal_sso_requests', 'account_identity_link_previews',
                'account_identity_link_requests', 'portal_sso_limits',
                'mcp_oauth_registration_limits')]
            await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=tables))
        async with AsyncSession(engine) as session:
            now = 1800000000
            cutoff = now - 23*3600
            for i in range(502):
                await session.execute(text("INSERT INTO mcp_oauth_codes VALUES (:id,'s','c','u','r','scope','challenge',:expiry)"), {'id':str(i),'expiry':cutoff if i==501 else cutoff-1})
            await session.commit()
            self.assertEqual((await run_retention(session,now))['mcp_oauth_codes'],500)
            self.assertEqual((await run_retention(session,now))['mcp_oauth_codes'],1)
            self.assertEqual((await run_retention(session,now))['mcp_oauth_codes'],0)
            self.assertEqual((await session.execute(text('SELECT COUNT(*) FROM mcp_oauth_codes'))).scalar(),1)
        await engine.dispose()

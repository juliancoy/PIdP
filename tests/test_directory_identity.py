import os
os.environ.setdefault('SECRET_KEY','synthetic-identity-test-key')
os.environ.setdefault('DATABASE_URL','postgresql+asyncpg://test:test@localhost/test')
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request
from models import User, WebsiteUser
from directory_identity import link_verified_portal_provider

class DirectoryIdentityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        root=Path(__file__).resolve().parents[1]
        for name in ['0001_initial.sql','0010_account_identity_links.sql','0016_normalized_account_email.sql']:
            self.db.executescript((root/'serverless/migrations'/name).read_text())
        self.db.executescript("""INSERT INTO users(id,email,provider,provider_account_id)VALUES('owner','owner@example.test','google','google-owner');
        INSERT INTO websites(id,owner_id,name,slug)VALUES('site','owner','Portal','orgportal');
        INSERT INTO website_users(id,website_id,email,provider,provider_account_id)VALUES('member','site','owner@example.test','google','google-owner');""")
        db=self.db
        class Session:
            async def execute(self,statement,params):return db.execute(str(statement),params)
        self.session=Session()
    def tearDown(self):self.db.close()
    async def test_verified_provider_link_parity(self):
        p=dict(email='owner@example.test',provider_account_id='google-owner',raw={'email_verified':False})
        await link_verified_portal_provider(self.session,'google',p,'orgportal')
        self.assertEqual(self.db.execute('SELECT count(*) FROM account_identity_links').fetchone()[0],0)
        p['raw']['email_verified']=True
        await link_verified_portal_provider(self.session,'google',p,'orgportal')
        await link_verified_portal_provider(self.session,'google',p,'orgportal')
        self.assertEqual(self.db.execute('SELECT website_user_id,canonical_user_id FROM account_identity_links').fetchall(),[('member','owner')])
    async def test_inactive_and_wrong_provider_do_not_link(self):
        p=dict(email='owner@example.test',provider_account_id='google-owner',raw={'email_verified':True})
        await link_verified_portal_provider(self.session,'github',p,'orgportal')
        self.db.execute("UPDATE users SET is_active=0")
        await link_verified_portal_provider(self.session,'google',p,'orgportal')
        self.assertEqual(self.db.execute('SELECT count(*) FROM account_identity_links').fetchone()[0],0)
    def test_orm_normalizes_email_and_database_rejects_variants(self):
        self.assertEqual(User(email=' Owner@Example.Test ').email,'owner@example.test')
        self.assertEqual(WebsiteUser(email=' Owner@Example.Test ').email,'owner@example.test')
        with self.assertRaises(sqlite3.IntegrityError):self.db.execute("INSERT INTO users(id,email)VALUES('duplicate',' OWNER@EXAMPLE.TEST ')")
    async def test_service_authorization_and_email_conflict(self):
        import main
        request=Request({'type':'http','headers':[(b'authorization',b'Bearer pidp_pat_fixture')]})
        owner=SimpleNamespace(id=uuid4(),is_active=True)
        with patch.object(main,'_get_api_token_owner_and_record',AsyncMock(return_value=(owner,SimpleNamespace(scope='service')))),patch.object(main,'portal_directory_aliases',AsyncMock(return_value=[])):
            response=await main.directory_identities(request,self.session)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.headers['cache-control'],'no-store')
        with patch.object(main,'_get_api_token_owner_and_record',AsyncMock(return_value=(owner,SimpleNamespace(scope='org_mcp')))):
            with self.assertRaises(main.HTTPException) as caught:await main.directory_identities(request,self.session)
            self.assertEqual(caught.exception.status_code,403)
        conflict=IntegrityError('INSERT',{},Exception('uq_users_email_normalized'))
        self.assertEqual((await main.duplicate_email_error(request,conflict)).status_code,409)

if __name__=='__main__':unittest.main()

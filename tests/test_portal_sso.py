import os
import json
os.environ.setdefault('SECRET_KEY','sso-test-secret')
os.environ.setdefault('DATABASE_URL','postgresql+asyncpg://test:test@localhost/test')
import unittest
import uuid
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient
import portal_sso as sso
from models import PortalSsoRequest, Website, WebsiteUser, User, PortalSsoLimit, AccountIdentityLink
@compiles(JSONB,'sqlite')
def sqlite_json(type_,compiler,**kw): return 'JSON'
class AsyncAdapter:
    def __init__(self,session):self.session=session
    async def execute(self,statement):return self.session.execute(statement)
    async def commit(self):self.session.commit()
    def add(self,row):self.session.add(row)
class SsoTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
        for model in [User,Website,WebsiteUser,PortalSsoRequest,PortalSsoLimit,AccountIdentityLink]:model.__table__.create(self.engine)
        self.user_id=uuid.uuid4()
        with self.engine.begin() as c:
            c.exec_driver_sql("INSERT INTO users(id,email,is_active,created_at,identity_data) VALUES (?,?,1,CURRENT_TIMESTAMP,'null')",(self.user_id.hex,'member@example.test'))
        self.website_id=uuid.uuid4()
        self.member_id=uuid.uuid4()
        with Session(self.engine) as records:
            records.add(Website(id=self.website_id,owner_id=self.user_id,name='Members',slug='members'))
            records.add(WebsiteUser(id=self.member_id,website_id=self.website_id,email='member@example.test',is_active=True))
            records.commit()
        self.db=Session(self.engine,expire_on_commit=False)
        async def dependency():yield AsyncAdapter(self.db)
        app=FastAPI();app.include_router(sso.router);app.dependency_overrides[sso.get_session]=dependency
        self.client=TestClient(app,base_url='https://one.example',follow_redirects=False)
        self.settings=patch.multiple(sso.settings,public_base_url='https://id.example',portal_auth_origins='https://one.example,https://two.example',portal_sso_app_slug='members',portal_clients_json=json.dumps({**{origin:{'name':'Test Portal','accountApp':'members','callbacks':['/auth/callback','/p/auth/callback']} for origin in ['https://one.example','https://two.example','https://orgportal.cc']},'https://codecollective.us':{'name':'Test Portal','accountApp':'members','callbacks':['/auth/callback','/p/auth/callback'],'restartOrigin':'https://orgportal.cc'}}));self.settings.start()
        self.decode=patch.object(sso,'safe_decode_token',return_value={'sub':str(self.member_id),'actor_type':'website_user','website_id':str(self.website_id)});self.decode_mock=self.decode.start()
        self.issue=patch.object(sso,'create_access_token',return_value='local-session');self.issue_mock=self.issue.start()
    def tearDown(self):
        self.issue.stop();self.decode.stop();self.settings.stop();self.client.close();self.db.close();self.engine.dispose()
    def test_member_handoff_is_bound_to_browser_origin_and_one_use(self):
        for host in ['one.example','two.example']:
            r=self.client.get(f'https://{host}/auth/sso/start',params={'app':'members','next':f'https://{host}/auth/callback?next=%2Fpeople'})
            self.assertEqual(r.status_code,303)
            a=self.client.get(r.headers['location']);self.assertEqual(a.status_code,303)
            complete=a.headers['location'].replace('/pidp/auth','/auth')
            self.assertNotIn('token=',complete)
            wrong=complete.replace(host,'wrong.example');self.assertEqual(self.client.get(wrong).status_code,400)
            result=self.client.get(complete);self.assertEqual(result.status_code,303)
            self.assertEqual(result.headers['location'],f'https://{host}/auth/callback?next=%2Fpeople')
            self.assertIn('HttpOnly',result.headers['set-cookie']);self.assertNotIn('Domain=',result.headers['set-cookie'])
            self.assertEqual(self.client.get(complete).status_code,400)
    def test_owner_session_requires_explicit_member_link(self):
        self.decode_mock.return_value = {'sub': str(self.user_id), 'actor_type': 'owner'}
        started = self.client.get('/auth/sso/start', params={'app': 'members'})
        denied = self.client.get(started.headers['location'])
        self.assertEqual(denied.status_code, 200)
        self.assertIn('Link my portal account', denied.text)
        self.assertIn('Sign in to the portal separately', denied.text)
        self.assertEqual(self.db.query(AccountIdentityLink).count(), 0)
        self.assertIsNone(self.db.query(PortalSsoRequest).one().code_hash)
        self.db.add(AccountIdentityLink(subject=f'website:{self.website_id}:{self.member_id}',
            canonical_user_id=self.user_id, website_id=self.website_id,
            website_user_id=self.member_id, linked_at='2026-10-05T00:00:00Z'))
        self.db.commit()
        authorized = self.client.get(started.headers['location'])
        self.assertEqual(authorized.status_code, 303)
        self.assertIn('/auth/sso/complete?', authorized.headers['location'])

    def test_retired_portal_restarts_on_orgportal(self):
        with patch.object(sso.settings, 'portal_auth_origins', 'https://codecollective.us,https://orgportal.cc'):
            response = self.client.get('https://codecollective.us/auth/sso/start', params={'app':'members',
                'next':'https://codecollective.us/p/auth/callback?next=%2Fchat','provider':'google','login_hint':'123456789'})
            self.assertEqual(response.status_code,303)
            target = urlsplit(response.headers['location'])
            params = parse_qs(target.query)
            self.assertEqual(target.netloc,'orgportal.cc')
            self.assertEqual(target.path,'/pidp/auth/sso/start')
            self.assertEqual(params['next'],['https://orgportal.cc/auth/callback?next=%2Fchat'])
            self.assertEqual(params['provider'],['google'])
            self.assertEqual(params['login_hint'],['123456789'])
            self.assertNotIn('set-cookie',response.headers)
            self.assertEqual(self.db.query(PortalSsoRequest).count(),0)

    def test_every_registered_product_keeps_its_destination_and_namespace(self):
        from portal_clients import DEFAULTS
        with patch.multiple(sso.settings,portal_clients_json='',portal_auth_origins=','.join(DEFAULTS)):
            self.db.query(Website).one().slug='code-collective'
            self.db.commit()
            for origin, client in DEFAULTS.items():
                if client.get('restartOrigin'):
                    continue
                started=self.client.get(origin+'/auth/sso/start',params={'app':'code-collective','next':origin+'/auth/callback?next=%2Fpeople'})
                self.assertEqual(started.status_code,303)
                authorized=self.client.get(started.headers['location'])
                self.assertEqual(authorized.status_code,303)
                self.assertIn(origin+'/pidp/auth/sso/complete',authorized.headers['location'])
                completed=self.client.get(authorized.headers['location'].replace('/pidp/auth','/auth'))
                self.assertEqual(completed.status_code,303)
                self.assertEqual(completed.headers['location'],origin+'/auth/callback?next=%2Fpeople')
                self.assertNotIn('Domain=',completed.headers['set-cookie'])
                self.assertEqual(self.issue_mock.call_args.kwargs['extra_claims']['actor_type'],'website_user')
                self.assertEqual(self.issue_mock.call_args.kwargs['extra_claims']['website_id'],str(self.website_id))

    def test_external_returns_unknown_apps_and_wrong_namespace_are_rejected(self):
        for params in [{'app':'other'},{'app':'members','next':'https://evil.example/auth/callback'}]:
            self.assertEqual(self.client.get('/auth/sso/start',params=params).status_code,400)
        started=self.client.get('/auth/sso/start',params={'app':'members','next':'https://one.example/auth/callback'})
        self.decode_mock.return_value={'sub':str(self.user_id),'actor_type':'website_user','website_id':'other'}
        result=self.client.get(started.headers['location']);self.assertIn('/app/login',result.headers['location'])
    def test_missing_application_does_not_create_an_owner_handoff(self):
        self.db.query(WebsiteUser).delete()
        self.db.query(Website).delete()
        self.db.commit()
        result=self.client.get('/auth/sso/start',params={'app':'members'})
        self.assertEqual(result.status_code,503)
        self.assertEqual(result.json()['detail'],'application_not_registered')
        self.assertEqual(self.db.query(PortalSsoRequest).count(),0)
    def test_google_selection_reauthenticates_in_the_application_namespace(self):
        started = self.client.get('/auth/sso/start', params={'app':'members', 'provider':'google', 'login_hint':'123456789'})
        self.assertEqual(parse_qs(urlsplit(started.headers['location']).query)['login_hint'], ['123456789'])
        # Even an existing valid session must authenticate the selected account.
        authorized = self.client.get(started.headers['location'])
        target = urlsplit(authorized.headers['location'])
        self.assertEqual(target.path, '/auth/google/login')
        params = parse_qs(target.query)
        self.assertEqual(params['app'], ['members'])
        self.assertEqual(params['login_hint'], ['123456789'])
        self.assertNotIn('owner', params)
        self.assertNotIn('login_hint', parse_qs(urlsplit(params['next'][0]).query))
    def test_hints_do_not_select_identities_for_other_providers(self):
        for provider, hint in [('github', '123456789'), ('google', 'invalid@example.test')]:
            started = self.client.get('/auth/sso/start', params={'app':'members', 'provider':provider, 'login_hint':hint})
            self.assertNotIn('login_hint', parse_qs(urlsplit(started.headers['location']).query))
if __name__=='__main__':unittest.main()

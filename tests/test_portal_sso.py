import os
import json
os.environ.setdefault('SECRET_KEY','sso-test-secret')
os.environ.setdefault('DATABASE_URL','postgresql+asyncpg://test:test@localhost/test')
import unittest
import uuid
from unittest.mock import patch, AsyncMock
from urllib.parse import urlsplit, parse_qs
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient
import portal_sso as sso
from models import PortalSsoRequest, PortalDesktopRequest, Website, WebsiteUser, User, PortalSsoLimit, AccountIdentityLink, BrowserSession
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
        for model in [User,Website,WebsiteUser,PortalSsoRequest,PortalDesktopRequest,PortalSsoLimit,AccountIdentityLink,BrowserSession]:model.__table__.create(self.engine)
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
        self.browser_claims=patch.object(sso,'browser_claims',new=AsyncMock(side_effect=lambda *_:self.decode_mock.return_value));self.browser_claims.start()
        self.issue=patch.object(sso,'create_access_token',wraps=sso.create_access_token);self.issue_mock=self.issue.start()
    def tearDown(self):
        self.browser_claims.stop();self.issue.stop();self.decode.stop();self.settings.stop();self.client.close();self.db.close();self.engine.dispose()
    def test_native_browser_handoff_requires_pkce_cookie_origin_and_one_use(self):
        import base64,hashlib
        verifier='v'*64
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        params={'redirect_uri':'http://127.0.0.1:49321/callback','code_challenge':challenge,'code_challenge_method':'S256','state':'s'*43}
        started=self.client.get('/auth/sso/start',params=params)
        self.assertEqual(started.status_code,200)
        ticket=started.json()['request']
        cookie=self.client.cookies.get(sso.BROWSER)
        authorized=self.client.get(started.json()['authorization_url'])
        callback=urlsplit(authorized.headers['location']);query=parse_qs(callback.query)
        self.assertEqual(callback.netloc,'127.0.0.1:49321')
        self.assertEqual(query['state'],['s'*43])
        proof={'request':ticket,'code':query['code'][0],'code_verifier':verifier}
        self.assertEqual(self.client.get('/auth/sso/complete',params=proof).status_code,400)
        self.assertEqual(self.client.post('/auth/sso/complete',json={**proof,'code_verifier':'x'*64}).status_code,400)
        self.assertEqual(self.client.post('https://two.example/auth/sso/complete',json=proof,headers={'cookie':sso.BROWSER+'='+cookie}).status_code,400)
        self.client.cookies.clear()
        self.assertEqual(self.client.post('/auth/sso/complete',json=proof).status_code,400)
        self.client.cookies.set(sso.BROWSER,cookie,domain='one.example',path='/')
        finished=self.client.post('/auth/sso/complete',json=proof)
        self.assertEqual(finished.status_code,303)
        self.assertIn('HttpOnly',finished.headers['set-cookie'])
        self.assertEqual(self.client.post('/auth/sso/complete',json=proof).status_code,400)
        self.assertEqual(self.db.query(PortalDesktopRequest).count(),0)

    def test_native_requests_reject_unsafe_or_incomplete_callbacks(self):
        params={'redirect_uri':'http://127.0.0.1:49321/callback','code_challenge':'a'*43,'code_challenge_method':'S256','state':'s'*43}
        for uri in ['https://evil.example/callback','http://localhost:49321/callback','http://127.0.0.1:49321/other','http://127.0.0.1:49321/callback?x=1','http://user@127.0.0.1:49321/callback','http://127.0.0.1:80/callback']:
            self.assertEqual(self.client.get('/auth/sso/start',params={**params,'redirect_uri':uri}).status_code,400)
        self.assertEqual(self.client.get('/auth/sso/start',params={**params,'code_challenge_method':'plain'}).status_code,400)
        self.assertEqual(self.client.get('/auth/sso/start',params={**params,'state':'short'}).status_code,400)

    def test_prompt_select_account_and_fresh_login_preserve_context(self):
        started=self.client.get('/auth/sso/start',params={'prompt':'select_account'})
        self.assertEqual(started.status_code,303)
        self.assertIn('prompt=select_account',started.headers['location'])
        chooser=self.client.get(started.headers['location'])
        self.assertEqual(chooser.status_code,200)
        self.assertIn('Choose an account',chooser.text)
        self.assertIn('prompt=login',chooser.text)
        self.assertIn('app=members',chooser.text)
        self.assertIsNone(self.db.query(PortalSsoRequest).one().code_hash)
        from urllib.parse import urlsplit,parse_qs
        ticket=parse_qs(urlsplit(started.headers['location']).query)['request'][0]
        fresh=self.client.get('https://id.example/auth/sso/authorize',params={'request':ticket,'prompt':'login'})
        self.assertEqual(fresh.status_code,303)
        self.assertIn('/app/login',fresh.headers['location'])
        self.assertIn('prompt=login',fresh.headers['location'])
        self.assertEqual(self.client.get('/auth/sso/start',params={'prompt':'unsupported'}).status_code,400)

    def test_no_usable_session_goes_directly_to_login_without_an_empty_chooser(self):
        from urllib.parse import urlsplit, parse_qs
        destination='https://one.example/auth/callback?next=%2Fevents%2Fdemo%23apply'
        started=self.client.get('/auth/sso/start',params={'prompt':'select_account','next':destination})
        ticket=parse_qs(urlsplit(started.headers['location']).query)['request'][0]
        for claims in [{}, {'sub':str(uuid.uuid4()),'actor_type':'website_user','website_id':str(self.website_id)},
                       {'sub':str(self.member_id),'actor_type':'website_user','website_id':str(uuid.uuid4())}]:
            with self.subTest(claims=claims):
                self.decode_mock.return_value=claims
                response=self.client.get(started.headers['location'])
                self.assertEqual(response.status_code,303, 'No empty chooser or extra click')
                login=urlsplit(response.headers['location'])
                self.assertEqual(login.path,'/app/login')
                params=parse_qs(login.query)
                self.assertEqual(params['app'],['members'])
                self.assertEqual(params['prompt'],['login'])
                resume=parse_qs(urlsplit(params['next'][0]).query)
                self.assertEqual(resume,{'request':[ticket]})
                row=self.db.query(PortalSsoRequest).one()
                self.assertEqual(row.next,destination)
                self.assertIsNone(row.code_hash)

    def test_expired_request_has_safe_html_retry(self):
        started=self.client.get('/auth/sso/start')
        row=self.db.query(PortalSsoRequest).one()
        row.expires_at=0
        self.db.commit()
        response=self.client.get(started.headers['location'])
        self.assertEqual(response.status_code,400)
        self.assertIn('text/html',response.headers['content-type'])
        self.assertIn('<button type="submit">Try again</button>',response.text)
        self.assertIn('action="https://one.example/pidp/auth/sso/start"',response.text)
        self.assertNotIn(row.id,response.text)
        fallback=self.client.get('https://id.example/auth/sso/authorize?request=missing&next=https://evil.example')
        self.assertIn('action="https://orgportal.cc/users/login"',fallback.text)
        self.assertNotIn('evil.example',fallback.text)

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
    def test_shared_primary_account_requires_no_second_login(self):
        self.decode_mock.return_value = {'sub':str(self.user_id),'actor_type':'owner'}
        with patch.multiple(sso.settings,portal_shared_identity=True,portal_sso_app_slug='members'):
            started=self.client.get('/auth/sso/start')
            authorized=self.client.get(started.headers['location'])
            self.assertEqual(authorized.status_code,303)
            completed=self.client.get(authorized.headers['location'].replace('/pidp/auth','/auth'))
            self.assertEqual(completed.status_code,303)
            self.assertEqual(self.issue_mock.call_args.kwargs['subject'],str(self.user_id))
            self.assertEqual(self.issue_mock.call_args.kwargs['extra_claims']['actor_type'],'owner')

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
            self.db.query(Website).one().slug='orgportal'
            self.db.commit()
            for origin, client in DEFAULTS.items():
                if client.get('restartOrigin'):
                    continue
                started=self.client.get(origin+'/auth/sso/start',params={'app':'orgportal','next':origin+'/auth/callback?next=%2Fpeople'})
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

    def test_path_mounted_central_handoff_keeps_prefix(self):
        with patch.object(sso.settings,'public_base_url','https://id.example/pidp'):
            started=self.client.get('/auth/sso/start')
            self.assertTrue(started.headers['location'].startswith('https://id.example/pidp/auth/sso/authorize?'))
            authorize=started.headers['location'].replace('/pidp/auth','/auth')
            result=self.client.get(authorize,params={'prompt':'login','request':parse_qs(urlsplit(authorize).query)['request'][0]})
            self.assertEqual(result.status_code,303)
            self.assertTrue(result.headers['location'].startswith('https://id.example/pidp/app/login?'))

    def test_tenant_handoff_keeps_original_authentication_time(self):
        import time
        auth_time=int(time.time())-1800
        self.decode_mock.return_value={**self.decode_mock.return_value,'auth_time':auth_time}
        started=self.client.get('/auth/sso/start')
        authorized=self.client.get(started.headers['location'])
        self.assertEqual(authorized.status_code,303)
        self.assertEqual(self.db.query(PortalSsoRequest).one().auth_time,auth_time)
        completed=self.client.get(authorized.headers['location'].replace('/pidp/auth','/auth'))
        self.assertEqual(completed.status_code,303)
        from security import safe_decode_token
        claims=safe_decode_token(self.client.cookies.get('pidp_token'))
        self.assertEqual(claims['auth_time'],auth_time)

if __name__=='__main__':unittest.main()

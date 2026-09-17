import base64
import hashlib
import json
import os
import re
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault('SECRET_KEY', 'oauth-test-secret')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwk, jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from starlette.requests import Request
from security import create_access_token
import mcp_authorization as oauth


class Database:
    def __init__(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript((Path(__file__).parents[1] / 'serverless/migrations/0006_mcp_authorization.sql').read_text())
        self.db.executescript((Path(__file__).parents[1] / 'serverless/migrations/0007_mcp_client_registration.sql').read_text())
        self.db.executescript((Path(__file__).parents[1] / 'serverless/migrations/0008_mcp_login_handoff.sql').read_text())

    async def execute(self, sql, params):
        cursor = self.db.execute(str(sql), params)
        class Result:
            returns_rows = cursor.description is not None
            def mappings(self):
                return cursor.fetchall()
        return Result()

    async def commit(self):
        self.db.commit()

    async def rollback(self):
        self.db.rollback()


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.issuer = 'https://id.example'
        self.resource = 'https://portal.example/api/org/mcp'
        key = jwk.construct(ec.generate_private_key(ec.SECP256R1()), 'ES256').to_dict()
        key['kid'] = 'test-key'
        self.client_config = dict(name='Uploader', tokenEndpointAuthMethod='none', redirectUris=['http://127.0.0.1/callback'],
            resources=[self.resource], scopes=oauth.SCOPES)
        self.setting_patch = patch.multiple(oauth.settings, mcp_oauth_issuer=self.issuer, mcp_oauth_private_jwk=json.dumps(key),
            mcp_oauth_dynamic_registration=False, mcp_oauth_portals_json='{}',
            mcp_oauth_clients_json=json.dumps({'native': self.client_config}),
            mcp_oauth_resources_json=json.dumps({self.resource: {'secretHash': oauth.digest('resource-secret-at-least-32-characters')}}))
        self.setting_patch.start()
        self.active = patch.object(oauth, 'active_subject', AsyncMock(return_value=True)); self.active.start()
        self.actor = patch.object(oauth, 'session', AsyncMock(return_value=dict(subject='owner:alice', display='alice', hash='session-hash'))); self.actor.start()
        app = FastAPI(); app.include_router(oauth.router)
        async def get_db():
            yield self.db
        app.dependency_overrides[oauth.get_session] = get_db
        self.client = TestClient(app, base_url=self.issuer)
        self.params = dict(response_type='code', client_id='native', redirect_uri='http://127.0.0.1:49152/callback', resource=self.resource,
            scope='org:events.read org:events.write', code_challenge_method='S256', state='state',
            code_challenge=base64.urlsafe_b64encode(hashlib.sha256(b'v' * 43).digest()).decode().rstrip('='))

    def tearDown(self):
        self.client.close(); self.actor.stop(); self.active.stop(); self.setting_patch.stop(); self.db.db.close()

    def post(self, path, data, **kwargs):
        return self.client.post('/oauth/mcp/' + path, data=data, follow_redirects=False, **kwargs)

    def code(self):
        consent = self.client.get('/oauth/mcp/authorize', params=self.params)
        self.assertEqual(consent.status_code, 200, consent.text)
        self.assertEqual(consent.headers['referrer-policy'], 'same-origin')
        target = urlsplit(self.params['redirect_uri'])
        self.assertIn("form-action 'self' " + target.scheme + '://' + target.netloc, consent.headers['content-security-policy'])
        nonce = re.search('name="request" value="([^"]+)"', consent.text)[1]
        response = self.post('authorize', dict(request=nonce, decision='allow'), headers={'origin': self.issuer})
        self.assertEqual(response.status_code, 303, response.text)
        params = parse_qs(urlsplit(response.headers['location']).query)
        self.assertEqual(params['iss'], [self.issuer]); self.assertEqual(params['state'], ['state'])
        return params['code'][0]

    def exchange(self, code, **changes):
        data = dict(grant_type='authorization_code', client_id='native', code=code, redirect_uri=self.params['redirect_uri'],
                    resource=self.resource, code_verifier='v' * 43)
        data.update(changes)
        return self.post('token', data)

    def introspect(self, token):
        return self.post('introspect', dict(token=token, resource=self.resource), headers={'authorization': 'Bearer resource-secret-at-least-32-characters'}).json()

    def test_portal_handoff_preserves_identity_and_completes_consent(self):
        self.actor.stop()
        with patch.object(oauth.settings, 'mcp_oauth_portals_json', json.dumps({self.resource: {
                'name': 'MedTech', 'loginUrl': 'https://portal.example/users/mcp-connect'}})), \
                patch.object(oauth, 'identity_session', AsyncMock(return_value=None)) as identity:
            start = self.client.get('/oauth/mcp/authorize', params=self.params, follow_redirects=False)
            self.assertEqual(start.status_code, 303, start.text)
            target = urlsplit(start.headers['location'])
            self.assertEqual(target.netloc, 'portal.example')
            request = parse_qs(target.query)['request'][0]
            self.assertIn('HttpOnly', start.headers['set-cookie'])
            self.assertNotIn('Domain=', start.headers['set-cookie'])
            browser = self.client.cookies.get(oauth.BROWSER_COOKIE)
            self.assertEqual(self.post('handoff', {'request': request}, headers={'origin': 'https://portal.example'}).status_code, 401)
            identity.return_value = dict(subject='website:portal-site:member', display='member@example.test', hash='portal-session')
            metadata = self.client.get('/oauth/mcp/handoff', params={'request': request}).json()
            self.assertEqual(metadata['account'], 'member@example.test')
            self.assertEqual(metadata['portal'], 'MedTech')
            self.assertEqual(self.post('handoff', {'request': request}, headers={'origin': 'https://evil.example'}).status_code, 403)
            self.assertEqual(self.post('handoff', {'request': request}).status_code, 403)
            result = self.post('handoff', {'request': request}, headers={'origin': 'https://portal.example'})
            self.assertEqual(result.status_code, 200, result.text)
            resume = result.json()['redirect_url']
            self.assertEqual(self.post('handoff', {'request': request}, headers={'origin': 'https://portal.example'}).status_code, 400)
            self.client.cookies.clear()
            self.assertEqual(self.client.get(resume, follow_redirects=False).status_code, 400)
            self.client.cookies.set(oauth.BROWSER_COOKIE, 'z' * 54)
            self.assertEqual(self.client.get(resume, follow_redirects=False).status_code, 400)
            self.client.cookies.set(oauth.BROWSER_COOKIE, browser)
            resumed = self.client.get(resume, follow_redirects=False)
            self.assertEqual(resumed.status_code, 303, resumed.text)
            self.assertIn(oauth.SESSION_COOKIE, resumed.headers['set-cookie'])
            self.assertFalse(self.introspect(self.client.cookies.get(oauth.SESSION_COOKIE))['active'])
            self.assertEqual(self.client.get(resume, follow_redirects=False).status_code, 400)
            tokens = self.exchange(self.code()).json()
            claims = jwt.decode(tokens['access_token'], oauth.configuration()['keys'][0], algorithms=['ES256'], issuer=self.issuer, audience=self.resource)
            self.assertEqual(claims['sub'], 'website:portal-site:member')
            self.assertTrue(self.introspect(tokens['access_token'])['active'])
            self.assertEqual(self.client.get('/oauth/mcp/connections').status_code, 200)

    def test_portal_handoff_expiry_and_invalid_configuration(self):
        self.actor.stop()
        with patch.object(oauth.settings, 'mcp_oauth_portals_json', json.dumps({self.resource: {
                'name': 'MedTech', 'loginUrl': 'https://portal.example/users/mcp-connect'}})):
            start = self.client.get('/oauth/mcp/authorize', params=self.params, follow_redirects=False)
            request = parse_qs(urlsplit(start.headers['location']).query)['request'][0]
            self.db.db.execute('UPDATE mcp_oauth_logins SET expires_at = 0')
            self.assertEqual(self.post('handoff', {'request': request}, headers={'origin': 'https://portal.example'}).status_code, 400)
        with patch.object(oauth.settings, 'mcp_oauth_portals_json', json.dumps({self.resource: {
                'name': 'Bad', 'loginUrl': 'https://portal.example/users/mcp-connect?next=https://evil.example'}})):
            self.assertEqual(self.client.get('/oauth/mcp/authorize', params=self.params).status_code, 503)

    def test_native_flow_rotation_replay_and_revocation(self):
        discovery = self.client.get('/.well-known/oauth-authorization-server').json()
        self.assertIn('none', discovery['token_endpoint_auth_methods_supported'])
        code = self.code()
        self.assertEqual(self.exchange(code, client_secret='').status_code, 401)
        self.assertEqual(self.exchange(code, code_verifier='x' * 43).status_code, 400)
        self.assertEqual(self.exchange(code, redirect_uri='http://127.0.0.1:54321/callback').status_code, 400)
        response = self.exchange(code); self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        tokens = response.json()
        claims = jwt.decode(tokens['access_token'], oauth.configuration()['keys'][0], algorithms=['ES256'], issuer=self.issuer, audience=self.resource)
        self.assertEqual(claims['sub'], 'owner:alice'); self.assertEqual(claims['exp'] - claims['iat'], 300)
        self.assertEqual(self.exchange(code).status_code, 400)
        self.assertTrue(self.introspect(tokens['access_token'])['active'])
        refresh = dict(grant_type='refresh_token', client_id='native', refresh_token=tokens['refresh_token'])
        renewed = self.post('token', refresh).json()
        self.assertIn('refresh_token', renewed)
        self.assertEqual(self.post('token', refresh).status_code, 400)
        self.assertFalse(self.introspect(renewed['access_token'])['active'])
        tokens = self.exchange(self.code()).json()
        self.assertEqual(self.post('revoke', dict(client_id='native', token=tokens['refresh_token'])).status_code, 200)
        self.assertFalse(self.introspect(tokens['access_token'])['active'])

    def test_shared_redirect_contract_and_csrf(self):
        cases = json.loads((Path(__file__).parent / 'oauth_redirect_cases.json').read_text())
        for case in cases:
            params = {**self.params, 'redirect_uri': case['uri']}
            result = self.client.get('/oauth/mcp/authorize', params=params)
            self.assertEqual(result.status_code, 200 if case['allowed'] else 400, case['uri'])
        self.assertEqual(self.post('authorize', dict(request='bad', decision='allow'), headers={'origin': 'https://evil.example'}).status_code, 403)
        self.assertEqual(self.post('token', dict(grant_type='client_credentials', client_id='native')).status_code, 400)

    def test_confidential_clients_still_require_secret_and_user_consent(self):
        client = {**self.client_config, 'secretHash': oauth.digest('client-secret-at-least-32-characters'), 'redirectUris': ['https://client.example/callback']}
        del client['tokenEndpointAuthMethod']
        oauth.settings.mcp_oauth_clients_json = json.dumps({'native': client})
        self.params['redirect_uri'] = 'https://client.example/callback'
        code = self.code()
        self.assertEqual(self.exchange(code).status_code, 401)
        self.assertEqual(self.exchange(code, client_secret='client-secret-at-least-32-characters').status_code, 200)

    def test_denial_expiry_scope_and_account_revocation(self):
        page = self.client.get('/oauth/mcp/authorize', params=self.params)
        nonce = re.search('name="request" value="([^"]+)"', page.text)[1]
        denied = self.post('authorize', dict(request=nonce, decision='deny'), headers={'origin': self.issuer})
        self.assertIn('error=access_denied', denied.headers['location'])
        code = self.code(); self.db.db.execute('UPDATE mcp_oauth_codes SET expires_at=0'); self.db.db.commit()
        self.assertEqual(self.exchange(code).status_code, 400)
        tokens = self.exchange(self.code()).json()
        with patch.object(oauth, 'active_subject', AsyncMock(return_value=False)):
            self.assertFalse(self.introspect(tokens['access_token'])['active'])
            self.assertEqual(self.post('token', dict(grant_type='refresh_token', client_id='native', refresh_token=tokens['refresh_token'])).status_code, 400)

    def test_account_connections_csrf_and_subject_binding(self):
        tokens = self.exchange(self.code()).json()
        page = self.client.get('/oauth/mcp/connections')
        grant = re.search('name="grant" value="([^"]+)"', page.text)[1]
        csrf = re.search('name="csrf" value="([^"]+)"', page.text)[1]
        self.assertEqual(self.post('connections', dict(grant=grant, csrf='wrong'), headers={'origin': self.issuer}).status_code, 403)
        with patch.object(oauth, 'session', AsyncMock(return_value=dict(subject='owner:bob', display='bob', hash='bob-session'))):
            self.assertEqual(self.post('connections', dict(grant=grant, csrf=csrf), headers={'origin': self.issuer}).status_code, 403)
        self.assertTrue(self.introspect(tokens['access_token'])['active'])
        self.assertEqual(self.post('connections', dict(grant=grant, csrf=csrf), headers={'origin': self.issuer}).status_code, 303)
        self.assertFalse(self.introspect(tokens['access_token'])['active'])

    def test_dynamic_registration_requires_consent_pkce_and_supports_client_revocation(self):
        metadata = dict(client_name='Codex', token_endpoint_auth_method='none', redirect_uris=['http://127.0.0.1/callback'])
        self.assertEqual(self.client.post('/oauth/mcp/register', json=metadata).status_code, 403)
        oauth.settings.mcp_oauth_dynamic_registration = True
        discovery = self.client.get('/.well-known/oauth-authorization-server').json()
        self.assertEqual(discovery['registration_endpoint'], self.issuer + '/oauth/mcp/register')
        response = self.client.post('/oauth/mcp/register', json=metadata)
        self.assertEqual(response.status_code, 201, response.text)
        client = response.json(); self.assertNotIn('client_secret', client)
        self.params['client_id'] = client['client_id']
        del self.params['resource']
        page = self.client.get('/oauth/mcp/authorize', params=self.params)
        self.assertIn('self-reported', page.text)
        with patch.object(oauth, 'session', AsyncMock(return_value=None)):
            login = self.client.get('/oauth/mcp/authorize', params=self.params, follow_redirects=False)
            self.assertEqual(login.status_code, 303)
            self.assertIn('/app/login', login.headers['location'])
        code = self.code()
        self.assertEqual(self.exchange(code, client_id=client['client_id'], code_verifier='x' * 43).status_code, 400)
        self.assertEqual(self.exchange(code, client_id=client['client_id'], redirect_uri='http://127.0.0.1:49152/wrong').status_code, 400)
        response = self.post('token', dict(grant_type='authorization_code', client_id=client['client_id'], code=code,
            redirect_uri=self.params['redirect_uri'], code_verifier='v' * 43))
        self.assertEqual(response.status_code, 200, response.text)
        tokens = response.json(); self.assertTrue(self.introspect(tokens['access_token'])['active'])
        self.db.db.execute('UPDATE mcp_oauth_clients SET revoked=1 WHERE id=?', (client['client_id'],)); self.db.db.commit()
        self.assertFalse(self.introspect(tokens['access_token'])['active'])
        self.assertEqual(self.post('token', dict(client_id=client['client_id'], grant_type='refresh_token', refresh_token=tokens['refresh_token'])).status_code, 401)

    def test_shared_registration_policy_and_rate_limit(self):
        oauth.settings.mcp_oauth_dynamic_registration = True
        cases = json.loads((Path(__file__).parent / 'oauth_registration_cases.json').read_text())
        for case in cases:
            self.db.db.execute('DELETE FROM mcp_oauth_registration_limits'); self.db.db.commit()
            response = self.client.post('/oauth/mcp/register', json=case['metadata'])
            self.assertEqual(response.status_code, case['status'], response.text + str(case['metadata']))
            if response.status_code == 201 and response.json().get('client_secret'):
                client = response.json()
                stored = self.db.db.execute('SELECT client_json FROM mcp_oauth_clients WHERE id=?', (client['client_id'],)).fetchone()[0]
                self.assertNotIn(client['client_secret'], stored)
        self.db.db.execute('DELETE FROM mcp_oauth_registration_limits'); self.db.db.commit()
        for i in range(11):
            response = self.client.post('/oauth/mcp/register', json={})
            self.assertEqual(response.status_code, 429 if i == 10 else 400)

    def test_dynamic_confidential_client_method_is_enforced(self):
        oauth.settings.mcp_oauth_dynamic_registration = True
        for method in ('client_secret_basic', 'client_secret_post'):
            response = self.client.post('/oauth/mcp/register', json=dict(client_name='Remote client', token_endpoint_auth_method=method,
                redirect_uris=['https://client.example/callback']))
            self.assertEqual(response.status_code, 201, response.text)
            client = response.json()
            self.params.update(client_id=client['client_id'], redirect_uri='https://client.example/callback')
            code = self.code()
            self.assertEqual(self.exchange(code, client_id=client['client_id']).status_code, 401)
            data = dict(grant_type='authorization_code', client_id=client['client_id'], code=code, redirect_uri=self.params['redirect_uri'],
                        resource=self.resource, code_verifier='v' * 43)
            headers = {}
            if method == 'client_secret_basic':
                headers['authorization'] = 'Basic ' + base64.b64encode(f'{client["client_id"]}:{client["client_secret"]}'.encode()).decode()
            else:
                data['client_secret'] = client['client_secret']
            result = self.post('token', data, headers=headers)
            self.assertEqual(result.status_code, 200, result.text)


class IdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_session_and_active_namespaced_identity(self):
        engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        owner = '00000000-0000-0000-0000-000000000001'
        site = '00000000-0000-0000-0000-000000000002'
        async with engine.begin() as conn:
            await conn.execute(text('CREATE TABLE users (id TEXT, is_active BOOLEAN)'))
            await conn.execute(text('CREATE TABLE website_users (id TEXT, website_id TEXT, is_active BOOLEAN)'))
            await conn.execute(text('INSERT INTO users VALUES (:id, 1)'), {'id': owner.replace('-', '')})
            await conn.execute(text('INSERT INTO website_users VALUES (:id, :site, 1)'), {'id': owner.replace('-', ''), 'site': site.replace('-', '')})
        try:
            async with AsyncSession(engine) as db:
                token = create_access_token(owner)
                request = Request({'type': 'http', 'headers': [(b'cookie', f'pidp_token={token}'.encode())]})
                actor = await oauth.identity_session(request, db)
                self.assertEqual(actor['subject'], f'owner:{owner}')
                self.assertTrue(await oauth.active_subject(db, f'website:{site}:{owner}'))
                self.assertFalse(await oauth.active_subject(db, f'website:{owner}:{owner}'))
                await db.execute(text('UPDATE users SET is_active=0')); await db.commit()
                self.assertIsNone(await oauth.identity_session(request, db))
                self.assertTrue(await oauth.active_subject(db, f'website:{site}:{owner}'))
                self.assertFalse(await oauth.active_subject(db, 'owner:not-a-uuid'))
        finally:
            await engine.dispose()


if __name__ == '__main__':
    unittest.main()

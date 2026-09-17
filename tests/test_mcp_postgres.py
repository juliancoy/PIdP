"""Optional real-PostgreSQL checks; each run owns and removes an isolated schema."""
import asyncio
import base64
import hashlib
import json
import os
import re
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

os.environ.setdefault('SECRET_KEY', 'oauth-test-secret')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwk
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
import mcp_authorization as oauth


@unittest.skipUnless(os.environ.get('PIDP_OAUTH_TEST_DATABASE_URL'), 'Set PIDP_OAUTH_TEST_DATABASE_URL to an isolated local PostgreSQL test database')
class PostgresOAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_schema_and_atomic_code_and_refresh_claims(self):
        database = os.environ['PIDP_OAUTH_TEST_DATABASE_URL']
        url = urlsplit(database)
        self.assertIn(url.hostname, ('127.0.0.1', 'localhost'))
        self.assertEqual(url.path, '/oauth_test')
        schema = 'oauth_test_' + uuid4().hex
        engine = create_async_engine(database, connect_args={'server_settings': {'search_path': schema}})
        issuer, resource = 'https://id.example', 'https://portal.example/mcp'
        key = jwk.construct(ec.generate_private_key(ec.SECP256R1()), 'ES256').to_dict()
        key['kid'] = 'test-key'
        try:
            async with engine.begin() as connection:
                await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
                tables = [t for t in oauth.Base.metadata.sorted_tables if t.name.startswith('mcp_oauth_')]
                await connection.run_sync(lambda conn: oauth.Base.metadata.create_all(conn, tables=tables))
                await connection.run_sync(lambda conn: oauth.Base.metadata.create_all(conn, tables=tables, checkfirst=True))
            app = FastAPI(); app.include_router(oauth.router)
            async def session():
                async with AsyncSession(engine) as db:
                    yield db
            app.dependency_overrides[oauth.get_session] = session
            with patch.multiple(oauth.settings, mcp_oauth_issuer=issuer, mcp_oauth_private_jwk=json.dumps(key),
                mcp_oauth_dynamic_registration=True,
                mcp_oauth_clients_json=json.dumps({'native': dict(name='Test', tokenEndpointAuthMethod='none',
                    redirectUris=['http://127.0.0.1/callback'], resources=[resource], scopes=oauth.SCOPES)}),
                mcp_oauth_resources_json=json.dumps({resource: {'secretHash': oauth.digest('resource-secret-at-least-32-characters')}})), \
                patch.object(oauth, 'session', AsyncMock(return_value=dict(subject='owner:alice', display='Alice', hash='session-hash'))), \
                patch.object(oauth, 'active_subject', AsyncMock(return_value=True)):
                async with AsyncClient(transport=ASGITransport(app=app), base_url=issuer) as client:
                    registration = await client.post('/oauth/mcp/register', json=dict(client_name='Postgres test', token_endpoint_auth_method='none', redirect_uris=['http://127.0.0.1/callback']))
                    self.assertEqual(registration.status_code, 201, registration.text)
                    params = dict(response_type='code', client_id='native', redirect_uri='http://127.0.0.1:49152/callback',
                        resource=resource, scope='org:events.read org:events.write', state='state', code_challenge_method='S256',
                        code_challenge=base64.urlsafe_b64encode(hashlib.sha256(b'v' * 43).digest()).decode().rstrip('='))
                    params['client_id'] = registration.json()['client_id']
                    consent = await client.get('/oauth/mcp/authorize', params=params)
                    self.assertEqual(consent.status_code, 200, consent.text)
                    nonce = re.search('name="request" value="([^"]+)"', consent.text)[1]
                    allowed = await client.post('/oauth/mcp/authorize', data=dict(request=nonce, decision='allow'), headers={'origin': issuer})
                    self.assertEqual(allowed.status_code, 303, allowed.text)
                    code = parse_qs(urlsplit(allowed.headers['location']).query)['code'][0]
                    exchange = dict(grant_type='authorization_code', client_id=params['client_id'], code=code,
                        redirect_uri=params['redirect_uri'], resource=resource, code_verifier='v' * 43)
                    results = await asyncio.gather(*(client.post('/oauth/mcp/token', data=exchange) for _ in range(2)))
                    self.assertEqual(sorted(r.status_code for r in results), [200, 400], [r.text for r in results])
                    tokens = next(r.json() for r in results if r.status_code == 200)
                    refresh = dict(grant_type='refresh_token', client_id=params['client_id'], refresh_token=tokens['refresh_token'])
                    results = await asyncio.gather(*(client.post('/oauth/mcp/token', data=refresh) for _ in range(2)))
                    self.assertEqual(sorted(r.status_code for r in results), [200, 400], [r.text for r in results])
                    renewed = next(r.json() for r in results if r.status_code == 200)
                    status = await client.post('/oauth/mcp/introspect', data=dict(token=renewed['access_token'], resource=resource),
                        headers={'authorization': 'Bearer resource-secret-at-least-32-characters'})
                    self.assertEqual(status.json(), {'active': False})
        finally:
            async with engine.begin() as connection:
                await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            await engine.dispose()


if __name__ == '__main__':
    unittest.main()

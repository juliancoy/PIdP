import asyncio
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

from starlette.requests import Request
from test_smoke import _load_main_module


def request(form=None):
    body = __import__('urllib.parse', fromlist=['urlencode']).urlencode(form or {}).encode()
    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}
    return Request({'type':'http','method':'POST','scheme':'https','server':('id.example',443),
                    'path':'/auth/resend-verification','query_string':b'',
                    'headers':[(b'host',b'id.example'),(b'content-type',b'application/x-www-form-urlencoded')]},receive)


class EmailVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = _load_main_module()

    def setUp(self):
        self.user = SimpleNamespace(email='member@example.test',identity_data={},is_active=True,provider=None,provider_account_id=None)
        result = SimpleNamespace(scalar_one_or_none=lambda:self.user)
        self.session = SimpleNamespace(execute=AsyncMock(return_value=result),commit=AsyncMock())

    def test_resend_cooldown_and_return_context(self):
        form={'email':self.user.email,'next':'/profile'}
        with patch.object(self.main,'_resolve_frontend_redirect_for_website',return_value='/profile'), \
             patch.object(self.main,'_stored_email_delivery_settings',AsyncMock(return_value={})), \
             patch.object(self.main,'_send_verification_email',AsyncMock()) as send:
            for _ in range(2):
                response=asyncio.run(self.main.resend_email_verification(request(form),self.session))
                self.assertEqual(response.status_code,303)
            self.assertEqual(send.await_count,1)
            self.assertEqual(self.user.identity_data['email_verification']['next'],'/profile')

    def test_link_completion_replay_expiry_and_namespace(self):
        url=self.main._prepare_email_verification(self.user,request(),next_url='/profile')
        token=parse_qs(urlparse(url).query)['token'][0]
        response=asyncio.run(self.main.verify_email(request(),self.user.email,token,None,self.session))
        self.assertIn('Email+verified',response.headers['location'])
        self.assertIn('next=%2Fprofile',response.headers['location'])
        response=asyncio.run(self.main.verify_email(request(),self.user.email,token,None,self.session))
        self.assertIn('invalid',response.headers['location'])
        self.main._prepare_email_verification(self.user,request())
        self.user.identity_data['email_verification']['expires_at']=(datetime.utcnow()-timedelta(days=1)).isoformat()
        response=asyncio.run(self.main.verify_email(request(),self.user.email,token,None,self.session))
        self.assertIn('expired',response.headers['location'])
        missing=SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda:None)))
        with patch.object(self.main,'shared_identity',return_value=False):
            response=asyncio.run(self.main.verify_email(request(),self.user.email,token,'other-app',missing))
        self.assertIn('invalid',response.headers['location'])
        self.assertEqual(missing.execute.await_count,1)

    def test_application_registration_creates_an_application_account(self):
        from models import WebsiteUser
        from uuid import uuid4
        site = SimpleNamespace(id=uuid4(), slug='members')
        self.session.execute = AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda:None))
        self.session.add = Mock()
        self.session.flush = AsyncMock()
        self.session.refresh = AsyncMock()
        with patch.object(self.main, 'hash_password', return_value='fixture-password-hash'), \
             patch.object(self.main, '_require_trusted_browser_origin'), \
             patch.object(self.main, 'shared_identity', return_value=False), \
             patch.object(self.main, '_resolve_login_website', AsyncMock(return_value=site)), \
             patch.object(self.main, '_resolve_frontend_redirect_for_website', return_value='/profile'), \
             patch.object(self.main, '_stored_email_delivery_settings', AsyncMock(return_value={})), \
             patch.object(self.main, '_send_verification_email', AsyncMock()):
            response = asyncio.run(self.main.frontend_register(request({'email':'new@example.test', 'password':'password123', 'app':'members', 'next':'/profile'}), self.session))
        account = self.session.add.call_args.args[0]
        self.assertIsInstance(account, WebsiteUser)
        self.assertEqual(account.website_id, site.id)
        self.assertEqual(response.status_code, 303)
        self.assertIn('Check+your+email', response.headers['location'])

import os
os.environ.setdefault('SECRET_KEY','portal-policy-test')
os.environ.setdefault('DATABASE_URL','postgresql+asyncpg://test:test@localhost/test')
import json
import unittest
from pathlib import Path
from unittest.mock import patch
import portal_clients as policy
ROOT=Path(__file__).parents[1]
class PortalClientsTests(unittest.TestCase):
    def test_shared_policy_for_every_product(self):
        defaults=json.loads((ROOT/'shared/portal-clients.json').read_text())
        cases=json.loads((ROOT/'shared/portal-return-cases.json').read_text())
        with patch.multiple(policy.settings,portal_auth_origins=','.join(defaults),portal_clients_json=''):
            for origin, client in defaults.items():
                self.assertEqual(policy.portal_client(origin)['name'],client['name'])
                self.assertEqual(policy.portal_client(origin)['accountApp'],'code-collective')
                self.assertIsNone(policy.sso_return(origin,'wrong','/auth/callback'))
                if not client.get('restartOrigin'):
                    for case in cases:
                        self.assertEqual(bool(policy.sso_return(origin,client['accountApp'],case['value'])),case['valid'],origin+' '+case['value'])
            self.assertIsNone(policy.portal_client('https://unregistered.example'))
    def test_browser_redirect_tricks_and_explicit_native_returns(self):
        with patch.multiple(policy.settings,portal_auth_origins='https://orgportal.cc',portal_clients_json='',public_base_url='https://id.example',frontend_redirect_url='',allowed_native_redirect_schemes='org.arkavo.portal'):
            for value in ['//evil.example','/\\evil.example','https://user:password@orgportal.cc/auth/callback','javascript:alert(1)','https://evil.example']:
                self.assertIsNone(policy.browser_return(value,'https://id.example'))
            self.assertEqual(policy.browser_return('org.arkavo.portal://auth/callback','https://id.example'),'org.arkavo.portal://auth/callback')

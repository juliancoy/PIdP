import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

os.environ.setdefault('SECRET_KEY', 'local-login-test-secret')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://test:test@localhost/test')
sys.path.insert(0, str(Path(__file__).parents[1]))

from starlette.requests import Request
from local_login import local_login_enabled, settings


def request(host='localhost:8443', client='127.0.0.1', origin='https://localhost:8443', site='same-origin'):
    return Request({
        'type': 'http', 'scheme': 'https', 'server': ('localhost', 8443),
        'path': '/pidp/app/login', 'root_path': '/pidp',
        'headers': [(b'host', host.encode()), (b'origin', origin.encode()),
                    (b'x-forwarded-for', client.encode()), (b'sec-fetch-site', site.encode())],
        'client': ('172.30.0.7', 1234),
    })


class LocalLoginTests(unittest.TestCase):
    def setUp(self):
        self.config = patch.multiple(
            settings, env='dev', public_base_url='https://localhost:8443/pidp',
            admin_user_ids=str(uuid5(NAMESPACE_URL, 'orgportal:local-developer-admin')),
        )
        self.config.start()
        self.addCleanup(self.config.stop)

    def test_local_origin_with_proxy_prefix(self):
        self.assertTrue(local_login_enabled(request()))

    def test_remote_clients_and_cross_origin_requests_are_denied(self):
        for changes in [dict(host='example.com'), dict(client='192.168.1.5'),
                        dict(origin='https://evil.example'), dict(site='cross-site')]:
            with self.subTest(changes=changes):
                self.assertFalse(local_login_enabled(request(**changes)))

    def test_production_and_unallowlisted_deployments_are_denied(self):
        for changes in [dict(env='production'), dict(admin_user_ids=''),
                        dict(public_base_url='https://orgportal.cc/pidp')]:
            with self.subTest(changes=changes), patch.multiple(settings, **changes):
                self.assertFalse(local_login_enabled(request()))

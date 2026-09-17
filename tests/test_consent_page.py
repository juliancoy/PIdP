import base64
import hashlib
import re
import unittest

from consent_page import render_consent_page


class ConsentPageTests(unittest.TestCase):
    def test_branding_escaping_and_content_security_hash(self):
        markup, policy = render_consent_page(client='<Codex>{{css}}', account='member@example.com',
            resource='https://medtech.social/api/org/mcp', callback='http://127.0.0.1:1234/callback', request='consent-test',
            change_account='/oauth/mcp/authorize?prompt=login', requested=['org:events.read', 'org:events.write'], dynamic=True)
        self.assertIn('Baltimore MedTech', markup)
        self.assertIn('https://medtech.social/images/baltimore-medtech-logo-square.jpg', markup)
        self.assertIn('&lt;Codex&gt;{{css}}', markup)
        self.assertNotIn('<Codex>', markup)
        self.assertNotIn('<script', markup)
        self.assertIn('not verified by PIdP', markup)
        css = re.search(r'<style>(.*?)</style>', markup, re.S)[1]
        digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
        self.assertIn("style-src 'sha256-" + digest + "'", policy)
        self.assertNotIn('unsafe-inline', policy)

    def test_other_portals_do_not_receive_medtech_branding(self):
        markup, policy = render_consent_page(client='App', account='member', resource='https://portal.example/mcp',
            callback='https://app.example/callback', request='consent-test', change_account='/oauth/mcp/authorize',
            requested=['org:events.read'], dynamic=False, portal={'name': 'Community Portal', 'loginUrl': 'https://portal.example/users/mcp-connect'})
        self.assertIn('Community Portal', markup)
        self.assertNotIn('Baltimore MedTech', markup)
        self.assertIn("img-src 'none'", policy)

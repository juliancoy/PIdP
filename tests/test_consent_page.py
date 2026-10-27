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
        self.assertEqual(markup.count('<form '), 1)
        self.assertIn('Confirm your account and review the requested permissions', markup)
        self.assertIn('Permissions requested by', markup)
        self.assertIn('Signed in as', markup)
        self.assertIn('Allow access', markup)
        self.assertIn('>Deny<', markup)
        self.assertIn('not verified by PIdP', markup)
        css = re.search(r'<style>(.*?)</style>', markup, re.S)[1]
        digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
        self.assertIn("style-src 'sha256-" + digest + "'", policy)
        self.assertNotIn('unsafe-inline', policy)

    def test_admin_switch_preserves_oauth_request_without_granting_authority(self):
        from urllib.parse import urlsplit, parse_qs
        args = dict(client='App', account='member', resource='https://portal.example/mcp',
                    callback='https://app.example/callback', request='consent-test',
                    change_account='/oauth/mcp/authorize?state=original&code_challenge=proof&prompt=login&browser=other',
                    requested=['org:portal.read'], dynamic=False)
        markup, _ = render_consent_page(**args)
        import html
        href = html.unescape(re.search(r'href="([^"]+)">Sign in as a system administrator', markup)[1])
        params = parse_qs(urlsplit(href).query)
        self.assertEqual(params, dict(state=['original'], code_challenge=['proof'], prompt=['login'], account=['system_admin']))
        self.assertNotIn('name="account" value="system_admin"', markup)
        admin, _ = render_consent_page(**args, system_admin_login=True)
        self.assertIn('name="account" value="system_admin"', admin)
        self.assertNotIn('>Sign in as a system administrator</a>', admin)

    def test_other_portals_do_not_receive_medtech_branding(self):
        markup, policy = render_consent_page(client='App', account='member', resource='https://portal.example/mcp',
            callback='https://app.example/callback', request='consent-test', change_account='/oauth/mcp/authorize',
            requested=['org:events.read'], dynamic=False, portal={'name': 'Community Portal', 'loginUrl': 'https://portal.example/users/mcp-connect'})
        self.assertIn('Community Portal', markup)
        self.assertNotIn('Baltimore MedTech', markup)
        self.assertIn("img-src 'none'", policy)


    def test_same_service_sign_in_has_clear_heading_and_keeps_consent(self):
        args = dict(client='Swarm Control', account='member', resource='https://compai.lifetech.fyi/api/swarm',
                    callback='https://compai.lifetech.fyi/auth/callback', request='consent-test',
                    change_account='/oauth/mcp/authorize', requested=['swarm:control'], dynamic=False)
        markup, _ = render_consent_page(**args)
        self.assertIn('<h1>Continue to Swarm Control</h1>', markup)
        self.assertIn('with your PIdP account', markup)
        self.assertIn('Control your swarm', markup)
        self.assertIn('Allow access', markup)
        self.assertIn('>Deny<', markup)
        for changed in (dict(dynamic=True), dict(callback='https://other.example/callback')):
            other, _ = render_consent_page(**{**args, **changed})
            self.assertIn('<h1>Connect Swarm Control to Swarm Control</h1>', other)

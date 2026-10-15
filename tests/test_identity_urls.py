import unittest
from identity_urls import mounted_identity_path, rewrite_identity_html

class IdentityMountTests(unittest.TestCase):
    def test_rewrites_identity_links_without_changing_portal_or_external_destinations(self):
        for path in ['/app/login?next=%2Fpeople','/auth/google/login','/profile','/assets/css/app.css']:
            self.assertEqual(mounted_identity_path(path,'/pidp'),'/pidp'+path)
        for path in ['/auth/callback','/people','//evil.test/app/login','https://example.test/app/login','/pidp/app/login']:
            self.assertEqual(mounted_identity_path(path,'/pidp'),path)
        self.assertEqual(rewrite_identity_html('<form action="/app/login"><input value="/people"><a href="/auth/callback">Back</a></form>','/pidp'),'<form action="/pidp/app/login"><input value="/people"><a href="/auth/callback">Back</a></form>')

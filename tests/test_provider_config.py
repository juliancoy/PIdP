import unittest
from provider_config import provider_enabled

class ProviderConfigTests(unittest.TestCase):
    def test_placeholders_and_incomplete_credentials_are_disabled(self):
        for provider in ('google','github'):
            self.assertFalse(provider_enabled(provider,f'{provider}-client-id',f'{provider}-client-secret'))
            self.assertFalse(provider_enabled(provider,'configured-id',None))
            self.assertFalse(provider_enabled(provider,None,'configured-secret'))
            self.assertFalse(provider_enabled(provider,'configured-id','changeme'))
            self.assertTrue(provider_enabled(provider,'configured-id','configured-secret'))
        self.assertFalse(provider_enabled('unknown','configured-id','configured-secret'))

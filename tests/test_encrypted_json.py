from __future__ import annotations

import base64
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_DIR = Path(__file__).resolve().parents[1]
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'postgresql+asyncpg://user:pass@localhost:5432/testdb')
import encrypted_json


class EncryptedJsonTests(unittest.TestCase):
    def tearDown(self):
        encrypted_json._fernets.cache_clear()

    def test_encrypt_json_wraps_and_decrypts_payload(self):
        key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        with patch.object(encrypted_json.settings, 'pii_encryption_keys', key):
            encrypted_json._fernets.cache_clear()
            payload = {'address_line1': '123 Main St', 'maslow_now': {'shelter': 2}}
            stored = encrypted_json.encrypt_json(payload)
            self.assertNotEqual(stored, payload)
            self.assertTrue(stored['__arkavo_encrypted_json__'])
            self.assertNotIn('123 Main St', str(stored))
            self.assertEqual(encrypted_json.decrypt_json(stored), payload)

    def test_encrypt_json_leaves_plaintext_when_key_absent_for_dev(self):
        with patch.object(encrypted_json.settings, 'pii_encryption_keys', ''):
            encrypted_json._fernets.cache_clear()
            payload = {'display_name': 'Example'}
            self.assertEqual(encrypted_json.encrypt_json(payload), payload)
            self.assertEqual(encrypted_json.decrypt_json(payload), payload)

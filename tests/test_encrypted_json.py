from __future__ import annotations

import base64
import importlib
import os
import sys
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[1]
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))


def _reload_encrypted_json(key: str | None):
    if key is None:
        os.environ.pop("PII_ENCRYPTION_KEYS", None)
    else:
        os.environ["PII_ENCRYPTION_KEYS"] = key
    os.environ.setdefault("SECRET_KEY", "test-secret-key")
    os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/testdb")
    for module_name in ("config", "encrypted_json"):
        sys.modules.pop(module_name, None)
    return importlib.import_module("encrypted_json")


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


def test_encrypt_json_wraps_and_decrypts_payload():
    encrypted_json = _reload_encrypted_json(_fernet_key())
    payload = {"address_line1": "123 Main St", "maslow_now": {"shelter": 2}}

    stored = encrypted_json.encrypt_json(payload)

    assert stored != payload
    assert stored["__arkavo_encrypted_json__"] is True
    assert "123 Main St" not in str(stored)
    assert encrypted_json.decrypt_json(stored) == payload


def test_encrypt_json_leaves_plaintext_when_key_absent_for_dev():
    encrypted_json = _reload_encrypted_json(None)
    payload = {"display_name": "Example"}

    assert encrypted_json.encrypt_json(payload) == payload
    assert encrypted_json.decrypt_json(payload) == payload

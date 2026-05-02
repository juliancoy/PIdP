from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from config import settings

LOG = logging.getLogger(__name__)
_ENCRYPTED_MARKER = "__arkavo_encrypted_json__"
_PRODUCTION_ENVS = {"prod", "production"}


def _configured_keys() -> list[str]:
    raw = getattr(settings, "pii_encryption_keys", "") or ""
    return [key.strip() for key in raw.split(",") if key.strip()]


@lru_cache(maxsize=1)
def _fernets() -> tuple[Fernet, ...]:
    keys = _configured_keys()
    return tuple(Fernet(key.encode("utf-8")) for key in keys)


def pii_encryption_enabled() -> bool:
    return bool(_configured_keys())


def validate_pii_encryption_config() -> None:
    keys = _configured_keys()
    env = (getattr(settings, "env", "") or "").strip().lower()
    require = bool(getattr(settings, "require_pii_encryption", False)) or env in _PRODUCTION_ENVS
    if require and not keys:
        raise RuntimeError("PII encryption is required but PII_ENCRYPTION_KEYS is not configured")
    if not keys:
        LOG.warning("PII field encryption is disabled; identity_data will be stored as plaintext JSON")
        return
    _fernets()


def encrypt_json(value: Any) -> Any:
    if value is None:
        value = {}
    if isinstance(value, dict) and value.get(_ENCRYPTED_MARKER) is True:
        return value
    if not pii_encryption_enabled():
        return value
    plaintext = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    token = _fernets()[0].encrypt(plaintext).decode("utf-8")
    return {
        _ENCRYPTED_MARKER: True,
        "v": 1,
        "alg": "fernet",
        "ciphertext": token,
    }


def decrypt_json(value: Any) -> Any:
    if not isinstance(value, dict) or value.get(_ENCRYPTED_MARKER) is not True:
        return value or {}
    token = value.get("ciphertext")
    if not isinstance(token, str) or not token:
        raise ValueError("Encrypted JSON payload is missing ciphertext")
    for fernet in _fernets():
        try:
            plaintext = fernet.decrypt(token.encode("utf-8"))
            return json.loads(plaintext.decode("utf-8"))
        except InvalidToken:
            continue
    raise ValueError("Encrypted JSON payload cannot be decrypted with configured PII keys")


class EncryptedJSONB(TypeDecorator):
    """JSONB column that encrypts new writes when PII_ENCRYPTION_KEYS is configured."""

    impl = JSONB
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        return encrypt_json(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        return decrypt_json(value)

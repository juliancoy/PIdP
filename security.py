from __future__ import annotations

from datetime import datetime, timedelta

from jose import JWTError, jwt, jwk
from jose.utils import base64url_encode
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import User


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_jwt_private_key = None
_jwt_public_key = None
_jwt_kid = None


def _load_or_generate_keys():
    global _jwt_private_key, _jwt_public_key, _jwt_kid
    if _jwt_private_key and _jwt_public_key and _jwt_kid:
        return _jwt_private_key, _jwt_public_key, _jwt_kid

    if settings.jwt_private_key and settings.jwt_public_key:
        _jwt_private_key = settings.jwt_private_key
        _jwt_public_key = settings.jwt_public_key
    else:
        # Dev fallback: generate ephemeral RSA keypair if none provided.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        _jwt_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        _jwt_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    thumbprint_source = _jwt_public_key.encode("utf-8")
    digest = hashlib.sha256(thumbprint_source).digest()
    _jwt_kid = base64url_encode(digest).decode("utf-8")
    return _jwt_private_key, _jwt_public_key, _jwt_kid


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    # bcrypt only considers the first 72 bytes; truncate to avoid runtime errors.
    if len(password.encode("utf-8")) > 72:
        password = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(password)


def create_access_token(subject: str, email: str | None = None) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    if email:
        payload["email"] = email
    if settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer
    if settings.jwt_audience:
        payload["aud"] = settings.jwt_audience

    if settings.token_algorithm.startswith("RS"):
        private_key, _, kid = _load_or_generate_keys()
        return jwt.encode(payload, private_key, algorithm=settings.token_algorithm, headers={"kid": kid})
    return jwt.encode(payload, settings.secret_key, algorithm=settings.token_algorithm)


async def authenticate_user(session: AsyncSession, email: str, password: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not user.hashed_password:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def decode_token(token: str) -> dict:
    options = {}
    if settings.jwt_issuer:
        options["issuer"] = settings.jwt_issuer
    if settings.jwt_audience:
        options["audience"] = settings.jwt_audience
    if settings.token_algorithm.startswith("RS"):
        _, public_key, _ = _load_or_generate_keys()
        return jwt.decode(token, public_key, algorithms=[settings.token_algorithm], **options)
    return jwt.decode(token, settings.secret_key, algorithms=[settings.token_algorithm], **options)


async def get_user_by_id(session: AsyncSession, user_id: str) -> User | None:
    result = await session.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


def safe_decode_token(token: str) -> dict | None:
    try:
        return decode_token(token)
    except JWTError:
        return None


def get_jwks() -> dict:
    if not settings.token_algorithm.startswith("RS"):
        return {"keys": []}
    _, public_key, kid = _load_or_generate_keys()
    key = jwk.construct(public_key, settings.token_algorithm)
    key_dict = key.to_dict()
    key_dict["kid"] = kid
    return {"keys": [key_dict]}

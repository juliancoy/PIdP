from __future__ import annotations

import json
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode

from config import settings
from db import engine, get_session
from models import Base, User
from oauth import fetch_social_profile, oauth
from schemas import Token, UserCreate, UserPublic, UserProfileUpdate, UserPublicProfile
from security import authenticate_user, create_access_token, hash_password, safe_decode_token, get_jwks


app = FastAPI(title=settings.app_name)

if settings.origins_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def _get_s3_client(endpoint_override: str | None = None):
    endpoint = endpoint_override or settings.minio_endpoint
    if not endpoint or not settings.minio_access_key or not settings.minio_secret_key:
        return None
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key,
        region_name="us-east-1",
    )


def _ensure_bucket(client) -> None:
    bucket = settings.minio_bucket
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError:
        client.create_bucket(Bucket=bucket)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    try:
        client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    except ClientError:
        pass


@app.on_event("startup")
async def startup() -> None:
    if settings.auto_create_tables:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return get_jwks()


@app.post("/auth/register", response_model=UserPublic)
async def register_user(payload: UserCreate, session: AsyncSession = Depends(get_session)) -> UserPublic:
    result = await session.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account already exists. Please log in.",
        )

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@app.post("/auth/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> Token:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(subject=str(user.id), email=user.email)
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserPublic)
async def get_me(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> UserPublic:
    payload = safe_decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await session.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@app.get("/auth/users", response_model=list[UserPublic])
async def find_users(
    email: str,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[UserPublic]:
    payload = safe_decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await session.execute(select(User).where(User.email.ilike(email)))
    users = result.scalars().all()
    return users


@app.get("/auth/public/users", response_model=list[UserPublicProfile])
async def get_public_users(ids: str, session: AsyncSession = Depends(get_session)) -> list[UserPublicProfile]:
    id_list = [item.strip() for item in ids.split(",") if item.strip()]
    if not id_list:
        return []
    result = await session.execute(select(User).where(User.id.in_(id_list)))
    users = result.scalars().all()
    profiles = []
    for user in users:
        identity = user.identity_data or {}
        profiles.append(
            UserPublicProfile(
                id=user.id,
                full_name=user.full_name,
                display_name=identity.get("display_name"),
                avatar_url=identity.get("avatar_url"),
            )
        )
    return profiles


@app.put("/auth/me", response_model=UserPublic)
async def update_me(
    payload: UserProfileUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> UserPublic:
    profile = payload.model_dump(exclude_unset=True)
    full_name = profile.pop("full_name", None)

    payload_data = safe_decode_token(token)
    if not payload_data or not payload_data.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await session.execute(select(User).where(User.id == payload_data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if full_name is not None:
        user.full_name = full_name

    identity = dict(user.identity_data or {})
    identity.update(profile)
    user.identity_data = identity

    await session.commit()
    await session.refresh(user)
    return user


@app.post("/auth/avatar/upload-url")
async def create_avatar_upload_url(token: str = Depends(oauth2_scheme)) -> JSONResponse:
    payload = safe_decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    internal_client = _get_s3_client()
    if not internal_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MinIO not configured")

    _ensure_bucket(internal_client)
    object_key = f"avatars/{payload['sub']}/{uuid4().hex}.png"
    public_endpoint = settings.minio_public_base_url.rstrip("/")
    signing_client = None
    if public_endpoint.startswith("http://") or public_endpoint.startswith("https://"):
        signing_client = _get_s3_client(endpoint_override=public_endpoint)
    if not signing_client:
        signing_client = internal_client
    try:
        upload_url = signing_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": settings.minio_bucket,
                "Key": object_key,
                "ContentType": "image/png",
            },
            ExpiresIn=300,
        )
    except ClientError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    public_url = f"{public_endpoint}/{settings.minio_bucket}/{object_key}"
    return JSONResponse({"upload_url": upload_url, "public_url": public_url, "object_key": object_key})


@app.get("/auth/{provider}/login")
async def social_login(provider: str, request: Request):
    if provider not in oauth:
        raise HTTPException(status_code=400, detail="Provider not enabled")

    redirect_uri = settings.google_redirect_uri if provider == "google" else settings.github_redirect_uri
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI not configured")

    return await oauth[provider].authorize_redirect(request, redirect_uri)


@app.get("/auth/{provider}/callback")
async def social_callback(
    provider: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    profile = await fetch_social_profile(provider, request)
    if not profile.get("email"):
        raise HTTPException(status_code=400, detail="Provider did not return an email")

    result = await session.execute(
        select(User).where(
            (User.provider == provider) & (User.provider_account_id == profile["provider_account_id"])
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        result = await session.execute(select(User).where(User.email == profile["email"]))
        user = result.scalar_one_or_none()

    if not user:
        user = User(
            email=profile["email"],
            full_name=profile.get("full_name"),
            provider=provider,
            provider_account_id=profile.get("provider_account_id"),
            identity_data=profile.get("raw", {}),
        )
        session.add(user)
    else:
        user.provider = provider
        user.provider_account_id = profile.get("provider_account_id")
        user.identity_data = profile.get("raw", {})

    await session.commit()
    await session.refresh(user)

    token = create_access_token(subject=str(user.id), email=user.email)
    if settings.frontend_redirect_url:
        params = urlencode({"token": token, "token_type": "bearer"})
        return RedirectResponse(f"{settings.frontend_redirect_url}#{params}")
    return JSONResponse({"access_token": token, "token_type": "bearer"})

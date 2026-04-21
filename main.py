from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from uuid import UUID, uuid4

import boto3
import httpx
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from urllib.parse import urlencode, urlparse

from config import settings
from db import engine, get_session
from models import Base, User, Website, WebsiteUser
from oauth import fetch_social_profile, oauth
from schemas import (
    Token,
    UserCreate,
    UserProfileUpdate,
    UserPublic,
    UserPublicProfile,
    WebsiteCreate,
    WebsitePublic,
    WebsiteSchemaField,
    WebsiteSchemaUpdate,
    WebsiteUserCreate,
    WebsiteUserLogin,
    WebsiteUserPublic,
    WebsiteUserUpdate,
)
from security import (
    authenticate_user,
    create_access_token,
    get_jwks,
    hash_password,
    safe_decode_token,
    verify_password,
)

optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)

LOG = logging.getLogger(__name__)
MAX_WEBSITES_PER_OWNER = 5
DEFAULT_MAX_USERS_PER_WEBSITE = 10
FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
FRONTEND_ASSETS_DIR = FRONTEND_DIR / "assets"
FRONTEND_TEMPLATES_DIR = FRONTEND_DIR / "templates"
SESSION_COOKIE_NAME = "pidp_token"
SYSTEM_SCHEMA_FIELDS = {
    "display_name": WebsiteSchemaField(
        type="string",
        required=False,
        label="Display Name",
        description="Public-facing name for the website user.",
        system=True,
    ).model_dump(),
    "avatar_url": WebsiteSchemaField(
        type="string",
        required=False,
        label="Avatar URL",
        description="Public profile image URL for the website user.",
        system=True,
    ).model_dump(),
    "first_name": WebsiteSchemaField(
        type="string",
        required=False,
        label="First Name",
        description="Given name stored for the website user.",
        system=True,
    ).model_dump(),
    "last_name": WebsiteSchemaField(
        type="string",
        required=False,
        label="Last Name",
        description="Family name stored for the website user.",
        system=True,
    ).model_dump(),
}


app = FastAPI(title=settings.app_name)
app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS_DIR)), name="pidp-assets")
templates = Jinja2Templates(directory=str(FRONTEND_TEMPLATES_DIR))


def _load_pidp_editme():
    try:
        import pidp_editme

        return pidp_editme
    except Exception:
        return None


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


def _set_session_cookie(response: RedirectResponse, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=settings.access_token_expire_minutes * 60,
    )


def _clear_session_cookie(response: RedirectResponse) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def _request_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return request.cookies.get(SESSION_COOKIE_NAME)


def _required_request_token(request: Request, token: str | None = None) -> str:
    resolved = token or _request_token(request)
    if not resolved:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return resolved


def _render_template(
    request: Request,
    template_name: str,
    context: dict,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context={
            "request": request,
            "page_title": "PIdP",
            "active_page": None,
            "viewer": None,
            "flash_error": request.query_params.get("error"),
            "flash_message": request.query_params.get("message"),
            **context,
        },
        status_code=status_code,
    )


def _normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if not slug:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Website slug is invalid")
    if len(slug) > 120:
        slug = slug[:120].rstrip("-")
    return slug


def _normalize_website_schema(fields: dict[str, WebsiteSchemaField]) -> dict:
    normalized: dict[str, dict] = {}
    for field_name, field in fields.items():
        key = field_name.strip()
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,62}", key):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Schema field '{field_name}' is invalid",
            )
        if key in SYSTEM_SCHEMA_FIELDS:
            system_field = SYSTEM_SCHEMA_FIELDS[key]
            incoming = field.model_dump()
            if incoming["type"] != system_field["type"] or incoming["required"] != system_field["required"]:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Field '{key}' is reserved and cannot be redefined",
                )
            continue
        normalized[key] = field.model_dump()
    normalized.update(SYSTEM_SCHEMA_FIELDS)
    return normalized


def _validate_identity_data(identity_data: dict | None, schema_fields: dict) -> dict:
    payload = dict(identity_data or {})
    allowed_fields = set(schema_fields.keys())
    unknown_fields = sorted(set(payload.keys()) - allowed_fields)
    if unknown_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown identity fields: {', '.join(unknown_fields)}",
        )

    for field_name, definition in schema_fields.items():
        if definition.get("required") and field_name not in payload:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required identity field: {field_name}",
            )
        if field_name not in payload:
            continue
        value = payload[field_name]
        field_type = definition.get("type")
        if field_type == "string" and not isinstance(value, str):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} must be a string")
        if field_type == "number" and not isinstance(value, (int, float)):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} must be a number")
        if field_type == "boolean" and not isinstance(value, bool):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} must be a boolean")
        if field_type == "array" and not isinstance(value, list):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} must be an array")
        if field_type == "object" and not isinstance(value, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} must be an object")
    return payload


async def _get_s3_client(endpoint_override: str | None = None):
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


async def _store_social_avatar(
    user_id: str,
    provider: str,
    avatar_url: str,
) -> dict | None:
    if not avatar_url:
        return None
    client = await _get_s3_client()
    if not client:
        return None
    try:
        await run_in_threadpool(_ensure_bucket, client)
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as http:
            resp = await http.get(avatar_url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "image/jpeg").split(";")[0].strip()
            ext = {
                "image/png": "png",
                "image/jpeg": "jpg",
                "image/jpg": "jpg",
                "image/gif": "gif",
                "image/webp": "webp",
            }.get(content_type, "jpg")
            object_key = f"avatars/{user_id}/{uuid4().hex}.{ext}"
            await run_in_threadpool(
                client.put_object,
                Bucket=settings.minio_bucket,
                Key=object_key,
                Body=resp.content,
                ContentType=content_type,
            )
        public_endpoint = (settings.minio_public_base_url or "").rstrip("/")
        if not public_endpoint:
            return None
        return {
            "avatar_url": f"{public_endpoint}/{settings.minio_bucket}/{object_key}",
            "avatar_object_key": object_key,
            "avatar_source": provider,
        }
    except Exception as exc:
        LOG.warning(
            "Social avatar storage degraded because MinIO is unavailable or misconfigured. "
            "Bring the minio service up to restore stored avatars. provider=%s user_id=%s error=%s",
            provider,
            user_id,
            exc,
        )
        return {
            "avatar_url": avatar_url,
            "avatar_source": f"{provider}-external",
        }


async def _get_current_owner(token: str, session: AsyncSession) -> User:
    payload = safe_decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload.get("actor_type") == "website_user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Website user tokens cannot manage websites")

    result = await session.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


async def _get_owned_website(session: AsyncSession, owner_id: UUID, website_id: UUID) -> Website:
    result = await session.execute(select(Website).where((Website.id == website_id) & (Website.owner_id == owner_id)))
    website = result.scalar_one_or_none()
    if not website:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website not found")
    return website


async def _count_websites_for_owner(session: AsyncSession, owner_id: UUID) -> int:
    result = await session.execute(select(func.count()).select_from(Website).where(Website.owner_id == owner_id))
    return result.scalar_one()


async def _count_users_for_website(session: AsyncSession, website_id: UUID) -> int:
    result = await session.execute(select(func.count()).select_from(WebsiteUser).where(WebsiteUser.website_id == website_id))
    return result.scalar_one()


async def _get_request_owner(request: Request, session: AsyncSession) -> User | None:
    token = _request_token(request)
    if not token:
        return None
    try:
        return await _get_current_owner(token, session)
    except HTTPException:
        return None


async def _website_user_counts(session: AsyncSession, websites: list[Website]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for website in websites:
        counts[str(website.id)] = await _count_users_for_website(session, website.id)
    return counts


def _profile_fields(user: User) -> dict[str, str]:
    identity = dict(user.identity_data or {})
    organizations = identity.get("organizations") or []
    if not isinstance(organizations, list):
        organizations = []
    return {
        "full_name": user.full_name or "",
        "display_name": identity.get("display_name") or "",
        "first_name": identity.get("first_name") or "",
        "last_name": identity.get("last_name") or "",
        "city": identity.get("city") or "",
        "state": identity.get("state") or "",
        "avatar_url": identity.get("avatar_url") or "",
        "bio": identity.get("bio") or "",
        "organizations": ", ".join(item for item in organizations if isinstance(item, str)),
    }


@app.on_event("startup")
async def startup() -> None:
    if settings.auto_create_tables:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


@app.get("/", include_in_schema=False)
async def frontend_home(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return _render_template(
            request,
            "home.html",
            {
                "page_title": "PIdP Console",
                "active_page": "home",
                "configuration": {
                    "google_enabled": settings.social_enabled("google"),
                    "github_enabled": settings.social_enabled("github"),
                },
            },
        )

    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    websites = list(result.scalars().all())
    return _render_template(
        request,
        "dashboard.html",
        {
            "page_title": "PIdP Dashboard",
            "active_page": "home",
            "viewer": owner,
            "websites": websites,
        },
    )


@app.post("/session/login", include_in_schema=False)
async def frontend_login(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    user = await authenticate_user(session, email, password)
    if not user:
        return RedirectResponse(url="/?error=Invalid+credentials", status_code=status.HTTP_303_SEE_OTHER)

    token = create_access_token(subject=str(user.id), email=user.email)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response


@app.post("/session/register", include_in_schema=False)
async def frontend_register(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    full_name = str(form.get("full_name") or "").strip() or None

    result = await session.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        return RedirectResponse(url="/?error=Account+already+exists", status_code=status.HTTP_303_SEE_OTHER)

    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token = create_access_token(subject=str(user.id), email=user.email)
    response = RedirectResponse(url="/?message=Account+created", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response


@app.post("/session/logout", include_in_schema=False)
async def frontend_logout() -> RedirectResponse:
    response = RedirectResponse(url="/?message=Signed+out", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookie(response)
    return response


@app.get("/profile", include_in_schema=False)
async def frontend_profile(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    websites = list(result.scalars().all())
    return _render_template(
        request,
        "profile.html",
        {
            "page_title": "Your Profile",
            "active_page": "profile",
            "viewer": owner,
            "websites": websites,
            "profile_fields": _profile_fields(owner),
        },
    )


@app.post("/profile", include_in_schema=False)
async def frontend_profile_update(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    form = await request.form()
    profile = {
        "display_name": str(form.get("display_name") or "").strip() or None,
        "first_name": str(form.get("first_name") or "").strip() or None,
        "last_name": str(form.get("last_name") or "").strip() or None,
        "city": str(form.get("city") or "").strip() or None,
        "state": str(form.get("state") or "").strip() or None,
        "avatar_url": str(form.get("avatar_url") or "").strip() or None,
        "bio": str(form.get("bio") or "").strip() or None,
        "organizations": [
            item.strip()
            for item in str(form.get("organizations") or "").split(",")
            if item.strip()
        ],
    }

    owner.full_name = str(form.get("full_name") or "").strip() or None
    identity = dict(owner.identity_data or {})
    for key, value in profile.items():
        if value in (None, "", []):
            identity.pop(key, None)
        else:
            identity[key] = value
    owner.identity_data = identity
    await session.commit()
    return RedirectResponse(url="/profile?message=Profile+saved", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/sites", include_in_schema=False)
async def frontend_sites(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    websites = list(result.scalars().all())
    counts = await _website_user_counts(session, websites)
    return _render_template(
        request,
        "sites.html",
        {
            "page_title": "Your Websites",
            "active_page": "sites",
            "viewer": owner,
            "websites": websites,
            "website_counts": counts,
        },
    )


@app.post("/sites", include_in_schema=False)
async def frontend_create_site(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    website_count = await _count_websites_for_owner(session, owner.id)
    if website_count >= MAX_WEBSITES_PER_OWNER:
        return RedirectResponse(
            url="/sites?error=Website+limit+reached",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    form = await request.form()
    name = str(form.get("name") or "").strip()
    slug = _normalize_slug(str(form.get("slug") or "").strip() or name)
    description = str(form.get("description") or "").strip() or None

    existing = await session.execute(select(Website).where(Website.slug == slug))
    if existing.scalar_one_or_none():
        return RedirectResponse(url="/sites?error=Website+slug+already+exists", status_code=status.HTTP_303_SEE_OTHER)

    website = Website(
        owner_id=owner.id,
        name=name,
        slug=slug,
        description=description,
        user_schema=dict(SYSTEM_SCHEMA_FIELDS),
        max_users=DEFAULT_MAX_USERS_PER_WEBSITE,
    )
    session.add(website)
    await session.commit()
    return RedirectResponse(url="/sites?message=Website+created", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/billing", include_in_schema=False)
async def frontend_billing(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    websites = list(result.scalars().all())
    return _render_template(
        request,
        "billing.html",
        {
            "page_title": "Billing",
            "active_page": "billing",
            "viewer": owner,
            "websites": websites,
        },
    )


@app.get("/sites/{website_id}", include_in_schema=False)
async def frontend_site_detail(
    website_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(url="/?error=Sign+in+required", status_code=status.HTTP_303_SEE_OTHER)

    website = await _get_owned_website(session, owner.id, website_id)
    result = await session.execute(
        select(WebsiteUser).where(WebsiteUser.website_id == website.id).order_by(WebsiteUser.created_at)
    )
    users = list(result.scalars().all())
    return _render_template(
        request,
        "site_detail.html",
        {
            "page_title": website.name,
            "active_page": "sites",
            "viewer": owner,
            "website": website,
            "website_users": users,
        },
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return get_jwks()


@app.get("/configuration")
async def configuration() -> dict:
    config = _load_pidp_editme()
    if config is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="pidp_editme unavailable")
    return {
        "base_addr": getattr(config, "BASE_ADDR", None),
        "google_client_id": getattr(config, "PIDP_GOOGLE_CLIENT_ID", None),
        "google_redirect_uri": getattr(config, "PIDP_GOOGLE_REDIRECT_URI", None),
        "github_client_id": getattr(config, "PIDP_GITHUB_CLIENT_ID", None),
        "github_redirect_uri": getattr(config, "PIDP_GITHUB_REDIRECT_URI", None),
        "frontend_redirect_url": getattr(config, "PIDP_FRONTEND_REDIRECT_URL", None),
        "minio_endpoint": getattr(config, "MINIO_ENDPOINT", None),
        "minio_bucket": getattr(config, "MINIO_BUCKET", None),
        "minio_public_base_url": getattr(config, "MINIO_PUBLIC_BASE_URL", None),
    }


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
    user = await _get_current_owner(token, session)
    return user


@app.get("/auth/users", response_model=list[UserPublic])
async def find_users(
    email: str,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[UserPublic]:
    await _get_current_owner(token, session)
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
    user = await _get_current_owner(token, session)

    if full_name is not None:
        user.full_name = full_name

    identity = dict(user.identity_data or {})
    identity.update(profile)
    user.identity_data = identity

    await session.commit()
    await session.refresh(user)
    return user


@app.post("/auth/avatar/upload-url")
async def create_avatar_upload_url(
    request: Request,
    token: str | None = Depends(optional_oauth2_scheme),
) -> JSONResponse:
    payload = safe_decode_token(_required_request_token(request, token))
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    internal_client = await _get_s3_client()
    if not internal_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MinIO not configured")

    try:
        _ensure_bucket(internal_client)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MinIO is unavailable. Bring the minio service up before uploading avatars.",
        ) from exc
    object_key = f"avatars/{payload['sub']}/{uuid4().hex}.png"
    public_endpoint = settings.minio_public_base_url.rstrip("/")
    signing_client = None
    if public_endpoint.startswith("http://") or public_endpoint.startswith("https://"):
        signing_client = await _get_s3_client(endpoint_override=public_endpoint)
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


@app.post("/profile/avatar", include_in_schema=False)
async def commit_profile_avatar(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required")

    payload = await request.json()
    avatar_url = str(payload.get("avatar_url") or "").strip()
    object_key = str(payload.get("object_key") or "").strip()
    if not avatar_url or not object_key:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="avatar_url and object_key are required")

    identity = dict(owner.identity_data or {})
    identity["avatar_url"] = avatar_url
    identity["avatar_object_key"] = object_key
    identity["avatar_source"] = "uploaded"
    owner.identity_data = identity

    await session.commit()
    await session.refresh(owner)
    return JSONResponse(
        {
            "avatar_url": identity["avatar_url"],
            "avatar_object_key": identity["avatar_object_key"],
        }
    )


@app.post("/websites", response_model=WebsitePublic)
async def create_website(
    payload: WebsiteCreate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_current_owner(token, session)
    website_count = await _count_websites_for_owner(session, owner.id)
    if website_count >= MAX_WEBSITES_PER_OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Each account may only create {MAX_WEBSITES_PER_OWNER} websites",
        )

    slug = _normalize_slug(payload.slug or payload.name)
    existing = await session.execute(select(Website).where(Website.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Website slug already exists")

    website = Website(
        owner_id=owner.id,
        name=payload.name.strip(),
        slug=slug,
        description=payload.description,
        user_schema=dict(SYSTEM_SCHEMA_FIELDS),
        max_users=DEFAULT_MAX_USERS_PER_WEBSITE,
    )
    session.add(website)
    await session.commit()
    await session.refresh(website)
    return website


@app.get("/websites", response_model=list[WebsitePublic])
async def list_websites(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[WebsitePublic]:
    owner = await _get_current_owner(token, session)
    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    return result.scalars().all()


@app.get("/websites/{website_id}", response_model=WebsitePublic)
async def get_website(
    website_id: UUID,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_current_owner(token, session)
    return await _get_owned_website(session, owner.id, website_id)


@app.put("/websites/{website_id}/schema", response_model=WebsitePublic)
async def update_website_schema(
    website_id: UUID,
    payload: WebsiteSchemaUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_current_owner(token, session)
    website = await _get_owned_website(session, owner.id, website_id)
    website.user_schema = _normalize_website_schema(payload.fields)
    await session.commit()
    await session.refresh(website)
    return website


@app.get("/websites/{website_id}/users", response_model=list[WebsiteUserPublic])
async def list_website_users(
    website_id: UUID,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[WebsiteUserPublic]:
    owner = await _get_current_owner(token, session)
    await _get_owned_website(session, owner.id, website_id)
    result = await session.execute(
        select(WebsiteUser).where(WebsiteUser.website_id == website_id).order_by(WebsiteUser.created_at)
    )
    return result.scalars().all()


@app.post("/websites/{website_id}/users", response_model=WebsiteUserPublic)
async def create_website_user(
    website_id: UUID,
    payload: WebsiteUserCreate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsiteUserPublic:
    owner = await _get_current_owner(token, session)
    website = await _get_owned_website(session, owner.id, website_id)
    user_count = await _count_users_for_website(session, website.id)
    if user_count >= website.max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Website user limit reached ({website.max_users})",
        )

    existing = await session.execute(
        select(WebsiteUser).where((WebsiteUser.website_id == website.id) & (WebsiteUser.email == payload.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Website user already exists")

    identity_data = _validate_identity_data(payload.identity_data, website.user_schema or SYSTEM_SCHEMA_FIELDS)
    website_user = WebsiteUser(
        website_id=website.id,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        identity_data=identity_data,
    )
    session.add(website_user)
    await session.commit()
    await session.refresh(website_user)
    return website_user


@app.put("/websites/{website_id}/users/{website_user_id}", response_model=WebsiteUserPublic)
async def update_website_user(
    website_id: UUID,
    website_user_id: UUID,
    payload: WebsiteUserUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsiteUserPublic:
    owner = await _get_current_owner(token, session)
    website = await _get_owned_website(session, owner.id, website_id)

    result = await session.execute(
        select(WebsiteUser).where((WebsiteUser.id == website_user_id) & (WebsiteUser.website_id == website.id))
    )
    website_user = result.scalar_one_or_none()
    if not website_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website user not found")

    if payload.full_name is not None:
        website_user.full_name = payload.full_name
    if payload.is_active is not None:
        website_user.is_active = payload.is_active
    if payload.identity_data is not None:
        website_user.identity_data = _validate_identity_data(payload.identity_data, website.user_schema)

    await session.commit()
    await session.refresh(website_user)
    return website_user


@app.post("/websites/{website_slug}/auth/register", response_model=WebsiteUserPublic)
async def register_website_user(
    website_slug: str,
    payload: WebsiteUserCreate,
    session: AsyncSession = Depends(get_session),
) -> WebsiteUserPublic:
    result = await session.execute(select(Website).where(Website.slug == _normalize_slug(website_slug)))
    website = result.scalar_one_or_none()
    if not website:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website not found")

    user_count = await _count_users_for_website(session, website.id)
    if user_count >= website.max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Website user limit reached ({website.max_users})",
        )

    existing = await session.execute(
        select(WebsiteUser).where((WebsiteUser.website_id == website.id) & (WebsiteUser.email == payload.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Website user already exists")

    website_user = WebsiteUser(
        website_id=website.id,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        identity_data=_validate_identity_data(payload.identity_data, website.user_schema or SYSTEM_SCHEMA_FIELDS),
    )
    session.add(website_user)
    await session.commit()
    await session.refresh(website_user)
    return website_user


@app.post("/websites/{website_slug}/auth/token", response_model=Token)
async def login_website_user(
    website_slug: str,
    payload: WebsiteUserLogin,
    session: AsyncSession = Depends(get_session),
) -> Token:
    result = await session.execute(select(Website).where(Website.slug == _normalize_slug(website_slug)))
    website = result.scalar_one_or_none()
    if not website:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website not found")

    result = await session.execute(
        select(WebsiteUser).where((WebsiteUser.website_id == website.id) & (WebsiteUser.email == payload.email))
    )
    website_user = result.scalar_one_or_none()
    if not website_user or not website_user.hashed_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not website_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Website user is inactive")

    if not verify_password(payload.password, website_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(
        subject=str(website_user.id),
        email=website_user.email,
        extra_claims={"actor_type": "website_user", "website_id": str(website.id)},
    )
    return Token(access_token=token)


@app.get("/websites/{website_slug}/auth/me", response_model=WebsiteUserPublic)
async def get_website_user_me(
    website_slug: str,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsiteUserPublic:
    payload = safe_decode_token(token)
    if not payload or payload.get("actor_type") != "website_user" or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid website user token")

    result = await session.execute(select(Website).where(Website.slug == _normalize_slug(website_slug)))
    website = result.scalar_one_or_none()
    if not website:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website not found")
    if payload.get("website_id") != str(website.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token does not belong to this website")

    result = await session.execute(
        select(WebsiteUser).where((WebsiteUser.id == payload["sub"]) & (WebsiteUser.website_id == website.id))
    )
    website_user = result.scalar_one_or_none()
    if not website_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website user not found")
    return website_user


@app.get("/auth/{provider}/login")
async def social_login(provider: str, request: Request):
    client = oauth.create_client(provider)
    if client is None:
        raise HTTPException(status_code=400, detail="Provider not enabled")

    redirect_uri = settings.google_redirect_uri if provider == "google" else settings.github_redirect_uri
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI not configured")

    next_url = request.query_params.get("next")
    if next_url and next_url.startswith("/"):
        request.session["frontend_redirect_url"] = next_url
    elif next_url:
        request.session["frontend_redirect_url"] = next_url
    return await client.authorize_redirect(request, redirect_uri)


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

    identity = dict(user.identity_data or {})
    existing_avatar_url = identity.get("avatar_url")
    existing_avatar_key = identity.get("avatar_object_key")
    raw_profile = dict(profile.get("raw", {}) or {})
    raw_profile.pop("picture", None)
    raw_profile.pop("avatar_url", None)
    identity.update(raw_profile)
    if existing_avatar_key:
        identity["avatar_object_key"] = existing_avatar_key
    if existing_avatar_url:
        identity["avatar_url"] = existing_avatar_url
    if not existing_avatar_url and not existing_avatar_key and profile.get("avatar_url"):
        if not user.id:
            user.id = uuid4()
        stored = await _store_social_avatar(str(user.id), provider, profile["avatar_url"])
        if stored:
            identity.update(stored)
    user.identity_data = identity

    await session.commit()
    await session.refresh(user)

    token = create_access_token(subject=str(user.id), email=user.email)
    redirect_target = request.session.pop("frontend_redirect_url", None)
    if redirect_target:
        if redirect_target.startswith("/"):
            pass
        else:
            parsed = urlparse(redirect_target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                redirect_target = None
            elif parsed.netloc == request.url.netloc:
                redirect_target = f"{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"
    if redirect_target:
        if redirect_target.startswith("/"):
            response = RedirectResponse(redirect_target, status_code=status.HTTP_303_SEE_OTHER)
            _set_session_cookie(response, token)
            return response
        params = urlencode({"token": token, "token_type": "bearer"})
        return RedirectResponse(f"{redirect_target}#{params}")
    if settings.frontend_redirect_url:
        parsed = urlparse(settings.frontend_redirect_url)
        if parsed.netloc == request.url.netloc:
            response = RedirectResponse(parsed.path or "/", status_code=status.HTTP_303_SEE_OTHER)
            _set_session_cookie(response, token)
            return response
        params = urlencode({"token": token, "token_type": "bearer"})
        return RedirectResponse(f"{settings.frontend_redirect_url}#{params}")
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response

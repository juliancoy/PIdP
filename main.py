from __future__ import annotations

import json
import logging
import os
import re
import secrets
import hashlib
from datetime import datetime
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
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from urllib.parse import quote, urlencode, urlparse

from config import settings
from db import SessionLocal, engine, get_session
from encrypted_json import validate_pii_encryption_config
from models import Base, User, UserAPIToken, Website, WebsiteUser
from oauth import fetch_social_profile, oauth
from schemas import (
    APITokenCreate,
    APITokenIssued,
    APITokenPublic,
    APITokenUpdate,
    ServiceTokenInfo,
    Token,
    UserCreate,
    UserProfileUpdate,
    UserPublic,
    UserPublicProfile,
    WebsiteCreate,
    WebsiteAuthConfigUpdate,
    WebsiteBrandingUpdate,
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
    "birth_date": WebsiteSchemaField(
        type="string",
        required=False,
        label="Birthday",
        description="Birthday stored as YYYY-MM-DD for the website user.",
        system=True,
    ).model_dump(),
}


app = FastAPI(title=settings.app_name)
app.mount("/assets", StaticFiles(directory=str(FRONTEND_ASSETS_DIR)), name="pidp-assets")
templates = Jinja2Templates(directory=str(FRONTEND_TEMPLATES_DIR))


if settings.origins_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="pidp_oauth_session",
    https_only=True,
    same_site="none",
    max_age=20 * 60,
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

ALLOWED_API_TOKEN_SCOPES = {"service", "org_portal", "org_mcp", "org_admin"}
TOKEN_SCOPE_GRANTS: dict[str, list[str]] = {
    "service": ["service:*"],
    "org_portal": [
        "org:profile.read",
        "org:profile.write",
        "org:events.attend",
        "org:chat.use",
    ],
    "org_mcp": [
        "org:mcp.use",
        "org:profile.read",
        "org:events.read",
    ],
    "org_admin": [
        "org:*",
        "org:admin.read",
        "org:admin.write",
        "org:mcp.use",
    ],
}


def _is_request_secure(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=settings.access_token_expire_minutes * 60,
    )


def _clear_session_cookie(response: Response) -> None:
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
            "ui_base": "",
            "asset_base": "/assets",
            **context,
        },
        status_code=status_code,
    )


def _resolve_frontend_redirect_target(request: Request, raw_target: str | None) -> str | None:
    redirect_target = (raw_target or "").strip() or None
    if not redirect_target:
        return None
    if redirect_target.startswith("/"):
        return redirect_target
    parsed = urlparse(redirect_target)
    native_scheme = (parsed.scheme or "").strip().lower()
    if native_scheme and native_scheme in settings.native_redirect_schemes_list:
        return redirect_target
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.netloc == request.url.netloc:
        return f"{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"
    request_lane = _host_environment_lane(_request_host(request))
    target_lane = _host_environment_lane(parsed.netloc)
    if (
        not settings.allow_cross_lane_redirect
        and request_lane
        and target_lane
        and request_lane != target_lane
    ):
        return None
    return redirect_target


def _host_environment_lane(host: str | None) -> str | None:
    normalized = _normalize_host(host)
    if not normalized:
        return None
    return "dev" if normalized.startswith("dev.") else "prod"


def _lane_host_for_request_host(request_host: str, lane: str) -> str:
    normalized = _normalize_host(request_host) or request_host
    if lane == "dev":
        if normalized.startswith("dev."):
            return normalized
        return f"dev.{normalized}"
    if normalized.startswith("dev."):
        return normalized[4:]
    return normalized


def _cross_lane_login_redirect(request: Request, raw_target: str | None) -> str | None:
    if not settings.allow_cross_lane_redirect:
        return None
    resolved_target = _resolve_frontend_redirect_target(request, raw_target)
    if not resolved_target or resolved_target.startswith("/"):
        return None

    parsed_target = urlparse(resolved_target)
    target_lane = _host_environment_lane(parsed_target.netloc)
    request_host = _request_host(request)
    request_lane = _host_environment_lane(request_host)
    if not target_lane or not request_lane or target_lane == request_lane or not request_host:
        return None

    desired_host = _lane_host_for_request_host(request_host, target_lane)
    if desired_host == request_host:
        return None

    scheme = "https" if _is_request_secure(request) else request.url.scheme
    query = request.url.query
    path = request.url.path or "/"
    return f"{scheme}://{desired_host}{path}{f'?{query}' if query else ''}"


def _normalize_host(value: str | None) -> str | None:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc.strip().lower()
    if raw.startswith("[") and "]" in raw:
        host, _, port = raw.partition("]")
        raw = f"{host}]"
        if port.startswith(":"):
            raw = f"{raw}{port}"
    if ":" in raw and not raw.startswith("["):
        host, _, port = raw.partition(":")
        if port and port.isdigit():
            raw = host
    raw = raw.strip(".")
    if not raw:
        return None
    return raw


def _normalize_origin(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    host = _normalize_host(parsed.netloc)
    if not host:
        return None
    default_port = (parsed.scheme == "https" and parsed.port in {None, 443}) or (parsed.scheme == "http" and parsed.port in {None, 80})
    if parsed.port and not default_port:
        return f"{parsed.scheme}://{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"


def _request_origin(request: Request) -> str | None:
    origin = _normalize_origin(request.headers.get("origin"))
    if origin:
        return origin
    referer = (request.headers.get("referer") or "").strip()
    if not referer:
        return None
    parsed = urlparse(referer)
    if not parsed.scheme or not parsed.netloc:
        return None
    return _normalize_origin(f"{parsed.scheme}://{parsed.netloc}")


def _trusted_origins(request: Request) -> set[str]:
    trusted: set[str] = set()
    request_origin = _normalize_origin(f"{request.url.scheme}://{request.url.netloc}")
    if request_origin:
        trusted.add(request_origin)
    for configured in settings.origins_list:
        normalized = _normalize_origin(configured)
        if normalized:
            trusted.add(normalized)
    return trusted


def _require_trusted_browser_origin(request: Request) -> None:
    origin = _request_origin(request)
    if not origin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing Origin/Referer")
    if origin not in _trusted_origins(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Untrusted origin")


def _normalize_host_list(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in values or []:
        host = _normalize_host(item)
        if not host or host in seen:
            continue
        normalized.append(host)
        seen.add(host)
    return normalized


def _normalize_origin_list(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in values or []:
        origin = _normalize_origin(item)
        if not origin or origin in seen:
            continue
        normalized.append(origin)
        seen.add(origin)
    return normalized


ALLOWED_BACKGROUND_STYLES = {"default", "gradient-warm", "gradient-ocean", "gradient-slate"}


def _safe_branding_text(value: str | None, max_length: int) -> str:
    text = (value or "").strip()
    return text[:max_length]


def _normalize_hex_color(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", text):
        return ""
    return text.lower()


def _normalize_website_branding(raw: dict | None) -> dict[str, str]:
    data = dict(raw or {})
    background_style = _safe_branding_text(str(data.get("background_style") or ""), 32)
    if background_style not in ALLOWED_BACKGROUND_STYLES:
        background_style = "default"
    return {
        "logo_url": _safe_branding_text(str(data.get("logo_url") or ""), 1024),
        "hero_eyebrow": _safe_branding_text(str(data.get("hero_eyebrow") or ""), 120),
        "hero_title": _safe_branding_text(str(data.get("hero_title") or ""), 200),
        "hero_subtitle": _safe_branding_text(str(data.get("hero_subtitle") or ""), 360),
        "primary_button_label": _safe_branding_text(str(data.get("primary_button_label") or ""), 60),
        "accent_color": _normalize_hex_color(str(data.get("accent_color") or "")),
        "accent_deep_color": _normalize_hex_color(str(data.get("accent_deep_color") or "")),
        "accent_soft_color": _normalize_hex_color(str(data.get("accent_soft_color") or "")),
        "background_style": background_style,
    }


def _website_branding(website: Website | None) -> dict[str, str]:
    if not website:
        return _normalize_website_branding({})
    return _normalize_website_branding(getattr(website, "branding", {}) or {})


def _frontend_login_path(
    app_slug: str | None = None,
    next_url: str | None = None,
    error: str | None = None,
    message: str | None = None,
) -> str:
    params: dict[str, str] = {}
    if app_slug:
        params["app"] = app_slug
    if next_url:
        params["next"] = next_url
    if error:
        params["error"] = error
    if message:
        params["message"] = message
    if not params:
        return "/app/login"
    return f"/app/login?{urlencode(params)}"


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


def _social_website_identity_payload(profile: dict[str, Any], schema_fields: dict) -> dict[str, Any]:
    raw = dict(profile.get("raw", {}) or {})
    email = str(profile.get("email") or "").strip()
    full_name = str(profile.get("full_name") or "").strip()
    first_name = str(raw.get("given_name") or raw.get("first_name") or "").strip()
    last_name = str(raw.get("family_name") or raw.get("last_name") or "").strip()
    if not first_name and full_name and " " in full_name:
        first_name = full_name.split(" ", 1)[0].strip()
    if not last_name and full_name and " " in full_name:
        last_name = full_name.rsplit(" ", 1)[-1].strip()
    display_name = full_name or (email.split("@", 1)[0] if "@" in email else email)
    avatar_url = str(profile.get("avatar_url") or "").strip()

    payload: dict[str, Any] = {}
    if "display_name" in schema_fields and display_name:
        payload["display_name"] = display_name
    if "first_name" in schema_fields and first_name:
        payload["first_name"] = first_name
    if "last_name" in schema_fields and last_name:
        payload["last_name"] = last_name
    if "avatar_url" in schema_fields and avatar_url:
        payload["avatar_url"] = avatar_url

    # Satisfy required fields when social profile does not provide them.
    for field_name, definition in schema_fields.items():
        if not definition.get("required") or field_name in payload:
            continue
        field_type = definition.get("type")
        if field_type == "string":
            payload[field_name] = ""
        elif field_type == "number":
            payload[field_name] = 0
        elif field_type == "boolean":
            payload[field_name] = False
        elif field_type == "array":
            payload[field_name] = []
        elif field_type == "object":
            payload[field_name] = {}

    return _validate_identity_data(payload, schema_fields)


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
        use_ssl=settings.minio_use_ssl,
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


def _s3_encryption_args() -> dict[str, str]:
    algorithm = (settings.minio_server_side_encryption or "").strip()
    if not algorithm:
        return {}
    return {"ServerSideEncryption": algorithm}


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
                **_s3_encryption_args(),
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


async def _get_current_owner_for_token_admin(token: str, session: AsyncSession) -> User:
    if token.startswith("pidp_pat_"):
        owner, api_token = await _get_api_token_owner_and_record(token, session)
        scope = _normalize_api_token_scope(api_token.scope)
        if scope != "org_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PAT scope does not permit token administration",
            )
        return owner
    return await _get_current_owner(token, session)


async def _get_current_website_user(token: str, session: AsyncSession) -> WebsiteUser:
    payload = safe_decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid website user token")
    if payload.get("actor_type") != "website_user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token is not a website user token")
    website_id = str(payload.get("website_id") or "").strip()
    if not website_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid website user token")

    result = await session.execute(
        select(WebsiteUser).where(
            (WebsiteUser.id == payload["sub"])
            & (WebsiteUser.website_id == website_id)
        )
    )
    website_user = result.scalar_one_or_none()
    if not website_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Website user not found")
    return website_user


def _hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _is_pidp_sysadmin(user: User) -> bool:
    user_id = str(user.id or "").strip()
    email = str(user.email or "").strip().lower()
    if user_id and user_id in settings.admin_user_ids_list:
        return True
    if email and email in settings.admin_emails_list:
        return True

    identity = user.identity_data or {}
    if not isinstance(identity, dict):
        return False
    if _truthy(identity.get("is_sysadmin")):
        return True
    roles = identity.get("roles")
    if isinstance(roles, list):
        normalized = {str(item).strip().lower() for item in roles if str(item).strip()}
        if "sysadmin" in normalized or "admin" in normalized:
            return True
    return False


def _to_user_public(user: User) -> UserPublic:
    return UserPublic(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        provider=user.provider,
        identity_data=user.identity_data,
        is_sysadmin=_is_pidp_sysadmin(user),
        is_active=user.is_active,
        created_at=user.created_at,
    )


def _create_owner_access_token(user: User) -> str:
    return create_access_token(
        subject=str(user.id),
        email=user.email,
        extra_claims={"is_sysadmin": _is_pidp_sysadmin(user)},
    )


def _to_user_public_from_website_user(website_user: WebsiteUser) -> UserPublic:
    return UserPublic(
        id=website_user.id,
        email=website_user.email,
        full_name=website_user.full_name,
        provider=website_user.provider,
        identity_data=website_user.identity_data,
        is_sysadmin=False,
        is_active=website_user.is_active,
        created_at=website_user.created_at,
    )


def _create_website_user_access_token(website_user: WebsiteUser) -> str:
    return create_access_token(
        subject=str(website_user.id),
        email=website_user.email,
        extra_claims={
            "actor_type": "website_user",
            "website_id": str(website_user.website_id),
        },
    )


def _generate_api_token() -> str:
    return f"pidp_pat_{secrets.token_urlsafe(40)}"


def _normalize_api_token_scope(raw_scope: str | None) -> str:
    scope = (raw_scope or "service").strip().lower()
    if scope not in ALLOWED_API_TOKEN_SCOPES:
        allowed = ", ".join(sorted(ALLOWED_API_TOKEN_SCOPES))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported API token scope '{scope}'. Allowed: {allowed}",
        )
    return scope


def _scope_grants(scope: str) -> list[str]:
    return list(TOKEN_SCOPE_GRANTS.get(scope, []))


async def _issue_or_reactivate_api_token(
    session: AsyncSession,
    owner_id: UUID,
    name: str,
    scope: str = "service",
) -> tuple[str, UserAPIToken]:
    normalized_scope = _normalize_api_token_scope(scope)
    existing_result = await session.execute(
        select(UserAPIToken).where(
            (UserAPIToken.owner_id == owner_id)
            & (UserAPIToken.name == name)
        )
    )
    existing = existing_result.scalar_one_or_none()
    if existing and existing.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active API token with this name already exists")

    raw_token = _generate_api_token()
    token_hash = _hash_api_token(raw_token)
    try:
        if existing:
            existing.token_hash = token_hash
            existing.scope = normalized_scope
            existing.is_active = True
            existing.last_used_at = None
            api_token = existing
        else:
            api_token = UserAPIToken(
                owner_id=owner_id,
                name=name,
                token_hash=token_hash,
                scope=normalized_scope,
            )
            session.add(api_token)
        await session.commit()
        await session.refresh(api_token)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API token with this name already exists")

    return raw_token, api_token


async def _cycle_api_token(
    session: AsyncSession,
    owner_id: UUID,
    token_id: UUID,
) -> tuple[str, UserAPIToken]:
    result = await session.execute(
        select(UserAPIToken).where(
            (UserAPIToken.id == token_id)
            & (UserAPIToken.owner_id == owner_id)
        )
    )
    api_token = result.scalar_one_or_none()
    if not api_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API token not found")

    raw_token = _generate_api_token()
    api_token.token_hash = _hash_api_token(raw_token)
    api_token.is_active = True
    api_token.last_used_at = None
    try:
        await session.commit()
        await session.refresh(api_token)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Failed to rotate API token")

    return raw_token, api_token


async def _get_api_token_owner_and_record(raw_token: str, session: AsyncSession) -> tuple[User, UserAPIToken]:
    token_hash = _hash_api_token(raw_token)
    result = await session.execute(
        select(UserAPIToken, User)
        .join(User, User.id == UserAPIToken.owner_id)
        .where(
            (UserAPIToken.token_hash == token_hash)
            & (UserAPIToken.is_active.is_(True))
        )
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")
    api_token, owner = row
    _normalize_api_token_scope(api_token.scope)
    api_token.last_used_at = datetime.utcnow()
    await session.commit()
    return owner, api_token


async def _get_owner_from_api_token(raw_token: str, session: AsyncSession) -> User:
    owner, _token = await _get_api_token_owner_and_record(raw_token, session)
    return owner


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    return auth_header.split(" ", 1)[1].strip()


async def _get_service_owner(request: Request, session: AsyncSession) -> User:
    raw_token = _extract_bearer_token(request)
    if raw_token.startswith("pidp_pat_"):
        return await _get_owner_from_api_token(raw_token, session)
    return await _get_current_owner(raw_token, session)


def _request_base_url(request: Request) -> str:
    direct_host = (request.headers.get("host") or "").split(",", 1)[0].strip()
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip()
    host = direct_host or forwarded_host or request.url.netloc
    scheme = "https" if _is_request_secure(request) else request.url.scheme
    return f"{scheme}://{host}/"


def _request_host(request: Request) -> str | None:
    # Prefer the direct Host header set by the trusted edge proxy.
    # X-Forwarded-Host can be injected/rewritten across hops and should only be fallback.
    direct_host = (request.headers.get("host") or "").split(",", 1)[0].strip()
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip()
    host = direct_host or forwarded_host or request.url.netloc
    return _normalize_host(host)


def _website_allowed_origins(website: Website) -> set[str]:
    configured = _normalize_origin_list(list(website.allowed_redirect_origins or []))
    if configured:
        return set(configured)

    derived: set[str] = set()
    for host in _normalize_host_list(list(website.login_hosts or [])):
        derived.add(f"https://{host}")
    return derived


def _is_native_redirect_target(target: str) -> bool:
    parsed = urlparse(target)
    scheme = (parsed.scheme or "").strip().lower()
    return bool(scheme and scheme in settings.native_redirect_schemes_list)


def _resolve_frontend_redirect_for_website(
    request: Request,
    raw_target: str | None,
    website: Website | None,
) -> str | None:
    resolved = _resolve_frontend_redirect_target(request, raw_target)
    if not resolved:
        return None
    if _is_native_redirect_target(resolved):
        return resolved
    if resolved.startswith("/") or website is None:
        return resolved

    parsed = urlparse(resolved)
    candidate = _normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    if not candidate:
        return None
    allowed = _website_allowed_origins(website)
    if not allowed:
        LOG.warning(
            "No redirect origins configured for website slug=%s; allowing redirect in compatibility mode",
            website.slug,
        )
        return resolved
    if candidate in allowed:
        return resolved
    return None


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


async def _resolve_login_website(session: AsyncSession, raw_slug: str | None) -> Website | None:
    if not raw_slug:
        return None
    candidate = raw_slug.strip()
    if not candidate:
        return None
    try:
        normalized = _normalize_slug(candidate)
    except HTTPException:
        return None
    result = await session.execute(select(Website).where(Website.slug == normalized))
    return result.scalar_one_or_none()


async def _resolve_login_website_from_host(session: AsyncSession, request: Request) -> Website | None:
    host = _request_host(request)
    if not host:
        return None
    result = await session.execute(select(Website).order_by(Website.created_at))
    for website in result.scalars().all():
        if host in _normalize_host_list(list(website.login_hosts or [])):
            return website
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


async def _ensure_runtime_schema() -> None:
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "ALTER TABLE websites "
                    "ADD COLUMN IF NOT EXISTS login_hosts JSONB NOT NULL DEFAULT '[]'::jsonb"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE websites "
                    "ADD COLUMN IF NOT EXISTS allowed_redirect_origins JSONB NOT NULL DEFAULT '[]'::jsonb"
                )
            )
            await conn.execute(
                text(
                    "ALTER TABLE websites "
                    "ADD COLUMN IF NOT EXISTS branding JSONB NOT NULL DEFAULT '{}'::jsonb"
                )
            )
    except Exception as exc:
        LOG.warning("Runtime schema patch skipped: %s", exc)


async def _warn_identity_uuid_collisions() -> None:
    try:
        async with SessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT w.id, w.email, w.website_id "
                    "FROM website_users w "
                    "JOIN users u ON u.id = w.id"
                )
            )
            rows = result.all()
            if not rows:
                return
            LOG.warning(
                "Identity UUID collision detected between users and website_users. "
                "These must be distinct principals. collisions=%s",
                len(rows),
            )
            for row in rows:
                LOG.warning(
                    "collision id=%s email=%s website_id=%s",
                    row[0],
                    row[1],
                    row[2],
                )
    except Exception as exc:
        LOG.warning("UUID collision check skipped: %s", exc)


@app.on_event("startup")
async def startup() -> None:
    validate_pii_encryption_config()
    if settings.auto_create_tables:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    await _ensure_runtime_schema()
    await _warn_identity_uuid_collisions()


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
                "login_next": request.query_params.get("next") or "",
                "login_branding": _website_branding(None),
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


@app.get("/login", include_in_schema=False)
@app.get("/login/", include_in_schema=False)
async def frontend_login_alias(request: Request) -> RedirectResponse:
    next_url = (request.query_params.get("next") or "").strip()
    if next_url:
        encoded = quote(next_url, safe="")
        return RedirectResponse(url=f"/?next={encoded}", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/app/login", include_in_schema=False)
@app.get("/app/login/", include_in_schema=False)
async def frontend_app_login(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    lane_redirect = _cross_lane_login_redirect(request, request.query_params.get("next"))
    if lane_redirect:
        return RedirectResponse(url=lane_redirect, status_code=status.HTTP_303_SEE_OTHER)

    force_owner_login = _truthy(request.query_params.get("owner"))
    auto_login = _truthy(request.query_params.get("auto"))
    app_slug = (request.query_params.get("app") or "").strip()
    if force_owner_login:
        app_slug = ""
    raw_next = (request.query_params.get("next") or "").strip() or None
    website = await _resolve_login_website(session, app_slug) if app_slug else None
    if not website and not app_slug and not force_owner_login:
        website = await _resolve_login_website_from_host(session, request)
    resolved_next = _resolve_frontend_redirect_for_website(request, raw_next, website)
    if raw_next and not resolved_next:
        LOG.info("Rejected app login redirect target for app=%s next=%s", app_slug or "none", raw_next)
    branding = _website_branding(website)
    if app_slug and not website:
        return _render_template(
            request,
            "home.html",
            {
                "page_title": "Application Login",
                "active_page": "home",
                "login_next": resolved_next or "",
                "login_app_slug": app_slug,
                "app_lookup_error": f"Unknown application '{app_slug}'.",
                "login_branding": branding,
                "configuration": {
                    "google_enabled": settings.social_enabled("google"),
                    "github_enabled": settings.social_enabled("github"),
                },
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if auto_login and not force_owner_login:
        provider: str | None = None
        if settings.social_enabled("google"):
            provider = "google"
        elif settings.social_enabled("github"):
            provider = "github"
        if provider:
            params = {}
            if resolved_next:
                params["next"] = resolved_next
            if website:
                params["app"] = website.slug
            query = urlencode(params) if params else ""
            target = f"/auth/{provider}/login"
            if query:
                target = f"{target}?{query}"
            return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    request_token = _request_token(request)
    if request_token:
        payload = safe_decode_token(request_token)
        if payload and payload.get("sub"):
            actor_type = str(payload.get("actor_type") or "owner")
            can_bypass = False
            if actor_type == "website_user":
                if not force_owner_login:
                    try:
                        website_user = await _get_current_website_user(request_token, session)
                        if website is None or str(website_user.website_id) == str(website.id):
                            can_bypass = True
                    except HTTPException:
                        can_bypass = False
            else:
                try:
                    await _get_current_owner(request_token, session)
                    can_bypass = True
                except HTTPException:
                    can_bypass = False

            if can_bypass:
                if resolved_next:
                    if not resolved_next.startswith("/"):
                        params = urlencode({"token": request_token, "token_type": "bearer"})
                        return RedirectResponse(f"{resolved_next}#{params}", status_code=status.HTTP_303_SEE_OTHER)
                    return RedirectResponse(url=resolved_next, status_code=status.HTTP_303_SEE_OTHER)
                return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    return _render_template(
        request,
        "home.html",
        {
            "page_title": f"Sign in to {website.name}" if website else "PIdP Console",
            "active_page": "home",
            "login_next": resolved_next or "",
            "login_app_slug": website.slug if website else "",
            "login_force_owner": force_owner_login,
            "login_app_name": website.name if website else "",
            "login_app_description": website.description if website else "",
            "login_branding": branding,
            "configuration": {
                "google_enabled": settings.social_enabled("google"),
                "github_enabled": settings.social_enabled("github"),
            },
        },
    )


@app.post("/session/login", include_in_schema=False)
async def frontend_login(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    _require_trusted_browser_origin(request)
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    next_url = str(form.get("next") or "").strip()
    requested_app = str(form.get("app") or "").strip()
    force_owner_login = _truthy(form.get("owner"))
    if force_owner_login:
        requested_app = ""
    app_website = await _resolve_login_website(session, requested_app)
    if not app_website and not requested_app and not force_owner_login:
        app_website = await _resolve_login_website_from_host(session, request)
    app_slug = app_website.slug if app_website else ""
    redirect_target = _resolve_frontend_redirect_for_website(request, next_url, app_website)
    if next_url and not redirect_target:
        LOG.info("Rejected login redirect target for app=%s next=%s", app_slug or "none", next_url)
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or requested_app or None,
                error="Redirect URL is not allowed for this application",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    user = await authenticate_user(session, email, password)
    if not user:
        LOG.info("Login failed for email=%s app=%s", email, app_slug or requested_app or "none")
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or requested_app or None,
                next_url=next_url or None,
                error="Invalid credentials",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    token = _create_owner_access_token(user)
    LOG.info("Login succeeded for user=%s app=%s", user.email, app_slug or "none")
    if redirect_target:
        request.session["frontend_redirect_url"] = redirect_target
    redirect_target = _resolve_frontend_redirect_target(request, request.session.pop("frontend_redirect_url", None))
    if redirect_target and not redirect_target.startswith("/"):
        params = urlencode({"token": token, "token_type": "bearer"})
        return RedirectResponse(f"{redirect_target}#{params}")
    response = RedirectResponse(url=redirect_target or "/", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response


@app.post("/session/register", include_in_schema=False)
async def frontend_register(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    _require_trusted_browser_origin(request)
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    full_name = str(form.get("full_name") or "").strip() or None
    next_url = str(form.get("next") or "").strip()
    requested_app = str(form.get("app") or "").strip()
    force_owner_login = _truthy(form.get("owner"))
    if force_owner_login:
        requested_app = ""
    app_website = await _resolve_login_website(session, requested_app)
    if not app_website and not requested_app and not force_owner_login:
        app_website = await _resolve_login_website_from_host(session, request)
    app_slug = app_website.slug if app_website else ""
    redirect_target = _resolve_frontend_redirect_for_website(request, next_url, app_website)
    if next_url and not redirect_target:
        LOG.info("Rejected register redirect target for app=%s next=%s", app_slug or "none", next_url)
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or requested_app or None,
                error="Redirect URL is not allowed for this application",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    result = await session.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or requested_app or None,
                next_url=next_url or None,
                error="Account already exists",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    LOG.info("Completed frontend registration email=%s", user.email)

    token = _create_owner_access_token(user)
    LOG.info("Registration succeeded for email=%s app=%s", user.email, app_slug or "none")
    if redirect_target:
        request.session["frontend_redirect_url"] = redirect_target
    redirect_target = _resolve_frontend_redirect_target(request, request.session.pop("frontend_redirect_url", None))
    if redirect_target and not redirect_target.startswith("/"):
        params = urlencode({"token": token, "token_type": "bearer"})
        return RedirectResponse(f"{redirect_target}#{params}")
    response = RedirectResponse(url=redirect_target or "/?message=Account+created", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response


@app.post("/session/logout", include_in_schema=False)
async def frontend_logout(request: Request) -> RedirectResponse:
    _require_trusted_browser_origin(request)
    response = RedirectResponse(
        url="/?message=Signed+out",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _clear_session_cookie(response)
    return response


@app.get("/profile", include_in_schema=False)
async def frontend_profile(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    websites = list(result.scalars().all())
    token_result = await session.execute(
        select(UserAPIToken)
        .where(UserAPIToken.owner_id == owner.id)
        .order_by(UserAPIToken.created_at.desc())
    )
    api_tokens = list(token_result.scalars().all())
    issued_service_token = request.session.pop("issued_service_token", None)
    token_scopes = [scope for scope in ("service", "org_portal", "org_mcp", "org_admin") if scope in ALLOWED_API_TOKEN_SCOPES]
    return _render_template(
        request,
        "profile.html",
        {
            "page_title": "Your Profile",
            "active_page": "profile",
            "viewer": owner,
            "websites": websites,
            "profile_fields": _profile_fields(owner),
            "api_tokens": api_tokens,
            "issued_service_token": issued_service_token,
            "token_scopes": token_scopes,
            "token_scope_grants": {scope: _scope_grants(scope) for scope in token_scopes},
        },
    )


@app.post("/profile", include_in_schema=False)
async def frontend_profile_update(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
    return RedirectResponse(
        url="/profile?message=Profile+saved",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/profile/tokens", include_in_schema=False)
async def frontend_create_profile_token(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    form = await request.form()
    name = str(form.get("name") or "").strip()
    scope_raw = str(form.get("scope") or "service").strip().lower()
    if not name:
        return RedirectResponse(
            url="/profile?error=Token+name+is+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        scope = _normalize_api_token_scope(scope_raw)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            return RedirectResponse(
                url="/profile?error=Unsupported+token+scope",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    try:
        raw_token, _ = await _issue_or_reactivate_api_token(
            session=session,
            owner_id=owner.id,
            name=name,
            scope=scope,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_409_CONFLICT:
            return RedirectResponse(
                url="/profile?error=Active+API+token+with+this+name+already+exists",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    request.session["issued_service_token"] = raw_token
    return RedirectResponse(
        url="/profile?message=API+token+created.+Copy+it+now.",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/profile/tokens/{token_id}/revoke", include_in_schema=False)
async def frontend_revoke_profile_token(
    token_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    result = await session.execute(
        select(UserAPIToken).where(
            (UserAPIToken.id == token_id)
            & (UserAPIToken.owner_id == owner.id)
        )
    )
    api_token = result.scalar_one_or_none()
    if not api_token:
        return RedirectResponse(
            url="/profile?error=API+token+not+found",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    api_token.is_active = False
    await session.commit()
    return RedirectResponse(
        url="/profile?message=Service+token+revoked",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/profile/tokens/{token_id}/cycle", include_in_schema=False)
async def frontend_cycle_profile_token(
    token_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        raw_token, _ = await _cycle_api_token(session, owner.id, token_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return RedirectResponse(
                url="/profile?error=API+token+not+found",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if exc.status_code == status.HTTP_409_CONFLICT:
            return RedirectResponse(
                url="/profile?error=Could+not+cycle+token",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    request.session["issued_service_token"] = raw_token
    return RedirectResponse(
        url="/profile?message=Service+token+cycled.+Copy+it+now.",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/sites", include_in_schema=False)
async def frontend_sites(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
        return RedirectResponse(
            url="/sites?error=Website+slug+already+exists",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    website = Website(
        owner_id=owner.id,
        name=name,
        slug=slug,
        description=description,
        user_schema=dict(SYSTEM_SCHEMA_FIELDS),
        branding=_normalize_website_branding({}),
        max_users=DEFAULT_MAX_USERS_PER_WEBSITE,
    )
    session.add(website)
    await session.commit()
    return RedirectResponse(
        url="/sites?message=Website+created",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/billing", include_in_schema=False)
async def frontend_billing(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
            "website_branding": _website_branding(website),
            "website_users": users,
        },
    )


@app.post("/sites/{website_id}/personalization", include_in_schema=False)
async def frontend_site_personalization_update(
    website_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    owner = await _get_request_owner(request, session)
    if not owner:
        return RedirectResponse(
            url="/?error=Sign+in+required",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    website = await _get_owned_website(session, owner.id, website_id)
    form = await request.form()
    branding = _normalize_website_branding(
        {
            "logo_url": str(form.get("logo_url") or ""),
            "hero_eyebrow": str(form.get("hero_eyebrow") or ""),
            "hero_title": str(form.get("hero_title") or ""),
            "hero_subtitle": str(form.get("hero_subtitle") or ""),
            "primary_button_label": str(form.get("primary_button_label") or ""),
            "accent_color": str(form.get("accent_color") or ""),
            "accent_deep_color": str(form.get("accent_deep_color") or ""),
            "accent_soft_color": str(form.get("accent_soft_color") or ""),
            "background_style": str(form.get("background_style") or "default"),
        }
    )
    website.branding = branding
    await session.commit()
    return RedirectResponse(
        url=f"/sites/{website.id}?message=Client+personalization+saved",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return get_jwks()


@app.get("/configuration")
async def configuration(request: Request) -> dict:
    base_addr = _request_base_url(request)
    return {
        "base_addr": base_addr,
        "google_client_id": settings.google_client_id,
        "google_redirect_uri": settings.google_redirect_uri,
        "github_client_id": settings.github_client_id,
        "github_redirect_uri": settings.github_redirect_uri,
        "frontend_redirect_url": settings.frontend_redirect_url,
        "minio_endpoint": settings.minio_endpoint,
        "minio_bucket": settings.minio_bucket,
        "minio_public_base_url": settings.minio_public_base_url,
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
    return _to_user_public(user)


@app.post("/auth/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> Token:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = _create_owner_access_token(user)
    return Token(access_token=token)


@app.post("/auth/session/login", status_code=status.HTTP_204_NO_CONTENT)
async def login_for_session_cookie(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> Response:
    _require_trusted_browser_origin(request)
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = _create_owner_access_token(user)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _set_session_cookie(response, token)
    return response


@app.post("/auth/session/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_session_cookie(request: Request) -> Response:
    _require_trusted_browser_origin(request)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_session_cookie(response)
    return response


@app.post("/auth/session/exchange", status_code=status.HTTP_204_NO_CONTENT)
async def exchange_access_token_for_session_cookie(
    request: Request,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> Response:
    _require_trusted_browser_origin(request)
    payload = safe_decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload.get("actor_type") == "website_user":
        website_user = await _get_current_website_user(token, session)
        rotated_token = _create_website_user_access_token(website_user)
    else:
        user = await _get_current_owner(token, session)
        rotated_token = _create_owner_access_token(user)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _set_session_cookie(response, rotated_token)
    return response


@app.get("/auth/session-token", response_model=Token)
async def auth_session_token(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Token:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = safe_decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload.get("actor_type") == "website_user":
        await _get_current_website_user(token, session)
    else:
        await _get_current_owner(token, session)
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserPublic)
async def get_me(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> UserPublic:
    payload = safe_decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if payload.get("actor_type") == "website_user":
        website_user = await _get_current_website_user(token, session)
        return _to_user_public_from_website_user(website_user)
    user = await _get_current_owner(token, session)
    return _to_user_public(user)


@app.post("/auth/tokens", response_model=APITokenIssued)
async def create_api_token(
    payload: APITokenCreate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> APITokenIssued:
    owner = await _get_current_owner_for_token_admin(token, session)
    normalized_name = payload.name.strip()
    if not normalized_name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Token name is required")

    raw_token, api_token = await _issue_or_reactivate_api_token(
        session=session,
        owner_id=owner.id,
        name=normalized_name,
        scope=payload.scope,
    )

    return APITokenIssued(
        token=raw_token,
        token_id=api_token.id,
        name=api_token.name,
        scope=api_token.scope,
        scope_grants=_scope_grants(api_token.scope),
    )


@app.get("/auth/tokens", response_model=list[APITokenPublic])
async def list_api_tokens(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[APITokenPublic]:
    owner = await _get_current_owner_for_token_admin(token, session)
    result = await session.execute(
        select(UserAPIToken)
        .where(UserAPIToken.owner_id == owner.id)
        .order_by(UserAPIToken.created_at.desc())
    )
    rows = list(result.scalars().all())
    return [
        APITokenPublic(
            id=row.id,
            name=row.name,
            scope=row.scope,
            scope_grants=_scope_grants(row.scope),
            is_active=row.is_active,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
        )
        for row in rows
    ]


@app.patch("/auth/tokens/{token_id}", response_model=APITokenPublic)
async def update_api_token(
    token_id: UUID,
    payload: APITokenUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> APITokenPublic:
    owner = await _get_current_owner_for_token_admin(token, session)
    result = await session.execute(
        select(UserAPIToken).where(
            (UserAPIToken.id == token_id)
            & (UserAPIToken.owner_id == owner.id)
        )
    )
    api_token = result.scalar_one_or_none()
    if not api_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API token not found")

    next_name = payload.name.strip()
    if not next_name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Token name is required")
    api_token.name = next_name
    try:
        await session.commit()
        await session.refresh(api_token)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API token with this name already exists")

    return APITokenPublic(
        id=api_token.id,
        name=api_token.name,
        scope=api_token.scope,
        scope_grants=_scope_grants(api_token.scope),
        is_active=api_token.is_active,
        created_at=api_token.created_at,
        last_used_at=api_token.last_used_at,
    )


@app.delete("/auth/tokens/{token_id}")
async def revoke_api_token(
    token_id: UUID,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> dict:
    owner = await _get_current_owner_for_token_admin(token, session)
    result = await session.execute(
        select(UserAPIToken).where(
            (UserAPIToken.id == token_id)
            & (UserAPIToken.owner_id == owner.id)
        )
    )
    api_token = result.scalar_one_or_none()
    if not api_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API token not found")
    api_token.is_active = False
    await session.commit()
    return {"revoked": True, "token_id": str(token_id)}


@app.post("/auth/tokens/{token_id}/cycle", response_model=APITokenIssued)
async def cycle_api_token(
    token_id: UUID,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> APITokenIssued:
    owner = await _get_current_owner_for_token_admin(token, session)
    raw_token, api_token = await _cycle_api_token(session, owner.id, token_id)
    return APITokenIssued(
        token=raw_token,
        token_id=api_token.id,
        name=api_token.name,
        scope=api_token.scope,
        scope_grants=_scope_grants(api_token.scope),
    )


@app.get("/service/me", response_model=UserPublic)
async def service_me(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> UserPublic:
    owner = await _get_service_owner(request, session)
    return _to_user_public(owner)


@app.get("/service/token-info", response_model=ServiceTokenInfo)
async def service_token_info(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ServiceTokenInfo:
    raw_token = _extract_bearer_token(request)
    if raw_token.startswith("pidp_pat_"):
        owner, api_token = await _get_api_token_owner_and_record(raw_token, session)
        return ServiceTokenInfo(
            token_kind="pat",
            actor_type="owner",
            scope=api_token.scope,
            scope_grants=_scope_grants(api_token.scope),
            owner=_to_user_public(owner),
        )
    payload = safe_decode_token(raw_token)
    if payload and payload.get("actor_type") == "website_user":
        website_user = await _get_current_website_user(raw_token, session)
        return ServiceTokenInfo(
            token_kind="jwt",
            actor_type="website_user",
            scope="session",
            scope_grants=["session:*"],
            owner=_to_user_public_from_website_user(website_user),
        )
    owner = await _get_current_owner(raw_token, session)
    return ServiceTokenInfo(
        token_kind="jwt",
        actor_type="owner",
        scope="session",
        scope_grants=["session:*"],
        owner=_to_user_public(owner),
    )


@app.get("/service/websites", response_model=list[WebsitePublic])
async def service_list_websites(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> list[WebsitePublic]:
    owner = await _get_service_owner(request, session)
    result = await session.execute(select(Website).where(Website.owner_id == owner.id).order_by(Website.created_at))
    return list(result.scalars().all())


@app.post("/service/websites", response_model=WebsitePublic)
async def service_create_website(
    payload: WebsiteCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_service_owner(request, session)
    website_count = await _count_websites_for_owner(session, owner.id)
    if website_count >= MAX_WEBSITES_PER_OWNER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
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
        login_hosts=_normalize_host_list(payload.login_hosts),
        allowed_redirect_origins=_normalize_origin_list(payload.allowed_redirect_origins),
        branding=_normalize_website_branding({}),
        user_schema=dict(SYSTEM_SCHEMA_FIELDS),
        max_users=DEFAULT_MAX_USERS_PER_WEBSITE,
    )
    session.add(website)
    await session.commit()
    await session.refresh(website)
    return website


@app.get("/auth/users", response_model=list[UserPublic])
async def find_users(
    email: str,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> list[UserPublic]:
    await _get_current_owner(token, session)
    result = await session.execute(select(User).where(User.email.ilike(email)))
    users = result.scalars().all()
    return [_to_user_public(user) for user in users]


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
    return _to_user_public(user)


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
                **_s3_encryption_args(),
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
        login_hosts=_normalize_host_list(payload.login_hosts),
        allowed_redirect_origins=_normalize_origin_list(payload.allowed_redirect_origins),
        branding=_normalize_website_branding({}),
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


@app.put("/websites/{website_id}/auth-config", response_model=WebsitePublic)
async def update_website_auth_config(
    website_id: UUID,
    payload: WebsiteAuthConfigUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_current_owner(token, session)
    website = await _get_owned_website(session, owner.id, website_id)
    website.login_hosts = _normalize_host_list(payload.login_hosts)
    website.allowed_redirect_origins = _normalize_origin_list(payload.allowed_redirect_origins)
    await session.commit()
    await session.refresh(website)
    return website


@app.put("/websites/{website_id}/branding", response_model=WebsitePublic)
async def update_website_branding(
    website_id: UUID,
    payload: WebsiteBrandingUpdate,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> WebsitePublic:
    owner = await _get_current_owner(token, session)
    website = await _get_owned_website(session, owner.id, website_id)
    website.branding = _normalize_website_branding(payload.model_dump())
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
async def social_login(
    provider: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    lane_redirect = _cross_lane_login_redirect(request, request.query_params.get("next"))
    if lane_redirect:
        return RedirectResponse(url=lane_redirect, status_code=status.HTTP_303_SEE_OTHER)

    client = oauth.create_client(provider)
    if client is None:
        raise HTTPException(status_code=400, detail="Provider not enabled")

    redirect_uri = settings.google_redirect_uri if provider == "google" else settings.github_redirect_uri
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI not configured")

    next_url = request.query_params.get("next")
    force_owner_login = _truthy(request.query_params.get("owner"))
    app_slug = (request.query_params.get("app") or "").strip()
    if force_owner_login:
        app_slug = ""
    website: Website | None = None
    # Keep only one active OAuth attempt per provider per browser session.
    # This avoids stale/accumulated state keys causing callback mismatches.
    stale_state_keys = [
        key for key in list(request.session.keys()) if isinstance(key, str) and key.startswith(f"_state_{provider}_")
    ]
    for key in stale_state_keys:
        request.session.pop(key, None)
    if app_slug:
        website = await _resolve_login_website(session, app_slug)
        if not website:
            return RedirectResponse(
                url=_frontend_login_path(
                    app_slug=app_slug,
                    next_url=(next_url or "").strip() or None,
                    error=f"Unknown application '{app_slug}'",
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )
    if not website and not force_owner_login:
        website = await _resolve_login_website_from_host(session, request)
        if website:
            app_slug = website.slug
    request.session["social_login_force_owner"] = force_owner_login
    if app_slug:
        request.session["social_login_app_slug"] = app_slug
    resolved_next = _resolve_frontend_redirect_for_website(request, next_url, website)
    if next_url and not resolved_next:
        LOG.info("Rejected social redirect target provider=%s app=%s next=%s", provider, app_slug or "none", next_url)
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or None,
                error="Redirect URL is not allowed for this application",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if resolved_next:
        request.session["frontend_redirect_url"] = resolved_next
    LOG.info("Starting social login provider=%s app=%s", provider, app_slug or "none")
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/{provider}/callback")
async def social_callback(
    provider: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    force_owner_login = _truthy(request.session.pop("social_login_force_owner", False))
    app_slug = request.session.pop("social_login_app_slug", None)
    login_website: Website | None = None
    if app_slug:
        login_website = await _resolve_login_website(session, app_slug)
    if not login_website and not force_owner_login:
        login_website = await _resolve_login_website_from_host(session, request)
    if login_website and not app_slug:
        app_slug = login_website.slug
    callback_state = (request.query_params.get("state") or "").strip()
    if callback_state:
        expected_state_key = f"_state_{provider}_{callback_state}"
        if expected_state_key not in request.session:
            LOG.warning(
                "OAuth callback missing expected session state key provider=%s host=%s state=%s",
                provider,
                _request_host(request) or "unknown",
                callback_state,
            )
            return RedirectResponse(
                url=_frontend_login_path(
                    app_slug=app_slug or None,
                    error=f"{provider.capitalize()} sign-in session expired. Please try again.",
                ),
                status_code=status.HTTP_303_SEE_OTHER,
            )
    try:
        profile = await fetch_social_profile(provider, request)
    except HTTPException as exc:
        detail = str(getattr(exc, "detail", "") or "").strip()
        message = f"{provider.capitalize()} sign-in failed. Please try again."
        if detail and detail.lower() not in {"provider not enabled"}:
            message = detail
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or None,
                error=message,
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except Exception:
        LOG.exception("Unhandled social callback error provider=%s", provider)
        return RedirectResponse(
            url=_frontend_login_path(
                app_slug=app_slug or None,
                error=f"{provider.capitalize()} sign-in failed. Please try again.",
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if not profile.get("email"):
        raise HTTPException(status_code=400, detail="Provider did not return an email")

    if login_website:
        provider_account_id = str(profile.get("provider_account_id") or "").strip()
        email = str(profile.get("email") or "").strip().lower()
        result = await session.execute(
            select(WebsiteUser).where(
                (WebsiteUser.website_id == login_website.id)
                & (WebsiteUser.provider == provider)
                & (WebsiteUser.provider_account_id == provider_account_id)
            )
        )
        website_user = result.scalar_one_or_none()
        if not website_user:
            result = await session.execute(
                select(WebsiteUser).where(
                    (WebsiteUser.website_id == login_website.id)
                    & (WebsiteUser.email.ilike(email))
                )
            )
            website_user = result.scalar_one_or_none()

        schema_fields = dict(login_website.user_schema or SYSTEM_SCHEMA_FIELDS)
        identity_data = _social_website_identity_payload(profile, schema_fields)
        if not website_user:
            website_user = WebsiteUser(
                website_id=login_website.id,
                email=email,
                full_name=profile.get("full_name"),
                provider=provider,
                provider_account_id=provider_account_id or None,
                identity_data=identity_data,
                is_active=True,
            )
            session.add(website_user)
        else:
            website_user.email = email
            website_user.full_name = profile.get("full_name")
            website_user.provider = provider
            website_user.provider_account_id = provider_account_id or website_user.provider_account_id
            website_user.identity_data = identity_data
            website_user.is_active = True

        await session.commit()
        await session.refresh(website_user)
        token = _create_website_user_access_token(website_user)
        redirect_target = _resolve_frontend_redirect_target(request, request.session.pop("frontend_redirect_url", None))
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

    token = _create_owner_access_token(user)
    redirect_target = _resolve_frontend_redirect_target(request, request.session.pop("frontend_redirect_url", None))
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

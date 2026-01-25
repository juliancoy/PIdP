from __future__ import annotations

from typing import Any

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException

from app.config import settings


def build_oauth() -> OAuth:
    oauth = OAuth()

    if settings.social_enabled("google"):
        oauth.register(
            name="google",
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            access_token_url="https://oauth2.googleapis.com/token",
            client_kwargs={"scope": "openid email profile"},
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        )

    if settings.social_enabled("github"):
        oauth.register(
            name="github",
            client_id=settings.github_client_id,
            client_secret=settings.github_client_secret,
            authorize_url="https://github.com/login/oauth/authorize",
            access_token_url="https://github.com/login/oauth/access_token",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "read:user user:email"},
        )

    return oauth


oauth = build_oauth()


async def fetch_social_profile(provider: str, request) -> dict[str, Any]:
    if provider not in oauth:
        raise HTTPException(status_code=400, detail="Provider not enabled")

    client = oauth[provider]
    token = await client.authorize_access_token(request)

    if provider == "google":
        userinfo = await client.parse_id_token(request, token)
        return {
            "email": userinfo.get("email"),
            "full_name": userinfo.get("name"),
            "provider_account_id": userinfo.get("sub"),
            "raw": userinfo,
        }

    if provider == "github":
        resp = await client.get("user", token=token)
        profile = resp.json()
        email = profile.get("email")
        if not email:
            email_resp = await client.get("user/emails", token=token)
            emails = email_resp.json()
            primary = next((item for item in emails if item.get("primary")), {})
            email = primary.get("email") or (emails[0].get("email") if emails else None)
        return {
            "email": email,
            "full_name": profile.get("name") or profile.get("login"),
            "provider_account_id": str(profile.get("id")),
            "raw": profile,
        }

    raise HTTPException(status_code=400, detail="Unsupported provider")

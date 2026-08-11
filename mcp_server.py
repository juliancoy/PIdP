from __future__ import annotations

import base64
import json
import os
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP


def _base_url() -> str:
    return os.getenv("PIDP_BASE_URL", "https://id.codecollective.us").rstrip("/")


def _pat() -> str:
    token = os.getenv("PIDP_PAT", "").strip()
    if not token:
        raise ValueError("PIDP_PAT is required")
    return token


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_pat()}"}


def _decode_session_cookie(cookie_value: str) -> dict[str, Any]:
    if not cookie_value:
        return {}
    first_part = cookie_value.split(".", 1)[0]
    padded = first_part + ("=" * (-len(first_part) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        return parsed
    return {}


mcp = FastMCP("pidp")


@mcp.tool()
async def service_me() -> dict[str, Any]:
    """Return identity for the PAT owner from /service/me."""
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(f"{_base_url()}/service/me", headers=_auth_headers())
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):
        return payload
    return {"raw": payload}


@mcp.tool()
async def list_service_websites() -> list[dict[str, Any]]:
    """List websites visible to the PAT owner from /service/websites."""
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(f"{_base_url()}/service/websites", headers=_auth_headers())
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, list):
        return payload
    return [{"raw": payload}]


@mcp.tool()
async def create_service_website(name: str, slug: str | None = None, description: str | None = None) -> dict[str, Any]:
    """Create a website for the PAT owner via /service/websites."""
    body: dict[str, Any] = {"name": name}
    if slug:
        body["slug"] = slug
    if description:
        body["description"] = description

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            f"{_base_url()}/service/websites",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json=body,
        )

    if response.is_error:
        detail: Any
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        return {
            "ok": False,
            "status": response.status_code,
            "error": detail,
        }

    payload = response.json()
    if isinstance(payload, dict):
        payload.setdefault("ok", True)
        return payload
    return {"ok": True, "raw": payload}


@mcp.tool()
async def check_login_redirect_authorization(next_url: str, provider: str = "google") -> dict[str, Any]:
    """Check whether PiDP accepts a frontend next URL in /auth/{provider}/login.

    Returns HTTP status, provider redirect location, and decoded `frontend_redirect_url`
    stored in the session cookie when available.
    """
    encoded_next = quote(next_url, safe="")
    login_url = f"{_base_url()}/auth/{provider}/login?next={encoded_next}"

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
        response = await client.get(login_url)

    location = response.headers.get("location", "")
    set_cookie = response.headers.get("set-cookie", "")

    session_value = ""
    if set_cookie.lower().startswith("session="):
        session_value = set_cookie.split(";", 1)[0].split("session=", 1)[1]

    decoded = _decode_session_cookie(session_value) if session_value else {}

    return {
        "ok": response.status_code in (301, 302, 303, 307, 308),
        "status": response.status_code,
        "login_url": login_url,
        "redirect_location": location,
        "stored_frontend_redirect_url": decoded.get("frontend_redirect_url"),
        "provider": provider,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")

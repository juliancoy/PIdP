from __future__ import annotations

import importlib
import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
from starlette.responses import JSONResponse


REPO_DIR = Path(__file__).resolve().parents[1]
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))


def _load_main_module():
    os.environ["SECRET_KEY"] = "test-secret-key"
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost:5432/testdb"
    os.environ["AUTO_CREATE_TABLES"] = "false"
    os.environ["GOOGLE_CLIENT_ID"] = "google-client-id"
    os.environ["GOOGLE_CLIENT_SECRET"] = "google-client-secret"
    os.environ["GOOGLE_REDIRECT_URI"] = "https://dev.pidp.arkavo.org/auth/google/callback"
    os.environ["GITHUB_CLIENT_ID"] = "github-client-id"
    os.environ["GITHUB_CLIENT_SECRET"] = "github-client-secret"
    os.environ["GITHUB_REDIRECT_URI"] = "https://dev.pidp.arkavo.org/auth/github/callback"
    os.environ["FRONTEND_REDIRECT_URL"] = "https://dev.pidp.arkavo.org/auth/callback"
    os.environ["MINIO_ENDPOINT"] = "http://minio:9000"
    os.environ["MINIO_BUCKET"] = "pidp-avatars"
    os.environ["MINIO_PUBLIC_BASE_URL"] = "https://dev.pidp.arkavo.org/s3"

    for module_name in ("config", "db", "main"):
        if module_name in sys.modules:
            del sys.modules[module_name]

    return importlib.import_module("main")


class _FakeScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeExecuteResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalarResult(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, websites):
        self._websites = websites

    async def execute(self, *_args, **_kwargs):
        return _FakeExecuteResult(self._websites)

    async def commit(self):
        return None


class PidpSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = _load_main_module()

    def setUp(self):
        self.main.app.dependency_overrides.clear()

    def tearDown(self):
        self.main.app.dependency_overrides.clear()

    def test_social_login_preserves_next_as_frontend_redirect_url(self):
        class _FakeOAuthClient:
            async def authorize_redirect(self, request, redirect_uri):
                return JSONResponse(
                    {
                        "saved_next": request.session.get("frontend_redirect_url"),
                        "redirect_uri": redirect_uri,
                    }
                )

        original_create_client = self.main.oauth.create_client
        original_resolve_login_website_from_host = self.main._resolve_login_website_from_host
        self.main.oauth.create_client = lambda provider: _FakeOAuthClient() if provider == "google" else None
        async def _fake_resolve_login_website_from_host(_session, _request):
            return None
        self.main._resolve_login_website_from_host = _fake_resolve_login_website_from_host
        try:
            with TestClient(self.main.app) as client:
                response = client.get("/auth/google/login?next=/sites")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["saved_next"], "/sites")
            self.assertEqual(payload["redirect_uri"], os.environ["GOOGLE_REDIRECT_URI"])
        finally:
            self.main.oauth.create_client = original_create_client
            self.main._resolve_login_website_from_host = original_resolve_login_website_from_host

    def test_configuration_matches_runtime_env_and_host(self):
        with TestClient(self.main.app) as client:
            response = client.get(
                "/configuration",
                headers={
                    "host": "dev.pidp.arkavo.org",
                    "x-forwarded-proto": "https",
                },
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["base_addr"], "https://dev.pidp.arkavo.org/")
        self.assertEqual(payload["google_redirect_uri"], os.environ["GOOGLE_REDIRECT_URI"])
        self.assertEqual(payload["github_redirect_uri"], os.environ["GITHUB_REDIRECT_URI"])
        self.assertEqual(payload["frontend_redirect_url"], os.environ["FRONTEND_REDIRECT_URL"])

    def test_service_endpoints_accept_service_pat(self):
        owner = SimpleNamespace(
            id=uuid4(),
            email="owner@example.com",
            full_name="Owner Example",
            provider=None,
            identity_data={},
            is_active=True,
            created_at=datetime.utcnow(),
        )
        website = SimpleNamespace(
            id=uuid4(),
            owner_id=owner.id,
            name="Example Site",
            slug="example-site",
            description=None,
            login_hosts=[],
            allowed_redirect_origins=[],
            user_schema={},
            max_users=10,
            created_at=datetime.utcnow(),
        )

        async def _override_get_session():
            yield _FakeSession([website])

        async def _fake_get_owner_from_api_token(raw_token, _session):
            if not raw_token.startswith("pidp_pat_"):
                raise AssertionError("Expected service PAT token")
            return owner

        original_get_owner_from_api_token = self.main._get_owner_from_api_token
        self.main._get_owner_from_api_token = _fake_get_owner_from_api_token
        self.main.app.dependency_overrides[self.main.get_session] = _override_get_session
        try:
            with TestClient(self.main.app) as client:
                headers = {"Authorization": "Bearer pidp_pat_test_smoke_token"}
                me_response = client.get("/service/me", headers=headers)
                sites_response = client.get("/service/websites", headers=headers)

            self.assertEqual(me_response.status_code, 200)
            self.assertEqual(sites_response.status_code, 200)
            self.assertEqual(me_response.json()["email"], owner.email)
            self.assertEqual(len(sites_response.json()), 1)
            self.assertEqual(sites_response.json()[0]["slug"], website.slug)
        finally:
            self.main._get_owner_from_api_token = original_get_owner_from_api_token

    def test_app_login_renders_website_specific_branding(self):
        website = SimpleNamespace(
            id=uuid4(),
            owner_id=uuid4(),
            name="Code Collective",
            slug="code-collective",
            description="Portal sign-in for Code Collective",
            login_hosts=["portal.arkavo.org"],
            allowed_redirect_origins=["https://portal.arkavo.org"],
            user_schema={},
            max_users=10,
            created_at=datetime.utcnow(),
        )

        async def _fake_resolve_login_website(_session, raw_slug):
            if raw_slug == website.slug:
                return website
            return None

        original_resolve_login_website = self.main._resolve_login_website
        self.main._resolve_login_website = _fake_resolve_login_website
        try:
            with TestClient(self.main.app) as client:
                response = client.get(f"/app/login?app={website.slug}&next=%2F")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Sign In To", response.text)
            self.assertIn(website.name, response.text)
            self.assertIn("name=\"app\" value=\"code-collective\"", response.text)
        finally:
            self.main._resolve_login_website = original_resolve_login_website

    def test_app_login_resolves_website_from_host_when_app_omitted(self):
        website = SimpleNamespace(
            id=uuid4(),
            owner_id=uuid4(),
            name="Code Collective",
            slug="code-collective",
            description="Portal sign-in for Code Collective",
            login_hosts=["portal.arkavo.org"],
            allowed_redirect_origins=["https://portal.arkavo.org"],
            user_schema={},
            max_users=10,
            created_at=datetime.utcnow(),
        )

        async def _fake_resolve_login_website_from_host(_session, _request):
            return website

        original_resolve_login_website_from_host = self.main._resolve_login_website_from_host
        self.main._resolve_login_website_from_host = _fake_resolve_login_website_from_host
        try:
            with TestClient(self.main.app) as client:
                response = client.get("/app/login", headers={"host": "portal.arkavo.org"})
            self.assertEqual(response.status_code, 200)
            self.assertIn("Code Collective", response.text)
            self.assertIn("name=\"app\" value=\"code-collective\"", response.text)
        finally:
            self.main._resolve_login_website_from_host = original_resolve_login_website_from_host

    def test_social_login_rejects_disallowed_redirect_origin(self):
        website = SimpleNamespace(
            id=uuid4(),
            owner_id=uuid4(),
            name="Code Collective",
            slug="code-collective",
            description="Portal sign-in for Code Collective",
            login_hosts=["portal.arkavo.org"],
            allowed_redirect_origins=["https://portal.arkavo.org"],
            user_schema={},
            max_users=10,
            created_at=datetime.utcnow(),
        )

        class _FakeOAuthClient:
            async def authorize_redirect(self, request, redirect_uri):
                return JSONResponse(
                    {
                        "saved_next": request.session.get("frontend_redirect_url"),
                        "redirect_uri": redirect_uri,
                    }
                )

        async def _fake_resolve_login_website(_session, raw_slug):
            if raw_slug == website.slug:
                return website
            return None

        original_create_client = self.main.oauth.create_client
        original_resolve_login_website = self.main._resolve_login_website
        self.main.oauth.create_client = lambda provider: _FakeOAuthClient() if provider == "google" else None
        self.main._resolve_login_website = _fake_resolve_login_website
        try:
            with TestClient(self.main.app) as client:
                response = client.get(
                    "/auth/google/login?app=code-collective&next=https://evil.example/path",
                    follow_redirects=False,
                )
            self.assertEqual(response.status_code, 303)
            self.assertIn("/app/login?app=code-collective", response.headers["location"])
            self.assertIn("Redirect+URL+is+not+allowed+for+this+application", response.headers["location"])
        finally:
            self.main.oauth.create_client = original_create_client
            self.main._resolve_login_website = original_resolve_login_website


if __name__ == "__main__":
    unittest.main()

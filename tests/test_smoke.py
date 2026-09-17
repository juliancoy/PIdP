from __future__ import annotations

import importlib
import os
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi.testclient import TestClient
from jose import jwt
from starlette.responses import JSONResponse, Response


REPO_DIR = Path(__file__).resolve().parents[1]
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))


def _load_main_module():
    os.environ["SECRET_KEY"] = "test-secret-key"
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost:5432/testdb"
    os.environ["AUTO_CREATE_TABLES"] = "false"
    os.environ["GOOGLE_CLIENT_ID"] = "google-client-id"
    os.environ["GOOGLE_CLIENT_SECRET"] = "google-client-secret"
    os.environ["GOOGLE_REDIRECT_URI"] = "https://id.codecollective.us/auth/google/callback"
    os.environ["GITHUB_CLIENT_ID"] = "github-client-id"
    os.environ["GITHUB_CLIENT_SECRET"] = "github-client-secret"
    os.environ["GITHUB_REDIRECT_URI"] = "https://id.codecollective.us/auth/github/callback"
    os.environ["FRONTEND_REDIRECT_URL"] = "https://id.codecollective.us/auth/callback"
    os.environ["MINIO_ENDPOINT"] = "http://minio:9000"
    os.environ["MINIO_BUCKET"] = "pidp-avatars"
    os.environ["MINIO_PUBLIC_BASE_URL"] = "https://id.codecollective.us/s3"

    for module_name in ("config", "db", "encrypted_json", "main", "models"):
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

    def test_social_login_preserves_next_before_oauth_without_website_allowlist(self):
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
                response = client.get(
                    "/auth/google/login?next=https://evil.example/admin",
                    headers={
                        "host": "id.codecollective.us",
                        "x-forwarded-proto": "https",
                    },
                    follow_redirects=False,
                )
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["saved_next"], "https://evil.example/admin")
            self.assertEqual(payload["redirect_uri"], os.environ["GOOGLE_REDIRECT_URI"])
        finally:
            self.main.oauth.create_client = original_create_client
            self.main._resolve_login_website_from_host = original_resolve_login_website_from_host

    def test_app_login_preserves_next_without_website_allowlist(self):
        original_resolve_login_website_from_host = self.main._resolve_login_website_from_host
        async def _fake_resolve_login_website_from_host(_session, _request):
            return None
        self.main._resolve_login_website_from_host = _fake_resolve_login_website_from_host
        try:
            with TestClient(self.main.app) as client:
                response = client.get(
                    "/app/login?next=https://evil.example/admin",
                    headers={
                        "host": "id.codecollective.us",
                        "x-forwarded-proto": "https",
                    },
                    follow_redirects=False,
                )
            self.assertEqual(response.status_code, 200)
            self.assertIn('value="https://evil.example/admin"', response.text)
        finally:
            self.main._resolve_login_website_from_host = original_resolve_login_website_from_host

    def test_configuration_matches_runtime_env_and_host(self):
        with TestClient(self.main.app) as client:
            response = client.get(
                "/configuration",
                headers={
                    "host": "id.codecollective.us",
                    "x-forwarded-proto": "https",
                },
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["base_addr"], "https://id.codecollective.us/")
        self.assertEqual(payload["google_redirect_uri"], os.environ["GOOGLE_REDIRECT_URI"])
        self.assertEqual(payload["github_redirect_uri"], os.environ["GITHUB_REDIRECT_URI"])
        self.assertEqual(payload["frontend_redirect_url"], os.environ["FRONTEND_REDIRECT_URL"])

    def test_default_session_cookie_and_token_last_one_year(self):
        token = self.main.create_access_token(subject="user-1", email="user@example.com")
        claims = jwt.get_unverified_claims(token)
        expires_at = datetime.fromtimestamp(claims["exp"], UTC)
        lifetime = expires_at - datetime.now(UTC)
        self.assertGreaterEqual(lifetime.days, 364)

        response = Response()
        self.main._set_session_cookie(response, token)
        cookie = response.headers["set-cookie"]
        self.assertIn("Max-Age=31536000", cookie)

    def test_email_verification_state_hashes_tokens_and_oauth_bypasses(self):
        request = SimpleNamespace(
            headers={"host": "id.codecollective.us", "x-forwarded-proto": "https"},
            url=SimpleNamespace(scheme="https", netloc="id.codecollective.us"),
        )
        user = SimpleNamespace(
            email="new-user@example.com",
            provider=None,
            provider_account_id=None,
            identity_data={},
        )

        verification_url = self.main._prepare_email_verification(user, request)
        parsed = urlparse(verification_url)
        raw_token = parse_qs(parsed.query)["token"][0]

        self.assertFalse(self.main._is_email_verified(user))
        self.assertNotIn(raw_token, str(user.identity_data))
        self.assertEqual(
            user.identity_data["email_verification"]["token_hash"],
            self.main._verification_token_hash(raw_token),
        )

        user.identity_data = self.main._verified_identity(user.identity_data)
        self.assertTrue(self.main._is_email_verified(user))

        oauth_user = SimpleNamespace(
            email="oauth-user@example.com",
            provider="google",
            provider_account_id="google-123",
            identity_data={},
        )
        self.assertTrue(self.main._is_email_verified(oauth_user))

    def test_google_workspace_email_delivery_uses_workspace_smtp_defaults(self):
        original_delivery = self.main.settings.email_verification_delivery
        original_username = self.main.settings.google_workspace_smtp_username
        original_password = self.main.settings.google_workspace_smtp_password
        original_from = self.main.settings.google_workspace_email_from
        original_allowed = self.main.settings.google_workspace_allowed_senders
        original_smtp_host = self.main.settings.smtp_host
        try:
            self.main.settings.email_verification_delivery = "google_workspace"
            self.main.settings.google_workspace_smtp_username = "identity@example.com"
            self.main.settings.google_workspace_smtp_password = "app-password"
            self.main.settings.google_workspace_email_from = ""
            self.main.settings.google_workspace_allowed_senders = "noreply@example.com, identity@example.com"
            self.main.settings.smtp_host = None

            settings_payload = self.main._normalize_email_delivery_settings(
                {"delivery": "google_workspace", "sender": "noreply@example.com"}
            )
            config = self.main._email_delivery_config(settings_payload)
            self.assertEqual(config["host"], "smtp.gmail.com")
            self.assertEqual(config["port"], 587)
            self.assertEqual(config["from_email"], "noreply@example.com")
            self.assertEqual(config["username"], "identity@example.com")
            self.assertTrue(config["starttls"])

            admin_state = self.main._email_delivery_admin_state(settings_payload)
            self.assertTrue(admin_state["secret_present"])
            self.assertIn("noreply@example.com", admin_state["senders"])
        finally:
            self.main.settings.email_verification_delivery = original_delivery
            self.main.settings.google_workspace_smtp_username = original_username
            self.main.settings.google_workspace_smtp_password = original_password
            self.main.settings.google_workspace_email_from = original_from
            self.main.settings.google_workspace_allowed_senders = original_allowed
            self.main.settings.smtp_host = original_smtp_host

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

    def test_service_token_info_includes_pat_scope(self):
        owner = SimpleNamespace(
            id=uuid4(),
            email="owner@example.com",
            full_name="Owner Example",
            provider=None,
            identity_data={},
            is_active=True,
            created_at=datetime.utcnow(),
        )
        token_record = SimpleNamespace(scope="org_portal")

        async def _override_get_session():
            yield _FakeSession([])

        async def _fake_get_api_token_owner_and_record(raw_token, _session):
            if not raw_token.startswith("pidp_pat_"):
                raise AssertionError("Expected PAT token")
            return owner, token_record

        original = self.main._get_api_token_owner_and_record
        self.main._get_api_token_owner_and_record = _fake_get_api_token_owner_and_record
        self.main.app.dependency_overrides[self.main.get_session] = _override_get_session
        try:
            with TestClient(self.main.app) as client:
                headers = {"Authorization": "Bearer pidp_pat_test_smoke_token"}
                response = client.get("/service/token-info", headers=headers)
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["token_kind"], "pat")
            self.assertEqual(payload["scope"], "org_portal")
            self.assertIn("org:profile.write", payload["scope_grants"])
            self.assertEqual(payload["owner"]["email"], owner.email)
        finally:
            self.main._get_api_token_owner_and_record = original

    def test_app_login_renders_website_specific_branding(self):
        website = SimpleNamespace(
            id=uuid4(),
            owner_id=uuid4(),
            name="Code Collective",
            slug="code-collective",
            description="Portal sign-in for Code Collective",
            login_hosts=["codecollective.us"],
            allowed_redirect_origins=["https://codecollective.us"],
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
            self.assertIn("Sign in to", response.text)
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
            login_hosts=["codecollective.us"],
            allowed_redirect_origins=["https://codecollective.us"],
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
                response = client.get("/app/login", headers={"host": "codecollective.us"})
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
            login_hosts=["codecollective.us"],
            allowed_redirect_origins=["https://codecollective.us"],
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

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "PIdP"
    env: str = "dev"
    secret_key: str
    access_token_expire_minutes: int = 60
    token_algorithm: str = "RS256"
    jwt_private_key: str | None = None
    jwt_public_key: str | None = None
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    database_url: str
    auto_create_tables: bool = False
    allowed_origins: str = ""
    admin_emails: str = ""
    admin_user_ids: str = ""

    google_client_id: str | None = None
    google_client_secret: str | None = None
    google_redirect_uri: str | None = None

    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_redirect_uri: str | None = None
    frontend_redirect_url: str | None = None
    allow_cross_lane_redirect: bool = False
    allowed_native_redirect_schemes: str = "org.arkavo.portal"
    minio_endpoint: str | None = None
    minio_access_key: str | None = None
    minio_secret_key: str | None = None
    minio_bucket: str = "pidp-avatars"
    minio_public_base_url: str = "/s3"

    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def origins_list(self) -> list[str]:
        if not self.allowed_origins:
            return []
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def native_redirect_schemes_list(self) -> list[str]:
        if not self.allowed_native_redirect_schemes:
            return []
        return [
            scheme.strip().lower()
            for scheme in self.allowed_native_redirect_schemes.split(",")
            if scheme.strip()
        ]

    def social_enabled(self, provider: str) -> bool:
        if provider == "google":
            return bool(self.google_client_id and self.google_client_secret)
        if provider == "github":
            return bool(self.github_client_id and self.github_client_secret)
        return False

    @property
    def admin_emails_list(self) -> list[str]:
        if not self.admin_emails:
            return []
        return [email.strip().lower() for email in self.admin_emails.split(",") if email.strip()]

    @property
    def admin_user_ids_list(self) -> list[str]:
        if not self.admin_user_ids:
            return []
        return [user_id.strip() for user_id in self.admin_user_ids.split(",") if user_id.strip()]


settings = Settings()

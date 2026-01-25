from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "PIdP"
    env: str = "dev"
    secret_key: str
    access_token_expire_minutes: int = 60
    token_algorithm: str = "HS256"
    database_url: str
    auto_create_tables: bool = False
    allowed_origins: str = ""

    google_client_id: str | None = None
    google_client_secret: str | None = None
    google_redirect_uri: str | None = None

    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_redirect_uri: str | None = None

    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def origins_list(self) -> list[str]:
        if not self.allowed_origins:
            return []
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    def social_enabled(self, provider: str) -> bool:
        if provider == "google":
            return bool(self.google_client_id and self.google_client_secret)
        if provider == "github":
            return bool(self.github_client_id and self.github_client_secret)
        return False


settings = Settings()

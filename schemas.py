from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

APITokenScope = Literal["service", "org_portal", "org_mcp", "org_admin"]


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


class UserPublic(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str | None = None
    provider: str | None = None
    identity_data: dict | None = None
    is_sysadmin: bool = False
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class APITokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scope: APITokenScope = "service"


class APITokenPublic(BaseModel):
    id: UUID
    name: str
    scope: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None

    class Config:
        from_attributes = True


class APITokenIssued(BaseModel):
    token: str
    token_id: UUID
    name: str
    scope: str


class ServiceTokenInfo(BaseModel):
    token_kind: Literal["pat", "jwt"]
    scope: str
    scope_grants: list[str] = Field(default_factory=list)
    owner: UserPublic


class TokenData(BaseModel):
    sub: str
    email: EmailStr | None = None


class UserProfileUpdate(BaseModel):
    full_name: str | None = None
    display_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    address_line1: str | None = None
    address_line2: str | None = None
    city: str | None = None
    state: str | None = None
    zip: str | None = None
    organizations: list[str] | None = None
    maslow_now: dict[str, int] | None = None
    maslow_future: dict[str, int] | None = None


class UserPublicProfile(BaseModel):
    id: UUID
    full_name: str | None = None
    display_name: str | None = None
    avatar_url: str | None = None


class WebsiteSchemaField(BaseModel):
    type: Literal["string", "number", "boolean", "array", "object"] = "string"
    required: bool = False
    label: str | None = None
    description: str | None = None
    system: bool = False


class WebsiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    login_hosts: list[str] = Field(default_factory=list)
    allowed_redirect_origins: list[str] = Field(default_factory=list)


class WebsiteAuthConfigUpdate(BaseModel):
    login_hosts: list[str] = Field(default_factory=list)
    allowed_redirect_origins: list[str] = Field(default_factory=list)


class WebsiteBrandingUpdate(BaseModel):
    logo_url: str | None = None
    hero_eyebrow: str | None = None
    hero_title: str | None = None
    hero_subtitle: str | None = None
    primary_button_label: str | None = None
    accent_color: str | None = None
    accent_deep_color: str | None = None
    accent_soft_color: str | None = None
    background_style: str | None = None


class WebsiteSchemaUpdate(BaseModel):
    fields: dict[str, WebsiteSchemaField] = Field(default_factory=dict)


class WebsitePublic(BaseModel):
    id: UUID
    owner_id: UUID
    name: str
    slug: str
    description: str | None = None
    login_hosts: list[str] = Field(default_factory=list)
    allowed_redirect_origins: list[str] = Field(default_factory=list)
    branding: dict = Field(default_factory=dict)
    user_schema: dict
    max_users: int
    created_at: datetime

    class Config:
        from_attributes = True


class WebsiteUserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None
    identity_data: dict = Field(default_factory=dict)


class WebsiteUserLogin(BaseModel):
    email: EmailStr
    password: str


class WebsiteUserUpdate(BaseModel):
    full_name: str | None = None
    identity_data: dict | None = None
    is_active: bool | None = None


class WebsiteUserPublic(BaseModel):
    id: UUID
    website_id: UUID
    email: EmailStr
    full_name: str | None = None
    provider: str | None = None
    identity_data: dict | None = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

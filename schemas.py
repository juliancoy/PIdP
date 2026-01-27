from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


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
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


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


class UserPublicProfile(BaseModel):
    id: UUID
    full_name: str | None = None
    display_name: str | None = None
    avatar_url: str | None = None

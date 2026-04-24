# PIdP Architecture (Current State)

This document describes the architecture currently implemented in this repository.

## Stack

- Backend: FastAPI (single `main.py` app).
- ORM/Data: SQLAlchemy Async + `asyncpg` against PostgreSQL.
- Auth: JWT via `python-jose`, password hashing via Passlib bcrypt.
- Social OAuth: Authlib for Google/GitHub.
- Templates/UI: Jinja2 templates + static CSS/JS assets.
- Object storage: S3-compatible API (MinIO expected) via `boto3`.

## Runtime Topology

- One API/web process serves:
  - JSON APIs
  - OAuth callback endpoints
  - server-rendered console pages
  - static assets under `/assets`
- PostgreSQL stores owners, websites, and website users.
- Optional MinIO stores uploaded avatar images.

## High-Level Modules

- `main.py`: App bootstrap, middleware, route handlers, schema validation helpers, storage integration.
- `config.py`: Environment-driven settings and provider enablement logic.
- `db.py`: Async SQLAlchemy engine/session lifecycle.
- `models.py`: SQLAlchemy models (`User`, `Website`, `WebsiteUser`).
- `schemas.py`: Pydantic request/response models.
- `security.py`: Token creation/verification, JWKS, password hashing, credential auth helper.
- `oauth.py`: Provider registration and social profile normalization.

## Data Model

### `users`

- Owner accounts for PIdP console and owner APIs.
- Key fields:
  - `id` (UUID PK)
  - `email` (unique)
  - `hashed_password` (nullable for pure social accounts)
  - `full_name`
  - `provider`, `provider_account_id`
  - `identity_data` (JSONB)

### `websites`

- Tenant-like client objects owned by `users`.
- Key fields:
  - `id` (UUID PK)
  - `owner_id` (FK -> `users.id`)
  - `name`, `slug` (unique), `description`
  - `user_schema` (JSONB field map)
  - `max_users` (default 10)

### `website_users`

- End users that belong to a single website/client.
- Key fields:
  - `id` (UUID PK)
  - `website_id` (FK -> `websites.id`)
  - `email`, `hashed_password`, `full_name`
  - `provider`, `provider_account_id`
  - `identity_data` (JSONB)
  - `is_active`
- Constraints:
  - unique `(website_id, email)`
  - unique `(website_id, provider, provider_account_id)`

## Identity and Token Model

- Owner tokens:
  - `sub = owner user id`
  - optional `email`, `iss`, `aud`
- Website user tokens:
  - `sub = website_user id`
  - `actor_type = "website_user"`
  - `website_id = owning website id`
- Owner-only endpoints reject website-user tokens.
- JWT signing:
  - default algorithm `RS256`
  - if RSA keys are absent, app generates ephemeral RSA keys at runtime
  - JWKS published at `/.well-known/jwks.json`

## Request Flows

### Local owner login

1. Owner posts credentials to `/auth/token` (API) or `/session/login` (form).
2. Credentials validated against `users`.
3. JWT issued.
4. API clients use bearer token; server-rendered flow also stores cookie `pidp_token`.

### Social owner login

1. Browser starts provider auth at `/auth/{provider}/login`.
2. Provider callback hits `/auth/{provider}/callback`.
3. Profile normalized; owner record created/updated.
4. JWT issued and user redirected:
   - internal path with session cookie, or
   - external frontend URL with token in fragment.

### Website user login

1. Website user posts to `/websites/{website_slug}/auth/token`.
2. User validated within that website context.
3. JWT includes `actor_type=website_user` and `website_id`.
4. `/websites/{website_slug}/auth/me` verifies token belongs to that website.

### Avatar upload

1. Authenticated owner requests `/auth/avatar/upload-url`.
2. Backend ensures bucket exists and returns presigned PUT URL + public URL/object key.
3. Browser uploads image directly to object storage.
4. Browser commits metadata to `/profile/avatar`, which updates owner `identity_data`.

## Schema Enforcement

- Website `user_schema` is normalized with reserved/system fields always present.
- Website user `identity_data` writes are validated against that schema:
  - unknown field rejection
  - required field enforcement
  - type checking

## Frontend Architecture

- Primary UI path is server-rendered Jinja templates under `frontend/templates/`.
- Static assets mounted from `frontend/assets`.
- Theme state is managed client-side in `localStorage`.
- Profile avatar editor is a client-side canvas workflow.

## Middleware and Security Controls

- `SessionMiddleware` enabled (used for social callback redirect state and cookie-backed console auth).
- Optional CORS middleware enabled when `ALLOWED_ORIGINS` is configured.
- Session cookie is `HttpOnly`, `Secure`, `SameSite=Lax`.
- Password hashing truncates over-72-byte UTF-8 inputs before bcrypt hashing (bcrypt limit handling).

## Deployment / Startup

- `Dockerfile` runs `uvicorn main:app`.
- `run.py` can orchestrate local containers (Postgres + app) via `docker_utils.py`.
- Table auto-creation is gated by `AUTO_CREATE_TABLES`.

# PIdP (People's Identity Provider)

PIdP is a token-based identity provider (IdP) built with FastAPI. It supports local credentials with hashed passwords, optional OAuth2 social sign-in (enabled via environment variables), and stores identity data in a parallel Postgres database.

It now also supports self-service website onboarding:

- Each account owner can create up to `5` websites.
- Each website can hold up to `10` website users.
- Website owners can define the schema for per-user JSON identity data.
- Core identity fields remain reserved and undeletable: `display_name`, `avatar_url`, `first_name`, `last_name`.

## Features

- JWT access tokens
- Password hashing with bcrypt
- Postgres-backed identity store
- Optional social sign-in (Google, GitHub) toggled by env vars
- Async FastAPI stack

## Architecture Diagrams

### System Components

```mermaid
flowchart LR
    Browser[Owner Browser / Web Console]
    WebsiteClient[Website Client / Integrator]
    API[FastAPI App]
    DB[(PostgreSQL)]
    OAuth[Google/GitHub OAuth]
    S3[(MinIO / S3 Bucket)]

    Browser -->|Session + API Calls| API
    WebsiteClient -->|Website User Auth APIs| API
    API -->|SQLAlchemy Async| DB
    API -->|OAuth Redirect + Callback| OAuth
    API -->|Presigned Upload + Avatar Metadata| S3
```

### Owner Authentication Flow

```mermaid
sequenceDiagram
    actor U as Owner
    participant P as PIdP API
    participant D as PostgreSQL

    U->>P: POST /auth/register (email/password)
    P->>D: Insert users row (hashed_password)
    D-->>P: User created
    P-->>U: 200 UserPublic

    U->>P: POST /auth/token (username/password)
    P->>D: Lookup user by email
    D-->>P: User row
    P-->>U: JWT access_token

    U->>P: GET /auth/me (Bearer token)
    P-->>U: Current owner profile
```

### Data Model Relationships

```mermaid
erDiagram
    users ||--o{ websites : owns
    websites ||--o{ website_users : contains

    users {
        uuid id PK
        string email UK
        text hashed_password
        string full_name
        string provider
        string provider_account_id
        jsonb identity_data
        bool is_active
        datetime created_at
    }

    websites {
        uuid id PK
        uuid owner_id FK
        string name
        string slug UK
        text description
        jsonb user_schema
        int max_users
        datetime created_at
    }

    website_users {
        uuid id PK
        uuid website_id FK
        string email
        text hashed_password
        string full_name
        string provider
        string provider_account_id
        jsonb identity_data
        bool is_active
        datetime created_at
    }
```

## Frontend Modes

PIdP uses environment-based frontend channels:

- Default behavior is `stable` with no env required.
- `FRONTEND_CHANNEL=stable|dev` sets the deployment default channel.
- Runtime cookie (`pidp_frontend_channel`) selects `stable` or `dev` and overrides the deployment default.
- `stable` serves from `frontend/stable/` (falls back to `frontend/` if snapshot is missing).
- `dev` serves live-edit files from `frontend/templates/` and `frontend/assets/`.
- `FRONTEND_STABLE_COMMIT=<git-sha>` pins `stable` to frontend files from that exact commit.
- Admin control API/UI can update the stable commit at runtime and persist it to `frontend/.control-state.json`.
- Admin control API/UI can set a desired backend image (`backend_image_ref`) persisted in the same control state.

This keeps one canonical route surface (`/`) and lets deployment decide which channel is active.

The active channel is shown in the UI (`Prod` or `Dev`) with a built-in toggle in the app chrome.
Use the toggle to switch channels at runtime (stored in a cookie), regardless of deployment default.
When `FRONTEND_STABLE_COMMIT` is set, the prod badge shows `Prod @ <sha7>`.

To promote current dev UI to stable (recommended before production deploy):

```bash
./scripts/promote_frontend.sh
```

## Quickstart

1. Create a virtual environment and install dependencies.
2. Configure environment variables (see below).
3. Run the API server.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/pidp
export SECRET_KEY=change-me

uvicorn app.main:app --reload
```

## Environment Variables

Core settings:

- `DATABASE_URL` (required): Async SQLAlchemy URL for Postgres.
- `SECRET_KEY` (required): Secret for JWT signing and session middleware.
- `ACCESS_TOKEN_EXPIRE_MINUTES` (optional, default `60`)
- `TOKEN_ALGORITHM` (optional, default `HS256`)
- `AUTO_CREATE_TABLES` (optional, default `false`)
- `ALLOWED_ORIGINS` (optional, comma-separated)
- `FRONTEND_STABLE_COMMIT` (optional, git ref/sha used for `stable` frontend snapshot)
- `ADMIN_EMAILS` (optional, comma-separated admin emails allowed to manage control endpoints)
- `PIDP_PROD_IMAGE` (optional prod release image override; default `ghcr.io/juliancoy/pidp:latest`)
- `PIDP_DEV_IMAGE` (optional local dev image tag used for the watcher container; default `pidp-dev`)
- `PIDP_PROD_PUBLIC_BASE_URL` (optional explicit prod callback base, e.g. `https://pidp.example.com/`)
- `PIDP_DEV_PUBLIC_BASE_URL` (optional explicit dev callback base, e.g. `https://dev.pidp.example.com/`)

Social sign-in (set both client id/secret to enable):

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URI`

## API Overview

- `POST /auth/register` Register a local user.
- `POST /auth/token` OAuth2 password flow, returns JWT access token.
- `GET /auth/me` Returns the current user.
- `POST /auth/tokens` Create a user-scoped API token for service access.
- `GET /auth/tokens` List API tokens for the current user.
- `DELETE /auth/tokens/{token_id}` Revoke one of the current user's API tokens.
- `POST /auth/tokens/{token_id}/cycle` Rotate a token secret (same token id/name, new bearer value; re-activates if revoked).
- `POST /websites` Create a website owned by the authenticated account, capped at 5 sites.
- `GET /websites` List the authenticated owner's websites.
- `PUT /websites/{website_id}/schema` Replace the website user-data schema while preserving the reserved fields.
- `POST /websites/{website_id}/users` Owner-created website user, capped at 10 users per site.
- `GET /websites/{website_id}/users` List website users for an owned site.
- `PUT /websites/{website_id}/users/{website_user_id}` Update website user data with schema validation.
- `POST /websites/{website_slug}/auth/register` Public self-registration for a website user.
- `POST /websites/{website_slug}/auth/token` Website-user login for a specific website.
- `GET /websites/{website_slug}/auth/me` Returns the current website user.
- `GET /auth/{provider}/login` Start social sign-in.
- `GET /auth/{provider}/callback` Social provider callback, returns JWT.
- `GET /health` Health check.
- `GET /control/frontend/stable-commit` Admin-only control status for prod commit pin.
- `PUT /control/frontend/stable-commit` Admin-only update for prod commit pin (`{"commit":"<ref>"}` or `{"commit":null}`).
- `GET /service/me` User-scoped service identity endpoint (`Authorization: Bearer pidp_pat_...`).
- `GET /service/websites` List websites scoped to token owner.
- `POST /service/websites` Create website scoped to token owner.

Control behavior:

- Frontend prod commit pin requests are persisted in `frontend/.control-state.json`.

Deployment behavior:

- `python run.py` starts two app containers sharing one Postgres database:
  - `pidp` (prod): pulled release image, no source bind mount, no reload.
  - `pidp-dev` (dev): local source bind mount with `uvicorn --reload`.
- Recommended routing:
  - `pidp.<domain>` -> `pidp`
  - `dev.pidp.<domain>` -> `pidp-dev`
- Release image publishing is automated via GitHub Actions workflow:
  - `.github/workflows/pidp-release.yml`
- Optional automatic deploy from GitHub Actions (main branch) uses SSH to run:
  - `scripts/deploy_pidp.sh <image@sha256:digest>`
  - Required GitHub repository secrets:
    - `PIDP_DEPLOY_HOST`
    - `PIDP_DEPLOY_USER`
    - `PIDP_DEPLOY_SSH_KEY`
    - `PIDP_DEPLOY_PATH` (optional; defaults to `~/Documents/arkavo-platform`)

## Notes

- Social sign-in is disabled unless provider client id and secret are set.
- PIdP only stores hashed passwords; plaintext is never persisted.
- Identity data can be stored in the `identity_data` JSONB column.
- Existing databases will need matching schema changes for the new `websites` and `website_users` tables if you are not starting from an empty database with `AUTO_CREATE_TABLES=true`.

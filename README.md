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

## Notes

- Social sign-in is disabled unless provider client id and secret are set.
- PIdP only stores hashed passwords; plaintext is never persisted.
- Identity data can be stored in the `identity_data` JSONB column.
- Existing databases will need matching schema changes for the new `websites` and `website_users` tables if you are not starting from an empty database with `AUTO_CREATE_TABLES=true`.

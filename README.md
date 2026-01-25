# PIdP (People's Identity Provider)

PIdP is a token-based identity provider (IdP) built with FastAPI. It supports local credentials with hashed passwords, optional OAuth2 social sign-in (enabled via environment variables), and stores identity data in a parallel Postgres database.

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
- `GET /auth/{provider}/login` Start social sign-in.
- `GET /auth/{provider}/callback` Social provider callback, returns JWT.
- `GET /health` Health check.

## Notes

- Social sign-in is disabled unless provider client id and secret are set.
- PIdP only stores hashed passwords; plaintext is never persisted.
- Identity data can be stored in the `identity_data` JSONB column.

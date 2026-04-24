# PIdP Features (Current State)

This document reflects the features currently implemented in this repository as of April 2026.

## Core Identity

- Owner account registration with email/password (`POST /auth/register`).
- Owner login via OAuth2 password flow returning bearer JWTs (`POST /auth/token`).
- Current owner lookup (`GET /auth/me`).
- Owner profile update (`PUT /auth/me`) with both top-level and JSON identity fields.
- Passwords are hashed with bcrypt via Passlib.

## Social Login

- Optional Google and GitHub login flows:
  - `GET /auth/{provider}/login`
  - `GET /auth/{provider}/callback`
- Providers are only active when corresponding client id/secret config is set.
- Social callback creates or links owner accounts by provider account and/or email.
- If configured, callback can redirect to external frontend and pass token in URL fragment.

## JWT and Discovery

- JWT issuance supports asymmetric signing by default (`RS256`) and can also use symmetric algorithms.
- Optional `iss` and `aud` claims are supported via settings.
- JWKS endpoint is exposed at `GET /.well-known/jwks.json` (non-empty for RSA algorithms).

## Website (Client) Management

- Create website/client owned by authenticated owner (`POST /websites`).
- List owned websites (`GET /websites`).
- Get owned website details (`GET /websites/{website_id}`).
- Hard cap of 5 websites per owner account.
- Slug normalization enforces lowercase URL-safe slugs.

## Website User Schema

- Each website stores a JSON schema-like field map (`user_schema`).
- Owner can replace schema (`PUT /websites/{website_id}/schema`).
- Built-in reserved/system fields are always present:
  - `display_name`
  - `avatar_url`
  - `first_name`
  - `last_name`
- Reserved fields cannot be redefined to incompatible types or required settings.

## Website User Accounts

- Owner can create website users (`POST /websites/{website_id}/users`).
- Owner can list website users (`GET /websites/{website_id}/users`).
- Owner can update website users (`PUT /websites/{website_id}/users/{website_user_id}`), including activation state.
- Public self-registration for website users by website slug (`POST /websites/{website_slug}/auth/register`).
- Website user login by website slug (`POST /websites/{website_slug}/auth/token`).
- Website user self lookup (`GET /websites/{website_slug}/auth/me`).
- Website-level user limit enforced (default/max configured per site at creation: 10).
- Website user uniqueness constraints:
  - `(website_id, email)`
  - `(website_id, provider, provider_account_id)`

## Identity Data Validation

- Website user `identity_data` is validated against website `user_schema`:
  - unknown fields rejected
  - required fields enforced
  - type checks for `string | number | boolean | array | object`

## Web Console (Server-Rendered)

- Jinja-rendered console pages:
  - `/` (home/login or dashboard)
  - `/profile`
  - `/sites`
  - `/sites/{website_id}`
  - `/billing` (placeholder summary page)
- Session cookie (`pidp_token`) is set for server-rendered flows.
- Theme mode switcher with `system`, `light`, `dark`, and `auto`.

## Avatar Uploads

- Owner avatar upload flow in profile UI:
  - Client-side crop/zoom editor to PNG.
  - Presigned upload URL generation (`POST /auth/avatar/upload-url`).
  - Profile avatar commit (`POST /profile/avatar`).
- Object storage targets MinIO/S3-compatible API via `boto3`.
- Social avatars can be mirrored into object storage on first social login when no custom avatar exists.

## Operational Endpoints

- Health check: `GET /health`.
- Runtime configuration exposure from `pidp_editme.py`: `GET /configuration`.

## Current Caveats / Partial Areas

- Billing page is a UI placeholder; no payment provider integration is implemented.

# PIdP Serverless Worker

This directory contains a Cloudflare-native implementation of the PIdP base JSON API.

## Stack

- Cloudflare Workers
- TypeScript
- Hono
- D1 for relational data
- R2 for avatar object storage
- Web Crypto for JWT signing and password hashing

## Implemented

- Health/configuration endpoints
- Owner registration/login/profile
- Owner JWT sessions
- Personal access tokens
- Service token introspection
- Website CRUD/configuration
- Website user registration/login/profile
- Public user profile lookup
- R2-backed avatar upload route
- Google/GitHub OAuth for owner and website-user login
- Profile contact, website, and social link fields, including contact/public email, phone, mobile, work phone, fax, SMS, WhatsApp, Telegram, Signal, GitHub, LinkedIn, X/Twitter, Instagram, Facebook, YouTube, TikTok, Threads, Bluesky, Mastodon, Discord, Twitch, Snapchat, Pinterest, Reddit, Medium, Substack, and Linktree
- Public link-tree style profile pages at `/u/:userId` and `/sites/:websiteSlug/users/:websiteUserId/profile`

## Not Yet Implemented

- Server-rendered Jinja console parity
- RS256/JWKS key publishing
- Fernet-compatible encrypted JSON migration
- Direct compatibility with existing bcrypt password hashes

The serverless implementation uses PBKDF2-SHA256 through Web Crypto for new password hashes. Existing Python bcrypt hashes need either a migration/reset flow or a Worker-compatible bcrypt/argon2 WASM implementation.

## Setup

Install dependencies:

```sh
npm install
```

Create a D1 database and update `wrangler.jsonc` with the returned database id:

```sh
npx wrangler d1 create pidp
```

Set required secrets:

```sh
npx wrangler secret put SECRET_KEY
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
```

Set OAuth callback URLs in `wrangler.jsonc` or as environment-specific vars:

```txt
GOOGLE_REDIRECT_URI=https://<your-worker-host>/auth/google/callback
GITHUB_REDIRECT_URI=https://<your-worker-host>/auth/github/callback
FRONTEND_REDIRECT_URL=https://<your-frontend-host>/auth/callback
```

Apply migrations:

```sh
npm run db:migrate:local
npm run db:migrate:remote
```

Run locally:

```sh
npm run dev
```

Check Cloudflare/Wrangler status before deployment:

```sh
npm run deploy:status
```

Deploy:

```sh
npm run deploy:serverless
```

Useful deployment flags:

```sh
npm run deploy:serverless -- --dry-run
npm run deploy:serverless -- --skip-migrations
```

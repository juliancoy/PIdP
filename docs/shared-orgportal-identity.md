# OrgPortal domain and shared-account migration plan

**Decision: use `orgportal.cc` for the portal and `id.orgportal.cc` for isolated identity; consolidate
portal credentials into primary PIdP accounts. Implementation remains disabled;
this plan and its rehearsal do not authorize production cutover.** The checked-in
configuration uses `PORTAL_SHARED_IDENTITY=false`, `PORTAL_SSO_APP_SLUG=orgportal`
and `PUBLIC_BASE_URL=https://orgportal.cc/pidp`. This document describes a future
cutover, not evidence of deployed settings or database state.

## Agreed destination

The product goal is one account, one sign-in entry point, and one coherent set of
identity settings. PIdP stays the identity implementation; OrgPortal stays the
owner of organizations, membership, permissions and tenant branding.

| Public address | Responsibility |
| --- | --- |
| `https://orgportal.cc/` | Portal, communities and organization settings |
| `https://id.orgportal.cc/app/login` | Central login and registration |
| `https://id.orgportal.cc/profile` | PIdP identity/account entry point |
| `https://id.orgportal.cc/auth/google/callback` | Google callback |
| `https://id.orgportal.cc/auth/github/callback` | GitHub callback |
| `https://orgportal.cc/api/org/*` | Organization API |
| `https://orgportal.cc/api/chat/*` | Chat HTTP API; verify WebSocket routing separately |
| `https://orgportal.cc/mcp` | Agent resource |
| `https://orgportal.cc/oauth/mcp/*` | OAuth registration, authorization, tokens and grant operations |
| `https://orgportal.cc/.well-known/oauth-authorization-server` | Issuer discovery |
| `https://orgportal.cc/.well-known/jwks.json` | Public signing keys |

The target identity issuer is `https://id.orgportal.cc`. Identity pages and OAuth
protocol endpoints use that separate origin. `id.codecollective.us` and same-origin
primary login pages are retirement targets. Do not create a second identity database or independent token issuer.
Tenant domains retain their branding and initiate validated browser-bound SSO at
the central login; their own host-only sessions remain scoped to each tenant.

## Rollout sequence

1. **Inventory and baseline.** Record actual deployed public URLs, callback
   registrations, issuer, signing-key IDs, resources, clients, grants, provider
   links and settings links. Record backups and independently verify primary
   account access before any credential change. Stored production secrets/provider
   console registrations are not established by checked-in config alone.
2. **Consolidate accounts.** Keep the current `/pidp` public base, database, keys,
   issuer and provider callbacks during the credential migration. Apply the
   reviewed consolidation under maintenance, then enable shared identity only
   after the account acceptance gates below pass.
3. **Unify the entry points and settings.** Send first-party sign-in/registration
   and reusable account-security settings to the canonical PIdP mount. Keep
   organization-specific settings in OrgPortal and preserve the validated tenant
   return context. Acceptance requires no duplicate credential or identity-settings
   workflow presented to users.
4. **Reconcile protocol configuration.** Set provider callbacks to the canonical
   addresses above and update clients/resources and all first-party links. If the
   deployed issuer already equals `https://orgportal.cc`, retain its keys/grants.
   If it differs, explicitly register/reconnect clients and obtain new consent at
   the new issuer. Never relabel old tokens or silently rewrite grant ownership.
   Reject foreign-issuer tokens. Client reconnection is planned work, not a promise
   of backwards compatibility.
5. **Retire alternate hosts.** After canonical acceptance, remove old identity
   domain routes, callback registrations and old links in their owning releases.
   Do not retain legacy login flows. Confirm required clients are connected before
   removing their former issuer. Do not remove tenant public websites.

## Account consolidation

The target must equal the deployment's configured `PORTAL_SSO_APP_SLUG`. Never
substitute a historical slug. A missing target aborts. Case-insensitive email
collisions, duplicate emails, missing linked accounts, ID collisions and differing
active states require operator resolution. Email alone never proves ownership;
existing verified links or matching immutable provider identities establish links.
Do not reactivate disabled accounts or infer administrator access.

New primary accounts retain member IDs and credentials. Existing primary accounts
keep their own credentials, including a missing password: a member password must
not create an additional login method on an existing primary account. Differing
password hashes do not establish differing passwords. Users with existing primary
accounts must demonstrate primary sign-in before cutover. This migration does not
establish a password-reset flow; resolve access failures while member credentials
still exist rather than assuming recovery is available. Member passwords
are cleared on apply; member rows and subject aliases remain. Communicate the
credential change to affected users before cutover.

Python deployments run from the PIdP root with the deployment's configuration:

```sh
PYTHONPATH=. python scripts/migrate_shared_credentials.py --app orgportal
# Only after the rollout gates below:
PYTHONPATH=. python scripts/migrate_shared_credentials.py --app orgportal --apply --writes-paused --backup-verified
```

Python apply locks the identity tables and executes planning and writes in one
PostgreSQL transaction. Preview performs no writes; it is not a concurrency lock.

For D1, use `serverless/scripts/migrate-shared-credentials.mjs`'s exported
`migrateSharedCredentials(db, options)` with the actual deployment D1 binding.
Supply `appSlug`, `configuredAppSlug` and boolean `sharedIdentity` from verified
configuration. Default behavior returns counts only, not a collision audit. Apply
requires `apply: true`, `writesPaused: true` and `backupVerified: true`.
The helper binds the target slug and submits the complete draft SQL through one
transactional `DB.batch`; any failed guard rolls back all statements. Do not run
`docs/proposals/0012_shared_orgportal_credentials.sql` directly or split it into
independent remote calls. The helper is operator-only and has no public endpoint.

An offline SQLite operator command is available from `serverless/` (Node 24+):

```sh
node scripts/migrate-shared-credentials.mjs --config wrangler.jsonc --database /absolute/path/to/isolated.sqlite --app orgportal
# Append --apply --writes-paused --backup /absolute/path/to/new-backup.sqlite for an isolated apply.
```

The CLI opens only an existing offline SQLite copy, checks the explicit config,
and creates a consistent private SQLite backup before apply. It performs no
network requests and does not read `.env` files. Stop the local runtime before
copying its SQLite database, including its WAL, or use a consistent SQLite backup.
Never point it at a running runtime database. It does not place an application
into maintenance; writes must remain paused through cutover. D1 bindings use the
transactional batch helper above; this CLI rehearses exported/local SQLite copies.

## Cutover gates

1. Inventory the exact target, account links, case-insensitive collisions, disabled
   accounts, affected primary credentials and outstanding grants. Resolve ambiguous
   ownership using authenticated proof, not email matching.
2. Verify a consistent backup and rehearse restoring it in isolation. Pause all
   identity writes and keep login traffic in maintenance through apply and flag
   activation; keep the same application slug in PIdP and OrgPortal.
3. Apply to an isolated restored database first. With explicit test authorization,
   check password/social login, expired-handoff recovery, disabled accounts, old sessions, OAuth
   grants, tenant isolation and organization/admin permission denials in both
   runtimes. Existing subjects must retain their permissions without escalation.
4. After explicit production authorization, back up again, apply atomically while
   writes are paused, and enable shared identity only after successful migration.
   Resume traffic only after the authorized acceptance checks pass. A zero-member
   inventory requires explanation; it does not prove migration success.

## Rollback

Turning the flag off is insufficient: member password hashes were removed.
Before reopening traffic, restore the complete pre-cutover identity database and
matching configuration while writes remain paused. A SQL failure inside the batch
or Python transaction needs no data restore, but verify rollback before retrying.

If writes have resumed, restoring the backup can lose registrations, password
changes, revocations and links created after it. Re-enter maintenance and reconcile
those changes before any restore; do not overwrite live identity state blindly.
There is no automatic post-cutover reverse migration. Do not approve a rollout
without an agreed maintenance window and recovery procedure.


## Earlier same-origin rehearsal: 2026-10-24

This historical rehearsal is superseded for browser-origin isolation by the
separate-origin local deployment below.

The adopted domain plan was rehearsed without changing active identity data,
production DNS/routes, provider registrations or the shared-identity feature flag.

- Headless Chromium used a loopback HTTPS server executing the actual OrgPortal
  edge router and PIdP Worker modules. Chromium mapped `orgportal.cc` and the tenant
  host to loopback and blocked other DNS resolution. Synthetic accounts exercised
  migration, password login, mounted account pages, reload, tenant SSO and
  host-only cookies. No production identity data was served to the browser.
- Both Google and GitHub authorization URLs used the canonical callback paths.
  Real provider-console registrations and real provider exchanges were not tested.
- MCP consent, authorization-code exchange, introspection and refresh passed with
  issuer `https://orgportal.cc` and resource `https://orgportal.cc/mcp`.
  Validation under a foreign issuer was rejected.
- Organization API, chat API and MCP forwarding passed through the actual edge
  router with synthetic upstream responses. This does not prove authenticated
  organization writes, live chat/WebSockets or a deployed service binding.
- A fresh offline copy of the local archived identity dataset migrated all 15
  members. All 46 existing primary-account records and unrelated tables, including
  sessions and grants, stayed unchanged. Restoring the created backup exactly
  reproduced every original table's data.
- Focused results: 34 protocol/migration tests, 11 edge tests and one headless
  browser rehearsal passed. Whitespace/reference review also passed.

Repeat from the PIdP `serverless/` directory, with Node 24+, OpenSSL, installed npm
dependencies, the sibling OrgPortal checkout and Playwright Chromium available:

```sh
IDENTITY_DOMAIN_REPORT=/absolute/path/to/private-report npm run test:domain-rehearsal
node --import tsx --test test/mcp-authorization.test.mjs test/identity-urls.test.mjs test/portal-oauth.test.mjs test/shared-credentials-migration.test.mjs
```

From OrgPortal, run the routing checks:

```sh
node --test cloudflare/identity.test.mjs cloudflare/mcp-origin.test.mjs cloudflare/chat-websocket.test.mjs cloudflare/orgportal-platform.test.mjs
```

The archived-data rehearsal uses the offline SQLite command above on a fresh
private copy, compares existing primary records and all unrelated tables, restores
its generated backup, and compares every table again. Never place archive data,
credentials, session tokens or database copies in source control.

Remaining cutover evidence: deployed issuer/client inventory, verified primary
access for affected people, real provider registrations, first-party settings and
sign-in link inventory, required client reconnection, live WebSocket checks,
maintenance-window backup/restore and owning-service release acceptance.


## Separate-origin local deployment

Portal: `https://localhost:8443`. Identity: `https://id.localhost:8443`.
The same gateway terminates TLS using certificates covering both hosts; the host
boundary, not the port, provides isolation. Primary account pages are never
proxied into the portal origin. The portal exposes only tenant-session and
browser-bound SSO endpoints. Identity cookies stay host-only on `id.localhost`;
tenant cookies stay on the portal. Identity CORS excludes the portal origin.
A portal script must fail to read the signed-in identity response, while normal
navigation and validated SSO remain functional. Account consolidation is still a
separate data operation; changing the local origins does not apply it.

Production domain/provider/issuer changes require the owning release and are not
performed by this local activation. Reconnect clients if their issuer changes;
never relabel grants or tokens. All first-party identity links and provider
registrations must use `id.orgportal.cc` at cutover.

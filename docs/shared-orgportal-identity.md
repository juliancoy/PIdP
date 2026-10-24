# Proposed shared OrgPortal identity migration

**Status: disabled; not authorized for production application.** The checked-in
configuration uses `PORTAL_SHARED_IDENTITY=false`, `PORTAL_SSO_APP_SLUG=orgportal`
and `PUBLIC_BASE_URL=https://orgportal.cc/pidp`. This document describes a future
cutover, not evidence of deployed settings or database state.

## Account consolidation

Consolidation changes the credential store, not the login hostname. Keep the
current public base URL, provider callback URLs, issuer, keys, database and tenant
same-origin `/pidp` proxies throughout this migration. A later hostname move must
have its own review and rollout; `id.orgportal.cc` is not required here.

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

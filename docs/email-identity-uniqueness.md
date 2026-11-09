# Email identity uniqueness repair — 2026-11-09

PIdP preserves primary and website credential namespaces. Normalized email
(`lower(trim(email))`) is unique within each namespace, including concurrent
writes. Different names are irrelevant to identity; different-email accounts
remain independent unless explicitly linked.

Fresh verified Google callbacks can establish a portal canonical alias only
when the immutable Google subject and normalized email both match one active
primary identity. Existing links are never overwritten. Credentials, provider
namespaces and organization permissions are not migrated or merged.

The private POST `/service/directory-identities` accepts only an active service
PAT owned by the configured portal website owner. It returns linked account
IDs and canonical IDs, never email addresses, with no-store caching. OrgPortal
uses a dedicated PIDP_DIRECTORY_TOKEN and a one-minute bounded in-memory read
cache. This creates no new persistent personal-data store. Existing identity
link deletion/backup handling applies. Directory aliases must never confer
organization permissions.

## Explicit production migration review

Migration 0016 adds expression indexes only. It fails closed if prior normalized
collisions exist; no rows are deleted or changed. Existing code and rollback
versions remain compatible. Revert the indexes only as an explicit database
operation; a Worker rollback does not undo them. Audit on 2026-11-09 found zero
primary and zero per-website normalized collisions.

Pre-change D1 recovery bookmark:
`0000238a-00000072-0000511e-7cd0a5b3a7f7a7091957c17c65136af3`.
Recovery is an operator action and must preserve subsequent legitimate writes.

Two existing unlinked portal accounts match an active primary by the same
Google subject AND normalized email. A guarded one-time repair may add only
these missing aliases, after checking both proofs and collision counts. It
must not overwrite links, transfer memberships, or erase credentials. The
shared-identity credential cutover remains disabled.

Focused test results and content fingerprints are adjacent to the serverless
tests. Production rollout evidence is recorded separately after deployment.

## Applied production result

2026-11-09: both normalized unique indexes installed explicitly after the zero-
collision audit. Added exactly two missing aliases with matching active Google
subjects and normalized emails; no remaining eligible unlinked aliases. No
credential deletions or organization role transfers. Shared identity remains
false. PostgreSQL migration script is provided for deployments using that
runtime; production here uses D1.

PIdP tested/released source: b03b053931db275569527de0738b047dcff3713c.
Previous version: 0983b6ee-24bc-4c7c-89bd-2390dad0333b.
New version: 8c33e914-e3b2-4efc-9229-4a01ba233248.
Code-only upload inherited all live bindings and runtime settings. A dedicated
portal-owner service credential was bound as PIDP_DIRECTORY_TOKEN; the existing
PIDP_SERVICE_TOKEN was preserved. The first secret edit was refused by Cloudflare
because the latest uploaded version was not deployed; its credential was disabled.
After the tested OrgPortal release, the dedicated credential was rotated and
bound successfully. No credential value was written to logs or source.

OrgPortal tested/released source: c5fdf11ea396dbbc3fe244d148a9b810d24f438c.
Previous API version: 62580b3e-ec32-4361-a107-49e5dc66d4b4.
Code release: 74ec8e1e-3db3-4a43-bc85-752f2f45f8c9.
After the directory-secret binding: d943b6d1-2659-472d-b0dc-b001ba2fa9f8.
Anonymous LifeTech directory, users HTML, referenced JS and API proxy checks pass.
Linked aliases are grouped while distinct same-name accounts remain visible.
No production authenticated browser tests were run. Focused tests and both
TypeScript checks passed; earlier failed expectations and their corrections
remain recorded in adjacent test logs. No gradual/canary rollout was performed.

## Registered accounts without activity

The protected directory response now includes basic active website-user IDs
and display names for the configured portal, scoped to its owner. It excludes
unrelated tenants, inactive accounts, email addresses and other contact details.
OrgPortal combines these names with its existing directory sources before alias
grouping, search and pagination. No contact page, activity event or persistent
copy is created. A basic profile fallback exposes only that existing display
name when a registered account has no public contact page. Contact-page opt-in
and organization permissions retain their existing behavior. This fixes accounts
that were absent because they had no OrgPortal activity/profile records.

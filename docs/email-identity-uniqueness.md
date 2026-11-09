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

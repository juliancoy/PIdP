# Proposed shared OrgPortal identity migration

**Status: proposal only.** This migration has not been applied or enabled. The
current production identity URL is `https://orgportal.cc/pidp`; the proposed
`id.orgportal.cc` endpoint below is not the current deployment. The SQL is kept
outside `serverless/migrations` so ordinary deployment cannot apply it. Review
account ownership, collisions, runtime parity and rollback before authorizing it.

The proposed design would let OrgPortal and its communities use one PIdP primary account and one sign-in screen
at `https://id.orgportal.cc`. PIdP continues to own passwords, social provider
credentials, recovery, sessions, profile and connected-app grants. Tenant sites
start a validated browser-bound SSO handoff and receive their own host-only session;
they do not run a separate credential registration or login screen.

Only after a separate migration review and authorization, enable `PORTAL_SHARED_IDENTITY=true` with `PORTAL_SSO_APP_SLUG=code-collective`.
The historical slug is retained as an application/subject alias. It does not select
a credential store. Shared-app password and social sign-in use primary accounts.
Unrelated registered PIdP applications retain their own namespace behavior.

Draft SQL at `docs/proposals/0012_shared_orgportal_credentials.sql` would consolidate existing
shared members. Python deployments use `python scripts/migrate_shared_credentials.py`
for a count-only preview, then `--apply` in one transaction. New primary accounts
retain the member ID. Existing verified links remain authoritative. An operator-run
migration can reconcile an existing primary account when both records contain the
same provider and immutable provider subject; an email-only collision aborts.
Competing password hashes abort. Passwords move to `users`; member rows remain as
subject aliases for active sessions and OAuth grants. No primary account is given
an administrator designation by this migration.

SSO emits an existing linked member subject when present, preserving its domain
permissions and membership context. Otherwise a primary identity can enter the
portal without creating a second account. Membership and administrator permission
remain independently checked by OrgPortal. OAuth consent still requires approval.

The original Worker, D1 database, keys and old OAuth issuer/endpoints remain in
place for existing connected applications. `id.codecollective.us` remains a
compatibility endpoint. Provider redirect URIs registered at Google/GitHub remain
on that hostname; the validated callback is forwarded to the browser at
`id.orgportal.cc` before its code is exchanged. Registering new provider callback
URLs can retire that compatibility dependency in a later provider configuration
change. Do not deploy a second database or copy signing/provider secrets.

Deploy PIdP and apply the identity migration before deploying the portal sign-in
redirects. Preserve deployed bindings, including MCP resources and provider secrets.
OrgPortal owns its frontend release; use the OrgPortal repository release workflow.

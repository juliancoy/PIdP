# Portal identity boundaries and rollout

PIdP authenticates a person. OrgPortal decides what that person may do in an
organization. CodeCollective hosts shared deployment infrastructure; its domain,
branding, and historical account namespace must not select OrgPortal destinations.

| Responsibility | Owner | Contract |
| --- | --- | --- |
| Credentials, social providers, OAuth, sessions, account linking | PIdP | Authenticate in the requested account namespace; verify both accounts before linking. |
| Portal registration and trusted sign-in presentation | PIdP | Operator-controlled origin, display name, account namespace, and callback policy. |
| Portal brand configuration and navigation | OrgPortal | Supplies product configuration; login returns to the initiating registered portal. |
| Memberships, tenant roles, organization authority | OrgPortal | Check live domain permissions; OAuth consent is not membership. |
| Shared hosting and release orchestration | CodeCollective | Infrastructure ownership does not grant identity or domain authority. |

## Explicit registration

Register portal origins independently of account namespaces. The retained
`code-collective` namespace identifies existing credentials, not a product name
or redirect destination. Do not rename it without a separately reviewed account
migration. Register OrgPortal, LifeTech, MedTech and Timebank with their own names
and origins. Legacy CodeCollective portal entry points restart on OrgPortal before
creating any browser-bound ticket.

PIdP must derive presentation from registered origins or validated server-side
SSO tickets. Query strings cannot supply a trusted brand or broader rights.
Registration and the transport origin allowlist must both permit a portal.

## Return policy

One shared policy in each PIdP runtime validates SSO callbacks, MCP bridge returns,
and nested portal destinations. Match exact origins and registered callback paths.
Reject credentials, protocol-relative URLs, backslashes, control characters,
duplicate parameters, fragments on handoffs, and external nested destinations.
Validate the saved ticket again during authorization, account linking, and session
completion. Bind completion to the initiating browser and origin; codes are
short-lived and single use. Registration changes must invalidate old handoffs.

## User paths

Regular portal sign-in uses a website-member session. A primary account can use
an explicitly verified existing link. Without one, offer two-account linking with
confirmation or a separate portal sign-in. Preserve the original destination.
System-admin MCP login is an explicit primary-account flow. PIdP checks current
system authority; OrgPortal independently checks scopes and domain authorization.
Never infer a link or authority from email, matching IDs, branding, or consent.

## Implementation status

| Area | Status |
| --- | --- |
| Live PIdP system-admin verification in MCP | Deployed |
| Explicit account-link recovery and saved-return resume | Deployed |
| Legacy `/p/` callback restart | Deployed |
| Origin-specific registration and sign-in branding | Worker deployed; public routes verified on all seven origins; Python parity tested |
| Central callback and nested destination policy | Worker deployed; invalid returns rejected in live checks; Python parity tested |
| Cross-portal regression coverage in Python and Worker | 80 Worker tests, 33 Python tests, and local mobile/desktop sign-in render checks pass |
| Production authenticated browser verification | Requires user sign-in; automation uses local fixtures only |

## Verification and release

Run cross-portal sign-in, missing-link, explicit link, expiry/replay, namespace
substitution, callback tampering, and host-only cookie tests in both runtimes.
Cover registration revocation and unchanged credential namespaces. Never use real
credentials or production authenticated browser automation in tests.

Release PIdP independently, preserving live variables and credentials. Release
OrgPortal frontend/backend through CodeCollective only when their code changes.
Inspect production health and unauthenticated registration/sign-in routes. Report
which paths were tested locally and which user sign-ins remain unverified.

## Registration configuration

`shared/portal-clients.json` is the checked-in production registry consumed by both
runtimes. `PORTAL_CLIENTS_JSON` (`portal_clients_json` in Python) replaces that
registry for local deployments or operator-managed additions. Every entry has
`name`, `accountApp`, and `callbacks`; retired hosts additionally have a
`restartOrigin` that names another registered portal. `PORTAL_AUTH_ORIGINS` is
still required as the transport allowlist. Listing a host there alone does not
register it or grant users access.

Example isolated local registration:

```json
{
  "http://localhost:5173": {
    "name": "OrgPortal Local",
    "accountApp": "local-portal",
    "callbacks": ["/auth/callback"]
  }
}
```

Create the matching PIdP website namespace through its normal administration API.
`GET /auth/sso/client` through a portal's `/pidp` proxy returns that host's public
registration. Browser SSO may omit `app`; PIdP chooses the registered namespace.
Older clients may supply `app` only when it matches the registration. The old
`PORTAL_SSO_APP_SLUG` setting remains compatible configuration but no longer
selects the namespace for every domain.

Registration changes apply to new requests and invalidate uncompleted tickets
whose origin, namespace or saved callback is no longer permitted. Do not put
credentials, tokens, or privileged identity mappings in the registry. Social
provider callback URLs remain on PIdP; browser tokens never travel in return
URLs. Explicit native app deep links retain their existing token handoff.

PIdP Worker release: `5a44fb80-3cb6-4cb9-b04e-4572cad47aea`. The Python backend implementation is tested in source; production continues to use the single Worker issuer. No account namespace or membership migration was performed.

Account selection, link recovery, and the isolated Docker clickthrough are documented in [the identity audit](testing/IDENTITY_CLICKTHROUGH_AUDIT.md).

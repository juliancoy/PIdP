# Account authorization in both PIdP backends

The Python server (`mcp_authorization.py`) and Worker
(`serverless/src/mcpAuthorization.ts`) implement the same account authorization
contract. Configured resources use the deployed portal login and show the signed-in account,
client, resource and requested permissions before consent. Neither a client ID nor
OAuth consent grants organization membership or event-management permissions.

Both backends expose authorization-server discovery, authorization, token,
introspection, revocation and account connections endpoints documented in
`serverless/MCP_AUTHORIZATION.md`. Both use ES256 access tokens lasting five
minutes, rotating refresh tokens with a 30-day absolute grant lifetime, two-minute
one-use codes, PKCE S256, resource binding, and session-bound consent. Replayed
refresh tokens revoke the grant. Disable accounts or revoke connections to deny
refresh and introspection immediately. OrgPortal must enable introspection.

The Python server keeps its existing `pidp_token` session cookie; the Worker keeps
`pidp_session`. Sessions are not interchangeable across deployments. Identity
namespaces are `owner:<id>` and `website:<website-id>:<id>` in both implementations.
OrgPortal's explicit subject mapping must point to the same existing account; do
not map by email or silently assign administrator privileges.

The portal handoff creates a separate `__Host-pidp_mcp_session` cookie on the
issuer in both runtimes. It does not copy, replace, or broaden the portal session.

## Portal browser login

Configure `MCP_OAUTH_PORTALS_JSON` with operator-controlled mappings from each
MCP resource to its deployed portal confirmation page:

```json
{
  "https://medtech.social/api/org/mcp": {
    "name": "MedTech",
    "loginUrl": "https://medtech.social/users/mcp-connect"
  }
}
```

The URL must be HTTPS, without credentials, query or fragment, and end in
`/users/mcp-connect` (a `/p/` mount is supported). Dynamic clients cannot set
these mappings. Apply Worker migration `0008_mcp_login_handoff.sql`, or run the
Python OAuth migration helper, before enabling the mapping. Release OrgPortal's
confirmation route through CodeCollective before enabling the PIdP mapping.

1. PIdP validates the client's authorization request and stores a ten-minute
   login handoff, binding it to a random, host-only HttpOnly browser cookie.
2. The browser visits the configured portal route. Its existing authenticated
   route guard uses the normal social/password login and preserves the return path.
3. The portal displays the authenticated account and requires an explicit
   continuation. Its same-origin `/pidp/oauth/mcp/handoff` POST uses the existing
   HttpOnly portal session. PIdP checks the configured portal Origin and active
   account; neither bearer tokens nor a client-supplied identity are accepted.
4. PIdP returns a one-use code, valid for at most two minutes. Only the original
   issuer browser can redeem it at `/oauth/mcp/resume`. The stored namespaced
   subject becomes a ten-minute, resource-bound MCP browser session, not a normal
   portal session or API access token. Owner and website-user subjects are retained
   exactly as authenticated by the portal; no email-based remapping takes place.
5. PIdP resumes the original authorization request and requires separate consent
   before issuing the client's PKCE-bound authorization code. Existing membership,
   scope, introspection and preview/apply requirements remain unchanged.

Login records and codes are hashed and atomically claimed. Login creation is
bounded to 20 pending records per browser, 30 starts per IP per hour, 1,000 starts
globally per hour, and 10,000 pending records globally. Expired records are pruned.
The Python service must receive a trusted ASGI peer address for its IP limit.
The portal proxy must preserve the browser Origin and forward the portal cookie;
do not replace either with a service credential or broadly enable credentialed CORS.

`prompt=login` returns to the portal confirmation page even when an MCP browser
session exists. The page offers account switching through the existing logout
flow. Expired or consumed links require a fresh login from the MCP client.
`/oauth/mcp/connections` uses the same bridge when a session is absent; operators
with multiple portal mappings must select a resource using its `resource` query.
Resources without a mapping retain the existing PIdP login path for compatibility.

## Automatic MCP client registration

For compatibility with clients that omit the OAuth `resource` parameter, both
runtimes infer it only when the client has exactly one permitted resource. This
applies to authorization and authorization-code exchange; explicit mismatches
and ambiguous missing resources are rejected. Token audiences remain bound to
the authorized resource.

With `MCP_OAUTH_DYNAMIC_REGISTRATION=true` and migration
`0007_mcp_client_registration.sql` applied, discovery advertises
`/oauth/mcp/register` for OAuth Dynamic Client Registration. Python uses the same
flag and creates the additional tables with `scripts/migrate_mcp_oauth.py`.
This supports standards-compliant desktop and hosted MCP clients without
overwriting the existing confidential client registrations.

Clients may register `none`, `client_secret_basic`, or `client_secret_post`.
Callbacks must be exact HTTPS URLs, or literal loopback HTTP URLs for public
clients. Only loopback ports may vary. Registration does not issue account access:
every connection still requires browser login, explicit consent, S256 PKCE,
resource binding and OrgPortal's account/organization permissions. No client
metadata URLs or logos are fetched. Self-reported client names and the callback
are identified on the consent screen. Confidential secrets are returned only at
registration and stored hashed.

Registration is limited to 10 requests per client IP per hour and 100 globally
per hour, with a maximum of 10,000 registrations. IPs are hashed; old rate-limit
rows are pruned. Python uses the trusted ASGI peer address (configure the proxy
trust boundary correctly); Cloudflare uses `CF-Connecting-IP`. Disabling the flag
also disables dynamically registered clients. Operators can revoke an individual
registration with its `revoked` field; existing account connections remain
user-revocable through the connections page.

For Codex:

```sh
codex mcp add medtech --url https://medtech.social/api/org/mcp
codex mcp login medtech --scopes org:events.read,org:events.write,org:portal.read,org:portal.write
```

For ChatGPT and other MCP clients, add the same server URL and choose OAuth.
Clients supporting Dynamic Client Registration can register their own callback.
Clients that require manual registration can continue using the configured client
list. Compatibility is protocol-based; only Codex is being connected in this
release, not every client product.

## Manual Native Uploader Registration

Merge this client into `MCP_OAUTH_CLIENTS_JSON` in the active PIdP deployment,
preserving existing clients. Client registration is operator-managed; the client
ID is public and no secret is distributed with the uploader.

```json
{
  "orgportal-local-upload": {
    "name": "OrgPortal local image upload",
    "tokenEndpointAuthMethod": "none",
    "redirectUris": ["http://127.0.0.1/callback"],
    "resources": ["https://medtech.social/api/org/mcp"],
    "scopes": ["org:events.read", "org:events.write"]
  }
}
```

Public clients must use literal loopback IP callbacks. Matching permits only the
port to vary; the requested callback including port is bound to the issued code.
No wildcard hosts, localhost DNS, callback query strings, fragments or embedded
credentials are allowed. Existing confidential clients keep HTTPS callbacks and
their current client-secret authentication. All clients require PKCE.

The shared `tests/oauth_redirect_cases.json` is executed by both test suites.
The native-app design follows https://www.rfc-editor.org/rfc/rfc8252.

## Configuration and release

Both implementations use `MCP_OAUTH_ISSUER`, `MCP_OAUTH_PRIVATE_JWK`,
`MCP_OAUTH_PUBLIC_JWKS`, `MCP_OAUTH_CLIENTS_JSON` and `MCP_OAUTH_RESOURCES_JSON`.
Use the existing secret manager. Never put signing keys or client/resource secrets
in source, command arguments, or chat. Preserve the currently deployed issuer,
signing keys and registrations when adding a client.

For Python, run `python scripts/migrate_mcp_oauth.py` against the intended database
as an explicit release step. It creates only the OAuth tables and indexes;
`AUTO_CREATE_TABLES` need not be enabled. The Worker uses D1 migrations 0006-0008.
The schemas share names and semantics but use their own backend databases.
Do not load balance OAuth traffic across independent grant databases, or switch
backends without migrating grants and preserving keys. Otherwise reconnect users.

Python's JWKS endpoint publishes OAuth ES256 public keys alongside its existing
session-verification keys. No private key material is returned.

Release PIdP through its own deployment path, then release OrgPortal through
CodeCollective. MedTech deployment must not deploy either backend. Before enabling
uploads, verify discovery advertises `none`, register the client and resource,
configure OrgPortal subject mappings/introspection, and test browser consent,
permission denial, one approved gallery upload, and account revocation.

## Tests

The login handoff is covered by both OAuth suites, a real-PostgreSQL atomic-claim
test, and OrgPortal's `web/tests/e2e/mcp-login.spec.ts` on desktop and mobile.
Browser tests mock authentication and provider responses; a real user's final
social sign-in and consent remain a separate production acceptance step.

PIdP also has a Chromium consent-form regression, including a real loopback
callback and revocation POST. Run from `serverless/`:

```sh
npx playwright install chromium
npm run test:browser
```

Consent pages use `Referrer-Policy: same-origin`, not `no-referrer`: Chromium
otherwise sends `Origin: null` on form POSTs and the CSRF check rejects them.
The consent CSP permits only self and the validated callback origin for
`form-action`, because Chromium also checks the post-consent redirect against
that directive. Callback URI validation, same-origin POST checks, and one-use
session-bound consent receipts remain required. Cross-site referrers are omitted.

Consent presentation is shared in `shared/mcp-consent.json`, rendered by
`consent_page.py` and `serverless/src/consentPage.ts`. The trusted MedTech host
uses the existing Baltimore MedTech logo and branding; other portals retain
their configured name. Inline CSS is authorized by its SHA-256 CSP hash, with
no inline scripts or unsafe-inline exception. The browser test checks desktop
and mobile layout, logo loading, and continued form/callback operation.

### Production release: 2026-09-17

- CodeCollective frontend: `3525612c-f95f-4230-a75a-87824e2868ee`.
- PIdP Worker: `a6882337-f566-472c-8df6-08abc270713b` (includes MedTech consent
  branding and the browser Origin/callback-CSP corrections).
- D1 migration 0008 applied; MedTech's mapping above enabled with existing
  variables and signing/client secrets preserved.
- Live MedTech login renders its branding, Google and GitHub options, and the
  MCP return route at desktop and mobile sizes. User consent is not automated.
- Codex completed the real browser authorization and reported a successful
  login to `medtech`. This verifies OAuth login, not event-management permissions
  or gallery uploads; OrgPortal's subject mapping and permissions still apply.
- The Python implementation is tested, not deployed by this Worker release.

Use Python 3.11+ with the project's requirements installed:

```sh
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -p 'test_mcp_authorization.py' -v
python -m unittest discover -s tests -p 'test_smoke.py' -v
cd serverless
node --import tsx --test test/mcp-authorization.test.mjs
npx tsc --noEmit
```

Local authorization tests exercise real SQLite code/grant SQL and signed JWTs.
Python identity-session checks are tested separately from the OAuth state machine.
`tests/test_mcp_postgres.py` additionally tests schema creation, concurrent code
redemption and refresh replay on PostgreSQL. Set `PIDP_OAUTH_TEST_DATABASE_URL`
to an isolated loopback database named `oauth_test` and run that test explicitly;
it creates and removes its own schema. It skips when the variable is absent.
Production acceptance must still exercise real account login on the Python
deployment and the Worker deployment.

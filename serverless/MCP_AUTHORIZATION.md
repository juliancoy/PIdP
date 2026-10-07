# PIdP authorization for OrgPortal MCP

PIdP now contains an OAuth authorization server for event MCP clients, alongside
its existing Google/GitHub and password login. Existing HS256 portal sessions and
PAT permissions are unchanged. New MCP access tokens are ES256 JWTs, with a
separate private key, issuer, exact resource audience, subject, event, and portal scopes.
This is OAuth authorization-server discovery, not a general OpenID Connect server;
there is no ID token or `openid` scope.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/.well-known/oauth-authorization-server` | Authorization metadata |
| `/.well-known/jwks.json` | Public ES256 keys only |
| `/oauth/mcp/authorize` | GET login/consent, POST allow/deny |
| `/oauth/mcp/token` | Authorization-code and rotating refresh-token grants |
| `/oauth/mcp/introspect` | Authenticated resource-server check for active grants/accounts |
| `/oauth/mcp/handoff` | Portal-session confirmation of a browser-bound login request |
| `/oauth/mcp/resume` | One-use return to issuer-side consent in the original browser |
| `/oauth/mcp/revoke` | Authenticated client revokes its refresh token's entire grant |
| `/oauth/mcp/connections` | Signed-in user lists/revokes their own connections |

Pre-registered confidential and native public clients are supported. Optional
Dynamic Client Registration is described in [account authorization](../docs/account-oauth.md#automatic-mcp-client-registration).
Configure deployed portal login with `MCP_OAUTH_PORTALS_JSON` and migration 0008;
see [portal browser login](../docs/account-oauth.md#portal-browser-login).
For manually registered confidential clients, configure the client ID
and secret manually in the ChatGPT connection. Client-metadata URL fetching is
not supported. Copy the exact callback URL from the
connection setup; never use wildcard redirects. Authorization requires PKCE S256,
resource binding, read scope, and a normal PIdP browser session. Clients with
exactly one permitted resource may omit `resource` at authorization and code
exchange; both runtimes infer that sole resource. Multiple-resource clients must
specify it explicitly, and explicit mismatches are always rejected.
Neither PATs nor a client secret can substitute for the user's consent.

Native public clients use `tokenEndpointAuthMethod: "none"`, no client secret,
and a literal loopback callback with PKCE S256. See
[account authorization and backend parity](../docs/account-oauth.md) for the
registration, Python-server implementation, and shared redirect tests.

Consent is escaped HTML with no third-party scripts, frame embedding, or referrer
leakage. Pending requests last ten minutes, bind to the exact login session and
subject, and are consumed atomically. Codes last two minutes and are atomically
bound to client, callback, resource and verifier. Tokens/consent nonces are hashed
in D1. Access tokens last five minutes. Refresh tokens rotate on every exchange,
have an absolute thirty-day grant lifetime, and replay revokes the whole grant.
Refresh requests cannot increase scope or change resource; reconnect for new scopes.
Serialize refresh requests: concurrent use or an ambiguous retry can revoke the
connection, requiring a new login/consent flow.

OrgPortal must enable introspection as described below for immediate revocation.
Resource servers that only verify JWT signatures retain access until token expiry.
Disabling a user or removing a client's configured resource/scope also makes
introspection and refresh fail. Introspection never accepts a client credential
in place of the separate resource credential, and does not expose other resources.
The revocation endpoint accepts refresh tokens; the account connections page also
revokes grants. No access-token revocation hint is advertised.

## Deployment handoff (not performed by the implementation)

1. Review and back up D1. Apply `0006_mcp_authorization.sql` with the other migrations.
2. Provision a new ES256 key using `node scripts/generate-mcp-key.mjs /secure/path/mcp-private.key`.
   Upload its contents as the `MCP_OAUTH_PRIVATE_JWK` Worker secret; keep the file in
   your secret manager and out of repositories. Do not reuse `SECRET_KEY`.
3. Set `MCP_OAUTH_ISSUER=https://id.codecollective.us` (HTTPS origin, no trailing slash).
4. Generate two independent high-entropy secrets of at least 32 characters: one for the ChatGPT client, one
   for OrgPortal introspection. Store each SHA-256 lowercase hex digest in PIdP's
   settings below; retain the original secrets only in their respective clients.
5. Configure `MCP_OAUTH_CLIENTS_JSON` and `MCP_OAUTH_RESOURCES_JSON` as secrets with
   the following shapes, replacing all placeholders. These are examples, not
   deployable credentials:

```json
{
  "chatgpt-orgportal": {
    "name": "ChatGPT · OrgPortal",
    "secretHash": "SHA256_OF_CHATGPT_CLIENT_SECRET",
    "redirectUris": ["EXACT_HTTPS_CALLBACK_FROM_CHATGPT"],
    "resources": ["https://medtech.social/api/org/mcp"],
    "scopes": ["org:events.read", "org:events.write", "org:portal.read", "org:portal.write"]
  }
}
```

```json
{
  "https://medtech.social/api/org/mcp": {
    "secretHash": "SHA256_OF_ORGPORTAL_INTROSPECTION_SECRET"
  }
}
```

6. In OrgPortal configure:

| Setting | Value |
| --- | --- |
| `MCP_PUBLIC_URL` | `https://medtech.social/api/org/mcp` |
| `MCP_OAUTH_ISSUER` | `https://id.codecollective.us` |
| `MCP_OAUTH_JWKS_URL` | `https://id.codecollective.us/.well-known/jwks.json` |
| `MCP_OAUTH_INTROSPECTION_URL` | `https://id.codecollective.us/oauth/mcp/introspect` |
| `MCP_OAUTH_INTROSPECTION_SECRET` | Original resource secret whose hash is stored in PIdP |
| `MCP_SUBJECT_MAP_JSON` | Explicit subject-to-existing-PIdP-ID map described below |

PIdP subjects are `owner:<user-id>` or `website:<website-id>:<website-user-id>` to
avoid conflating separate identity namespaces. Use the correct existing OrgPortal
identity: for example `{"owner:ACTUAL_ID":"ACTUAL_ID"}`. Never map a name or email
by guesswork. OrgPortal still checks organization management permissions and
event and portal scopes; PIdP consent grants no organization administration privileges.
Complete the existing `EVENT_INTEGRATIONS_JSON`, `EVENT_KEY_*`, approved branding,
and event audit migrations separately. This OAuth change creates no events.

7. Deploy PIdP and OrgPortal only when authorized. Both public discovery paths must
   reach their respective Workers, including OrgPortal's root-level protected-resource
   metadata route. Use one canonical MCP URL for this Worker configuration even if
   the API is reachable through several website aliases.
8. Configure the ChatGPT connection with that MCP URL, the registered client ID,
   and its original secret. Sign into the existing PIdP account and review consent.
   PIdP's existing Google/GitHub or password login remains the sign-in mechanism.

## Operations and acceptance

Run `npm ci --ignore-scripts`, `npm run typecheck`, and `npm test` using Node 24.
The authorization tests use real SQLite statements and generated test keys;
they exercise consent, PKCE, signature verification, refresh rotation/replay,
revocation, account deactivation, callback validation and authorization boundaries.
CI runs these checks without credentials or deployment.

Before opening access, configure edge rate limits for `/oauth/mcp/*` and existing
login endpoints. The application limits pending consent requests per session but
does not replace edge-level unauthenticated abuse controls. Do not log cookies,
authorization headers, form bodies, codes or tokens. Back up the grant tables
consistently. Periodically delete expired pending requests/codes, then refresh
rows belonging to expired grants, then expired grants. Keep used refresh hashes
until grant expiry so reuse remains detectable; choose any additional audit
retention in your operational policy. Access tokens have no sensitive profile fields.

For key rotation, add the outgoing key's public fields to `MCP_OAUTH_PUBLIC_JWKS`
(`{"keys":[...]}`), generate a new private key with a new `kid`, and keep old public
keys at least beyond access-token lifetime plus cache/clock margin. Never store
private `d` values in the public JWKS setting. Removing all issuer configuration
disables MCP authorization but leaves ordinary portal login in place.

Live acceptance still requires OAuth linking in ChatGPT, read-only access, denied
write attempts without write scope, one approved test-calendar write, user revocation
followed by a rejected MCP call, and verification that existing portal login works.
This implementation has not performed deployment, live linking or event mutation.

### Adding a separate portal resource

`MCP_OAUTH_RESOURCE_ADDITIONS_JSON` adds resource credentials and their browser
login handoffs without replacing the existing resource or portal maps. Each
entry is keyed by an exact HTTPS resource URL and contains `secretHash` (the
SHA-256 hash of that resource's introspection credential) and
`portal: {name, loginUrl}`. Duplicate existing resource URLs are rejected.
Python uses the equivalent `mcp_oauth_resource_additions_json` setting.

LifeTech uses `https://lifetech.fyi/api/org/mcp` and
`https://lifetech.fyi/users/mcp-connect`; MedTech remains
`https://medtech.social/api/org/mcp`. Grants, codes, refresh tokens, bridge
sessions and introspection remain bound to the exact resource. Dynamic clients
use the issuer's current resource list, including newly configured resources;
each resource still requires its own consent and audience-bound grant.

### OrgPortal platform resource

`MCP_OAUTH_RESOURCE_CONFIG_JSON` supplies additional resource credentials and
portal handoffs with the same shape as `MCP_OAUTH_RESOURCE_ADDITIONS_JSON`.
Duplicate resource URLs across these configurations or existing resources are
rejected. Python uses `mcp_oauth_resource_config_json` with the same contract.
The deployed OrgPortal resource is `https://orgportal.cc/api/org/mcp`, with login
at `https://orgportal.cc/users/mcp-connect`. Its credential hash is recorded in
`config/mcp-resources.json` and the Worker deployment variable; the corresponding
raw introspection credential exists only as an OrgPortal Worker secret.

### Separate Chrome profiles

Portal-backed authorization starts at an issuer-hosted browser handoff page.
Keep that page in the browser where ChatGPT opened it. Copy its sign-in link
into the other Chrome profile, sign in there if required, and enter the matching
eight-character code shown only in the original browser. Confirm the account
in the second browser, then return to the original browser, check the displayed
account and continue to the usual OAuth permission review. A same-browser
sign-in option is also available.

This is an internal identity bridge inspired by RFC 8628's separate-device
interaction, not a new OAuth grant type advertised to MCP clients. The normal
authorization-code flow, PKCE, resource audience, state, and registered callback
remain unchanged. No MCP authorization codes or access tokens pass through the second browser.

The bridge uses the existing login table: a hashed 320-bit request identifier,
a separate random 32-bit matching code, an HttpOnly initiating-browser cookie,
a ten-minute deadline and atomic one-use claims. Confirmation requires the
portal's authenticated account and exact origin. Pairing attempts are rate
limited. Status and completion require the original browser; completion checks
the account is still active. Cancellation deletes the pending bridge. Both
browsers explicitly confirm their part; account confirmation grants no MCP
permissions or organization role. Referrer-Policy same-origin keeps same-origin
form Origin checks working and prevents cross-origin capability URL leakage.

No schema migration is needed. Python and Worker implementations share the
contract. Security tests cover two isolated sessions, wrong code, wrong browser,
CSRF, replay and account-bound token issuance. The headless browser fixture uses an in-memory database and local HTTPS
servers with two isolated Chrome contexts in the local Docker Selenium service.
Set `WEBDRIVER_URL`, `BROWSER_TEST_HOST` (the container-reachable host), and
`BRIDGE_TEST_CERT_DIR` containing a disposable `test-key.pem` and
`test-cert.pem`; run `node --import tsx browser/cross-browser.mjs`. No real
accounts or production login endpoints are used.

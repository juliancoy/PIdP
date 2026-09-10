# PIdP authorization for OrgPortal MCP

PIdP now contains an OAuth authorization server for event MCP clients, alongside
its existing Google/GitHub and password login. Existing HS256 portal sessions and
PAT permissions are unchanged. New MCP access tokens are ES256 JWTs, with a
separate private key, issuer, exact resource audience, subject and event scopes.
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
| `/oauth/mcp/revoke` | Authenticated client revokes its refresh token's entire grant |
| `/oauth/mcp/connections` | Signed-in user lists/revokes their own connections |

Only pre-registered confidential clients are supported. Configure the client ID
and secret manually in the ChatGPT connection. There is no public dynamic client
registration or client-metadata URL fetching. Copy the exact callback URL from the
connection setup; never use wildcard redirects. Authorization requires PKCE S256,
the explicit `resource` parameter, read scope, and a normal PIdP browser session.
Neither PATs nor a client secret can substitute for the user's consent.

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
    "name": "ChatGPT · OrgPortal events",
    "secretHash": "SHA256_OF_CHATGPT_CLIENT_SECRET",
    "redirectUris": ["EXACT_HTTPS_CALLBACK_FROM_CHATGPT"],
    "resources": ["https://medtech.social/api/org/mcp"],
    "scopes": ["org:events.read", "org:events.write"]
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
event scopes; PIdP consent grants no organization administration privileges.
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

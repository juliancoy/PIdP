# OrgPortal identity mount

The browser-facing PIdP base is `https://orgportal.cc/pidp`. The existing
`pidp-codecollective` Worker, database, session signing key and account subjects
remain in use. OrgPortal forwards identity requests through its `PIDP` service
binding, strips the mount, removes untrusted forwarding headers, and preserves
the canonical origin for central SSO authorization. Tenant requests retain their
validated tenant origin and receive host-only cookies after a browser-bound handoff.

Set `APP_NAME=OrgPortal`, `PUBLIC_BASE_URL=https://orgportal.cc/pidp`,
`PORTAL_SSO_APP_SLUG=orgportal` and `FRONTEND_REDIRECT_URL=https://orgportal.cc/communities`.
Register the Google and GitHub callback URLs under
`https://orgportal.cc/pidp/auth/{provider}/callback` in their respective provider
settings before switching the live redirect bindings. Identity login and MCP
authorization no longer use the CodeCollective hostname. The MCP resource is `https://orgportal.cc/mcp`, with issuer
`https://orgportal.cc`. OAuth endpoints are under `/oauth/mcp/*` on that same
origin; issuer discovery and JWKS are at the root `/.well-known/*` paths.
The old platform `/api/org/mcp` URL is retired. Reconnect MCP clients using the
new resource; do not preserve an old token audience as an alias.
Set `MCP_OAUTH_ISSUER=https://orgportal.cc` on PIdP and the OrgPortal API,
`MCP_PUBLIC_URL=https://orgportal.cc/mcp`,
`MCP_OAUTH_JWKS_URL=https://orgportal.cc/.well-known/jwks.json` and
`MCP_OAUTH_INTROSPECTION_URL=https://orgportal.cc/oauth/mcp/introspect` on the API.
Keep the existing signing key, resource introspection credentials and database.

This cutover keeps `PORTAL_SHARED_IDENTITY=false`. Every community uses the
existing registered `orgportal` login application. Existing primary accounts,
member accounts, explicit account links, permissions and credentials are retained;
this routing release does not merge accounts or execute credential migrations.
The separately drafted shared-primary-account migration is not required here.

Release PIdP first with migrations disabled and all live secrets/bindings inherited.
Then release OrgPortal's frontend using `scripts/release.mjs`. No database schema
change is needed. `/auth/session` is read-only and returns only an authentication
boolean; the frontend Worker uses it to protect research pages before serving HTML.
Production verification is unauthenticated and read-only. Authenticated browser
checks must use the isolated local Docker deployment.

## MCP browser flow

Authorization uses this browser’s login by default and goes directly to portal SSO,
then the account and permissions consent page. The cross-browser pairing screen
is omitted from this normal path. Choose **Use another browser** on consent to
start an explicit paired handoff; clients may also request `browser=other` on
the authorization URL. Pairing still requires the matching code and the original
browser cookie. Consent remains explicit and permissions remain resource-bound.

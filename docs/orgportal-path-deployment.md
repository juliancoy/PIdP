# OrgPortal identity mount

The browser-facing PIdP base is `https://orgportal.cc/pidp`. The existing
`pidp-codecollective` Worker, database, session signing key and account subjects
remain in use. OrgPortal forwards identity requests through its `PIDP` service
binding, strips the mount, removes untrusted forwarding headers, and preserves
the canonical origin for central SSO authorization. Tenant requests retain their
validated tenant origin and receive host-only cookies after a browser-bound handoff.

Set `APP_NAME=OrgPortal`, `PUBLIC_BASE_URL=https://orgportal.cc/pidp`,
`PORTAL_SSO_APP_SLUG=orgportal` and `FRONTEND_REDIRECT_URL=https://orgportal.cc/communities`.
Keep the existing registered Google/GitHub callback URLs until provider settings
are separately updated. Both legacy identity hostnames redirect interactive login
entry points to the canonical mount. Existing MCP issuers and endpoints remain
unchanged for compatibility; the browser base is separate from the OAuth issuer.

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

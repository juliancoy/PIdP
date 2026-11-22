# Alternate portal domains

`shared/portal-clients.json` is the canonical, hand-edited registry for all
alternate portal origins. Both Python and serverless identity policy read it.
Each exact HTTPS origin declares its display name, account application, permitted
callback paths, optional restart origin, and explicit deployment policy:

- `deployment.orgPortalSite`: include its hostname in OrgPortal's site routing.
- `deployment.websiteLogin`: register it on the existing PIdP website application.

Aliases are separate exact origins; they do not automatically share browser
cookies or tenant memberships. `restartOrigin` retains the existing Code
Collective sign-in handoff. Deism's existing website-login exclusion is preserved;
its SSO client and OrgPortal routing remain registered.

After editing the registry, run from PIdP:

```sh
node scripts/sync-portal-domains.mjs --write
node scripts/sync-portal-domains.mjs --check
node scripts/sync-portal-domains.mjs --json
```

The sync command updates the generated `PORTAL_AUTH_ORIGINS` in this repository
and `ORGPORTAL_SITE_HOSTS` in sibling `../OrgPortal/cloudflare/wrangler.jsonc`.
It preserves unrelated config and never deploys. PIdP's metadata/build gate checks
for drift; a standalone checkout skips the optional sibling OrgPortal config.
`--json` emits the exact runtime registry binding and website login configuration
for an authorized configuration-only setup. `PORTAL_CLIENTS_JSON` is useful when
registering a domain on existing deployed code; ordinary releases read the same
registry directly. Do not hand-edit the generated allowlists.

Remote configuration remains a separate operation: preserve existing bindings,
credentials and website entries; verify current permissions; attach only the
requested organization/domain through OrgPortal's API. Tenant ownership, DNS,
branding and domain verification remain in their owning services. Adding a JSON
entry does not grant membership or authorize deploying either application.

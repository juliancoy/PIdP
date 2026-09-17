# Repository Boundaries

Follow `README.md#account-boundaries` and `docs/account-oauth.md`.

- PIdP owns credentials, social sign-in/callbacks, identity verification/recovery,
  sessions, stable identity subjects, core profiles/avatars, linked providers,
  and reusable account-security UI.
- PIdP owns OAuth client registration, consent, PKCE, token issuance/refresh,
  resource/scope binding, and grant revocation. Do not implement OrgPortal domain
  permissions or treat consent as membership or administrator access.
- OrgPortal lives in `../OrgPortal`, not a submodule. Organization membership,
  roles, member profiles, governance, chat, calendar/event workflows, and event
  galleries belong there. Retain existing provider interfaces and ownership;
  do not duplicate integration adapters during account-UI work.
- Preserve tenant account namespaces and validated portal return context.
  Never substitute owner login for website-user login, map privileged accounts
  by email, assume cross-origin cookies are shared, or accept arbitrary redirects.
- Portal branding and sign-in entry points may remain in OrgPortal; reusable
  authentication/security implementation belongs here. Document unfinished
  integration explicitly rather than describing planned behavior as deployed.
- Keep Python and serverless behavior equivalent and cover shared security
  contracts with tests in both runtimes. Storage/session mechanics may differ.
  Do not serve one issuer from independent grant databases.
- Release PIdP separately. Shared portal releases go through CodeCollective;
  MedTech releases must not deploy PIdP or OrgPortal. Never expose credentials,
  signing keys, session tokens, or OAuth secrets in logs or documentation.

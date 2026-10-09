# Account chooser and linking audit

PIdP supplies the authentication interface; LifeTech, OrgPortal, and MedTech
supply their registered product names and exact return origins. Credential
namespace names are not product labels. The secondary sign-in resolves its
branding through the same unexpired SSO ticket as the initial sign-in.

## Sign-in experience

`prompt=select_account` on `/auth/sso/start` presents the current active account
and an option to authenticate another portal account before issuing a handoff.
`prompt=login` requires a fresh sign-in rather than reusing the issuer session.
Unsupported prompt values are rejected. Both prompts preserve the browser-bound
request and validated portal return. Google authorization explicitly sends
`prompt=select_account`, following [Google's OpenID Connect documentation](https://developers.google.com/identity/openid-connect/openid-connect).

An unlinked primary identity sees the destination product and hostname, its
current email, separate portal sign-in, primary-account switching, and cancel.
Link confirmation offers switching either account. Changing the primary account
discards the old proof; changing the portal account discards the reviewed subject.
Both require a new confirmation. A conflicting link displays recovery choices
without disclosing another identity or transferring an existing link.

This is account-chooser and return-flow parity, not a claim of Google certification
or a complete reimplementation of Google Identity Services. PIdP currently keeps
one active issuer session per browser, rather than Google's remembered list of
multiple accounts. The existing production issuer remains `id.codecollective.us`;
its address is an infrastructure hostname, not the product destination. An issuer
hostname migration must coordinate its custom domain, provider callbacks, OAuth
client configuration, cookie behavior, and existing grants.

## Isolated container

Run from the PIdP checkout:

```sh
serverless/identity-lab/start.sh
node --test serverless/identity-lab/clickthrough.mjs
```

The dedicated `pidp-identity-lab` container executes the actual Worker handlers
with disposable SQLite fixtures. It uses an internal Docker network, read-only
source mounts, ephemeral storage, and test-only signing material. It has no
production database, provider secrets, or outbound access. Its companion
`pidp-identity-lab-gateway` publishes HTTPS only on loopback port 8891. Local
certificates live in ignored `.local/identity-lab/`. Restarting the lab resets
all fixture accounts, sessions, and links.

The browser blocks every request outside the four local hostnames. The fixture
serves portal landing/callback pages; it does not run the full OrgPortal UI.
Authenticated production browser testing remains outside this automated suite.

Test accounts use `Local-test-password-42` and `@example.test` addresses: `owner`,
`other`, `member`, and `alternate`. The issuer is
`https://pidp.localhost:8891`; product fixtures use `lifetech.localhost`,
`orgportal.localhost`, and `medtech.localhost` on the same port. Local browsers
must resolve those names to 127.0.0.1 and accept the disposable certificate.

## Audit coverage

| Scenario | Verification |
| --- | --- |
| Primary account without member link | Real browser recovery, product and destination labels |
| Wrong password | Real browser retry without losing LifeTech branding |
| Switch primary account during recovery | Real browser fresh owner authentication |
| Switch portal account during confirmation | Real browser fresh member authentication and renewed confirmation |
| Switch primary account after reviewing | Old browser proof discarded; both accounts authenticated again |
| Link conflict | Real browser recovery through another portal account |
| Explicit confirmation | No link or handoff before confirmation; final LifeTech return |
| Cancel | Return to the originating portal without linking |
| LifeTech / OrgPortal / MedTech | Account chooser and host-bound handoff at 390 and 1280 pixels |
| Bad destination / expired request / wrong handoff | Browser HTTP checks deny with 400 |
| CSRF / duplicate parameters / changed proofs | Server rejection and proof invalidation regression tests |
| Cross-origin or wrong-browser completion / replay | Existing Worker and Python SSO regression tests |
| Provider account chooser | Google authorization URL assertion; provider UI is not automated |

The audit caught two browser-only defects: `no-referrer` suppressed the form
Origin header, and confirmation's form-action policy blocked the cross-origin
handoff. Linking pages now send referrers only within the issuer and permit form
redirects only to registered portal origins. The CSRF check remains strict.

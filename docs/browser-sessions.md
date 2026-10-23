# Remembered browser login

Database migration `serverless/migrations/0013_browser_sessions.sql` was explicitly
reviewed for the 2026-10-23 release: it adds a constrained session table, expiry
index, and nullable original-authentication timestamp on SSO requests. It does
not rewrite account or credential data. Apply it before deploying this code. PostgreSQL local development uses the matching
`BrowserSession` SQLAlchemy model.

The user's policy is 30 days of inactivity, with a 90-day absolute limit measured
from password/provider sign-in. A session-token request renews the inactivity
window but never moves the absolute limit. Background timers are suspended by
mobile browsers; restoration uses the cookie instead of requiring a still-valid
in-memory access token.

- Cookie: host-only, `HttpOnly`, `Secure`, `SameSite=Lax`, 30-day `Max-Age` bounded
  by absolute expiration. It contains a signed session credential, never exposed
  in JavaScript responses or accepted as an API bearer token.
- API token: at most 60 minutes, kept in browser memory. Its session reference
  is checked server-side. Browser access tokens are not saved in localStorage.
- Logout deletes the server record and clears the cookie. Captured session and
  linked access tokens fail validation after revocation. Each tenant handoff
  gets its own record; tenant logout does not revoke another tenant's session.
- API credential management requires sign-in within the previous 15 minutes.
  Ordinary session renewal does not reset that authentication time.
- Account activity and live account/tenant authorization remain checked by the
  existing owner/member authorization functions. An offline or 5xx response is
  not an authoritative logout; the UI retries restoration on focus/online.
  An explicit offline sign-out is recorded as a noncredential local flag; it
  suppresses session restoration and retries server revocation after reconnect.
  Starting an explicit new sign-in clears that intent.
- Native token/deep-link storage remains separate. These changes and the Pixel
  tests cover Chrome/web login, not secure native credential storage.

## Session data lifecycle

The `browser_sessions` store contains only a SHA-256 hash of a random identifier,
owner or website-member IDs, tenant account namespace, and creation, idle-expiry,
and absolute-expiry timestamps. No raw credential, email, IP address, device
fingerprint, or user agent is stored. Access is internal authentication code;
there is no public session-directory API.

Expired records are removed by the existing bounded five-minute retention job.
Explicit logout deletes the record immediately. Foreign keys cascade records on
owner, member, or website deletion. Never enroll local test fixtures into public
replication. Session records and credentials must not enter logs, exports, or
public snapshots. Backups follow the existing operated service retention policy;
restoring an old authentication database can restore deleted session records,
so recovery must invalidate remembered sessions before reopening sign-in.

## Verification

`test/browser-sessions.test.mjs` and `tests/test_browser_sessions.py` exercise
renewal, expiry, revocation and account binding with controlled clocks. The
identity lab uses disposable local SQLite and dummy accounts. The full local
portal persistence script verifies real frontend hydration, browser restarts,
service recreation, and logout. `web/scripts/test-android-session-persistence.mjs`
in OrgPortal uses the physical Pixel over an ADB USB tunnel to isolated Docker;
it force-stops and restarts Chrome and restores any preexisting localhost cookies
in cleanup. No production account is used.

Policy rationale: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) recommends server-enforced inactivity/absolute bounds, renewal, and explicit invalidation. The specific 30-day inactivity and 90-day absolute values here are application policy, not universal OWASP timeout recommendations.

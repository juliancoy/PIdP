# Email verification

Password registration sends a verification link before permitting password sign-in.
The login page offers **Resend verification email** for missing or expired links,
including accounts created before verification was enforced. Links are single-use,
expire after 24 hours (configurable in Python), and preserve the validated sign-in
return destination. Resending is limited to once per minute per account and replaces
the previous link. Application accounts and owner accounts stay separate.
Existing social-provider verification follows the issuer's provider trust policy.
Email addresses are not editable through the profile endpoints; adding an email-change
flow must reset verification and verify the new address before using it.

## Delivery

Python uses its existing SMTP / Google Workspace delivery settings. Log mode does
not deliver email and no longer prints credential-bearing links. Configure SMTP
before exposing password registration to real users.

The Worker is configured with a Cloudflare Email Service binding named `EMAIL`,
restricted to `verification@notify.orgportal.cc`, and an `EMAIL_FROM` variable with
that address. Email Sending is enabled on `notify.orgportal.cc`. Cloudflare created
the dedicated return-path MX, SPF, DKIM and DMARC records without changing the
main domain's mail routing. A single self-test reached the account owner's Gmail
inbox on 2026-10-23; Gmail reported SPF, DKIM and DMARC passing.

The binding requires no API token or SMTP credentials. Keep its sender restriction
and `EMAIL_FROM` together when configuring another environment. Missing or failed
delivery returns 503 and never grants a session. Existing failed registrations can
use the resend form after delivery is repaired. Local Python delivery is separate
and still requires its existing SMTP settings.

`EMAIL_VERIFICATION_REQUIRED=false` disables the Worker gate only for isolated
local fixtures, matching Python's existing setting. Production must keep verification
enabled (the default). No database migration or additional token store is required;
only token hashes are stored in the account's existing identity data. Consuming a
link removes the pending challenge; account deletion removes its verification data.

## Production configuration verification (2026-10-23)

The isolated serverless candidate was published using the PIdP deployment helper
with existing variables/secrets retained and no database migrations. Deployed
Worker version: `5e9d9d32-8dea-479e-85b8-46c2e7f2ef64`. Its base commit is
`a852b3feae8c91a15e8b879295d8ff5283617ed8`, with the email changes explicitly
reported as a modified build. Unrelated workspace changes were excluded.

Before publication, 26 focused verification/login/deployment tests (including a
headless local browser flow), TypeScript checks, and a Wrangler dry-run passed.
The delivered self-test verified the sending domain; it did not create or modify a
production user account. Authenticated signup and link consumption were tested
locally with an isolated account database and captured mail.

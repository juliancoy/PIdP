# Physical Android login checks

This exercises real PIdP routes in disposable Docker, using synthetic accounts in
Pixel Chrome. It does not install or exercise the native APK or the OrgPortal SPA.
The fixture callback page replaces the portal's final callback UI. Google OAuth
is a local provider fixture in the desktop suite, not a real Google account test.

Enable USB debugging, authorize the host, and verify `adb devices` first.
From `serverless` run:

```sh
LAB_HOST_SUFFIX=localhost bash identity-lab/start.sh
adb reverse tcp:8891 tcp:8891
adb forward tcp:9223 localabstract:chrome_devtools_remote
node identity-lab/android-login-matrix.mjs
```

The runner opens a test tab in the existing Android Chrome instance. Test origins
use `*.localhost`, routed through USB to loopback-only Docker; no production
account is used. It clears only the fixture cookies and closes its own tab.
Forms submit through the browser form API after filling fields, avoiding Android
keyboard/viewport coordinate issues in CDP input automation.
The local self-signed certificate is temporarily accepted over CDP and certificate
checking is restored in cleanup. Do not browse real sites during the run.

Reports default to `/tmp/pidp-android-login-matrix/results.json`; override with
`ANDROID_LOGIN_REPORT`. `MATRIX_FILTER` selects scenario names by regular expression.
A passing rejection case verifies fail-closed security, not satisfactory recovery UX:
repeated callbacks still show `invalid_browser`, and superseded parallel login
requests show `invalid_handoff`.

Cleanup:

```sh
adb forward --remove tcp:9223
adb reverse --remove tcp:8891
docker rm -f pidp-identity-lab-gateway pidp-identity-lab
docker network rm pidp-identity-lab
```

"""Cross-browser identity handoff; the initiating browser retains OAuth consent."""
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit
from starlette.responses import HTMLResponse, RedirectResponse
from jose import jwt

async def handle(request, db, cfg, oauth):
    path = request.url.path
    if path not in ('/oauth/mcp/browser', '/oauth/mcp/browser/status', '/oauth/mcp/browser/finish', '/oauth/mcp/browser/cancel', '/oauth/mcp/link'):
        return None
    original = path != '/oauth/mcp/link'
    p = await oauth.form(request) if request.method == 'POST' else oauth.parameters(request.query_params.multi_items())
    token = p.get('request', '')
    if not re.fullmatch(r'login_[A-Za-z0-9_-]{43,100}', token):
        raise oauth.OAuthError('invalid_request')
    now = int(time.time())
    rows = await oauth.query(db, 'SELECT * FROM mcp_oauth_logins WHERE id=:id AND expires_at>=:now', id=oauth.digest(token), now=now)
    if not rows or rows[0]['resource'] not in cfg['portals']:
        raise oauth.OAuthError('login_expired')
    row = rows[0]
    portal = cfg['portals'][row['resource']]
    u = urlsplit(portal['loginUrl'])
    origin = u.scheme + '://' + u.netloc
    if original:
        browser = request.cookies.get(oauth.BROWSER_COOKIE, '')
        if str(request.base_url).rstrip('/') != cfg['issuer'] or request.headers.get('x-forwarded-host') or not browser or oauth.digest(browser) != row['browser_hash']:
            raise oauth.OAuthError('invalid_browser', 403)
    elif (request.headers.get('x-forwarded-host') or request.url.netloc) != u.netloc:
        raise oauth.OAuthError('invalid_portal', 403)
    code = row['display'] if not row['subject'] else ''
    esc = oauth.html.escape
    def page(title, body, script=''):
        nonce = secrets.token_urlsafe(32)
        headers = {**oauth.HEADERS, 'Referrer-Policy': 'same-origin', 'Content-Security-Policy': f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}
        return HTMLResponse(f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style nonce="{nonce}">body{{font:16px system-ui;background:#f4f7f8;color:#172b3a}}main{{max-width:560px;margin:6vh auto;padding:28px;background:white;border-radius:16px}}p{{line-height:1.6}}input,button{{font:inherit;padding:12px}}input{{width:95%}}button{{background:#155e59;color:white;border:0;border-radius:8px}}code{{font-size:24px;letter-spacing:3px}}</style><main><h1>{esc(title)}</h1>{body}</main>' + (f'<script nonce="{nonce}">{script}</script>' if script else ''), headers=headers)
    if path == '/oauth/mcp/browser/status' and request.method == 'GET':
        ready = bool(row['subject'] and row['code_hash'])
        return oauth.response(dict(ready=ready, **({'account': row['display']} if ready else {})))
    if path == '/oauth/mcp/browser' and request.method == 'GET':
        other = origin + '/pidp/oauth/mcp/link?' + urlencode({'request': token})
        callback = origin + '/auth/callback?' + urlencode({'next': '/users/mcp-connect?' + urlencode({'request': token})})
        same = origin + '/pidp/auth/sso/start?' + urlencode({'app': oauth.settings.portal_sso_app_slug, 'next': callback})
        script = "const request=" + json.dumps(token) + ";document.getElementById('copy').onclick=async()=>{const input=document.getElementById('link');input.select();try{await navigator.clipboard.writeText(input.value)}catch{}};let busy=false;const timer=setInterval(async()=>{if(busy||document.hidden)return;busy=true;try{const response=await fetch('/oauth/mcp/browser/status?'+new URLSearchParams({request}),{credentials:'same-origin',cache:'no-store'});if(!response.ok){clearInterval(timer);document.getElementById('status').textContent='This request expired or was completed. Start again from ChatGPT.';return}const data=await response.json();if(data.ready){clearInterval(timer);document.getElementById('account').textContent='Continue as '+data.account;document.getElementById('finish').hidden=false;document.getElementById('status').textContent='Account confirmed. Check the account before continuing.'}}catch{}finally{busy=false}},5000);"
        return page('Connect using another Chrome profile', f'<p>Keep this page open in your ChatGPT browser. Open the sign-in link in the Chrome profile where you use {esc(portal["name"])}.</p><label>Sign-in link<input readonly id="link" value="{esc(other)}"></label><button id="copy">Copy sign-in link</button><p>Enter this matching code in the other browser:</p><p><code>{code[:4]}-{code[4:]}</code></p><p>This request expires 10 minutes after it was started. Only connect your own account.</p><p id="status" role="status">Waiting for account confirmation…</p><form method="post" action="/oauth/mcp/browser/finish" hidden id="finish"><input type="hidden" name="request" value="{esc(token)}"><p id="account"></p><button>Continue to permissions</button></form><p><a href="{esc(same)}">Use this browser’s account instead</a></p><form method="post" action="/oauth/mcp/browser/cancel"><input type="hidden" name="request" value="{esc(token)}"><button>Cancel connection</button></form>', script)
    if path == '/oauth/mcp/link':
        if row['code_hash']:
            raise oauth.OAuthError('login_expired')
        actor = await oauth.identity_session(request, db)
        if request.method == 'GET':
            if not actor:
                callback = origin + '/pidp/oauth/mcp/link?' + urlencode({'request': token})
                return RedirectResponse(origin + '/pidp/auth/sso/start?' + urlencode({'app': oauth.settings.portal_sso_app_slug, 'next': callback}), status_code=303, headers=oauth.HEADERS)
            return page('Confirm your account', f'<p>You are signed in to {esc(portal["name"])} as <strong>{esc(actor["display"])}</strong>.</p><p>This will send your account identity to the browser where you started connecting ChatGPT. Access is approved separately in that browser.</p><p>Only continue if you started this connection yourself. Enter the matching code displayed in your ChatGPT browser.</p><form method="post" action="/pidp/oauth/mcp/link"><input type="hidden" name="request" value="{esc(token)}"><label>Matching code<input name="pairing_code" autocomplete="off" required maxlength="9" placeholder="ABCD-1234"></label><button>Confirm this account</button></form>')
        if request.method != 'POST' or request.headers.get('origin') != origin:
            raise oauth.OAuthError('invalid_request', 403)
        await oauth.anonymous_limit(request, db, 'pairing:', 10, 1000)
        if p.get('pairing_code', '').replace('-', '').upper() != code:
            raise oauth.OAuthError('invalid_pairing_code')
        if not actor:
            raise oauth.OAuthError('login_required', 401)
        claimed = await oauth.query(db, 'UPDATE mcp_oauth_logins SET subject=:subject,display=:display,code_hash=:code WHERE id=:id AND code_hash IS NULL AND expires_at>=:now RETURNING id', subject=actor['subject'], display=actor['display'], code=oauth.digest(secrets.token_urlsafe(40)), id=row['id'], now=now)
        if not claimed:
            raise oauth.OAuthError('login_expired')
        return page('Account confirmed', '<p>Return to your original ChatGPT browser to check this account and review permissions. You can close this tab.</p>')
    if path == '/oauth/mcp/browser/cancel' and request.method == 'POST':
        if request.headers.get('origin') != cfg['issuer']:
            raise oauth.OAuthError('invalid_request', 403)
        await oauth.query(db, 'DELETE FROM mcp_oauth_logins WHERE id=:id AND browser_hash=:browser', id=row['id'], browser=row['browser_hash'])
        return page('Connection cancelled', '<p>No access was approved. Start a fresh connection from ChatGPT when you are ready.</p>')
    if path == '/oauth/mcp/browser/finish' and request.method == 'POST':
        if request.headers.get('origin') != cfg['issuer']:
            raise oauth.OAuthError('invalid_request', 403)
        if not row['subject'] or not row['code_hash'] or not await oauth.active_subject(db, row['subject']):
            raise oauth.OAuthError('login_required', 401)
        claimed = await oauth.query(db, 'DELETE FROM mcp_oauth_logins WHERE id=:id AND browser_hash=:browser AND code_hash=:code AND expires_at>=:now RETURNING id', id=row['id'], browser=row['browser_hash'], code=row['code_hash'], now=now)
        if not claimed:
            raise oauth.OAuthError('login_expired')
        session = jwt.encode(dict(sub=row['subject'], iss=cfg['issuer'], aud=cfg['issuer'], iat=now, exp=now+600, jti=secrets.token_urlsafe(20), resource=row['resource'], display=row['display']), cfg['key'], algorithm='ES256', headers={'kid':cfg['key']['kid'], 'typ':'mcp-session+jwt'})
        result = RedirectResponse(row['return_path'], status_code=303, headers=oauth.HEADERS)
        result.set_cookie(oauth.SESSION_COOKIE, session, max_age=600, httponly=True, secure=True, samesite='lax', path='/')
        return result
    raise oauth.OAuthError('invalid_request')

def failure(request, exc, oauth):
    if request.url.path not in ('/oauth/mcp/browser', '/oauth/mcp/link', '/oauth/mcp/browser/finish', '/oauth/mcp/browser/cancel'):
        return None
    messages = {
        'invalid_pairing_code': ('Matching code incorrect', 'Go back and enter the matching code displayed in your original ChatGPT browser.'),
        'invalid_browser': ('Return to your ChatGPT browser', 'Complete this step in the browser where you started connecting ChatGPT.'),
        'login_required': ('Sign in required', 'Go back to the sign-in page and sign in before confirming your account.'),
        'login_expired': ('Connection expired or completed', 'Start a fresh connection from ChatGPT. Each sign-in link can be used once and expires after 10 minutes.'),
        'too_many_requests': ('Too many attempts', 'Please wait before starting another connection.'),
    }
    title, message = messages.get(exc.code, ('Unable to continue', 'Start a fresh connection from ChatGPT.'))
    return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + title + '</title><h1>' + title + '</h1><p>' + message + '</p>', status_code=exc.status, headers=oauth.HEADERS)

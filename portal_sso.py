"""Browser-bound, one-use PIdP session handoff; no session tokens in URLs."""
import re
import hashlib
import secrets
import time
from uuid import UUID
from urllib.parse import parse_qs, urlencode, urlparse
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from html import escape
from browser_pages import identity_document
from sqlalchemy import select, delete, update, text
from sqlalchemy.ext.asyncio import AsyncSession
from config import settings
from db import get_session
from models import PortalSsoRequest, Website, WebsiteUser, User, PortalSsoLimit, AccountIdentityLink
from security import safe_decode_token, create_access_token
from login_hints import google_login_hint
from portal_clients import portal_client, sso_return

router = APIRouter()
BROWSER = '__Host-pidp_sso_browser'

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def origins():
    return [s.strip() for s in settings.portal_auth_origins.split(',') if s.strip()]

def origin(request):
    host = request.headers.get('x-forwarded-host')
    if host and request.headers.get('x-forwarded-proto') == 'https':
        return 'https://' + host
    return f'{request.url.scheme}://{request.url.netloc}'

def issuer(request):
    return (settings.public_base_url or str(request.base_url)).rstrip('/')

def unique_query(request):
    if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params):
        raise HTTPException(400, 'invalid_request')

def redirect(url):
    return RedirectResponse(url, status_code=303, headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})

@router.get('/auth/sso/client')
async def registration(request: Request):
    client = portal_client(origin(request))
    if not client:
        raise HTTPException(400, 'invalid_portal')
    return {**client,'origin':client.get('restartOrigin') or origin(request)}

@router.get('/auth/sso/start')
async def start(request: Request, session: AsyncSession = Depends(get_session)):
    unique_query(request)
    destination = origin(request)
    client = portal_client(destination)
    if not client:
        raise HTTPException(400, 'invalid_portal')
    app_slug = request.query_params.get('app') or client['accountApp']
    if app_slug != client['accountApp']:
        raise HTTPException(400, 'unknown_application')
    target = sso_return(destination, app_slug, request.query_params.get('next') or '/auth/callback')
    if not target:
        raise HTTPException(400, 'invalid_return')
    prompt = request.query_params.get('prompt')
    if prompt and prompt not in ('select_account','login'):
        raise HTTPException(400, 'invalid_prompt')
    provider = request.query_params.get('provider')
    if provider and provider not in ('google','github'):
        raise HTTPException(400, 'invalid_provider')
    if client.get('restartOrigin'):
        destination_client = portal_client(client['restartOrigin'])
        if not destination_client:
            raise HTTPException(400, 'invalid_portal')
        parsed = urlparse(target)
        callback = client['restartOrigin']+'/auth/callback'+('?' + parsed.query if parsed.query else '')
        params = {'app':destination_client['accountApp'],'next':callback}
        if prompt:
            params['prompt'] = prompt
        if provider:
            params['provider'] = provider
        hint = google_login_hint(provider, request.query_params.get('login_hint'))
        if hint:
            params['login_hint'] = hint
        return redirect(client['restartOrigin']+'/pidp/auth/sso/start?' + urlencode(params))
    website = (await session.execute(select(Website).where(Website.slug == app_slug))).scalar_one_or_none()
    if website is None:
        raise HTTPException(503, 'application_not_registered')
    window = int(time.time()) // 60
    await session.execute(delete(PortalSsoLimit).where(PortalSsoLimit.window_start < window-1))
    permitted = (await session.execute(text("""INSERT INTO portal_sso_limits(ip_hash,window_start,requests) VALUES(:ip,:window,1)
        ON CONFLICT(ip_hash) DO UPDATE SET window_start=excluded.window_start,
        requests=CASE WHEN portal_sso_limits.window_start=excluded.window_start THEN portal_sso_limits.requests+1 ELSE 1 END
        WHERE portal_sso_limits.window_start!=excluded.window_start OR portal_sso_limits.requests<20 RETURNING ip_hash""")
        .bindparams(ip=digest(request.headers.get('cf-connecting-ip') or request.client.host),window=window))).scalar_one_or_none()
    if not permitted:
        raise HTTPException(429, 'too_many_requests')
    browser = secrets.token_urlsafe(40)
    row = PortalSsoRequest(id=secrets.token_urlsafe(40), browser_hash=digest(browser), origin=destination,
        next=target, website_id=str(website.id), app=app_slug, expires_at=int(time.time())+600)
    await session.execute(delete(PortalSsoRequest).where(PortalSsoRequest.expires_at < int(time.time())))
    session.add(row)
    await session.commit()
    params = {'request':row.id}
    if prompt:
        params['prompt'] = prompt
    if provider:
        params['provider'] = provider
    hint = google_login_hint(provider, request.query_params.get('login_hint'))
    if hint:
        params['login_hint'] = hint
    response = redirect(issuer(request)+'/auth/sso/authorize?'+urlencode(params))
    response.set_cookie(BROWSER,browser,max_age=600,secure=True,httponly=True,samesite='lax',path='/')
    return response

@router.get('/auth/sso/authorize')
async def authorize(request: Request, session: AsyncSession = Depends(get_session)):
    unique_query(request)
    parsed_issuer = urlparse(issuer(request))
    if origin(request) != f'{parsed_issuer.scheme}://{parsed_issuer.netloc}' or request.headers.get('x-forwarded-host'):
        raise HTTPException(400, 'issuer_required')
    row = (await session.execute(select(PortalSsoRequest).where(PortalSsoRequest.id == request.query_params.get('request'),
        PortalSsoRequest.expires_at >= int(time.time()), PortalSsoRequest.code_hash.is_(None)))).scalar_one_or_none()
    if not row or not sso_return(row.origin,row.app,row.next):
        raise HTTPException(400, 'expired_request')
    if not row.website_id:
        raise HTTPException(503, 'application_not_registered')
    prompt = request.query_params.get('prompt')
    if prompt and prompt not in ('select_account','login'):
        raise HTTPException(400, 'invalid_prompt')
    if prompt == 'select_account':
        resume = issuer(request) + '/auth/sso/authorize?' + urlencode({'request': row.id})
        login = issuer(request) + '/app/login?' + urlencode({'app': row.app, 'next': resume})
        claims = safe_decode_token(request.cookies.get('pidp_token','')) or {}
        selected = None
        if claims.get('sub'):
            if claims.get('actor_type') == 'website_user' and str(claims.get('website_id')) == row.website_id:
                selected = (await session.execute(select(WebsiteUser).where(WebsiteUser.id == UUID(str(claims['sub'])), WebsiteUser.website_id == UUID(row.website_id), WebsiteUser.is_active.is_(True)))).scalar_one_or_none()
            elif claims.get('actor_type','owner') == 'owner':
                selected = (await session.execute(select(User).where(User.id == UUID(str(claims['sub'])),User.is_active.is_(True)))).scalar_one_or_none()
        current = f'<p><a href="{escape(resume)}">Continue as {escape(selected.email)}</a></p>' if selected else ''
        return HTMLResponse(identity_document('Choose an account', f'<h1>Choose an account</h1><p>Continue to {escape(portal_client(row.origin)["name"])} at {escape(urlparse(row.origin).netloc)}.</p>{current}<p><a href="{escape(login)}">Use another portal account</a></p><p><a href="{escape(row.origin)}">Cancel</a></p><p>Authentication provided by PIdP.</p>'),headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    payload = {} if prompt == 'login' else safe_decode_token(request.cookies.get('pidp_token','')) or {}
    user = None
    if payload.get('actor_type') == 'website_user' and str(payload.get('website_id')) == row.website_id:
        user = (await session.execute(select(WebsiteUser).where(WebsiteUser.id == UUID(str(payload['sub'])),
            WebsiteUser.website_id == UUID(row.website_id), WebsiteUser.is_active.is_(True)))).scalar_one_or_none()
    elif payload.get('sub') and payload.get('actor_type', 'owner') == 'owner':
        owner = (await session.execute(select(User).where(User.id == UUID(str(payload['sub'])),
            User.is_active.is_(True)))).scalar_one_or_none()
        if owner:
            user = (await session.execute(select(WebsiteUser).join(AccountIdentityLink,
                AccountIdentityLink.website_user_id == WebsiteUser.id).where(
                AccountIdentityLink.canonical_user_id == owner.id,
                AccountIdentityLink.website_id == UUID(row.website_id),
                WebsiteUser.website_id == UUID(row.website_id), WebsiteUser.is_active.is_(True)))).scalar_one_or_none()
            if not user:
                link = issuer(request)+'/auth/account-links/connect?'+urlencode({'app':row.app,'sso':row.id})
                resume = issuer(request)+'/auth/sso/authorize?'+urlencode({'request':row.id})
                login = issuer(request)+'/app/login?'+urlencode({'app':row.app,'next':resume})
                return HTMLResponse(identity_document(f'Continue to {escape(portal_client(row.origin)["name"])}', f'<h1>Connect your {escape(portal_client(row.origin)["name"])} account</h1><p>Continue to {escape(portal_client(row.origin)["name"])} at {escape(urlparse(row.origin).netloc)}.</p><p>Signed in to PIdP as {escape(owner.email)}. Connect your portal account to continue with the same identity.</p><p><a href="{escape(link)}">Link my portal account</a></p><p><a href="{escape(login)}">Sign in to the portal separately</a></p><form method="post" action="/auth/account-links/switch?{escape(urlencode(dict(app=row.app,sso=row.id,account="primary")))}"><button>Use another PIdP account</button></form><p><a href="{escape(row.origin)}">Cancel and return to {escape(portal_client(row.origin)["name"])}</a></p><p>Authentication provided by PIdP. Linking requires signing in to both accounts and confirming the connection.</p>'),headers={'Cache-Control':'no-store','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
    hint = google_login_hint(request.query_params.get('provider'), request.query_params.get('login_hint'))
    if not user or hint:
        provider = request.query_params.get('provider')
        if provider and provider not in ('google','github'):
            raise HTTPException(400, 'invalid_provider')
        resume = issuer(request)+'/auth/sso/authorize?'+urlencode({'request':row.id})
        path = f'/auth/{provider}/login' if provider else '/app/login'
        params = {'next':resume}
        params['app'] = row.app
        if hint:
            params['login_hint'] = hint
        return redirect(issuer(request)+path+'?'+urlencode(params))
    code = secrets.token_urlsafe(40)
    claimed = (await session.execute(update(PortalSsoRequest).where(PortalSsoRequest.id == row.id,
        PortalSsoRequest.code_hash.is_(None), PortalSsoRequest.expires_at >= int(time.time()))
        .values(subject=f'website:{row.website_id}:{user.id}',code_hash=digest(code),expires_at=int(time.time())+120).returning(PortalSsoRequest.id))).scalar_one_or_none()
    await session.commit()
    if not claimed:
        raise HTTPException(400, 'expired_request')
    return redirect(row.origin+'/pidp/auth/sso/complete?'+urlencode({'request':row.id,'code':code}))

@router.get('/auth/sso/complete')
async def complete(request: Request, session: AsyncSession = Depends(get_session)):
    unique_query(request)
    browser = request.cookies.get(BROWSER)
    if not browser:
        raise HTTPException(400, 'invalid_browser')
    row = (await session.execute(delete(PortalSsoRequest).where(PortalSsoRequest.id == request.query_params.get('request'),
        PortalSsoRequest.code_hash == digest(request.query_params.get('code','')), PortalSsoRequest.browser_hash == digest(browser),
        PortalSsoRequest.origin == origin(request), PortalSsoRequest.expires_at >= int(time.time())).returning(PortalSsoRequest))).scalar_one_or_none()
    await session.commit()
    if not row or not row.subject or not sso_return(row.origin,row.app,row.next):
        raise HTTPException(400, 'invalid_handoff')
    parts = row.subject.split(':')
    if len(parts) == 3 and parts[0] == 'website' and parts[1] == row.website_id:
        user = (await session.execute(select(WebsiteUser).where(WebsiteUser.id == UUID(parts[2]),
            WebsiteUser.website_id == UUID(parts[1]),WebsiteUser.is_active.is_(True)))).scalar_one_or_none()
        claims = {'actor_type':'website_user','website_id':parts[1]}
    else:
        raise HTTPException(401, 'invalid_account')
    if not user:
        raise HTTPException(401, 'inactive_account')
    token = create_access_token(subject=str(user.id),email=user.email,extra_claims=claims)
    response = redirect(row.next)
    response.set_cookie('pidp_token',token,max_age=settings.access_token_expire_minutes*60,secure=True,httponly=True,samesite='lax',path='/')
    response.set_cookie(BROWSER,'',max_age=0,secure=True,httponly=True,samesite='lax',path='/')
    return response

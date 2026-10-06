"""Browser-bound, one-use PIdP session handoff; no session tokens in URLs."""
import hashlib
import secrets
import time
from uuid import UUID
from urllib.parse import urlencode, urlparse
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, delete, update, text
from sqlalchemy.ext.asyncio import AsyncSession
from config import settings
from db import get_session
from models import PortalSsoRequest, Website, WebsiteUser, User, PortalSsoLimit, AccountIdentityLink
from security import safe_decode_token, create_access_token
from login_hints import google_login_hint

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

def redirect(url):
    return RedirectResponse(url, status_code=303, headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})

@router.get('/auth/sso/start')
async def start(request: Request, session: AsyncSession = Depends(get_session)):
    destination = origin(request)
    if destination not in origins():
        raise HTTPException(400, 'invalid_portal')
    app_slug = request.query_params.get('app', '')
    if not settings.portal_sso_app_slug or app_slug != settings.portal_sso_app_slug:
        raise HTTPException(400, 'unknown_application')
    website = (await session.execute(select(Website).where(Website.slug == app_slug))).scalar_one_or_none()
    if website is None:
        raise HTTPException(503, 'application_not_registered')
    target = request.query_params.get('next', destination + '/auth/callback')
    parsed = urlparse(target)
    if f'{parsed.scheme}://{parsed.netloc}' != destination or parsed.path not in ('/auth/callback','/p/auth/callback') or parsed.username or parsed.password:
        raise HTTPException(400, 'invalid_return')
    provider = request.query_params.get('provider')
    if provider and provider not in ('google','github'):
        raise HTTPException(400, 'invalid_provider')
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
    parsed_issuer = urlparse(issuer(request))
    if origin(request) != f'{parsed_issuer.scheme}://{parsed_issuer.netloc}' or request.headers.get('x-forwarded-host'):
        raise HTTPException(400, 'issuer_required')
    row = (await session.execute(select(PortalSsoRequest).where(PortalSsoRequest.id == request.query_params.get('request'),
        PortalSsoRequest.expires_at >= int(time.time()), PortalSsoRequest.code_hash.is_(None)))).scalar_one_or_none()
    if not row or row.origin not in origins():
        raise HTTPException(400, 'expired_request')
    if not row.website_id:
        raise HTTPException(503, 'application_not_registered')
    payload = safe_decode_token(request.cookies.get('pidp_token','')) or {}
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
                raise HTTPException(403, 'account_link_required')
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
    browser = request.cookies.get(BROWSER)
    if not browser:
        raise HTTPException(400, 'invalid_browser')
    row = (await session.execute(delete(PortalSsoRequest).where(PortalSsoRequest.id == request.query_params.get('request'),
        PortalSsoRequest.code_hash == digest(request.query_params.get('code','')), PortalSsoRequest.browser_hash == digest(browser),
        PortalSsoRequest.origin == origin(request), PortalSsoRequest.expires_at >= int(time.time())).returning(PortalSsoRequest))).scalar_one_or_none()
    await session.commit()
    if not row or not row.subject or row.app != settings.portal_sso_app_slug or row.origin not in origins():
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

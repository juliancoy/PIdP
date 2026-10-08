"""Browser-bound, two-account proof and explicit link confirmation."""
import secrets
import time
from datetime import datetime, timezone
from html import escape
from uuid import uuid4
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update, delete
from sqlalchemy.dialects.postgresql import insert
from starlette.responses import HTMLResponse, RedirectResponse
from db import get_session
from models import User, Website, AccountIdentityLink, AccountIdentityLinkRequest, PortalSsoRequest
from config import settings
from portal_clients import sso_return, login_portal
from security import safe_decode_token
from account_identity import digest

COOKIE = '__Host-pidp_identity_link'
HEADERS = {'Cache-Control': 'no-store', 'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'none'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'"}


def page(title, body):
    return HTMLResponse(f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title><body><main><h1>{escape(title)}</h1>{body}</main></body></html>', headers=HEADERS)


def account_link_browser_routes(get_owner, get_member, session_dependency=get_session):
    router = APIRouter(prefix='/auth/account-links')

    def origin(request):
        return str(request.base_url).rstrip('/')

    def same_origin(request):
        if request.headers.get('origin') != origin(request):
            raise HTTPException(403, 'Invalid origin')

    async def continuation(request, session, website_id):
        ticket = request.query_params.get('sso')
        if not ticket:
            return ''
        result = await session.execute(select(PortalSsoRequest).where(PortalSsoRequest.id == ticket,
            PortalSsoRequest.website_id == str(website_id), PortalSsoRequest.expires_at >= int(time.time()),
            PortalSsoRequest.code_hash.is_(None)))
        row = result.scalar_one_or_none()
        if not row or not sso_return(row.origin,row.app,row.next):
            raise HTTPException(400, 'Sign-in request expired; restart from your portal')
        return '?' + urlencode({'sso': row.id})

    async def website(request, session):
        result = await session.execute(select(Website).where(Website.slug == request.query_params.get('app', '')))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(404, 'Application not found')
        return row

    @router.get('/connect')
    async def connect(request: Request, session=Depends(session_dependency)):
        app = await website(request, session)
        resume = await continuation(request, session, app.id)
        portal = await login_portal(app.slug, origin(request)+'/auth/sso/authorize?'+urlencode({'request':request.query_params.get('sso','')}),session)
        owner = None
        token = request.cookies.get('pidp_token')
        if token:
            try:
                owner = await get_owner(token, session)
            except HTTPException:
                pass
        if not owner or not owner.is_active:
            login = '/app/login?' + urlencode(dict(owner='true', next=str(request.url)))
            return page('Link your portal sign-in', f'<p>First sign in to your primary PIdP account.</p><a href="{escape(login)}">Sign in to PIdP</a>')
        action = '/auth/account-links/connect?' + urlencode(dict(app=app.slug)) + ('&'+resume[1:] if resume else '')
        return page('Link your portal sign-in', f'<p>Primary account: {escape(owner.full_name or owner.email)} ({escape(owner.email)})</p><p>Next, authenticate your {escape(portal["name"] if portal else app.name)} member account. Linking will give both sign-ins one personal profile and portal identity.</p><form method="post" action="{escape(action)}"><button>Authenticate the portal account</button></form>')

    @router.post('/connect')
    async def start(request: Request, session=Depends(session_dependency)):
        same_origin(request)
        token = request.cookies.get('pidp_token')
        if not token:
            raise HTTPException(401, 'Sign in to PIdP')
        owner = await get_owner(token, session)
        if not owner.is_active:
            raise HTTPException(401, 'Inactive account')
        app = await website(request, session)
        resume = await continuation(request, session, app.id)
        claims = safe_decode_token(token)
        now = int(time.time())
        nonce = 'identity_link_' + secrets.token_urlsafe(32)
        await session.execute(delete(AccountIdentityLinkRequest).where(AccountIdentityLinkRequest.expires_at < now))
        session.add(AccountIdentityLinkRequest(id=str(uuid4()), canonical_user_id=owner.id, website_id=app.id,
            browser_hash=digest(nonce), primary_proof_hash=digest(token), expires_at=min(now+600, int(claims['exp']))))
        await session.commit()
        login = '/app/login?' + urlencode(dict(app=app.slug, next=origin(request)+'/auth/account-links/finish'+resume))
        response = RedirectResponse(login, status_code=303, headers=HEADERS)
        response.set_cookie(COOKIE, nonce, max_age=600, secure=True, httponly=True, samesite='lax', path='/')
        return response

    async def context(request, session):
        nonce, token = request.cookies.get(COOKIE), request.cookies.get('pidp_token')
        if not nonce or not token:
            raise HTTPException(401, 'Restart account linking in the same browser')
        result = await session.execute(select(AccountIdentityLinkRequest).where(
            AccountIdentityLinkRequest.browser_hash == digest(nonce), AccountIdentityLinkRequest.expires_at >= int(time.time()),
            AccountIdentityLinkRequest.used_at.is_(None)))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(409, 'Account-link request expired or already used')
        result = await session.execute(select(User).where(User.id == row.canonical_user_id))
        owner = result.scalar_one_or_none()
        member = await get_member(token, session)
        if not owner or not owner.is_active or not member.is_active:
            raise HTTPException(401, 'Inactive account')
        if member.website_id != row.website_id:
            raise HTTPException(403, 'Sign in to the selected application')
        subject = f'website:{member.website_id}:{member.id}'
        if row.subject and row.subject != subject:
            raise HTTPException(409, 'Account changed; restart linking')
        result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.subject == subject))
        link = result.scalar_one_or_none()
        if link and link.canonical_user_id != owner.id:
            raise HTTPException(409, 'Account is linked to another identity')
        resume = await continuation(request, session, row.website_id)
        return row, owner, member, subject, resume

    @router.get('/finish')
    async def finish(request: Request, session=Depends(session_dependency)):
        row, owner, member, subject, resume = await context(request, session)
        changed = await session.execute(update(AccountIdentityLinkRequest).where(
            AccountIdentityLinkRequest.id == row.id, AccountIdentityLinkRequest.used_at.is_(None),
            AccountIdentityLinkRequest.expires_at >= int(time.time()),
            (AccountIdentityLinkRequest.subject.is_(None) | (AccountIdentityLinkRequest.subject == subject))
        ).values(subject=subject))
        if not changed.rowcount:
            raise HTTPException(409, 'Account-link request changed')
        await session.commit()
        return page('Confirm account link', f'<p>Primary PIdP account: {escape(owner.email)}</p><p>Portal account: {escape(member.email)}</p><p>These sign-ins will share your personal profile, onboarding, and portal identity. Organization access will use that person’s live memberships; website tokens remain website tokens.</p><form method="post" action="/auth/account-links/complete{escape(resume)}"><button>Link these accounts</button></form>')

    @router.post('/complete')
    async def complete(request: Request, session=Depends(session_dependency)):
        same_origin(request)
        row, owner, member, subject, resume = await context(request, session)
        if row.subject != subject:
            raise HTTPException(409, 'Review the account link first')
        at = datetime.now(timezone.utc).isoformat()
        claimed = await session.execute(update(AccountIdentityLinkRequest).where(
            AccountIdentityLinkRequest.id == row.id, AccountIdentityLinkRequest.used_at.is_(None),
            AccountIdentityLinkRequest.expires_at >= int(time.time()), AccountIdentityLinkRequest.subject == subject
        ).values(used_at=at).returning(AccountIdentityLinkRequest.id))
        if not claimed.scalar_one_or_none():
            raise HTTPException(409, 'Account-link request changed or already used')
        try:
            await session.execute(insert(AccountIdentityLink).values(subject=subject, canonical_user_id=owner.id,
                website_id=member.website_id,website_user_id=member.id,linked_at=at).on_conflict_do_nothing(index_elements=['subject']))
            result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.subject == subject))
            if result.scalar_one_or_none().canonical_user_id != owner.id:
                raise HTTPException(409, 'Account link changed')
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        if resume:
            response = RedirectResponse(origin(request)+'/auth/sso/authorize?'+urlencode({'request':request.query_params['sso']}),status_code=303,headers=HEADERS)
        else:
            response = page('Accounts linked', '<p>Your sign-ins now share one identity and personal profile.</p><p>Return to your portal to continue.</p>')
        response.delete_cookie(COOKIE, path='/', secure=True)
        return response

    return router

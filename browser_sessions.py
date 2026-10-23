"""Revocable remembered sessions; no raw session identifiers stored server-side."""
import hashlib
import secrets
import time
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import select, delete, update
from models import BrowserSession
from security import safe_decode_token, create_access_token

IDLE_SECONDS = 30 * 86400
ABSOLUTE_SECONDS = 90 * 86400

def digest(sid):
    return hashlib.sha256(sid.encode()).hexdigest()

async def validate_browser_session(session, claims):
    if not claims or not claims.get('sid'):
        return claims
    row = (await session.execute(select(BrowserSession).where(BrowserSession.id_hash == digest(claims['sid'])))).scalar_one_or_none()
    now = int(time.time())
    member = claims.get('actor_type') == 'website_user'
    if not row or row.expires_at <= now or row.absolute_expires_at <= now or (member and (str(row.website_user_id) != claims['sub'] or str(row.website_id) != claims.get('website_id'))) or (not member and str(row.owner_id) != claims['sub']):
        raise HTTPException(401, 'Session expired or revoked')
    return claims

async def browser_session(session, access_token, previous=None):
    claims = await validate_browser_session(session, safe_decode_token(access_token))
    if not claims:
        raise HTTPException(401, 'Invalid session')
    now = int(time.time())
    auth_time = claims.get('auth_time',now)
    sid, absolute = secrets.token_urlsafe(32), auth_time + ABSOLUTE_SECONDS
    if not previous and claims.get('sid'):
        previous = access_token
    if previous:
        old = await validate_browser_session(session, safe_decode_token(previous))
        if not old or not old.get('sid') or old['sub'] != claims['sub'] or old.get('website_id') != claims.get('website_id') or old.get('actor_type','owner') != claims.get('actor_type','owner'):
            raise HTTPException(401, 'Session account changed')
        sid = old['sid']
        auth_time = old.get('auth_time',now)
        row = (await session.execute(select(BrowserSession).where(BrowserSession.id_hash == digest(sid)))).scalar_one()
        absolute = row.absolute_expires_at
    expires = min(now + IDLE_SECONDS, absolute)
    if previous:
        result = await session.execute(update(BrowserSession).where(BrowserSession.id_hash == digest(sid), BrowserSession.expires_at > now, BrowserSession.absolute_expires_at > now).values(expires_at=expires))
        if not result.rowcount:
            raise HTTPException(401, 'Session expired')
    else:
        member = claims.get('actor_type') == 'website_user'
        session.add(BrowserSession(id_hash=digest(sid), owner_id=None if member else UUID(claims['sub']), website_user_id=UUID(claims['sub']) if member else None, website_id=UUID(claims['website_id']) if member else None, created_at=now, expires_at=expires, absolute_expires_at=absolute))
    await session.commit()
    identity = {k:v for k,v in claims.items() if k not in ('exp','jti','sid','token_use')}
    token = create_access_token(claims['sub'], extra_claims={**identity, 'sid':sid, 'auth_time':auth_time, 'token_use':'browser_session', 'exp':expires})
    return token, expires-now

async def revoke_browser_session(session, token):
    claims = safe_decode_token(token)
    if claims and claims.get('sid'):
        await session.execute(delete(BrowserSession).where(BrowserSession.id_hash == digest(claims['sid'])))
        await session.commit()

async def browser_claims(session, token):
    try:
        return await validate_browser_session(session, safe_decode_token(token)) or {}
    except HTTPException:
        return {}

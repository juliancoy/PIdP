"""PIdP owns stable person links; signed login/OAuth subjects stay unchanged."""
import hashlib
import json
import time
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update, delete
from sqlalchemy.dialects.postgresql import insert

from db import get_session
from security import safe_decode_token
from models import User, WebsiteUser, AccountIdentityLink, AccountIdentityLinkPreview


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


async def resolve_account_identity(session, subject):
    parts = subject.split(':')
    try:
        if len(parts) == 2 and parts[0] == 'owner':
            result = await session.execute(select(User).where(User.id == UUID(parts[1]), User.is_active.is_(True)))
            owner = result.scalar_one_or_none()
            if not owner:
                raise HTTPException(401, 'Inactive account')
            return dict(canonical_user_id=str(owner.id), account_id=str(owner.id), account_subject=subject)
        if len(parts) != 3 or parts[0] != 'website':
            raise HTTPException(401, 'Invalid account namespace')
        result = await session.execute(select(WebsiteUser).where(
            WebsiteUser.website_id == UUID(parts[1]), WebsiteUser.id == UUID(parts[2]), WebsiteUser.is_active.is_(True)))
        member = result.scalar_one_or_none()
        if not member:
            raise HTTPException(401, 'Inactive account')
        result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.subject == subject))
        link = result.scalar_one_or_none()
        if link:
            result = await session.execute(select(User).where(User.id == link.canonical_user_id, User.is_active.is_(True)))
            if not result.scalar_one_or_none():
                raise HTTPException(401, 'Inactive linked identity')
        return dict(canonical_user_id=str(link.canonical_user_id if link else member.id),
                    account_id=str(member.id), account_subject=subject)
    except ValueError:
        raise HTTPException(401, 'Invalid account namespace')


def account_link_routes(get_owner, get_member, session_dependency=get_session):
    router = APIRouter(prefix='/auth/account-links')

    def token(request):
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer ') or not auth[7:]:
            raise HTTPException(401, 'Authentication required')
        return auth[7:]

    async def proof(request, payload, session):
        secondary = payload.get('member_token')
        if not isinstance(secondary, str) or not secondary or len(secondary) > 16384:
            raise HTTPException(400, 'Authenticate the website account to link')
        primary = token(request)
        owner = await get_owner(primary, session)
        member = await get_member(secondary, session)
        if not owner.is_active or not member.is_active:
            raise HTTPException(401, 'Inactive account')
        subject = f'website:{member.website_id}:{member.id}'
        result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.subject == subject))
        existing = result.scalar_one_or_none()
        if existing and existing.canonical_user_id != owner.id:
            raise HTTPException(409, 'Account is already linked to another identity')
        fingerprint = digest(json.dumps([str(owner.id), subject, digest(primary), digest(secondary)], separators=(',', ':')))
        return owner, member, subject, fingerprint

    @router.get('')
    async def accounts(request: Request, session=Depends(session_dependency)):
        claims = safe_decode_token(token(request))
        if not claims:
            raise HTTPException(401, 'Invalid token')
        subject = f"website:{claims.get('website_id')}:{claims.get('sub')}" if claims.get('actor_type') == 'website_user' else f"owner:{claims.get('sub')}"
        identity = await resolve_account_identity(session, subject)
        result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.canonical_user_id == UUID(identity['canonical_user_id'])))
        return dict(canonical_user_id=identity['canonical_user_id'], accounts=[dict(subject=r.subject, website_id=str(r.website_id),
            website_user_id=str(r.website_user_id), linked_at=r.linked_at) for r in result.scalars().all()])

    @router.post('/preview')
    async def preview(request: Request, session=Depends(session_dependency)):
        payload = await request.json()
        owner, member, subject, fingerprint = await proof(request, payload, session)
        now = int(time.time())
        await session.execute(delete(AccountIdentityLinkPreview).where(AccountIdentityLinkPreview.expires_at < now))
        row = AccountIdentityLinkPreview(id=str(uuid4()), canonical_user_id=owner.id, subject=subject,
            website_id=member.website_id, website_user_id=member.id, proof_hash=fingerprint, expires_at=now+600)
        session.add(row)
        await session.commit()
        return dict(previewId=row.id, canonical_user_id=str(owner.id), account_id=str(member.id),
            account_subject=subject, expires_at=row.expires_at, effects=['Share personal profile and portal identity',
            'Keep website session and OAuth namespaces', 'Organization permissions still require live membership checks'])

    @router.post('/apply')
    async def apply(request: Request, session=Depends(session_dependency)):
        payload = await request.json()
        if payload.get('confirm') is not True or not isinstance(payload.get('previewId'), str):
            raise HTTPException(400, 'Confirm the reviewed preview')
        owner, member, subject, fingerprint = await proof(request, payload, session)
        at = datetime.now(timezone.utc).isoformat()
        claim = await session.execute(update(AccountIdentityLinkPreview).where(
            AccountIdentityLinkPreview.id == payload['previewId'], AccountIdentityLinkPreview.canonical_user_id == owner.id,
            AccountIdentityLinkPreview.subject == subject, AccountIdentityLinkPreview.proof_hash == fingerprint,
            AccountIdentityLinkPreview.expires_at >= int(time.time()), AccountIdentityLinkPreview.applied_at.is_(None)
        ).values(applied_at=at).returning(AccountIdentityLinkPreview.id))
        if not claim.scalar_one_or_none():
            raise HTTPException(409, 'Preview expired, changed, or already applied')
        try:
            await session.execute(insert(AccountIdentityLink).values(subject=subject, canonical_user_id=owner.id,
                website_id=member.website_id, website_user_id=member.id, linked_at=at).on_conflict_do_nothing(index_elements=['subject']))
            result = await session.execute(select(AccountIdentityLink).where(AccountIdentityLink.subject == subject))
            if result.scalar_one_or_none().canonical_user_id != owner.id:
                await session.rollback()
                raise HTTPException(409, 'Account link changed')
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        return dict(ok=True, previewId=payload['previewId'], **await resolve_account_identity(session, subject))

    return router

import os
os.environ.setdefault('SECRET_KEY','remembered-session-test-only')
os.environ.setdefault('DATABASE_URL','postgresql+asyncpg://test:test@localhost/test')
import time, unittest, uuid
from unittest.mock import patch
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from fastapi import HTTPException
from models import User, Website, WebsiteUser, BrowserSession
from security import create_access_token, safe_decode_token
from browser_sessions import browser_session, validate_browser_session, revoke_browser_session, IDLE_SECONDS, ABSOLUTE_SECONDS
from config import settings

@compiles(JSONB,'sqlite')
def sqlite_json(type_,compiler,**kw): return 'JSON'

class RememberedSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine=create_async_engine('sqlite+aiosqlite://')
        async with self.engine.begin() as conn:
            for model in [User,Website,WebsiteUser,BrowserSession]:
                await conn.run_sync(model.__table__.create)
        self.db=async_sessionmaker(self.engine,expire_on_commit=False)()
        self.user=User(id=uuid.uuid4(),email='remembered@example.test',is_active=True)
        self.db.add(self.user);await self.db.commit()
        self.policy=patch.object(settings,'access_token_expire_minutes',60);self.policy.start()
    async def asyncTearDown(self):
        self.policy.stop();await self.db.close();await self.engine.dispose()
    async def remembered(self):
        return await browser_session(self.db,create_access_token(str(self.user.id)))
    async def test_cookie_lives_30_days_and_binds_to_hashed_server_record(self):
        token,max_age=await self.remembered();claims=safe_decode_token(token)
        self.assertEqual(max_age,IDLE_SECONDS);self.assertEqual(claims['token_use'],'browser_session')
        row=(await self.db.execute(select(BrowserSession))).scalar_one()
        self.assertNotEqual(row.id_hash,claims['sid']);self.assertEqual(row.owner_id,self.user.id)
        self.assertLessEqual(safe_decode_token(create_access_token(str(self.user.id)))['exp']-int(time.time()),3600)
        await validate_browser_session(self.db,claims)
    async def test_logout_revokes_captured_session(self):
        token,_=await self.remembered();claims=safe_decode_token(token)
        await revoke_browser_session(self.db,token)
        with self.assertRaises(HTTPException):await validate_browser_session(self.db,claims)
    async def test_inactivity_expiry_and_account_substitution_are_rejected(self):
        token,_=await self.remembered();claims=safe_decode_token(token)
        with self.assertRaises(HTTPException):await validate_browser_session(self.db,{**claims,'sub':str(uuid.uuid4())})
        await self.db.execute(update(BrowserSession).values(expires_at=int(time.time())-1));await self.db.commit()
        with self.assertRaises(HTTPException):await validate_browser_session(self.db,claims)
    async def test_renewal_stops_at_absolute_lifetime(self):
        token,_=await self.remembered();initial=safe_decode_token(token)['auth_time']
        for day in [29,58,87]:
            with patch('browser_sessions.time.time',return_value=initial+day*86400):
                token,_=await browser_session(self.db,create_access_token(str(self.user.id)),token)
        claims=safe_decode_token(token);self.assertEqual(claims['exp'],initial+ABSOLUTE_SECONDS)
        with patch('browser_sessions.time.time',return_value=initial+91*86400):
            with self.assertRaises(HTTPException):await validate_browser_session(self.db,claims)
    async def test_api_credentials_require_recent_authentication_and_cookie_is_not_a_bearer(self):
        from main import _get_current_owner_for_token_admin, AccessTokenBearer
        from starlette.requests import Request
        token,_=await self.remembered();claims=safe_decode_token(token)
        stale=create_access_token(str(self.user.id),extra_claims={'sid':claims['sid'],'auth_time':int(time.time())-901})
        with self.assertRaises(HTTPException):await _get_current_owner_for_token_admin(stale,self.db)
        request=Request({'type':'http','headers':[(b'authorization',('Bearer '+token).encode())]})
        with self.assertRaises(HTTPException):await AccessTokenBearer(tokenUrl='/auth/token')(request)

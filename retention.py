"""Bounded expiry cleanup. Identity/grant deletion is deliberately separate."""
import asyncio
import logging
import time
from sqlalchemy import delete, select
from models import Base
from db import SessionLocal


async def run_retention(session, now=None, limit=500):
    cutoff = int(time.time() if now is None else now) - 23 * 3600
    if cutoff <= 0 or not 1 <= limit <= 500:
        raise ValueError('Invalid retention bounds')
    rules = [(name, 'expires_at', cutoff) for name in (
        'mcp_oauth_requests', 'mcp_oauth_codes', 'mcp_oauth_logins',
        'portal_sso_requests', 'account_identity_link_previews',
        'account_identity_link_requests')]
    rules += [('browser_sessions', 'expires_at', int(time.time() if now is None else now)), ('portal_sso_limits', 'window_start', cutoff // 60),
              ('mcp_oauth_registration_limits', 'window_start', cutoff // 3600)]
    from datetime import datetime, timezone, timedelta
    rules += [('oauth_live_statistics','day',(datetime.fromtimestamp(int(time.time() if now is None else now),timezone.utc)-timedelta(days=29)).date().isoformat())]
    counts = {}
    for name, column, value in rules:
        table = Base.metadata.tables[name]
        if name == 'oauth_live_statistics':
            from sqlalchemy import tuple_
            keys=list(table.primary_key.columns)
            selected=select(*keys).where(table.c[column]<value).order_by(*keys).limit(limit)
            result=await session.execute(delete(table).where(tuple_(*keys).in_(selected)))
            counts[name]=result.rowcount
            continue
        key = list(table.primary_key.columns)[0]
        selected = select(key).where(table.c[column] < value).order_by(key).limit(limit)
        result = await session.execute(delete(table).where(key.in_(selected)))
        counts[name] = result.rowcount
    await session.commit()
    return counts


async def retention_loop():
    while True:
        try:
            async with SessionLocal() as session:
                counts = await run_retention(session)
            logging.getLogger(__name__).info('pidp.retention counts=%s backlog=%s', counts, any(n == 500 for n in counts.values()))
        except Exception:
            # SQL errors can contain bound secrets; never log the exception.
            logging.getLogger(__name__).error('pidp.retention outcome=error')
        await asyncio.sleep(300)

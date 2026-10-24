"""Anonymous OAuth stage counters; no identities, credentials or raw request data."""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, parse_qs
from sqlalchemy import Table, Column, Text, Integer, text
from models import Base
from db import SessionLocal

Table('oauth_live_statistics',Base.metadata,
      Column('day',Text,primary_key=True),Column('stage',Text,primary_key=True),Column('outcome',Text,primary_key=True),
      Column('requests',Integer,nullable=False),Column('total_ms',Integer,nullable=False),Column('max_ms',Integer,nullable=False))
STAGES={
 '/oauth/mcp/register':'registration','/oauth/mcp/authorize':'authorization','/oauth/mcp/consent':'consent',
 '/oauth/mcp/token':'token_exchange_or_refresh','/oauth/mcp/revoke':'revocation','/oauth/mcp/introspect':'introspection',
 '/oauth/mcp/link':'browser_pairing','/oauth/mcp/browser/cancel':'browser_cancel','/oauth/mcp/connections':'connection_revocation','/oauth/mcp/resume':'resume','/oauth/mcp/handoff':'handoff','/oauth/mcp/browser/finish':'browser_link',
 '/auth/google/login':'google_login','/auth/google/callback':'google_callback',
 '/auth/github/login':'github_login','/auth/github/callback':'github_callback',
 '/auth/google-calendar/connect':'google_calendar_connect','/auth/google-calendar/callback':'google_calendar_callback',
}
async def record_oauth_statistics(stage,status,location,duration):
    query=parse_qs(urlsplit(location or '').query,keep_blank_values=True)
    outcome=('consent_denied' if query.get('error')==['access_denied'] else
             'rate_limited' if status==429 else 'server_error' if status>=500 else
             'rejected' if status in (401,403) else 'client_error' if status>=400 or 'error' in query else
             'redirect' if status>=300 else 'ok')
    ms=max(0,min(3600000,round(duration)))
    async with SessionLocal() as session:
        await session.execute(text('''INSERT INTO oauth_live_statistics(day,stage,outcome,requests,total_ms,max_ms)
            VALUES(:day,:stage,:outcome,1,:ms,:ms) ON CONFLICT(day,stage,outcome) DO UPDATE SET
            requests=oauth_live_statistics.requests+1,total_ms=oauth_live_statistics.total_ms+excluded.total_ms,
            max_ms=CASE WHEN oauth_live_statistics.max_ms>excluded.max_ms THEN oauth_live_statistics.max_ms ELSE excluded.max_ms END'''),
            {'day':datetime.now(timezone.utc).date().isoformat(),'stage':stage,'outcome':outcome,'ms':ms})
        await session.commit()
async def read_oauth_statistics(session,days):
    start=(datetime.now(timezone.utc)-timedelta(days=days-1)).date().isoformat()
    end=datetime.now(timezone.utc).date().isoformat()
    result=await session.execute(text('SELECT day,stage,outcome,requests,total_ms,max_ms FROM oauth_live_statistics WHERE day>=:start AND day<=:end ORDER BY day,stage,outcome'),{'start':start,'end':end})
    return {'source':'PIdP OAuth','days':days,'start':start,'asOf':datetime.now(timezone.utc).isoformat(),'rows':[dict(row) for row in result.mappings()]}

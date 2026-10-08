"""Operator-owned portal registration and shared SSO return policy."""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urljoin, parse_qs
from config import settings
DEFAULTS = json.loads((Path(__file__).parent/'shared/portal-clients.json').read_text())

def unsafe(value):
    return bool(re.search(r'[\\\x00-\x20\x7f]', value))

def local_destination(value):
    return value.startswith('/') and not value.startswith('//') and not unsafe(value)

def portal_client(origin):
    if origin not in [s.strip() for s in settings.portal_auth_origins.split(',')]:
        return None
    try:
        registry = json.loads(settings.portal_clients_json) if settings.portal_clients_json else DEFAULTS
        item = registry.get(origin)
        parsed = urlsplit(origin)
        if not item or not isinstance(item.get('name'),str) or not item['name'].strip() or not isinstance(item.get('accountApp'),str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]*',item['accountApp']):
            return None
        if parsed.scheme not in ('http','https') or parsed.username or parsed.password or origin != parsed.scheme+'://'+parsed.netloc:
            return None
        callbacks = item.get('callbacks')
        if not isinstance(callbacks,list) or not callbacks or any(not isinstance(p,str) or not local_destination(p) or '?' in p or '#' in p for p in callbacks):
            return None
        restart = item.get('restartOrigin')
        if restart and (restart == origin or not registry.get(restart) or registry[restart].get('restartOrigin') or restart not in [s.strip() for s in settings.portal_auth_origins.split(',')]):
            return None
        return item
    except (ValueError,TypeError,AttributeError):
        return None

def sso_return(origin, app, value):
    client = portal_client(origin)
    if not client or client['accountApp'] != app or unsafe(value) or value.startswith('//'):
        return None
    try:
        target = urljoin(origin+'/',value)
        parsed = urlsplit(target)
        if parsed.scheme+'://'+parsed.netloc != origin or parsed.username or parsed.password or parsed.fragment:
            return None
        params = parse_qs(parsed.query,keep_blank_values=True)
        if parsed.path == '/pidp/oauth/mcp/link':
            if set(params) != {'request'} or len(params['request']) != 1 or not re.fullmatch(r'login_[A-Za-z0-9_-]{43,100}',params['request'][0]):
                return None
        elif parsed.path not in client['callbacks'] or set(params)-{'next'} or len(params.get('next',[])) > 1 or (params.get('next',[''])[0] and not local_destination(params['next'][0])):
            return None
        return target
    except (ValueError,TypeError):
        return None


async def login_portal(app, next_url, session, request_origin=None):
    direct = portal_client(request_origin) if request_origin else None
    if direct and direct['accountApp'] == app:
        return direct
    try:
        from sqlalchemy import select
        from models import PortalSsoRequest
        import time
        target = urlsplit(urljoin(settings.public_base_url+'/',next_url))
        issuer = urlsplit(settings.public_base_url)
        if target.scheme+'://'+target.netloc != issuer.scheme+'://'+issuer.netloc or target.username or target.password:
            return None
        params = parse_qs(target.query)
        if target.path == '/auth/sso/authorize' and len(params.get('request',[])) == 1:
            row = (await session.execute(select(PortalSsoRequest).where(PortalSsoRequest.id == params['request'][0],
                PortalSsoRequest.expires_at >= int(time.time()),PortalSsoRequest.code_hash.is_(None)))).scalar_one_or_none()
            if row and row.app == app and sso_return(row.origin,row.app,row.next):
                return portal_client(row.origin)
    except (ValueError,TypeError):
        pass
    return None


def browser_return(value, issuer, extra_origins=()):
    if local_destination(value):
        return value
    if unsafe(value) or value.startswith('/'):
        return None
    try:
        target = urlsplit(value)
        if target.username or target.password:
            return None
        if target.scheme not in ('http','https'):
            return value if target.scheme in settings.native_redirect_schemes_list else None
        origin = target.scheme+'://'+target.netloc
        configured = {urlsplit(s).scheme+'://'+urlsplit(s).netloc for s in [issuer,settings.public_base_url,settings.frontend_redirect_url] if s}
        if origin in configured or origin in extra_origins or portal_client(origin):
            return value
    except (ValueError,TypeError):
        pass
    return None

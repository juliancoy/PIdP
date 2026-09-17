"""Account OAuth contract shared with serverless/src/mcpAuthorization.ts."""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, unquote, quote
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from jose import jwt
from sqlalchemy import Column, ForeignKey, Index, Integer, Table, Text, select, text
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from config import settings
from db import get_session
from models import Base, User, WebsiteUser
from security import safe_decode_token
from consent_page import render_consent_page

SCOPES = ['org:events.read', 'org:events.write', 'org:portal.read', 'org:portal.write']
# no-referrer makes browser form POSTs send Origin: null, breaking origin-bound CSRF checks.
HEADERS = {'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'Referrer-Policy': 'same-origin',
           'X-Content-Type-Options': 'nosniff',
           'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}

# Same table/column contract as D1 migration 0006; included in Base migrations.
for name, key, fields in [
    ('requests', 'id', 'session_hash subject client_id redirect_uri resource scope challenge state'),
    ('codes', 'hash', 'subject client_id redirect_uri resource scope challenge'),
    ('grants', 'id', 'subject client_id resource scope'),
]:
    Table('mcp_oauth_' + name, Base.metadata, Column(key, Text, primary_key=True),
          *(Column(field, Text, nullable=False) for field in fields.split()),
          Column('expires_at', Integer, nullable=False),
          *([Column('revoked', Integer, nullable=False, server_default='0')] if name == 'grants' else []))
Table('mcp_oauth_refresh', Base.metadata, Column('hash', Text, primary_key=True),
      Column('grant_id', Text, ForeignKey('mcp_oauth_grants.id'), nullable=False),
      Column('used', Integer, nullable=False, server_default='0'))
Index('mcp_oauth_grants_subject', Base.metadata.tables['mcp_oauth_grants'].c.subject)
Index('mcp_oauth_requests_expiry', Base.metadata.tables['mcp_oauth_requests'].c.expires_at)
Index('mcp_oauth_codes_expiry', Base.metadata.tables['mcp_oauth_codes'].c.expires_at)
Table('mcp_oauth_clients', Base.metadata, Column('id', Text, primary_key=True),
      Column('client_json', Text, nullable=False), Column('created_at', Integer, nullable=False),
      Column('revoked', Integer, nullable=False, server_default='0'))
Table('mcp_oauth_registration_limits', Base.metadata, Column('id', Text, primary_key=True),
      Column('window_start', Integer, nullable=False), Column('requests', Integer, nullable=False))
Index('mcp_oauth_registration_limits_window', Base.metadata.tables['mcp_oauth_registration_limits'].c.window_start)
Table('mcp_oauth_logins', Base.metadata, Column('id', Text, primary_key=True),
      Column('browser_hash', Text, nullable=False), Column('resource', Text, nullable=False),
      Column('return_path', Text, nullable=False), Column('subject', Text), Column('display', Text),
      Column('code_hash', Text, unique=True), Column('expires_at', Integer, nullable=False))
Index('mcp_oauth_logins_expiry', Base.metadata.tables['mcp_oauth_logins'].c.expires_at)
Index('mcp_oauth_logins_browser', Base.metadata.tables['mcp_oauth_logins'].c.browser_hash)
BROWSER_COOKIE = '__Host-pidp_mcp_browser'
SESSION_COOKIE = '__Host-pidp_mcp_session'


class OAuthError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def consent_headers(redirect):
    # Browser form-action also covers the redirect after the consent POST.
    target = urlsplit(redirect)
    origin = target.scheme + '://' + quote(target.netloc, safe='[]:.-')
    return {**HEADERS, 'Content-Security-Policy':
            f"default-src 'none'; form-action 'self' {origin}; frame-ancestors 'none'; base-uri 'none'"}


def https(value):
    u = urlsplit(value)
    _ = u.port
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError('HTTPS required')
    return value


def loopback(value):
    u = urlsplit(value)
    _ = u.port
    return u.scheme == 'http' and u.hostname in ('127.0.0.1', '::1') and not any(
        (u.username, u.password, u.fragment, u.query))


def redirect_allowed(client, value):
    try:
        actual = urlsplit(value)
        return any(value == registered or (
            client.get('tokenEndpointAuthMethod') == 'none' and loopback(value) and loopback(registered)
            and actual.hostname == urlsplit(registered).hostname and actual.path == urlsplit(registered).path
        ) for registered in client['redirectUris'])
    except ValueError:
        return False


def configuration():
    try:
        issuer = https(settings.mcp_oauth_issuer)
        u = urlsplit(issuer)
        if issuer != f'{u.scheme}://{u.netloc}':
            raise ValueError()
        key = json.loads(settings.mcp_oauth_private_jwk)
        if key['kty'] != 'EC' or key['crv'] != 'P-256' or not all(key.get(k) for k in ('d', 'x', 'y', 'kid')):
            raise ValueError()
        old = json.loads(settings.mcp_oauth_public_jwks)['keys']
        if not isinstance(old, list) or any(k.get('d') or k.get('kty') != 'EC' or k.get('crv') != 'P-256'
                                              or not all(k.get(f) for f in ('x', 'y', 'kid')) for k in old):
            raise ValueError()
        keys = [{**{f: k[f] for f in ('kty', 'crv', 'x', 'y', 'kid')}, 'alg': 'ES256', 'use': 'sig'}
                for k in [key, *(k for k in old if k['kid'] != key['kid'])]]
        clients = json.loads(settings.mcp_oauth_clients_json)
        resources = json.loads(settings.mcp_oauth_resources_json)
        portals = json.loads(settings.mcp_oauth_portals_json)
        for resource, portal in portals.items():
            if resource not in resources or not isinstance(portal['name'], str) or not portal['name'].strip() or len(portal['name']) > 120:
                raise ValueError()
            target = urlsplit(https(portal['loginUrl']))
            if target.query or not target.path.endswith('/users/mcp-connect'):
                raise ValueError()
        if not clients or not resources:
            raise ValueError()
        for resource, binding in resources.items():
            https(resource)
            if not re.fullmatch('[a-f0-9]{64}', binding['secretHash']):
                raise ValueError()
        for client in clients.values():
            if not all(client.get(k) for k in ('name', 'redirectUris', 'resources', 'scopes')):
                raise ValueError()
            if client.get('tokenEndpointAuthMethod') == 'none':
                if 'secretHash' in client or not all(loopback(v) for v in client['redirectUris']):
                    raise ValueError()
            else:
                if 'tokenEndpointAuthMethod' in client or not re.fullmatch('[a-f0-9]{64}', client.get('secretHash', '')):
                    raise ValueError()
                for value in client['redirectUris']:
                    https(value)
            if any(r not in resources for r in client['resources']) or any(s not in SCOPES for s in client['scopes']):
                raise ValueError()
        return dict(issuer=issuer, key=key, keys=keys, clients=clients, resources=resources, portals=portals)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise OAuthError('authorization_server_not_configured', 503)


async def query(db, sql, **params):
    result = await db.execute(text(sql), params)
    rows = [dict(row) for row in result.mappings()] if result.returns_rows else []
    await db.commit()
    return rows


async def active_subject(db, subject):
    parts = subject.split(':')
    try:
        if len(parts) == 2 and parts[0] == 'owner':
            statement = select(User.id).where(User.id == UUID(parts[1]), User.is_active.is_(True))
        elif len(parts) == 3 and parts[0] == 'website':
            statement = select(WebsiteUser.id).where(WebsiteUser.website_id == UUID(parts[1]),
                WebsiteUser.id == UUID(parts[2]), WebsiteUser.is_active.is_(True))
        else:
            return False
    except ValueError:
        return False
    return (await db.execute(statement)).scalar_one_or_none() is not None


async def identity_session(request, db):
    token = request.cookies.get('pidp_token')
    payload = safe_decode_token(token) if token else None
    if not payload:
        return None
    subject = (f"website:{payload.get('website_id')}:{payload.get('sub')}" if payload.get('actor_type') == 'website_user'
               else f"owner:{payload.get('sub')}")
    if not await active_subject(db, subject):
        return None
    return dict(subject=subject, display=str(payload.get('email') or payload['sub']), hash=digest(token))


async def session(request, db, resource=None):
    cfg = configuration()
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        try:
            if jwt.get_unverified_header(token).get('typ') != 'mcp-session+jwt':
                raise ValueError()
            payload = jwt.decode(token, cfg['keys'][0], algorithms=['ES256'], issuer=cfg['issuer'], audience=cfg['issuer'],
                                 options={'require_exp': True, 'require_sub': True})
            if (not resource or payload.get('resource') == resource) and payload.get('resource') in cfg['portals'] and await active_subject(db, payload['sub']):
                return dict(subject=payload['sub'], display=str(payload.get('display') or payload['sub']), hash=digest(token))
        except Exception:
            pass
    if resource in cfg['portals'] or (not resource and cfg['portals']):
        return None
    return await identity_session(request, db)


async def start_login(request, db, cfg, resource, return_path):
    portal = cfg['portals'].get(resource)
    if not portal:
        raise OAuthError('portal_login_not_configured', 503)
    await anonymous_limit(request, db, 'login:', 30, 1000)
    browser = request.cookies.get(BROWSER_COOKIE, '')
    if not re.fullmatch('[A-Za-z0-9_-]{43,100}', browser):
        browser = secrets.token_urlsafe(40)
    now = int(time.time())
    await query(db, 'DELETE FROM mcp_oauth_logins WHERE expires_at < :now', now=now)
    login_id = 'login_' + secrets.token_urlsafe(40)
    rows = await query(db, '''INSERT INTO mcp_oauth_logins (id, browser_hash, resource, return_path, expires_at)
        SELECT :id, :browser, :resource, :return_path, :expires WHERE
        (SELECT COUNT(*) FROM mcp_oauth_logins WHERE browser_hash = :browser) < 20
        AND (SELECT COUNT(*) FROM mcp_oauth_logins) < 10000 RETURNING id''',
        id=digest(login_id), browser=digest(browser), resource=resource, return_path=return_path, expires=now + 600)
    if not rows:
        raise OAuthError('too_many_requests', 429)
    result = RedirectResponse(portal['loginUrl'] + '?' + urlencode({'request': login_id}), status_code=303, headers=HEADERS)
    result.set_cookie(BROWSER_COOKIE, browser, max_age=600, httponly=True, secure=True, samesite='lax', path='/')
    return result


async def login_handoff(request, db, cfg):
    now = int(time.time())
    if request.method not in ('GET', 'POST'):
        raise OAuthError('invalid_request')
    p = await form(request) if request.method == 'POST' else parameters(request.query_params.multi_items())
    rows = await query(db, 'SELECT * FROM mcp_oauth_logins WHERE id = :id AND expires_at >= :now AND code_hash IS NULL',
                       id=digest(p.get('request', '')), now=now)
    row = rows[0] if rows else None
    portal = cfg['portals'].get(row['resource']) if row else None
    if not portal:
        raise OAuthError('login_expired')
    url = urlsplit(portal['loginUrl'])
    origin = f'{url.scheme}://{url.netloc}'
    if request.method == 'POST' and request.headers.get('origin') != origin:
        raise OAuthError('invalid_request', 403)
    actor = await identity_session(request, db)
    if not actor:
        raise OAuthError('login_required', 401)
    if request.method == 'GET':
        return response(dict(portal=portal['name'], portal_origin=origin, issuer=cfg['issuer'], account=actor['display']))
    code = 'handoff_' + secrets.token_urlsafe(40)
    rows = await query(db, '''UPDATE mcp_oauth_logins SET subject = :subject, display = :display, code_hash = :code, expires_at = :expires
        WHERE id = :id AND code_hash IS NULL AND expires_at >= :now RETURNING id''',
        subject=actor['subject'], display=actor['display'], code=digest(code), expires=min(row['expires_at'], now + 120), id=row['id'], now=now)
    if not rows:
        raise OAuthError('login_expired')
    return response(dict(redirect_url=cfg['issuer'] + '/oauth/mcp/resume?' + urlencode({'code': code})))


async def resume_login(request, db, cfg):
    p = parameters(request.query_params.multi_items())
    browser = request.cookies.get(BROWSER_COOKIE)
    if request.method != 'GET' or str(request.base_url).rstrip('/') != cfg['issuer'] or not browser or 'code' not in p:
        raise OAuthError('invalid_request')
    now = int(time.time())
    rows = await query(db, '''DELETE FROM mcp_oauth_logins WHERE code_hash = :code AND browser_hash = :browser
        AND expires_at >= :now RETURNING *''', code=digest(p['code']), browser=digest(browser), now=now)
    row = rows[0] if rows else None
    if not row or not row['subject'] or row['resource'] not in cfg['portals'] or not await active_subject(db, row['subject']):
        raise OAuthError('login_expired')
    token = jwt.encode(dict(sub=row['subject'], display=row['display'], resource=row['resource'], iss=cfg['issuer'],
                            aud=cfg['issuer'], iat=now, exp=now + 600, jti=str(uuid4())), cfg['key'], algorithm='ES256',
                       headers={'kid': cfg['key']['kid'], 'typ': 'mcp-session+jwt'})
    result = RedirectResponse(row['return_path'], status_code=303, headers=HEADERS)
    result.set_cookie(SESSION_COOKIE, token, max_age=600, httponly=True, secure=True, samesite='lax', path='/')
    return result


def parameters(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OAuthError('invalid_request')
        result[key] = value
    return result


async def form(request):
    if not request.headers.get('content-type', '').startswith('application/x-www-form-urlencoded'):
        raise OAuthError('invalid_request')
    return parameters(parse_qsl(await bounded_body(request), keep_blank_values=True))


async def bounded_body(request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 16384:
            raise OAuthError('invalid_request')
    return body.decode()


async def get_client(db, cfg, client_id):
    if client_id in cfg['clients']:
        return cfg['clients'][client_id]
    if not settings.mcp_oauth_dynamic_registration or not re.fullmatch('mcp_dynamic_[A-Za-z0-9_-]{20,100}', client_id or ''):
        return None
    rows = await query(db, 'SELECT client_json FROM mcp_oauth_clients WHERE id = :id AND revoked = 0', id=client_id)
    if not rows:
        return None
    client = json.loads(rows[0]['client_json'])
    return {**client, 'dynamic': True, 'resources': [r for r in client['resources'] if r in cfg['resources']]}


async def anonymous_limit(request, db, prefix='', ip_limit=10, global_limit=100):
    window = int(time.time()) // 3600
    await query(db, 'DELETE FROM mcp_oauth_registration_limits WHERE window_start < :window', window=window - 1)
    for key, limit in ((prefix + digest(request.client.host if request.client else 'unknown'), ip_limit), (prefix + 'global', global_limit)):
        row = await query(db, '''INSERT INTO mcp_oauth_registration_limits (id, window_start, requests)
            VALUES (:id, :window, 1) ON CONFLICT(id) DO UPDATE SET window_start = excluded.window_start,
            requests = CASE WHEN mcp_oauth_registration_limits.window_start = excluded.window_start THEN mcp_oauth_registration_limits.requests + 1 ELSE 1 END
            WHERE mcp_oauth_registration_limits.window_start != excluded.window_start OR mcp_oauth_registration_limits.requests < :limit RETURNING id''',
            id=key, window=window, limit=limit)
        if not row:
            raise OAuthError('too_many_requests', 429)


async def register_client(request, db, cfg):
    if not settings.mcp_oauth_dynamic_registration:
        raise OAuthError('registration_not_supported', 403)
    await anonymous_limit(request, db)
    if not request.headers.get('content-type', '').startswith('application/json'):
        raise OAuthError('invalid_client_metadata')
    try:
        p = json.loads(await bounded_body(request))
    except (ValueError, OAuthError):
        raise OAuthError('invalid_client_metadata')
    if not isinstance(p, dict):
        raise OAuthError('invalid_client_metadata')
    method = p.get('token_endpoint_auth_method', 'client_secret_basic')
    if method not in ('none', 'client_secret_basic', 'client_secret_post'):
        raise OAuthError('invalid_client_metadata')
    redirects = p.get('redirect_uris')
    if not isinstance(redirects, list) or not 1 <= len(redirects) <= 5:
        raise OAuthError('invalid_redirect_uri')
    for uri in redirects:
        try:
            if not isinstance(uri, str) or len(uri) > 2000 or '*' in uri:
                raise ValueError()
            if method == 'none' and loopback(uri):
                continue
            https(uri)
        except ValueError:
            raise OAuthError('invalid_redirect_uri')
    for field, allowed in (('grant_types', ['authorization_code', 'refresh_token']), ('response_types', ['code'])):
        value = p.get(field)
        if field in p and (not isinstance(value, list) or not value or any(v not in allowed for v in value)):
            raise OAuthError('invalid_client_metadata')
    if 'grant_types' in p and 'authorization_code' not in p['grant_types']:
        raise OAuthError('invalid_client_metadata')
    name = p.get('client_name', 'MCP client')
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or re.search('[\x00-\x1f\x7f]', name):
        raise OAuthError('invalid_client_metadata')
    if 'scope' in p and (not isinstance(p['scope'], str) or len(p['scope']) > 1000):
        raise OAuthError('invalid_client_metadata')
    requested = list(dict.fromkeys(p['scope'].split(' '))) if 'scope' in p else SCOPES
    requested = [s for s in requested if s]
    if SCOPES[0] not in requested or any(s not in SCOPES for s in requested):
        raise OAuthError('invalid_client_metadata')
    client_id = 'mcp_dynamic_' + secrets.token_urlsafe(32)
    secret = None if method == 'none' else 'mcp_client_' + secrets.token_urlsafe(32)
    client = dict(name=name.strip(), redirectUris=list(dict.fromkeys(redirects)), resources=list(cfg['resources']), scopes=requested,
                  tokenEndpointAuthMethod=method, dynamic=True)
    if secret:
        client['secretHash'] = digest(secret)
    issued = int(time.time())
    inserted = await query(db, '''INSERT INTO mcp_oauth_clients (id, client_json, created_at)
        SELECT :id, :client, :created WHERE (SELECT COUNT(*) FROM mcp_oauth_clients) < 10000 RETURNING id''',
        id=client_id, client=json.dumps(client), created=issued)
    if not inserted:
        raise OAuthError('too_many_requests', 429)
    result = dict(client_id=client_id, client_id_issued_at=issued, client_name=client['name'], redirect_uris=client['redirectUris'],
                  token_endpoint_auth_method=method, grant_types=['authorization_code', 'refresh_token'], response_types=['code'], scope=' '.join(requested))
    if secret:
        result.update(client_secret=secret, client_secret_expires_at=0)
    return JSONResponse(result, status_code=201, headers=HEADERS)


async def authenticate_client(request, p, cfg, db):
    client_id, secret = p.get('client_id', ''), p.get('client_secret', '')
    auth = request.headers.get('authorization')
    if auth:
        try:
            if not auth.startswith('Basic ') or secret:
                raise ValueError()
            basic_id, secret = (unquote(v) for v in base64.b64decode(auth[6:], validate=True).decode().split(':', 1))
            if client_id and client_id != basic_id:
                raise ValueError()
            client_id = basic_id
        except (ValueError, UnicodeError):
            raise OAuthError('invalid_client', 401)
    client = await get_client(db, cfg, client_id)
    if not client:
        raise OAuthError('invalid_client', 401)
    if client.get('tokenEndpointAuthMethod') == 'none':
        if auth or 'client_secret' in p:
            raise OAuthError('invalid_client', 401)
    elif ((client.get('tokenEndpointAuthMethod') == 'client_secret_basic' and not auth)
          or (client.get('tokenEndpointAuthMethod') == 'client_secret_post' and auth)
          or len(secret) < 32 or not hmac.compare_digest(digest(secret), client['secretHash'])):
        raise OAuthError('invalid_client', 401)
    return client_id, client


async def valid_grant(cfg, grant, db):
    client = await get_client(db, cfg, grant['client_id'])
    return (not grant['revoked'] and grant['expires_at'] > int(time.time()) and client
            and grant['resource'] in client['resources'] and all(s in client['scopes'] for s in grant['scope'].split()))


async def tokens(db, cfg, grant):
    issued = int(time.time())
    access = jwt.encode(dict(scope=grant['scope'], client_id=grant['client_id'], grant_id=grant['id'],
        iss=cfg['issuer'], aud=grant['resource'], sub=grant['subject'], iat=issued, exp=issued + 300, jti=str(uuid4())),
        cfg['key'], algorithm='ES256', headers={'kid': cfg['key']['kid'], 'typ': 'at+jwt'})
    refresh = 'mcp_refresh_' + secrets.token_urlsafe(32)
    await query(db, 'INSERT INTO mcp_oauth_refresh (hash, grant_id) VALUES (:hash, :grant)', hash=digest(refresh), grant=grant['id'])
    return dict(access_token=access, token_type='Bearer', expires_in=300, refresh_token=refresh, scope=grant['scope'])


def response(data):
    return JSONResponse(data, headers=HEADERS)


async def authorization_request(request, cfg, db):
    p = parameters(request.query_params.multi_items())
    if str(request.url).split('/oauth/')[0] != cfg['issuer'] or len(request.url.query) > 8192:
        raise OAuthError('invalid_request')
    client = await get_client(db, cfg, p.get('client_id'))
    if client and 'resource' not in p and len(client['resources']) == 1:
        p['resource'] = client['resources'][0]
    if not client or not redirect_allowed(client, p.get('redirect_uri', '')) or p.get('resource') not in client['resources']:
        raise OAuthError('invalid_request')
    requested = list(dict.fromkeys(p.get('scope', '').split()))
    if SCOPES[0] not in requested or any(s not in client['scopes'] for s in requested):
        raise OAuthError('invalid_scope')
    if p.get('response_type') != 'code' or p.get('code_challenge_method') != 'S256' or not re.fullmatch('[A-Za-z0-9_-]{43}', p.get('code_challenge', '')):
        raise OAuthError('invalid_request')
    return p, client, requested


router = APIRouter()


@router.api_route('/.well-known/oauth-authorization-server', methods=['GET'])
@router.api_route('/oauth/mcp/{endpoint}', methods=['GET', 'POST'])
async def dispatch(request: Request, endpoint: str = '', db=Depends(get_session)):
    try:
        return await handle(request, endpoint, db)
    except OAuthError as exc:
        return JSONResponse({'error': exc.code}, status_code=exc.status, headers=HEADERS)
    except Exception:
        # OAuth responses never expose SQL, tokens, or configuration values.
        await db.rollback()
        return JSONResponse({'error': 'server_error'}, status_code=503, headers=HEADERS)


async def handle(request, endpoint, db):
    cfg = configuration()
    issuer, now = cfg['issuer'], int(time.time())
    if endpoint == 'handoff':
        return await login_handoff(request, db, cfg)
    if endpoint == 'resume':
        return await resume_login(request, db, cfg)
    if not endpoint:
        return response(dict(issuer=issuer, authorization_endpoint=issuer + '/oauth/mcp/authorize',
            **({'registration_endpoint': issuer + '/oauth/mcp/register'} if settings.mcp_oauth_dynamic_registration else {}),
            token_endpoint=issuer + '/oauth/mcp/token', revocation_endpoint=issuer + '/oauth/mcp/revoke',
            introspection_endpoint=issuer + '/oauth/mcp/introspect', jwks_uri=issuer + '/.well-known/jwks.json',
            response_types_supported=['code'], grant_types_supported=['authorization_code', 'refresh_token'],
            code_challenge_methods_supported=['S256'], scopes_supported=SCOPES,
            authorization_response_iss_parameter_supported=True,
            token_endpoint_auth_methods_supported=['client_secret_basic', 'client_secret_post', 'none']))
    if endpoint == 'register':
        if request.method != 'POST':
            return Response(status_code=405, headers=HEADERS)
        return await register_client(request, db, cfg)
    if endpoint in ('authorize', 'connections'):
        if endpoint == 'authorize' and request.method == 'GET':
            p, client, requested = await authorization_request(request, cfg, db)
        resource = p['resource'] if endpoint == 'authorize' and request.method == 'GET' else None
        actor = None if resource and p.get('prompt') == 'login' else await session(request, db, resource)
        if request.method == 'GET' and not actor:
            params = dict(request.query_params)
            params.pop('prompt', None)
            return_path = request.url.path + ('?' + urlencode(params) if params else '')
            if resource in cfg['portals']:
                return await start_login(request, db, cfg, resource, return_path)
            if endpoint == 'connections' and cfg['portals']:
                resource = request.query_params.get('resource')
                if not resource and len(cfg['portals']) == 1:
                    resource = next(iter(cfg['portals']))
                return await start_login(request, db, cfg, resource, return_path)
            return RedirectResponse(issuer + '/app/login?next=' + quote(return_path, safe=''), status_code=303, headers=HEADERS)
        if request.method == 'POST':
            if request.headers.get('origin') != issuer:
                raise OAuthError('invalid_request', 403)
            if not actor:
                raise OAuthError('login_required', 401)
        if endpoint == 'connections':
            csrf = digest(actor['hash'] + ':mcp-revoke')
            if request.method == 'POST':
                p = await form(request)
                if not hmac.compare_digest(p.get('csrf', ''), csrf):
                    raise OAuthError('invalid_request', 403)
                await query(db, 'UPDATE mcp_oauth_grants SET revoked = 1 WHERE id = :id AND subject = :subject',
                            id=p.get('grant', ''), subject=actor['subject'])
                return RedirectResponse('/oauth/mcp/connections', status_code=303, headers=HEADERS)
            rows = await query(db, 'SELECT * FROM mcp_oauth_grants WHERE subject = :subject AND revoked = 0 AND expires_at > :now ORDER BY expires_at DESC LIMIT 100', subject=actor['subject'], now=now)
            items = ''.join(f'<form method="post"><p>{html.escape(g["client_id"])} - {html.escape(g["resource"])} ({html.escape(g["scope"])})</p><input type="hidden" name="grant" value="{html.escape(g["id"])}"><input type="hidden" name="csrf" value="{csrf}"><button>Revoke access</button></form>' for g in rows)
            return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><title>Connected apps</title><main><h1>Connected event apps</h1>' + (items or '<p>No active connections.</p>') + '</main></html>', headers=HEADERS)
        if request.method == 'GET':
            await query(db, 'DELETE FROM mcp_oauth_requests WHERE expires_at < :now', now=now)
            count = await query(db, 'SELECT COUNT(*) AS n FROM mcp_oauth_requests WHERE session_hash = :hash', hash=actor['hash'])
            if count[0]['n'] >= 20:
                raise OAuthError('too_many_requests', 429)
            nonce = 'consent_' + secrets.token_urlsafe(32)
            await query(db, 'INSERT INTO mcp_oauth_requests VALUES (:id, :session_hash, :subject, :client_id, :redirect_uri, :resource, :scope, :challenge, :state, :expires_at)',
                id=digest(nonce), session_hash=actor['hash'], subject=actor['subject'], client_id=p['client_id'],
                redirect_uri=p['redirect_uri'], resource=p['resource'], scope=' '.join(requested), challenge=p['code_challenge'], state=p.get('state', ''), expires_at=now + 600)
            portal = cfg['portals'].get(p['resource'])
            markup, policy = render_consent_page(client=client['name'], account=actor['display'], resource=p['resource'],
                callback=p['redirect_uri'], request=nonce, change_account='/oauth/mcp/authorize?' + urlencode({**p, 'prompt': 'login'}),
                requested=requested, dynamic=bool(client.get('dynamic')), portal=portal)
            headers = consent_headers(p['redirect_uri'])
            headers['Content-Security-Policy'] += '; ' + policy
            return HTMLResponse(markup, headers=headers)
        p = await form(request)
        if p.get('decision') not in ('allow', 'deny'):
            raise OAuthError('invalid_request')
        rows = await query(db, 'DELETE FROM mcp_oauth_requests WHERE id = :id AND session_hash = :hash AND subject = :subject AND expires_at >= :now RETURNING *',
            id=digest(p.get('request', '')), hash=actor['hash'], subject=actor['subject'], now=now)
        if not rows:
            raise OAuthError('invalid_request')
        row = rows[0]
        client = await get_client(db, cfg, row['client_id'])
        if not client or not redirect_allowed(client, row['redirect_uri']) or row['resource'] not in client['resources'] or any(s not in client['scopes'] for s in row['scope'].split()):
            raise OAuthError('invalid_request')
        target = urlsplit(row['redirect_uri'])
        params = dict(parse_qsl(target.query))
        params.update(state=row['state'], iss=issuer)
        if p['decision'] == 'deny':
            params['error'] = 'access_denied'
        else:
            code = 'mcp_code_' + secrets.token_urlsafe(32)
            await query(db, 'INSERT INTO mcp_oauth_codes VALUES (:hash, :subject, :client_id, :redirect_uri, :resource, :scope, :challenge, :expires_at)',
                hash=digest(code), **{k: row[k] for k in ('subject', 'client_id', 'redirect_uri', 'resource', 'scope', 'challenge')}, expires_at=now + 120)
            params['code'] = code
        return RedirectResponse(urlunsplit(target._replace(query=urlencode(params))), status_code=303, headers=consent_headers(row['redirect_uri']))
    if request.method != 'POST':
        return Response(status_code=405, headers=HEADERS)
    p = await form(request)
    if endpoint == 'introspect':
        resource = p.get('resource', '')
        binding = cfg['resources'].get(resource)
        auth = request.headers.get('authorization', '')
        secret = auth[7:] if auth.startswith('Bearer ') else ''
        if not binding or len(secret) < 32 or not hmac.compare_digest(digest(secret), binding['secretHash']):
            raise OAuthError('invalid_client', 401)
        try:
            header = jwt.get_unverified_header(p.get('token', ''))
            key = next(k for k in cfg['keys'] if k['kid'] == header.get('kid'))
            if header.get('typ') != 'at+jwt':
                raise ValueError()
            payload = jwt.decode(p.get('token', ''), key, algorithms=['ES256'], issuer=issuer, audience=resource,
                options={f'require_{k}': True for k in ('sub', 'exp', 'iat', 'jti')})
        except Exception:
            return response({'active': False})
        rows = await query(db, 'SELECT * FROM mcp_oauth_grants WHERE id = :id', id=payload.get('grant_id'))
        grant = rows[0] if rows else None
        if not grant or not await valid_grant(cfg, grant, db) or grant['resource'] != resource or grant['subject'] != payload['sub'] or grant['scope'] != payload.get('scope') or not await active_subject(db, grant['subject']):
            return response({'active': False})
        return response(dict(active=True, **{k: payload[k] for k in ('sub', 'iss', 'aud', 'scope', 'exp')}))
    client_id, client = await authenticate_client(request, p, cfg, db)
    if endpoint == 'revoke':
        await query(db, 'UPDATE mcp_oauth_grants SET revoked = 1 WHERE client_id = :client AND id IN (SELECT grant_id FROM mcp_oauth_refresh WHERE hash = :hash)', client=client_id, hash=digest(p.get('token', '')))
        return Response(status_code=200, headers=HEADERS)
    if endpoint != 'token':
        return Response(status_code=404, headers=HEADERS)
    if p.get('grant_type') == 'authorization_code':
        verifier = p.get('code_verifier', '')
        if not re.fullmatch('[A-Za-z0-9._~-]{43,128}', verifier):
            raise OAuthError('invalid_grant')
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        rows = await query(db, 'DELETE FROM mcp_oauth_codes WHERE hash = :hash AND client_id = :client_id AND redirect_uri = :redirect_uri AND resource = :resource AND challenge = :challenge AND expires_at >= :now RETURNING *',
            hash=digest(p.get('code', '')), client_id=client_id, redirect_uri=p.get('redirect_uri', ''),
            resource=p.get('resource', client['resources'][0] if len(client['resources']) == 1 else ''), challenge=challenge, now=now)
        if not rows:
            raise OAuthError('invalid_grant')
        row = rows[0]
        if row['resource'] not in client['resources'] or any(s not in client['scopes'] for s in row['scope'].split()) or not await active_subject(db, row['subject']):
            raise OAuthError('invalid_grant')
        grant = dict(id=str(uuid4()), subject=row['subject'], client_id=client_id, resource=row['resource'], scope=row['scope'], expires_at=now + 2592000, revoked=0)
        await query(db, 'INSERT INTO mcp_oauth_grants VALUES (:id, :subject, :client_id, :resource, :scope, :expires_at, :revoked)', **grant)
        return response(await tokens(db, cfg, grant))
    if p.get('grant_type') != 'refresh_token':
        raise OAuthError('unsupported_grant_type')
    hash_value = digest(p.get('refresh_token', ''))
    rows = await query(db, 'SELECT g.*, r.used FROM mcp_oauth_refresh r JOIN mcp_oauth_grants g ON g.id = r.grant_id WHERE r.hash = :hash AND g.client_id = :client', hash=hash_value, client=client_id)
    if not rows or not await valid_grant(cfg, rows[0], db) or not await active_subject(db, rows[0]['subject']):
        raise OAuthError('invalid_grant')
    grant = rows[0]
    if any(k in p and p[k] != grant[k] for k in ('resource', 'scope')):
        raise OAuthError('invalid_scope')
    claimed = await query(db, 'UPDATE mcp_oauth_refresh SET used = 1 WHERE hash = :hash AND used = 0 RETURNING hash', hash=hash_value)
    if not claimed:
        await query(db, 'UPDATE mcp_oauth_grants SET revoked = 1 WHERE id = :id', id=grant['id'])
        raise OAuthError('invalid_grant')
    return response(await tokens(db, cfg, grant))

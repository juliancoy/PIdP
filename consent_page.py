"""Shared, script-free consent presentation for Python and the Worker."""
import base64
import hashlib
import html
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

PAGE = json.loads((Path(__file__).parent / 'shared/mcp-consent.json').read_text())


def render_consent_page(*, client, account, resource, callback, request, change_account, requested, dynamic, portal=None, system_admin_login=False):
    url = urlsplit(portal['loginUrl'] if portal else resource)
    origin = url.scheme + '://' + url.netloc
    brand = PAGE['brands'].get(url.netloc)
    css = '\n'.join(PAGE['css'])
    style_hash = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    values = {key: html.escape(value) for key, value in dict(
        client=client, account=account, shortName=brand['shortName'] if brand else (portal['name'] if portal else 'OrgPortal'),
        brandName=brand['name'] if brand else (portal['name'] if portal else 'OrgPortal'),
        tagline=brand['tagline'] if brand else 'ACCOUNT AUTHORIZATION', portalUrl=origin, portalHost=url.netloc,
        resource=resource, callback=callback, request=request, changeAccount=change_account).items()}
    other_url = urlsplit(change_account)
    other_params = dict(parse_qsl(other_url.query)); other_params['browser'] = 'other'
    other_browser = urlunsplit(('', '', other_url.path, urlencode(other_params), ''))
    values['otherBrowser'] = f'<p><a href="{html.escape(other_browser)}">Use another browser</a></p>' if portal and not system_admin_login else ''
    values['accountMode'] = '<input type="hidden" name="account" value="system_admin">' if system_admin_login else ''
    admin_params = dict(parse_qsl(other_url.query))
    admin_params['account'] = 'system_admin'
    admin_params.pop('browser', None)
    admin_login = urlunsplit(('', '', other_url.path, urlencode(admin_params), ''))
    values['systemAdmin'] = ('<p>System administrator access. Group membership is not required to manage group profiles.</p>'
                            if system_admin_login else f'<p><a href="{html.escape(admin_login)}">Sign in as a system administrator</a></p>')
    values['css'] = css
    values['logo'] = f'<img src="{html.escape(brand["logo"])}" alt="{html.escape(brand["name"])} logo" width="52" height="52">' if brand else ''
    values['permissions'] = ''.join(
        f'<li><span class="check" aria-hidden="true">&#10003;</span><div><strong>{html.escape(PAGE["permissions"][scope][0])}</strong><p>{html.escape(PAGE["permissions"][scope][1])}</p></div></li>'
        for scope in requested)
    values['notice'] = '<p class="client-notice">This client name is self-reported, not verified by PIdP. Only continue if you started this connection.</p>' if dynamic else ''
    logo = urlsplit(brand['logo']) if brand else None
    image_origin = logo.scheme + '://' + logo.netloc if logo else "'none'"
    return (re.sub(r'\{\{(\w+)\}\}', lambda match: values[match[1]], '\n'.join(PAGE['html'])),
            f"style-src 'sha256-{style_hash}'; img-src {image_origin}")

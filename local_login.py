"""Password-free entry for the explicitly configured localhost developer admin."""
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5
from pathlib import Path
from ipaddress import IPv4Address

from config import settings


def local_login_enabled(request):
    loopback = {'localhost', 'id.localhost', '127.0.0.1', '::1'}
    # Docker forwards host-local connections with its bridge gateway as source.
    if Path('/.dockerenv').exists():
        for line in Path('/proc/net/route').read_text().splitlines()[1:]:
            fields = line.split()
            if fields[1] == '00000000':
                loopback.add(str(IPv4Address(bytes.fromhex(fields[2])[::-1])))
    client = request.headers.get('x-forwarded-for', '').split(',')[-1].strip()
    if not client and request.client:
        client = request.client.host
    origin = request.headers.get('origin')
    return (
        settings.env == 'dev'
        and urlsplit(settings.public_base_url or '').hostname in loopback
        and request.url.hostname in loopback
        and client in loopback
        and request.headers.get('sec-fetch-site') not in {'cross-site', 'same-site'}
        and (not origin or origin == f'{request.url.scheme}://{request.url.netloc}')
        and str(uuid5(NAMESPACE_URL, 'orgportal:local-developer-admin')) in settings.admin_user_ids_list
    )

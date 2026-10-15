"""Keep generated identity links on an explicitly configured public mount."""
import re

_IDENTITY = re.compile(r'^/(?:app(?:[/?]|$)|profile(?:[/?]|$)|u/|assets/|avatars/|auth/(?!callback(?:[/?]|$))|session/|websites(?:[/?]|$))')

def mounted_identity_path(path, prefix):
    return prefix + path if prefix and _IDENTITY.match(path) else path

def rewrite_identity_html(html, prefix):
    return re.sub(r'''((?:href|src|action)=["'])(/[^"']*)(["'])''',
                  lambda match: match[1] + mounted_identity_path(match[2], prefix) + match[3], html)

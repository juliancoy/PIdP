"""Provider account suggestions are hints only, never authenticated identities."""
import re


def google_login_hint(provider, value):
    if provider == 'google' and isinstance(value, str) and re.fullmatch(r'[0-9]{1,255}', value):
        return value
    return None

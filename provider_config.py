"""Do not advertise example OAuth credentials as a configured provider."""
def provider_enabled(provider, client_id, client_secret):
    if provider not in ('google', 'github'):
        return False
    placeholders = {f'{provider}-client-id', f'{provider}-client-secret', 'changeme'}
    return all(isinstance(value, str) and value.strip() and value.strip().lower() not in placeholders
               for value in (client_id, client_secret))

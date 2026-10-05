// Suggestions only: authentication still requires OAuth state/PKCE/code exchange.
export function googleLoginHint(provider: string | undefined, value: string | undefined): string | undefined {
  return provider === 'google' && value && value === value.trim() && /^[0-9]{1,255}$/.test(value) ? value : undefined;
}

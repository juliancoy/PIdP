import type { Env } from './types';

// PUBLIC_BASE_URL may include a mount path. Leading-slash URL resolution would
// discard that path and send identity traffic into the portal application.
export function identityUrl(env: Env, path: string, fallback = 'https://id.codecollective.us'): URL {
  return new URL(`${(env.PUBLIC_BASE_URL || new URL(fallback).origin).replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`);
}
export function identityPath(env: Env, path: string): string {
  const prefix = new URL(env.PUBLIC_BASE_URL || 'https://id.codecollective.us').pathname.replace(/\/+$/, '');
  return prefix && (path === prefix || path.startsWith(prefix + '/')) ? path.slice(prefix.length) || '/' : path;
}
export function mountedIdentityPath(path: string, prefix: string): string {
  if (!prefix || !/^\/(?:app(?:[/?]|$)|profile(?:[/?]|$)|u\/|assets\/|avatars\/|auth\/(?!callback(?:[/?]|$))|session\/|websites(?:[/?]|$))/.test(path)) return path;
  return prefix + path;
}

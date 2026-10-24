import type { Env, UserRow, WebsiteUserRow } from './types';
import { randomToken, sha256Hex } from './crypto';
import { HttpError } from './http';
import { identityUrl } from './identityUrls';

type Account = UserRow | WebsiteUserRow;
export function emailVerified(env: Env, user: Account): boolean {
  if (env.EMAIL_VERIFICATION_REQUIRED === 'false') return true;
  const identity = JSON.parse(user.identity_data || '{}');
  return Boolean((user.provider && user.provider_account_id) || identity.email_verified === true || identity.email_verified_at);
}
export function requireVerifiedEmail(env: Env, user: Account): void {
  if (!emailVerified(env, user)) throw new HttpError(403, 'Email verification required');
}
export async function sendVerification(env: Env, user: Account, app = '', next = '/profile'): Promise<void> {
  if (emailVerified(env, user)) return;
  if (!env.EMAIL || !env.EMAIL_FROM) throw new HttpError(503, 'Email delivery is not configured. Please try again later.');
  const identity = JSON.parse(user.identity_data || '{}');
  if (Date.parse(identity.email_verification?.sent_at || '') > Date.now() - 60_000) return;
  const token = randomToken('');
  const url = identityUrl(env, '/auth/verify-email');
  url.search = new URLSearchParams({email:user.email,token,...(app ? {app} : {})}).toString();
  identity.email_verified = false;
  identity.email_verification = {token_hash:await sha256Hex(token), sent_at:new Date().toISOString(), expires_at:new Date(Date.now()+86400_000).toISOString(), next};
  const table = 'website_id' in user ? 'website_users' : 'users';
  const updated = JSON.stringify(identity);
  const result = await env.DB.prepare(`UPDATE ${table} SET identity_data = ? WHERE id = ? AND identity_data = ?`).bind(updated,user.id,user.identity_data).run();
  if (!result.meta.changes) return;
  try {
    await env.EMAIL.send({from:env.EMAIL_FROM,to:user.email,subject:'Verify your email address',text:`Verify your email address to finish setting up your account:\n\n${url}\n\nThis link expires in 24 hours. If you did not request this, ignore this email.`});
  } catch {
    await env.DB.prepare(`UPDATE ${table} SET identity_data = ? WHERE id = ? AND identity_data = ?`).bind(user.identity_data,user.id,updated).run();
    throw new HttpError(503, 'Unable to send verification email. Please try again later.');
  }
}
export async function consumeVerification(env: Env, user: Account, token: string): Promise<string | null> {
  const identity = JSON.parse(user.identity_data || '{}');
  const pending = identity.email_verification;
  if (!pending || !token || pending.token_hash !== await sha256Hex(token) || !(Date.parse(pending.expires_at) > Date.now())) return null;
  delete identity.email_verification;
  identity.email_verified = true;
  identity.email_verified_at = new Date().toISOString();
  const table = 'website_id' in user ? 'website_users' : 'users';
  const result = await env.DB.prepare(`UPDATE ${table} SET identity_data = ? WHERE id = ? AND identity_data = ?`).bind(JSON.stringify(identity),user.id,user.identity_data).run();
  return result.meta.changes ? pending.next || '/profile' : null;
}

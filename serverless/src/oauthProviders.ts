import type { Env } from './types';
export function providerEnabled(env: Env, provider: string): boolean {
 if(provider!=='google' && provider!=='github')return false;
 const values=provider==='google'?[env.GOOGLE_CLIENT_ID,env.GOOGLE_CLIENT_SECRET]:[env.GITHUB_CLIENT_ID,env.GITHUB_CLIENT_SECRET];
 const placeholders=new Set([`${provider}-client-id`,`${provider}-client-secret`,'changeme']);
 return values.every(value=>typeof value==='string' && Boolean(value.trim()) && !placeholders.has(value.trim().toLowerCase()));
}

import defaults from '../../shared/portal-clients.json';
import type { Env } from './types';
export type PortalClient = { name: string; accountApp: string; callbacks: string[]; restartOrigin?: string };
const unsafe = (value: string) => /[\\\u0000-\u0020\u007f]/.test(value);
export function localDestination(value: string): boolean {
 return value.startsWith('/') && !value.startsWith('//') && !unsafe(value);
}
export function portalClient(env: Env, origin: string): PortalClient | null {
 if(!(env.PORTAL_AUTH_ORIGINS||'').split(',').map(s=>s.trim()).includes(origin))return null;
 try {
  const registry = env.PORTAL_CLIENTS_JSON ? JSON.parse(env.PORTAL_CLIENTS_JSON) : defaults;
  const item = Object.hasOwn(registry,origin) ? registry[origin] : null;
  if(!item || typeof item.name!=='string' || !item.name.trim() || typeof item.accountApp!=='string' || !/^[a-z0-9][a-z0-9-]*$/.test(item.accountApp) || !Array.isArray(item.callbacks) || !item.callbacks.length || item.callbacks.some((p:unknown)=>typeof p!=='string'||!localDestination(p)||/[?#]/.test(p)))return null;
  const parsed = new URL(origin);
  if(parsed.origin!==origin || parsed.username || parsed.password || !['http:','https:'].includes(parsed.protocol))return null;
  if(item.restartOrigin && (typeof item.restartOrigin!=='string'||item.restartOrigin===origin||!portalClientWithoutRestart(env,item.restartOrigin,registry)))return null;
  return item;
 }catch{return null}
}
function portalClientWithoutRestart(env:Env,origin:string,registry:Record<string,PortalClient>){
 const item=registry[origin];return item && !item.restartOrigin && (env.PORTAL_AUTH_ORIGINS||'').split(',').map(s=>s.trim()).includes(origin) && new URL(origin).origin===origin;
}
export function ssoReturn(env:Env,origin:string,app:string,value:string): URL | null {
 const client=portalClient(env,origin);if(!client || client.accountApp!==app || unsafe(value))return null;
 try {
  const target=new URL(value,origin);
  if(target.origin!==origin || target.username || target.password || target.hash || value.startsWith('//'))return null;
  const bridge=target.pathname==='/pidp/oauth/mcp/link';
  if(bridge){
   if([...target.searchParams.keys()].some(k=>k!=='request') || target.searchParams.getAll('request').length!==1 || !/^login_[A-Za-z0-9_-]{43,100}$/.test(target.searchParams.get('request')||''))return null;
  }else{
   if(!client.callbacks.includes(target.pathname) || [...target.searchParams.keys()].some(k=>k!=='next') || target.searchParams.getAll('next').length>1)return null;
   const next=target.searchParams.get('next');if(next && !localDestination(next))return null;
  }
  return target;
 }catch{return null}
}
export async function loginPortal(env:Env,app:string,next:string,requestOrigin?:string):Promise<PortalClient|null>{
 const direct=requestOrigin ? portalClient(env,requestOrigin) : null;
 if(direct?.accountApp===app)return direct;
 try{
  const target=new URL(next,env.PUBLIC_BASE_URL);
  const issuer=new URL(env.PUBLIC_BASE_URL!).origin;
  if(target.origin!==issuer || target.username || target.password)return null;
  const ticketParam=target.pathname==='/auth/sso/authorize'?'request':['/auth/account-links/finish','/auth/account-links/connect'].includes(target.pathname)?'sso':null;
  if(ticketParam && target.searchParams.getAll(ticketParam).length===1 && env.DB){
   const row=await env.DB.prepare('SELECT origin,app,next FROM portal_sso_requests WHERE id=? AND expires_at>=? AND code_hash IS NULL').bind(target.searchParams.get(ticketParam),Math.floor(Date.now()/1000)).first<{origin:string;app:string;next:string}>();
   if(row?.app===app && ssoReturn(env,row.origin,row.app,row.next))return portalClient(env,row.origin);
  }
 }catch{return null}
 return null;
}

export function browserReturn(env:Env,value:string,extraOrigins:string[]=[]):string|null{
 if(localDestination(value))return value;
 if(unsafe(value)||value.startsWith('/'))return null;
 try{
  const target=new URL(value);if(target.username||target.password)return null;
  const native=(env.NATIVE_REDIRECT_SCHEMES||'').split(',').map(s=>s.trim().replace(/:$/,''));
  if(!['http:','https:'].includes(target.protocol))return native.includes(target.protocol.slice(0,-1))?value:null;
  const configured=[env.PUBLIC_BASE_URL,env.FRONTEND_REDIRECT_URL].filter(Boolean).map(s=>new URL(s!).origin);
  if(configured.includes(target.origin)||extraOrigins.includes(target.origin)||portalClient(env,target.origin))return value;
 }catch{ /* Invalid or unregistered destinations fail closed. */ }
 return null;
}

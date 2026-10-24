import {browserSession} from './browserSessions';
import { identityUrl } from './identityUrls';
import {identityDocument, portalLoginBrand} from './identityPage';
import { Hono, type Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { randomToken, sha256Hex, verifyJwt } from './crypto';
import { websiteBySlug, websiteUserById, userById } from './db';
import type { Env } from './types';
import { googleLoginHint } from './loginHints';
import { portalClient, ssoReturn, sharedIdentity } from './portalClients';

const escapeHtml=(v:string)=>v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
type DesktopTicket = {id:string; redirect_uri:string;challenge:string;state:string;expires_at:number};
function nativeRequest(params:URLSearchParams) {
 const keys=['redirect_uri','code_challenge','code_challenge_method','state'];
 if(!keys.some(key=>params.has(key)))return null;
 const uri=params.get('redirect_uri')||'';
 try {
  const url=new URL(uri);
  if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||!url.port||url.pathname!=='/callback'||url.username||url.password||url.search||url.hash||uri!==`http://127.0.0.1:${url.port}/callback`)throw Error();
  if(params.get('code_challenge_method')!=='S256'||!(/^[A-Za-z0-9_-]{43}$/).test(params.get('code_challenge')||'')||!(/^[A-Za-z0-9_-]{43,128}$/).test(params.get('state')||''))throw Error();
  return {redirect_uri:uri,challenge:params.get('code_challenge')!,state:params.get('state')!};
 }catch{throw Error('invalid_native_request')}
}
async function pkceChallenge(verifier:string) {
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier)));
 return btoa(String.fromCharCode(...digest)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
}
const browserCookie = '__Host-pidp_sso_browser';
type Ticket = { id: string; browser_hash: string; origin: string; next: string; website_id: string; app: string; subject: string | null; code_hash: string | null; expires_at: number; auth_time: number | null };
const now = () => Math.floor(Date.now()/1000);
function origin(c: Context<{ Bindings: Env }>) {
 const host = c.req.header('x-forwarded-host');
 return host && c.req.header('x-forwarded-proto') === 'https' ? `https://${host}` : new URL(c.req.url).origin;
}
export function portalSso(issue: (env: Env, subject: string, authTime?: number) => Promise<string>) {
 const app = new Hono<{Bindings:Env}>();
 app.use('/auth/sso/*', async (c,next) => { c.header('Cache-Control','no-store');c.header('Referrer-Policy','no-referrer');const params=new URL(c.req.url).searchParams;for(const key of params.keys())if(params.getAll(key).length!==1)return c.json({error:'invalid_request'},400);await next(); });
 app.get('/auth/sso/client',c=>{const client=portalClient(c.env,origin(c));return client?c.json({name:client.name,accountApp:client.accountApp,callbacks:client.callbacks,origin:client.restartOrigin||origin(c)}):c.json({error:'invalid_portal'},400)});
 app.get('/auth/sso/start', async c => {
  let native;try{native=nativeRequest(new URL(c.req.url).searchParams)}catch{return c.json({error:'invalid_native_request'},400)}
  const destination=origin(c),client=portalClient(c.env,destination);
  if(!client)return c.json({error:'invalid_portal'},400);
  const appSlug=c.req.query('app') || client.accountApp;
  if(appSlug!==client.accountApp)return c.json({error:'unknown_application'},400);
  const target=ssoReturn(c.env,destination,appSlug,c.req.query('next')||'/auth/callback');
  if(!target)return c.json({error:'invalid_return'},400);
  const prompt=c.req.query('prompt');if(prompt && !['select_account','login'].includes(prompt))return c.json({error:'invalid_prompt'},400);
  const provider=c.req.query('provider');if(provider && !['google','github'].includes(provider))return c.json({error:'invalid_provider'},400);
  if(native && client.restartOrigin)return c.json({error:'native_origin_requires_direct_registration'},400);
  if(client.restartOrigin){
   const destinationClient=portalClient(c.env,client.restartOrigin);if(!destinationClient)return c.json({error:'invalid_portal'},400);
   const callback=new URL('/auth/callback',client.restartOrigin);callback.search=target.search;
   const restart=new URL('/pidp/auth/sso/start',client.restartOrigin);restart.searchParams.set('app',destinationClient.accountApp);restart.searchParams.set('next',callback.toString());
   if(provider)restart.searchParams.set('provider',provider);if(prompt)restart.searchParams.set('prompt',prompt);
   const hint=googleLoginHint(provider,c.req.query('login_hint'));if(hint)restart.searchParams.set('login_hint',hint);
   return c.redirect(restart.toString(),303);
  }
  const website=await websiteBySlug(c.env.DB,appSlug);
  if(!website)return c.json({error:'application_not_registered'},503);
  const window = Math.floor(now()/60);
  await c.env.DB.prepare('DELETE FROM portal_sso_limits WHERE window_start < ?').bind(window-1).run();
  const permitted = await c.env.DB.prepare(`INSERT INTO portal_sso_limits(ip_hash,window_start,requests) VALUES(?,?,1)
    ON CONFLICT(ip_hash) DO UPDATE SET window_start=excluded.window_start,
    requests=CASE WHEN portal_sso_limits.window_start=excluded.window_start THEN portal_sso_limits.requests+1 ELSE 1 END
    WHERE portal_sso_limits.window_start!=excluded.window_start OR portal_sso_limits.requests<20 RETURNING ip_hash`)
    .bind(await sha256Hex(c.req.header('cf-connecting-ip') || 'unknown'),window).first();
  if (!permitted) return c.json({error:'too_many_requests'},429);
  const browser=randomToken(''), id=randomToken('');
  await c.env.DB.prepare('DELETE FROM portal_sso_requests WHERE expires_at < ?').bind(now()).run();
  await c.env.DB.prepare('INSERT INTO portal_sso_requests (id,browser_hash,origin,next,website_id,app,expires_at) VALUES (?,?,?,?,?,?,?)')
   .bind(id,await sha256Hex(native?browser+':'+native.challenge:browser),destination,target.toString(),website.id,appSlug,now()+600).run();
  await c.env.DB.prepare('DELETE FROM portal_desktop_requests WHERE expires_at < ?').bind(now()).run();
  if(native)await c.env.DB.prepare('INSERT INTO portal_desktop_requests(id,redirect_uri,challenge,state,expires_at) VALUES(?,?,?,?,?)').bind(id,native.redirect_uri,native.challenge,native.state,now()+600).run();
  setCookie(c,browserCookie,browser,{secure:true,httpOnly:true,sameSite:'Lax',path:'/',maxAge:600});
  const authorize=identityUrl(c.env,'/auth/sso/authorize');
  authorize.searchParams.set('request',id);
  if(provider)authorize.searchParams.set('provider',provider);if(prompt)authorize.searchParams.set('prompt',prompt);
  const hint=googleLoginHint(provider,c.req.query('login_hint'));
  if(hint)authorize.searchParams.set('login_hint',hint);
  return native?c.json({authorization_url:authorize.toString(),request:id,expires_in:600}):c.redirect(authorize.toString(),303);
 });
 app.get('/auth/sso/authorize', async c => {
  if(new URL(c.req.url).origin!==new URL(c.env.PUBLIC_BASE_URL || c.req.url).origin || c.req.header('x-forwarded-host'))return c.json({error:'issuer_required'},400);
  const row=await c.env.DB.prepare('SELECT * FROM portal_sso_requests WHERE id=?').bind(c.req.query('request') || '').first<Ticket>();
  const target=row && ssoReturn(c.env,row.origin,row.app,row.next);
  if(!row || !target || row.expires_at<now() || row.code_hash){
   const restart=new URL('/users/login','https://orgportal.cc');
   if(row && target){restart.href=new URL('/pidp/auth/sso/start',row.origin).toString();restart.search=new URLSearchParams({app:row.app,next:target.toString(),prompt:'select_account'}).toString()}
   c.header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action https://orgportal.cc "+new URL(identityUrl(c.env,'/app/login')).origin+' '+(row && target ? row.origin : '')+"; frame-ancestors 'none'; base-uri 'none'");
   return c.html(identityDocument('Expired request',`<h1>Expired request</h1><p>This sign-in request has expired or already been used. Start again to continue.</p><form method="get" action="${escapeHtml(restart.origin+restart.pathname)}">${Array.from(restart.searchParams,([name,value])=>`<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join('')}<button type="submit">Try again</button></form>`),400);
  }
  if(!row.website_id)return c.json({error:'application_not_registered'},503);
  const prompt=c.req.query('prompt');if(prompt && !['select_account','login'].includes(prompt))return c.json({error:'invalid_prompt'},400);
  if(prompt==='select_account'){
   const resume=identityUrl(c.env,'/auth/sso/authorize');resume.searchParams.set('request',row.id);
   const login=identityUrl(c.env,'/app/login');login.searchParams.set('app',row.app);login.searchParams.set('next',resume.toString());login.searchParams.set('prompt','login');
   let email='';try{const claims=await verifyJwt(c.env,getCookie(c,'pidp_session')||'');const user=claims.actor_type==='website_user'?await websiteUserById(c.env.DB,claims.website_id!,claims.sub):await userById(c.env.DB,claims.sub);if(user?.is_active && (claims.actor_type!=='website_user'||claims.website_id===row.website_id))email=user.email}catch{}
   if(!email)return c.redirect(login.toString(),303);
   const brand = portalLoginBrand(portalClient(c.env,row.origin)!.name);
   c.header('Content-Security-Policy',`default-src 'none'; style-src 'unsafe-inline'; img-src ${brand ? new URL(brand.logo_url).origin : "'none'"}; frame-ancestors 'none'; base-uri 'none'`);
   return c.html(identityDocument(`Sign in to ${escapeHtml(portalClient(c.env,row.origin)!.name)}`,`<h1>Choose an account</h1><p>Continue to ${escapeHtml(portalClient(c.env,row.origin)!.name)} at ${escapeHtml(new URL(row.origin).host)}.</p>${email?`<p><a href="${escapeHtml(resume.toString())}">Continue as ${escapeHtml(email)}</a></p>`:''}<p><a href="${escapeHtml(login.toString())}">Use another portal account</a></p><p><a href="${escapeHtml(row.origin)}">Cancel</a></p><p>Authentication provided by PIdP.</p>`,portalClient(c.env,row.origin)!.name));
  }
  let account,authTime=now();
  try { if(prompt==='login')throw new Error('Fresh sign-in required');const payload=await verifyJwt(c.env,getCookie(c,'pidp_session') || '');authTime=payload.auth_time||now();
   if(payload.actor_type==='website_user' && payload.website_id===row.website_id){
    const user=await websiteUserById(c.env.DB,row.website_id,payload.sub);
    if(user?.is_active)account=`website:${row.website_id}:${user.id}`;
   } else if((payload.actor_type || 'owner')==='owner'){
    const owner=await userById(c.env.DB,payload.sub);
    if(owner?.is_active){
     const linked=await c.env.DB.prepare(`SELECT member.id FROM website_users member
      JOIN account_identity_links link ON link.website_user_id=member.id
      WHERE link.canonical_user_id=? AND link.website_id=? AND member.website_id=? AND member.is_active=1`)
      .bind(owner.id,row.website_id,row.website_id).first<{id:string}>();
     if(!linked && !sharedIdentity(c.env,row.app)){
      const link=identityUrl(c.env,'/auth/account-links/connect');link.searchParams.set('app',row.app);link.searchParams.set('sso',row.id);
      const resume=identityUrl(c.env,'/auth/sso/authorize');resume.searchParams.set('request',row.id);
      const login=identityUrl(c.env,'/app/login');login.searchParams.set('app',row.app);login.searchParams.set('next',resume.toString());
      c.header('Referrer-Policy','same-origin');
      c.header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
      return c.html(identityDocument(`Continue to ${escapeHtml(portalClient(c.env,row.origin)!.name)}`,`<h1>Connect your ${escapeHtml(portalClient(c.env,row.origin)!.name)} account</h1><p>Continue to ${escapeHtml(portalClient(c.env,row.origin)!.name)} at ${escapeHtml(new URL(row.origin).host)}.</p><p>Signed in to PIdP as ${escapeHtml(owner.email)}. Connect your portal account to continue with the same identity.</p><p><a href="${link.toString().replaceAll('&','&amp;')}">Link my portal account</a></p><p><a href="${login.toString().replaceAll('&','&amp;')}">Sign in to the portal separately</a></p><form method="post" action="/auth/account-links/switch?${escapeHtml(new URLSearchParams({app:row.app,sso:row.id,account:"primary"}).toString())}"><button>Use another PIdP account</button></form><p><a href="${escapeHtml(row.origin)}">Cancel and return to ${escapeHtml(portalClient(c.env,row.origin)!.name)}</a></p><p>Authentication provided by PIdP. Linking requires signing in to both accounts and confirming the connection.</p>`));
     }
     account=linked ? `website:${row.website_id}:${linked.id}` : `owner:${owner.id}`;
    }
   }
  } catch { /* Sign in in the requesting application namespace. */ }
  const hint=googleLoginHint(c.req.query('provider'),c.req.query('login_hint'));
  if(!account || hint){
   const provider=c.req.query('provider');
   if(provider && !['google','github'].includes(provider))return c.json({error:'invalid_provider'},400);
   const login=identityUrl(c.env,provider?`/auth/${provider}/login`:'/app/login');
   const resume=identityUrl(c.env,'/auth/sso/authorize');resume.searchParams.set('request',row.id);
   login.searchParams.set('app',row.app);
   login.searchParams.set('next',resume.toString());
   if(prompt==='login' && !provider)login.searchParams.set('prompt','login');
   if(hint)login.searchParams.set('login_hint',hint);
   return c.redirect(login.toString(),303);
  }
  const code=randomToken('');
  const claimed=await c.env.DB.prepare('UPDATE portal_sso_requests SET subject=?, auth_time=?, code_hash=?, expires_at=? WHERE id=? AND code_hash IS NULL AND expires_at>=? RETURNING id').bind(account,authTime,await sha256Hex(code),now()+120,row.id,now()).first();
  if(!claimed)return c.json({error:'expired_request'},400);
  const native=await c.env.DB.prepare('SELECT * FROM portal_desktop_requests WHERE id=? AND expires_at>=?').bind(row.id,now()).first<DesktopTicket>();
  if(native){const callback=new URL(native.redirect_uri);callback.search=new URLSearchParams({request:row.id,code,state:native.state}).toString();return c.redirect(callback.toString(),303)}
  const complete=new URL('/pidp/auth/sso/complete',row.origin);complete.searchParams.set('request',row.id);complete.searchParams.set('code',code);
  return c.redirect(complete.toString(),303);
 });
 app.on(['GET','POST'],'/auth/sso/complete', async c => {
  let params:Record<string,string>=Object.fromEntries(new URL(c.req.url).searchParams);
  if(c.req.method==='POST'){
   const body=await c.req.text();if(body.length>4096)return c.json({error:'invalid_request'},400);
   try{params=JSON.parse(body);if(!params||Array.isArray(params)||Object.values(params).some(v=>typeof v!=='string'))throw Error()}catch{return c.json({error:'invalid_request'},400)}
  }
  const native=await c.env.DB.prepare('SELECT * FROM portal_desktop_requests WHERE id=?').bind(params.request||'').first<DesktopTicket>();
  if(native){const verifier=params.code_verifier||'';if(c.req.method!=='POST'||native.expires_at<now()||!(/^[A-Za-z0-9._~-]{43,128}$/).test(verifier)||await pkceChallenge(verifier)!==native.challenge)return c.json({error:'invalid_pkce'},400)}
  else if(c.req.method==='POST')return c.json({error:'invalid_native_request'},400);

  const browser=getCookie(c,browserCookie);if(!browser)return c.json({error:'invalid_browser'},400);
  const row=await c.env.DB.prepare('DELETE FROM portal_sso_requests WHERE id=? AND code_hash=? AND browser_hash=? AND origin=? AND expires_at>=? RETURNING *')
   .bind(params.request || '',await sha256Hex(params.code || ''),await sha256Hex(native?browser+':'+native.challenge:browser),origin(c),now()).first<Ticket>();
  if(!row?.website_id || !row.subject || !(row.subject?.startsWith(`website:${row.website_id}:`) || (sharedIdentity(c.env,row.app) && /^owner:[^:]+$/.test(row.subject || ''))) || !ssoReturn(c.env,row.origin,row.app,row.next))return c.json({error:'invalid_handoff'},400);
  if(native)await c.env.DB.prepare('DELETE FROM portal_desktop_requests WHERE id=?').bind(row.id).run();
  let token;try{token=await issue(c.env,row.subject,row.auth_time||undefined);}catch{return c.json({error:'inactive_account'},401);}
  const remembered=await browserSession(c.env,token);
  setCookie(c,'pidp_session',remembered.token,{secure:true,httpOnly:true,sameSite:'Lax',path:'/',maxAge:remembered.maxAge});
  setCookie(c,browserCookie,'',{secure:true,httpOnly:true,sameSite:'Lax',path:'/',maxAge:0});
  return c.redirect(row.next,303);
 });
 return app;
}

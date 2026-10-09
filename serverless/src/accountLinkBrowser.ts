import {identityDocument} from './identityPage';
import {Hono,type Context} from 'hono';
import {getCookie,setCookie,deleteCookie} from 'hono/cookie';
import type {Env,UserRow,WebsiteUserRow} from './types';
import {first,userById,websiteBySlug,nowIso} from './db';
import {randomToken,sha256Hex,verifyJwt} from './crypto';
import {fail} from './http';
import {ssoReturn,loginPortal,portalClient} from './portalClients';
const cookie='__Host-pidp_identity_link';
const esc=(s:unknown)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
function page(title:string,body:string){return identityDocument(title,`<h1>${esc(title)}</h1>${body}`)}
type LinkRequest={id:string;canonical_user_id:string;website_id:string;expires_at:number;subject:string|null};
export function accountLinkBrowserRoutes(getOwner:(env:Env,token:string)=>Promise<UserRow>,getMember:(env:Env,token:string)=>Promise<WebsiteUserRow>){
 const app=new Hono<{Bindings:Env}>();
 app.use('*',async(c,next)=>{const params=new URL(c.req.url).searchParams;for(const key of params.keys())if(params.getAll(key).length!==1)fail(400,'Ambiguous request');c.header('Cache-Control','no-store');c.header('Referrer-Policy','same-origin');c.header('Content-Security-Policy',`default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${(c.env.PORTAL_AUTH_ORIGINS||'').split(',').map(s=>s.trim()).filter(s=>portalClient(c.env,s)).join(' ')}; frame-ancestors 'none'; base-uri 'none'`);await next()});
 async function continuation(c:Context<{Bindings:Env}>,websiteId:string){
  const id=c.req.query('sso');if(!id)return '';
  const row=await c.env.DB.prepare('SELECT id,origin,app,next FROM portal_sso_requests WHERE id=? AND website_id=? AND expires_at>=? AND code_hash IS NULL').bind(id,websiteId,Math.floor(Date.now()/1000)).first<{id:string;origin:string;app:string;next:string}>();
  if(!row || !ssoReturn(c.env,row.origin,row.app,row.next))fail(400,'Sign-in request expired; restart from your portal');
  return '?'+new URLSearchParams({sso:row.id}).toString();
 }
 function switchForm(app:string,resume:string,account:string,label:string){return `<form method="post" action="/auth/account-links/switch?${esc(new URLSearchParams({app,account}).toString())}${resume?"&amp;"+esc(resume.slice(1)):""}"><button>${esc(label)}</button></form>`}
 function sameOrigin(c:{req:{url:string;header(name:string):string|undefined}}){if(c.req.header('origin')!==new URL(c.req.url).origin)fail(403,'Invalid origin')}
 app.get('/connect',async c=>{
  const website=await websiteBySlug(c.env.DB,c.req.query('app')||'');if(!website)fail(404,'Application not found');
  const resume=await continuation(c,website.id);
  const portal=await loginPortal(c.env,website.slug,new URL('/auth/sso/authorize?'+new URLSearchParams({request:c.req.query('sso')||''}),c.req.url).toString());
  const token=getCookie(c,'pidp_session');let owner:UserRow|null=null;
  if(token)try{owner=await getOwner(c.env,token)}catch{owner=null}
  if(!owner?.is_active){const login=new URL('/app/login',c.req.url);login.searchParams.set('owner','true');login.searchParams.set('next',c.req.url);return c.html(page('Link your portal sign-in',`<p>First sign in to your primary PIdP account.</p><a href="${esc(login)}">Sign in to PIdP</a>`))}
  return c.html(page('Link your portal sign-in',`<p>Primary account: ${esc(owner.full_name||owner.email)} (${esc(owner.email)})</p><p>Next, authenticate your ${esc(portal?.name||website.name)} member account. Linking will give both sign-ins one personal profile and portal identity.</p><form method="post" action="/auth/account-links/connect?app=${esc(encodeURIComponent(website.slug))}${resume?'&amp;'+esc(resume.slice(1)):''}"><button>Authenticate the portal account</button></form>${switchForm(website.slug,resume,"primary","Use another PIdP account")}`));
 });
 app.post('/switch',async c=>{
  sameOrigin(c);
  const website=await websiteBySlug(c.env.DB,c.req.query('app')||'');if(!website)fail(404,'Application not found');
  const resume=await continuation(c,website.id),account=c.req.query('account');
  if(!['primary','portal'].includes(account||''))fail(400,'Invalid account selection');
  const nonce=getCookie(c,cookie);
  if(account==='portal'){
   const linked=await context(c,true);if(linked.row.website_id!==website.id)fail(403,'Wrong application');
   await c.env.DB.prepare('UPDATE account_identity_link_requests SET subject=NULL WHERE id=? AND used_at IS NULL').bind(linked.row.id).run();
  }else{
   const token=getCookie(c,'pidp_session');if(!token)fail(401,'Sign in to PIdP');const claims=await verifyJwt(c.env,token);const actor=claims.actor_type==='website_user'?await getMember(c.env,token):await getOwner(c.env,token);if(!actor.is_active)fail(401,'Inactive account');
   // A confirmation page holds the portal session, so authenticate the replacement
   // primary account afresh rather than accepting it as an owner proof.
   if(nonce)await c.env.DB.prepare('DELETE FROM account_identity_link_requests WHERE browser_hash=? AND used_at IS NULL').bind(await sha256Hex(nonce)).run();
   deleteCookie(c,cookie,{path:'/',secure:true});
  }
  const target=new URL('/app/login',c.req.url);
  target.searchParams.set(account==='primary'?'owner':'app',account==='primary'?'true':website.slug);
  target.searchParams.set('next',new URL(account==='primary'?'/auth/account-links/connect?'+new URLSearchParams({app:website.slug}).toString()+(resume?'&'+resume.slice(1):''):'/auth/account-links/finish'+resume,c.req.url).toString());
  target.searchParams.set('prompt','select_account');return c.redirect(target.toString(),303);
 });
 app.post('/connect',async c=>{
  sameOrigin(c);const token=getCookie(c,'pidp_session');if(!token)fail(401,'Sign in to PIdP');
  const owner=await getOwner(c.env,token);if(!owner.is_active)fail(401,'Inactive account');
  const website=await websiteBySlug(c.env.DB,c.req.query('app')||'');if(!website)fail(404,'Application not found');
  const resume=await continuation(c,website.id);
  const nonce=randomToken('identity_link_'),id=crypto.randomUUID(),now=Math.floor(Date.now()/1000);
  const claims=await verifyJwt(c.env,token);const expires=Math.min(now+600,claims.exp);
  await c.env.DB.batch([
   c.env.DB.prepare('DELETE FROM account_identity_link_requests WHERE expires_at<?').bind(now),
   c.env.DB.prepare('INSERT INTO account_identity_link_requests(id,canonical_user_id,website_id,browser_hash,primary_proof_hash,expires_at) VALUES(?,?,?,?,?,?)').bind(id,owner.id,website.id,await sha256Hex(nonce),await sha256Hex(token),expires),
  ]);
  setCookie(c,cookie,nonce,{path:'/',secure:true,httpOnly:true,sameSite:'Lax',maxAge:600});
  const login=new URL('/app/login',c.req.url);login.searchParams.set('app',website.slug);login.searchParams.set('next',new URL('/auth/account-links/finish'+resume,c.req.url).toString());
  return c.redirect(login.toString(),303);
 });
 async function context(c:Context<{Bindings:Env}>,switching=false){
  const nonce=getCookie(c,cookie),token=getCookie(c,'pidp_session');if(!nonce||!token)fail(401,'Restart account linking in the same browser');
  const row=await first<LinkRequest>(c.env.DB.prepare('SELECT * FROM account_identity_link_requests WHERE browser_hash=? AND expires_at>=? AND used_at IS NULL').bind(await sha256Hex(nonce),Math.floor(Date.now()/1000)));
  if(!row)fail(409,'Account-link request expired or already used');
  const [owner,member]=await Promise.all([userById(c.env.DB,row.canonical_user_id),getMember(c.env,token)]);
  if(!owner?.is_active||!member.is_active)fail(401,'Inactive account');
  if(member.website_id!==row.website_id)fail(403,'Sign in to the selected application');
  const subject=`website:${member.website_id}:${member.id}`;
  if(!switching&&row.subject&&row.subject!==subject)fail(409,'Account changed; restart linking');
  const link=await first<{canonical_user_id:string}>(c.env.DB.prepare('SELECT canonical_user_id FROM account_identity_links WHERE subject=?').bind(subject));
  if(!switching&&link&&link.canonical_user_id!==owner.id)fail(409,'Account is linked to another identity');
  const resume=await continuation(c,row.website_id);
  return {row,owner,member,subject,resume,conflict:Boolean(link&&link.canonical_user_id!==owner.id)};
 }
 app.get('/finish',async c=>{
  const {row,owner,member,subject,resume,conflict}=await context(c,true);
  const website=await c.env.DB.prepare('SELECT slug FROM websites WHERE id=?').bind(row.website_id).first<{slug:string}>();
  if(conflict || (row.subject && row.subject!==subject))return c.html(page('Choose a different account',`<p>This account cannot be connected with the current selection. Choose the matching PIdP account or another portal account.</p>${switchForm(website!.slug,resume,"portal","Use another portal account")}${switchForm(website!.slug,resume,"primary","Use another PIdP account")}`),409);
  const updated=await c.env.DB.prepare('UPDATE account_identity_link_requests SET subject=? WHERE id=? AND used_at IS NULL AND expires_at>=? AND (subject IS NULL OR subject=?)').bind(subject,row.id,Math.floor(Date.now()/1000),subject).run();
  if(!updated.meta.changes)fail(409,'Account-link request changed');
  return c.html(page('Confirm account link',`<p>Primary PIdP account: ${esc(owner.email)}</p><p>Portal account: ${esc(member.email)}</p><p>These accounts will share your profile. Your organization access stays tied to your memberships.</p><form method="post" action="/auth/account-links/complete${esc(resume)}"><button>Link these accounts</button></form>${switchForm(website!.slug,resume,"portal","Use another portal account")}${switchForm(website!.slug,resume,"primary","Use another PIdP account")}`));
 });
 app.post('/complete',async c=>{
  sameOrigin(c);const {row,owner,subject,resume}=await context(c);if(row.subject!==subject)fail(409,'Review the account link first');
  const at=nowIso(),now=Math.floor(Date.now()/1000);
  const results=await c.env.DB.batch([
   c.env.DB.prepare(`INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
    SELECT ?,canonical_user_id,website_id,?,? FROM account_identity_link_requests
    WHERE id=? AND subject=? AND expires_at>=? AND used_at IS NULL
    AND EXISTS(SELECT 1 FROM users WHERE id=canonical_user_id AND is_active=1)
    ON CONFLICT(subject) DO NOTHING`).bind(subject,subject.split(':')[2],at,row.id,subject,now),
   c.env.DB.prepare(`UPDATE account_identity_link_requests SET used_at=? WHERE id=? AND subject=? AND expires_at>=? AND used_at IS NULL
    AND EXISTS(SELECT 1 FROM account_identity_links WHERE subject=? AND canonical_user_id=?)`).bind(at,row.id,subject,now,subject,owner.id),
  ]);
  if(!results[1].meta.changes)fail(409,'Account-link request changed or already used');
  deleteCookie(c,cookie,{path:'/',secure:true});
  if(resume){const target=new URL('/auth/sso/authorize',c.req.url);target.searchParams.set('request',new URLSearchParams(resume.slice(1)).get('sso')!);return c.redirect(target.toString(),303);}
  return c.html(page('Accounts linked','<p>Your sign-ins now share one identity and personal profile.</p><p>Return to your portal to continue.</p>'));
 });
 return app;
}

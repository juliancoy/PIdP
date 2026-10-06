import {Hono,type Context} from 'hono';
import {getCookie,setCookie,deleteCookie} from 'hono/cookie';
import type {Env,UserRow,WebsiteUserRow} from './types';
import {first,userById,websiteBySlug,nowIso} from './db';
import {randomToken,sha256Hex,verifyJwt} from './crypto';
import {fail} from './http';
const cookie='__Host-pidp_identity_link';
const esc=(s:unknown)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
function page(title:string,body:string){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body><main><h1>${esc(title)}</h1>${body}</main></body></html>`}
type LinkRequest={id:string;canonical_user_id:string;website_id:string;expires_at:number;subject:string|null};
export function accountLinkBrowserRoutes(getOwner:(env:Env,token:string)=>Promise<UserRow>,getMember:(env:Env,token:string)=>Promise<WebsiteUserRow>){
 const app=new Hono<{Bindings:Env}>();
 app.use('*',async(c,next)=>{c.header('Cache-Control','no-store');c.header('Referrer-Policy','same-origin');c.header('Content-Security-Policy',"default-src 'none'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'");await next()});
 function sameOrigin(c:{req:{url:string;header(name:string):string|undefined}}){if(c.req.header('origin')!==new URL(c.req.url).origin)fail(403,'Invalid origin')}
 app.get('/connect',async c=>{
  const website=await websiteBySlug(c.env.DB,c.req.query('app')||'');if(!website)fail(404,'Application not found');
  const token=getCookie(c,'pidp_session');let owner:UserRow|null=null;
  if(token)try{owner=await getOwner(c.env,token)}catch{owner=null}
  if(!owner?.is_active){const login=new URL('/auth/google/login',c.req.url);login.searchParams.set('owner','true');login.searchParams.set('next',c.req.url);return c.html(page('Link your portal sign-in',`<p>First sign in to your primary PIdP account.</p><a href="${esc(login)}">Sign in to PIdP</a>`))}
  return c.html(page('Link your portal sign-in',`<p>Primary account: ${esc(owner.full_name||owner.email)} (${esc(owner.email)})</p><p>Next, authenticate your ${esc(website.name)} member account. Linking will give both sign-ins one personal profile and portal identity.</p><form method="post" action="/auth/account-links/connect?app=${esc(encodeURIComponent(website.slug))}"><button>Authenticate the portal account</button></form>`));
 });
 app.post('/connect',async c=>{
  sameOrigin(c);const token=getCookie(c,'pidp_session');if(!token)fail(401,'Sign in to PIdP');
  const owner=await getOwner(c.env,token);if(!owner.is_active)fail(401,'Inactive account');
  const website=await websiteBySlug(c.env.DB,c.req.query('app')||'');if(!website)fail(404,'Application not found');
  const nonce=randomToken('identity_link_'),id=crypto.randomUUID(),now=Math.floor(Date.now()/1000);
  const claims=await verifyJwt(c.env,token);const expires=Math.min(now+600,claims.exp);
  await c.env.DB.batch([
   c.env.DB.prepare('DELETE FROM account_identity_link_requests WHERE expires_at<?').bind(now),
   c.env.DB.prepare('INSERT INTO account_identity_link_requests(id,canonical_user_id,website_id,browser_hash,primary_proof_hash,expires_at) VALUES(?,?,?,?,?,?)').bind(id,owner.id,website.id,await sha256Hex(nonce),await sha256Hex(token),expires),
  ]);
  setCookie(c,cookie,nonce,{path:'/',secure:true,httpOnly:true,sameSite:'Lax',maxAge:600});
  const login=new URL('/auth/google/login',c.req.url);login.searchParams.set('app',website.slug);login.searchParams.set('next',new URL('/auth/account-links/finish',c.req.url).toString());
  return c.redirect(login.toString(),303);
 });
 async function context(c:Context<{Bindings:Env}>){
  const nonce=getCookie(c,cookie),token=getCookie(c,'pidp_session');if(!nonce||!token)fail(401,'Restart account linking in the same browser');
  const row=await first<LinkRequest>(c.env.DB.prepare('SELECT * FROM account_identity_link_requests WHERE browser_hash=? AND expires_at>=? AND used_at IS NULL').bind(await sha256Hex(nonce),Math.floor(Date.now()/1000)));
  if(!row)fail(409,'Account-link request expired or already used');
  const [owner,member]=await Promise.all([userById(c.env.DB,row.canonical_user_id),getMember(c.env,token)]);
  if(!owner?.is_active||!member.is_active)fail(401,'Inactive account');
  if(member.website_id!==row.website_id)fail(403,'Sign in to the selected application');
  const subject=`website:${member.website_id}:${member.id}`;
  if(row.subject&&row.subject!==subject)fail(409,'Account changed; restart linking');
  const link=await first<{canonical_user_id:string}>(c.env.DB.prepare('SELECT canonical_user_id FROM account_identity_links WHERE subject=?').bind(subject));
  if(link&&link.canonical_user_id!==owner.id)fail(409,'Account is linked to another identity');
  return {row,owner,member,subject};
 }
 app.get('/finish',async c=>{
  const {row,owner,member,subject}=await context(c);
  const updated=await c.env.DB.prepare('UPDATE account_identity_link_requests SET subject=? WHERE id=? AND used_at IS NULL AND expires_at>=? AND (subject IS NULL OR subject=?)').bind(subject,row.id,Math.floor(Date.now()/1000),subject).run();
  if(!updated.meta.changes)fail(409,'Account-link request changed');
  return c.html(page('Confirm account link',`<p>Primary PIdP account: ${esc(owner.email)}</p><p>Portal account: ${esc(member.email)}</p><p>These sign-ins will share your personal profile, onboarding, and portal identity. Organization access will use that person’s live memberships; website tokens remain website tokens.</p><form method="post" action="/auth/account-links/complete"><button>Link these accounts</button></form>`));
 });
 app.post('/complete',async c=>{
  sameOrigin(c);const {row,owner,subject}=await context(c);if(row.subject!==subject)fail(409,'Review the account link first');
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
  return c.html(page('Accounts linked','<p>Your sign-ins now share one identity and personal profile.</p><p>Return to your portal to continue.</p>'));
 });
 return app;
}

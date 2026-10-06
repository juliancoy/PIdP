import { Hono } from 'hono';
import type { Env, UserRow, WebsiteUserRow } from './types';
import { first, userById, websiteUserById, nowIso } from './db';
import { sha256Hex, verifyJwt } from './crypto';
import { bearerToken, fail, readJson } from './http';

export type AccountIdentity = { canonical_user_id: string; account_id: string; account_subject: string };
export async function resolveAccountIdentity(env: Env, subject: string): Promise<AccountIdentity> {
 const parts=subject.split(':');
 if(parts[0]==='owner' && parts.length===2){
  const owner=await userById(env.DB,parts[1]);
  if(!owner?.is_active)fail(401,'Inactive account');
  return {canonical_user_id:owner.id,account_id:owner.id,account_subject:subject};
 }
 if(parts[0]!=='website'||parts.length!==3)fail(401,'Invalid account namespace');
 const member=await websiteUserById(env.DB,parts[1],parts[2]);
 if(!member?.is_active)fail(401,'Inactive account');
 const link=await first<{canonical_user_id:string}>(env.DB.prepare('SELECT canonical_user_id FROM account_identity_links WHERE subject=?').bind(subject));
 if(link){const person=await userById(env.DB,link.canonical_user_id);if(!person?.is_active)fail(401,'Inactive linked identity');}
 return {canonical_user_id:link?.canonical_user_id||member.id,account_id:member.id,account_subject:subject};
}

export async function resolveTokenIdentity(env:Env,token:string){
 const payload=await verifyJwt(env,token);
 const subject=payload.actor_type==='website_user'?`website:${payload.website_id}:${payload.sub}`:`owner:${payload.sub}`;
 return resolveAccountIdentity(env,subject);
}

export function accountIdentityRoutes(
 getOwner:(env:Env,token:string)=>Promise<UserRow>,
 getMember:(env:Env,token:string)=>Promise<WebsiteUserRow>,
){
 const app=new Hono<{Bindings:Env}>();
 app.use('*',async(c,next)=>{c.header('Cache-Control','no-store');await next();});
 app.get('/',async c=>{
  const identity=await resolveTokenIdentity(c.env,bearerToken(c));
  const rows=await c.env.DB.prepare('SELECT subject,website_id,website_user_id,linked_at FROM account_identity_links WHERE canonical_user_id=? ORDER BY linked_at').bind(identity.canonical_user_id).all();
  return c.json({canonical_user_id:identity.canonical_user_id,accounts:rows.results});
 });
 async function proof(env:Env,ownerToken:string,memberToken:unknown){
  if(ownerToken.startsWith('pidp_pat_'))fail(403,'Use an authenticated account session');
  if(typeof memberToken!=='string'||!memberToken||memberToken.length>16384)fail(400,'Authenticate the website account to link');
  const [owner,member]=await Promise.all([getOwner(env,ownerToken),getMember(env,memberToken)]);
  if(!owner.is_active||!member.is_active)fail(401,'Inactive account');
  const subject=`website:${member.website_id}:${member.id}`;
  const existing=await first<{canonical_user_id:string}>(env.DB.prepare('SELECT canonical_user_id FROM account_identity_links WHERE subject=?').bind(subject));
  if(existing&&existing.canonical_user_id!==owner.id)fail(409,'Account is already linked to another identity');
  return {owner,member,subject,hash:await sha256Hex(JSON.stringify([owner.id,subject,await sha256Hex(ownerToken),await sha256Hex(memberToken)]))};
 }
 app.post('/preview',async c=>{
  const payload=await readJson<Record<string,unknown>>(c);
  const p=await proof(c.env,bearerToken(c),payload.member_token);
  const id=crypto.randomUUID(),expires=Math.floor(Date.now()/1000)+600;
  await c.env.DB.batch([
   c.env.DB.prepare('DELETE FROM account_identity_link_previews WHERE expires_at<?').bind(Math.floor(Date.now()/1000)),
   c.env.DB.prepare('INSERT INTO account_identity_link_previews(id,canonical_user_id,subject,website_id,website_user_id,proof_hash,expires_at) VALUES(?,?,?,?,?,?,?)').bind(id,p.owner.id,p.subject,p.member.website_id,p.member.id,p.hash,expires),
  ]);
  return c.json({previewId:id,canonical_user_id:p.owner.id,account_id:p.member.id,account_subject:p.subject,expires_at:expires,
   effects:['Share personal profile and portal identity','Keep website session and OAuth namespaces','Organization permissions still require live membership checks']});
 });
 app.post('/apply',async c=>{
  const payload=await readJson<Record<string,unknown>>(c);
  if(payload.confirm!==true||typeof payload.previewId!=='string')fail(400,'Confirm the reviewed preview');
  const p=await proof(c.env,bearerToken(c),payload.member_token);
  const now=Math.floor(Date.now()/1000),at=nowIso();
  const row=await first<{id:string}>(c.env.DB.prepare('SELECT id FROM account_identity_link_previews WHERE id=? AND canonical_user_id=? AND subject=? AND proof_hash=? AND expires_at>=? AND applied_at IS NULL').bind(payload.previewId,p.owner.id,p.subject,p.hash,now));
  if(!row)fail(409,'Preview expired, changed, or already applied');
  const results=await c.env.DB.batch([
   c.env.DB.prepare(`INSERT INTO account_identity_links(subject,canonical_user_id,website_id,website_user_id,linked_at)
    SELECT subject,canonical_user_id,website_id,website_user_id,? FROM account_identity_link_previews
    WHERE id=? AND canonical_user_id=? AND proof_hash=? AND expires_at>=? AND applied_at IS NULL
    ON CONFLICT(subject) DO NOTHING`).bind(at,row.id,p.owner.id,p.hash,now),
   c.env.DB.prepare('UPDATE account_identity_link_previews SET applied_at=? WHERE id=? AND canonical_user_id=? AND proof_hash=? AND expires_at>=? AND applied_at IS NULL AND EXISTS(SELECT 1 FROM account_identity_links WHERE subject=? AND canonical_user_id=?)').bind(at,row.id,p.owner.id,p.hash,now,p.subject,p.owner.id),
  ]);
  if(!results[1].meta.changes)fail(409,'Account link changed or preview already applied');
  return c.json({ok:true,previewId:row.id,...await resolveAccountIdentity(c.env,p.subject)});
 });
 return app;
}

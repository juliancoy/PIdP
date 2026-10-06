import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import app from '../src/index.ts';
import {signJwt} from '../src/crypto.ts';
import {resolveAccountIdentity} from '../src/accountIdentity.ts';
function fixture(){
 const sql=new DatabaseSync(':memory:');
 for(const name of ['0001_initial.sql','0010_account_identity_links.sql'])sql.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
 sql.exec(`INSERT INTO users(id,email,full_name) VALUES ('person','same@example.test','Person'),('other','other@example.test','Other');
 INSERT INTO websites(id,owner_id,name,slug) VALUES ('site','other','Site','site');
 INSERT INTO website_users(id,website_id,email,full_name) VALUES ('member','site','same@example.test','Member');`);
 const wrap=(query,params=[])=>({bind(...p){return wrap(query,p)},async first(){return sql.prepare(query).get(...params)||null},async all(){return {results:sql.prepare(query).all(...params)}},async run(){return {meta:sql.prepare(query).run(...params)}}});
 const DB={prepare:wrap,async batch(stmts){sql.exec('BEGIN IMMEDIATE');try{const r=[];for(const stmt of stmts)r.push(await stmt.run());sql.exec('COMMIT');return r}catch(e){sql.exec('ROLLBACK');throw e}}};
 const env={DB,SECRET_KEY:'central-identity-test',ADMIN_USER_IDS:'person'};
 const tokens=new Map();
 const credential=async claims=>{const key=JSON.stringify(claims);if(!tokens.has(key))tokens.set(key,await signJwt(env,claims));return tokens.get(key)};
 const request=async(path,body,claims={sub:'person'})=>app.request(`https://id.example${path}`,{method:body===undefined?'GET':'POST',headers:{Authorization:`Bearer ${await credential(claims)}`,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)},env);
 return {sql,env,request};
}
test('linking requires both account proofs, a bound one-use preview, and never derives identity from email',async()=>{
 const f=fixture();try{
  const subject='website:site:member';
  assert.equal((await resolveAccountIdentity(f.env,subject)).canonical_user_id,'member');
  assert.equal((await f.request('/auth/account-links/preview',{})).status,400);
  const wrong=await signJwt(f.env,{sub:'person'});
  assert.equal((await f.request('/auth/account-links/preview',{member_token:wrong})).status,403);
  const member_token=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  assert.equal((await f.request('/auth/account-links/preview',{member_token},{sub:'member',actor_type:'website_user',website_id:'site'})).status,403);
  const preview=await f.request('/auth/account-links/preview',{member_token});assert.equal(preview.status,200);
  const plan=await preview.json();assert.equal(plan.canonical_user_id,'person');
  assert.equal((await resolveAccountIdentity(f.env,subject)).canonical_user_id,'member');
  assert.equal((await f.request('/auth/account-links/apply',{member_token,previewId:plan.previewId,confirm:false})).status,400);
  assert.equal((await f.request('/auth/account-links/apply',{member_token,previewId:plan.previewId,confirm:true},{sub:'other'})).status,409);
  const applied=await f.request('/auth/account-links/apply',{member_token,previewId:plan.previewId,confirm:true});assert.equal(applied.status,200);
  assert.equal((await applied.json()).canonical_user_id,'person');
  assert.equal((await f.request('/auth/account-links/apply',{member_token,previewId:plan.previewId,confirm:true})).status,409);
  const profile=await (await f.request('/auth/me',undefined,{sub:'member',actor_type:'website_user',website_id:'site'})).json();
  assert.equal(profile.id,'person');assert.equal(profile.account_id,'member');assert.equal(profile.account_subject,subject);assert.equal(profile.is_sysadmin,false);
  assert.equal((await f.request('/auth/account-links/preview',{member_token},{sub:'other'})).status,409);
  f.sql.prepare("UPDATE website_users SET provider='github',provider_account_id='different',email='changed@example.test'").run();
  assert.equal((await resolveAccountIdentity(f.env,subject)).canonical_user_id,'person');
  f.sql.prepare("UPDATE users SET is_active=0 WHERE id='person'").run();
  await assert.rejects(resolveAccountIdentity(f.env,subject));
 }finally{f.sql.close()}
});
test('expired previews and changed secondary proofs cannot link or be replayed',async()=>{
 const f=fixture();try{
  const member_token=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const plan=await (await f.request('/auth/account-links/preview',{member_token})).json();
  const changed=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  assert.equal((await f.request('/auth/account-links/apply',{member_token:changed,previewId:plan.previewId,confirm:true})).status,409);
  f.sql.exec('UPDATE account_identity_link_previews SET expires_at=0');
  assert.equal((await f.request('/auth/account-links/apply',{member_token,previewId:plan.previewId,confirm:true})).status,409);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
 }finally{f.sql.close()}
});

test('browser linking binds both authenticated accounts to one browser and explicit confirmation',async()=>{
 const f=fixture();try{
  const primary=await signJwt(f.env,{sub:'person'}),secondary=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const call=(path,method='GET',cookie='',origin)=>app.request(`https://id.example/auth/account-links${path}`,{method,headers:{cookie,...(origin?{origin}:{})}},f.env);
  assert.match(await (await call('/connect?app=site')).text(),/Sign in to PIdP/);
  const startPage=await call('/connect?app=site','GET',`pidp_session=${primary}`);assert.equal(startPage.status,200);
  assert.equal((await call('/connect?app=site','POST',`pidp_session=${primary}`,'https://evil.example')).status,403);
  const start=await call('/connect?app=site','POST',`pidp_session=${primary}`,'https://id.example');assert.equal(start.status,303);
  const location=new URL(start.headers.get('location'));assert.equal(location.searchParams.get('app'),'site');assert.equal(location.searchParams.get('next'),'https://id.example/auth/account-links/finish');
  assert.ok(!location.href.includes(primary));
  const cookie=start.headers.get('set-cookie').split(';')[0];
  assert.match(start.headers.get('set-cookie'),/HttpOnly/);assert.match(start.headers.get('set-cookie'),/Secure/);
  assert.equal((await call('/finish','GET',`pidp_session=${secondary}`)).status,401);
  assert.equal((await call('/complete','POST',`${cookie}; pidp_session=${secondary}`,'https://id.example')).status,409);
  const review=await call('/finish','GET',`${cookie}; pidp_session=${secondary}`);assert.equal(review.status,200);assert.match(await review.text(),/Link these accounts/);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
  assert.equal((await call('/complete','POST',`${cookie}; pidp_session=${secondary}`,'https://evil.example')).status,403);
  const applied=await call('/complete','POST',`${cookie}; pidp_session=${secondary}`,'https://id.example');assert.equal(applied.status,200);
  assert.equal((await resolveAccountIdentity(f.env,'website:site:member')).canonical_user_id,'person');
  assert.equal((await call('/complete','POST',`${cookie}; pidp_session=${secondary}`,'https://id.example')).status,409);
 }finally{f.sql.close()}
});

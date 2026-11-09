import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {sha256Hex} from '../src/crypto.ts';
import {portalDirectoryAliases,linkVerifiedPortalProvider} from '../src/directoryIdentity.ts';
import app from '../src/index.ts';
function fixture(){
 const sql=new DatabaseSync(':memory:');
 for(const name of ['0001_initial.sql','0010_account_identity_links.sql','0016_normalized_account_email.sql'])sql.exec(readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8'));
 sql.exec(`INSERT INTO users(id,email,provider,provider_account_id)VALUES('owner','owner@example.test','google','google-owner'),('other','other@example.test','google','other-google');
 INSERT INTO websites(id,owner_id,name,slug)VALUES('site','owner','Portal','orgportal'),('private','other','Private','private');
 INSERT INTO website_users(id,website_id,email,provider,provider_account_id)VALUES('member','site','owner@example.test','google','google-owner'),('unrelated','site','other@example.test','google','different-google'),('private-member','private','owner@example.test','google','google-owner');`);
 const wrap=(q,p=[])=>({bind(...v){return wrap(q,v)},async first(){return sql.prepare(q).get(...p)||null},async all(){return{results:sql.prepare(q).all(...p)}},async run(){return{meta:sql.prepare(q).run(...p)}}});
 return {sql,env:{DB:{prepare:wrap},SECRET_KEY:'synthetic-key',PORTAL_SSO_APP_SLUG:'orgportal'}};
}
test('normalized unique email guards reject case/whitespace variants within each credential namespace',()=>{
 const f=fixture();try{
  assert.throws(()=>f.sql.prepare('INSERT INTO users(id,email)VALUES(?,?)').run('duplicate',' OWNER@Example.Test '),/UNIQUE/);
  assert.throws(()=>f.sql.prepare('INSERT INTO website_users(id,website_id,email)VALUES(?,?,?)').run('duplicate','site',' OWNER@Example.Test '),/UNIQUE/);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM users').get().n,2);
 }finally{f.sql.close()}
});
test('only verified immutable provider proof links portal aliases; repeated calls preserve existing links',async()=>{
 const f=fixture();try{
  const p={email:'owner@example.test',provider_account_id:'google-owner',raw:{email_verified:false}};
  await linkVerifiedPortalProvider(f.env,'google',p);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
  await linkVerifiedPortalProvider(f.env,'google',{...p,provider_account_id:'different',raw:{email_verified:true}});
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
  await linkVerifiedPortalProvider(f.env,'google',{...p,raw:{email_verified:true}});
  assert.deepEqual(await portalDirectoryAliases(f.env,'owner'),[{account_id:'member',canonical_user_id:'owner'}]);
  await linkVerifiedPortalProvider(f.env,'google',{...p,raw:{email_verified:true}});
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,1);
  assert.equal(f.sql.prepare("SELECT count(*) n FROM account_identity_links WHERE website_id='private'").get().n,0);
  await assert.rejects(portalDirectoryAliases(f.env,'other'),/owner required/);
 }finally{f.sql.close()}
});
test('inactive and ambiguous provider identities cannot acquire links',async()=>{
 const f=fixture();try{
  const p={email:'owner@example.test',provider_account_id:'google-owner',raw:{email_verified:true}};
  f.sql.exec("UPDATE users SET is_active=0 WHERE id='owner'");await linkVerifiedPortalProvider(f.env,'google',p);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
  f.sql.exec("UPDATE users SET is_active=1 WHERE id='owner'; INSERT INTO users(id,email,provider,provider_account_id) VALUES('collision','collision@example.test','google','google-owner')");
  await linkVerifiedPortalProvider(f.env,'google',p);assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
 }finally{f.sql.close()}
});
test('private directory mapping requires an active service PAT belonging to the portal owner',async()=>{
 const f=fixture();try{
  const token='pidp_pat_synthetic';f.sql.prepare('INSERT INTO user_api_tokens(id,owner_id,name,token_hash,scope)VALUES(?,?,?,?,?)').run('pat','owner','directory',await sha256Hex(token),'service');
  const call=(raw)=>app.request('https://id.example/service/directory-identities',{method:'POST',headers:{Authorization:'Bearer '+raw}},f.env);
  assert.equal((await call('wrong')).status,403);
  const ok=await call(token);assert.equal(ok.status,200);assert.equal(ok.headers.get('cache-control'),'no-store');assert.deepEqual(await ok.json(),{aliases:[]});
  f.sql.exec("UPDATE user_api_tokens SET scope='org_mcp'");assert.equal((await call(token)).status,403);
  f.sql.exec("UPDATE user_api_tokens SET scope='service',owner_id='other'");assert.equal((await call(token)).status,403);
 }finally{f.sql.close()}
});

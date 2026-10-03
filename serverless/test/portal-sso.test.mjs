import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { portalSso } from '../src/portalSso.ts';
import { signJwt, verifyJwt } from '../src/crypto.ts';
import fullApp from '../src/index.ts';
function fixture(real = false) {
 const sql=new DatabaseSync(':memory:');
 sql.exec(readFileSync(new URL('../migrations/0009_portal_sso.sql',import.meta.url),'utf8'));
 sql.exec(`CREATE TABLE websites(id TEXT,slug TEXT);INSERT INTO websites VALUES('site','members');
 CREATE TABLE users(id TEXT,is_active INTEGER,email TEXT,identity_data TEXT);INSERT INTO users VALUES('owner',1,'owner@example.test','{}');
 CREATE TABLE website_users(id TEXT,website_id TEXT,is_active INTEGER,email TEXT,identity_data TEXT,profile_data TEXT);INSERT INTO website_users VALUES('member','site',1,'member@example.test','{}','{}');`);
 const DB={prepare(query){const statement=sql.prepare(query);return{bind(...args){return{async run(){return statement.run(...args)},async first(){return statement.get(...args) || null}}}}}};
 const env={DB,SECRET_KEY:'test-key',PUBLIC_BASE_URL:'https://id.example',PORTAL_AUTH_ORIGINS:'https://one.example,https://two.example',PORTAL_SSO_APP_SLUG:'members'};
 const app=real ? fullApp : portalSso(async (_env,subject)=>'session-for-'+subject);
 const request=(host,path,headers={})=>app.request('https://'+host+path,{headers},env);
 return {env,sql,request};
}
async function start(f,host='one.example'){
 const r=await f.request(host,'/auth/sso/start?app='+f.env.PORTAL_SSO_APP_SLUG+'&next='+encodeURIComponent('https://'+host+'/auth/callback?next=%2Fpeople'));
 assert.equal(r.status,303);return{browser:r.headers.getSetCookie()[0].split(';')[0],authorize:r.headers.get('location')};
}
test('central sign-in makes browser-bound sessions on two domains without exposing bearer tokens',async()=>{
 const f=fixture();try{
 const session=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
 for(const host of ['one.example','two.example']){
 const s=await start(f,host);const u=new URL(s.authorize);
 const a=await f.request('id.example',u.pathname+u.search,{cookie:'pidp_session='+session});assert.equal(a.status,303);
 const complete=new URL(a.headers.get('location'));assert.equal(complete.origin,'https://'+host);assert.equal(complete.searchParams.has('token'),false);
 const path=complete.pathname.replace('/pidp','')+complete.search;
 for(const headers of [{},{cookie:'__Host-pidp_sso_browser=wrong'}])assert.equal((await f.request(host,path,headers)).status,400);
 assert.equal((await f.request(host==='one.example'?'two.example':'one.example',path,{cookie:s.browser})).status,400);
 const finished=await f.request(host,path,{cookie:s.browser});assert.equal(finished.status,303);
 assert.equal(finished.headers.get('location'),'https://'+host+'/auth/callback?next=%2Fpeople');assert.match(finished.headers.get('set-cookie'),/HttpOnly/);assert.doesNotMatch(finished.headers.get('set-cookie'),/Domain=/);
 assert.equal((await f.request(host,path,{cookie:s.browser})).status,400);
 }
 }finally{f.sql.close()}
});
test('untrusted origins, external returns, wrong apps, expired requests and namespace substitutions fail closed',async()=>{
 const f=fixture();try{
 assert.equal((await f.request('evil.example','/auth/sso/start?app=members')).status,400);
 assert.equal((await f.request('one.example','/auth/sso/start?app=other')).status,400);
 assert.equal((await f.request('one.example','/auth/sso/start?app=members&next=https://evil.example/auth/callback')).status,400);
 const s=await start(f);const url=new URL(s.authorize);const path=url.pathname+url.search;
 for(const payload of [{sub:'owner'},{sub:'member',actor_type:'website_user',website_id:'other'}]){
 const token=await signJwt(f.env,payload);const r=await f.request('id.example',path,{cookie:'pidp_session='+token});assert.match(r.headers.get('location'),/\/app\/login/);
 }
 f.sql.exec('UPDATE portal_sso_requests SET expires_at=0');assert.equal((await f.request('id.example',path)).status,400);
 }finally{f.sql.close()}
});
test('missing portal applications never fall back to an owner account',async()=>{
 const f=fixture();try{
 f.env.PORTAL_SSO_APP_SLUG='unregistered';
 const response=await f.request('one.example','/auth/sso/start?app=unregistered');
 assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'application_not_registered'});
 assert.equal(f.sql.prepare('SELECT count(*) n FROM portal_sso_requests').get().n,0);
 }finally{f.sql.close()}
});

test('full worker issues distinct authenticated session tokens for the same identity on each service', async () => {
 const f=fixture(true);try {
 const issuerSession=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site',email:'member@example.test'});
 const ids=[];
 for(const host of ['one.example','two.example']) {
  const s=await start(f,host);const u=new URL(s.authorize);
  const authorized=await f.request('id.example',u.pathname+u.search,{cookie:'pidp_session='+issuerSession});
  assert.equal(authorized.status,303);
  const complete=new URL(authorized.headers.get('location'));
  const finished=await f.request(host,complete.pathname.replace('/pidp','')+complete.search,{cookie:s.browser});
  assert.equal(finished.status,303);
  const cookie=finished.headers.getSetCookie().find(c=>c.startsWith('pidp_session='));
  const token=decodeURIComponent(cookie.split(';')[0].slice('pidp_session='.length));
  const claims=await verifyJwt(f.env,token);
  assert.equal(claims.sub,'member');assert.equal(claims.actor_type,'website_user');assert.equal(claims.website_id,'site');assert.notEqual(token,issuerSession);assert.notEqual(claims.is_sysadmin,true);
  ids.push(claims.jti);
 }
 assert.ok(ids[0]);assert.notEqual(ids[0],ids[1]);
 }finally{f.sql.close()}
});

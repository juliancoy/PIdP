import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { portalSso } from '../src/portalSso.ts';
import { signJwt, verifyJwt } from '../src/crypto.ts';
import fullApp from '../src/index.ts';
function fixture(real = false) {
 const sql=new DatabaseSync(':memory:');
 sql.exec('CREATE TABLE account_identity_links(subject TEXT,canonical_user_id TEXT,website_id TEXT,website_user_id TEXT,linked_at TEXT)');
 sql.exec(readFileSync(new URL('../migrations/0009_portal_sso.sql',import.meta.url),'utf8'));
 sql.exec(`CREATE TABLE websites(id TEXT PRIMARY KEY,slug TEXT);INSERT INTO websites VALUES('site','members');
 CREATE TABLE users(id TEXT PRIMARY KEY,is_active INTEGER,email TEXT,identity_data TEXT);INSERT INTO users VALUES('owner',1,'owner@example.test','{}');
 CREATE TABLE website_users(id TEXT PRIMARY KEY,website_id TEXT,is_active INTEGER,email TEXT,identity_data TEXT,profile_data TEXT);INSERT INTO website_users VALUES('member','site',1,'member@example.test','{}','{}');`);
 sql.exec(readFileSync(new URL('../migrations/0013_browser_sessions.sql',import.meta.url),'utf8'));
 const DB={prepare(query){const statement=sql.prepare(query);return{bind(...args){return{async run(){return statement.run(...args)},async first(){return statement.get(...args) || null}}}}}};
 const clients=Object.fromEntries(['https://one.example','https://two.example','https://orgportal.cc'].map(origin=>[origin,{name:'Test Portal',accountApp:'members',callbacks:['/auth/callback','/p/auth/callback']} ]));clients['https://codecollective.us']={name:'Test Portal',accountApp:'members',callbacks:['/auth/callback','/p/auth/callback'],restartOrigin:'https://orgportal.cc'};
 const env={PORTAL_CLIENTS_JSON:JSON.stringify(clients),DB,SECRET_KEY:'test-key',PUBLIC_BASE_URL:'https://id.example',PORTAL_AUTH_ORIGINS:'https://one.example,https://two.example',PORTAL_SSO_APP_SLUG:'members'};
 const app=real ? fullApp : portalSso(async (env,subject)=>{const parts=subject.split(':');return signJwt(env,{sub:parts.at(-1),actor_type:parts[0]==='website'?'website_user':'owner',...(parts[0]==='website'?{website_id:parts[1]}:{})})});
 const request=(host,path,headers={})=>app.request('https://'+host+path,{headers},env);
 return {env,sql,request};
}
async function start(f,host='one.example'){
 const r=await f.request(host,'/auth/sso/start?app='+f.env.PORTAL_SSO_APP_SLUG+'&next='+encodeURIComponent('https://'+host+'/auth/callback?next=%2Fpeople'));
 assert.equal(r.status,303);return{browser:r.headers.getSetCookie()[0].split(';')[0],authorize:r.headers.get('location')};
}
test('selected Google account goes through OAuth even with an existing application session', async () => {
 const f=fixture();
 try {
  const selected=await f.request('one.example','/auth/sso/start?app=members&provider=google&login_hint=123456789');
  const authorize=new URL(selected.headers.get('location'));
  assert.equal(authorize.searchParams.get('login_hint'),'123456789');
  const session=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const result=await f.request('id.example',authorize.pathname+authorize.search,{cookie:'pidp_session='+session});
  const login=new URL(result.headers.get('location'));
  assert.equal(login.pathname,'/auth/google/login');
  assert.equal(login.searchParams.get('app'),'members');
  assert.equal(login.searchParams.get('login_hint'),'123456789');
  assert.equal(login.searchParams.has('owner'),false);
  assert.equal(new URL(login.searchParams.get('next')).searchParams.has('login_hint'),false);
  for (const [provider,hint] of [['github','123456789'],['google','invalid@example.test']]) {
   const result=await f.request('one.example',`/auth/sso/start?app=members&provider=${provider}&login_hint=${hint}`);
   assert.equal(new URL(result.headers.get('location')).searchParams.has('login_hint'),false);
  }
 } finally { f.sql.close() }
});
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
 const token=await signJwt(f.env,payload);const r=await f.request('id.example',path,{cookie:'pidp_session='+token});if(payload.sub==='owner'){assert.equal(r.status,200);const html=await r.text();assert.match(html,/Link my portal account/);assert.match(html,/Sign in to the portal separately/);assert.equal(f.sql.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);assert.equal(f.sql.prepare('SELECT code_hash FROM portal_sso_requests').get().code_hash,null)}else assert.match(r.headers.get('location'),/\/app\/login/);
 }
 f.sql.exec('UPDATE portal_sso_requests SET expires_at=0');assert.equal((await f.request('id.example',path)).status,400);
 }finally{f.sql.close()}
});
test('missing portal applications never fall back to an owner account',async()=>{
 const f=fixture();try{
 f.env.PORTAL_SSO_APP_SLUG='unregistered';const clients=JSON.parse(f.env.PORTAL_CLIENTS_JSON);clients['https://one.example'].accountApp='unregistered';f.env.PORTAL_CLIENTS_JSON=JSON.stringify(clients);
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

test('owner session authorizes only through an explicit website member link',async()=>{
 const f=fixture();try{
 const started=await start(f);const url=new URL(started.authorize);
 f.sql.exec("INSERT INTO account_identity_links VALUES('website:site:member','owner','site','member','2026-10-06')");
 const token=await signJwt(f.env,{sub:'owner',actor_type:'owner'});
 const result=await f.request('id.example',url.pathname+url.search,{cookie:'pidp_session='+token});
 assert.equal(result.status,303);assert.match(result.headers.get('location'),/sso\/complete/);
 }finally{f.sql.close()}
});

test('only a validated cross-browser account link is accepted as a backend SSO return', async () => {
 const f=fixture();
 try{
  const destination='https://one.example/pidp/oauth/mcp/link?request=login_'+ 'a'.repeat(54);
  assert.equal((await f.request('one.example','/auth/sso/start?app=members&next='+encodeURIComponent(destination))).status,303);
  for(const value of [destination+'&request=second', destination+'&next=https://evil.example', destination.replace('login_','bad_'), destination+'#fragment',destination.replace('one.example','evil.example')]){
   assert.equal((await f.request('one.example','/auth/sso/start?app=members&next='+encodeURIComponent(value))).status,400);
  }
 }finally{f.sql.close()}
});

test('retired portal restarts login on OrgPortal before binding a browser or session',async()=>{
 const f=fixture();try{
  f.env.PORTAL_AUTH_ORIGINS+=',https://codecollective.us,https://orgportal.cc';
  const r=await f.request('codecollective.us','/auth/sso/start?'+new URLSearchParams({app:'members',next:'https://codecollective.us/p/auth/callback?next=%2Fchat',provider:'google',login_hint:'123456789'}));
  assert.equal(r.status,303);const url=new URL(r.headers.get('location'));assert.equal(url.origin,'https://orgportal.cc');assert.equal(url.pathname,'/pidp/auth/sso/start');assert.equal(url.searchParams.get('next'),'https://orgportal.cc/auth/callback?next=%2Fchat');assert.equal(url.searchParams.get('provider'),'google');assert.equal(url.searchParams.get('login_hint'),'123456789');assert.equal(r.headers.get('set-cookie'),null);assert.equal(f.sql.prepare('SELECT count(*) n FROM portal_sso_requests').get().n,0);
  const fresh=await f.request('orgportal.cc',url.pathname.replace('/pidp','')+url.search);assert.equal(fresh.status,303);const row=f.sql.prepare('SELECT origin,next FROM portal_sso_requests').get();assert.equal(row.origin,'https://orgportal.cc');assert.equal(row.next,'https://orgportal.cc/auth/callback?next=%2Fchat');
 }finally{f.sql.close()}
});

test('login branding follows the live portal ticket; revoked registrations cannot complete sign-in',async()=>{
 const f=fixture(true);try{
  const started=await start(f);const auth=new URL(started.authorize);
  const login=await f.request('id.example','/app/login?'+new URLSearchParams({app:'members',next:auth.href}));assert.equal(login.status,200);assert.match(await login.text(),/Sign in to Test Portal/);
  const token=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const authorized=await f.request('id.example',auth.pathname+auth.search,{cookie:'pidp_session='+token});assert.equal(authorized.status,303);
  const complete=new URL(authorized.headers.get('location'));
  f.env.PORTAL_CLIENTS_JSON='{}';
  assert.equal((await f.request('one.example',complete.pathname.replace('/pidp','')+complete.search,{cookie:started.browser})).status,400);
 }finally{f.sql.close()}
});

test('every registered product keeps its brand, host-only session and original destination',async()=>{
 const defaults=JSON.parse(readFileSync(new URL('../../shared/portal-clients.json',import.meta.url),'utf8'));
 const f=fixture(true);try{
  f.env.PORTAL_CLIENTS_JSON=undefined;f.env.PORTAL_AUTH_ORIGINS=Object.keys(defaults).join(',');f.env.PORTAL_SSO_APP_SLUG='orgportal';f.sql.exec("UPDATE websites SET slug='orgportal'");
  const token=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  for(const [origin,client] of Object.entries(defaults).filter(([,c])=>!c.restartOrigin)){
   const host=new URL(origin).host,started=await start(f,host),authorize=new URL(started.authorize);
   const login=await f.request('id.example','/app/login?'+new URLSearchParams({app:'orgportal',next:authorize.href}));assert.match(await login.text(),new RegExp('Sign in to '+client.name));
   const approved=await f.request('id.example',authorize.pathname+authorize.search,{cookie:'pidp_session='+token});assert.equal(approved.status,303);
   const complete=new URL(approved.headers.get('location'));assert.equal(complete.origin,origin);assert.equal(complete.searchParams.has('token'),false);
   const finished=await f.request(host,complete.pathname.replace('/pidp','')+complete.search,{cookie:started.browser});assert.equal(finished.status,303);assert.equal(finished.headers.get('location'),origin+'/auth/callback?next=%2Fpeople');
   const session=finished.headers.getSetCookie().find(c=>c.startsWith('pidp_session='));assert.ok(!session.includes('Domain='));const claims=await verifyJwt(f.env,decodeURIComponent(session.split(';')[0].slice('pidp_session='.length)));assert.equal(claims.actor_type,'website_user');assert.equal(claims.website_id,'site');assert.equal(claims.sub,'member');assert.notEqual(claims.is_sysadmin,true);
  }
 }finally{f.sql.close()}
});

test('account chooser and fresh login preserve portal context without silent session reuse',async()=>{
 const f=fixture();try{
  const session=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const started=await f.request('one.example','/auth/sso/start?prompt=select_account');
  const authorize=new URL(started.headers.get('location'));assert.equal(authorize.searchParams.get('prompt'),'select_account');
  const chooser=await f.request('id.example',authorize.pathname+authorize.search,{cookie:'pidp_session='+session});
  assert.equal(chooser.status,200);const html=await chooser.text();assert.match(html,/Choose an account/);assert.match(html,/Continue as member@example.test/);
  assert.equal(f.sql.prepare('SELECT code_hash FROM portal_sso_requests').get().code_hash,null);
  const fresh=await f.request('id.example',authorize.pathname+'?request='+authorize.searchParams.get('request')+'&prompt=login',{cookie:'pidp_session='+session});
  assert.match(fresh.headers.get('location'),/app\/login/);
  assert.equal((await f.request('one.example','/auth/sso/start?prompt=unknown')).status,400);
 }finally{f.sql.close()}
});

test('sign-in without a usable session goes straight to login and retains the return destination',async()=>{
 const f=fixture();try{
  const next='https://one.example/auth/callback?next=%2Fevents%2Fdemo%23apply';
  const started=await f.request('one.example','/auth/sso/start?'+new URLSearchParams({prompt:'select_account',next}));
  const authorize=new URL(started.headers.get('location'));
  const unknown=await signJwt(f.env,{sub:'missing',actor_type:'website_user',website_id:'site'});
  const wrongTenant=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'other'});
  for(const cookie of ['', 'pidp_session=invalid', 'pidp_session='+unknown, 'pidp_session='+wrongTenant]){
   const response=await f.request('id.example',authorize.pathname+authorize.search,{cookie});
   assert.equal(response.status,303,'No empty account chooser or extra click');
   const login=new URL(response.headers.get('location'));
   assert.equal(login.pathname,'/app/login');assert.equal(login.searchParams.get('app'),'members');
   assert.equal(login.searchParams.get('prompt'),'login');
   const resume=new URL(login.searchParams.get('next'));
   assert.equal(resume.searchParams.get('request'),authorize.searchParams.get('request'));
   assert.equal(resume.searchParams.has('prompt'),false,'Login must resume without another chooser');
   assert.equal(f.sql.prepare('SELECT next,code_hash FROM portal_sso_requests').get().next,next);
   assert.equal(f.sql.prepare('SELECT code_hash FROM portal_sso_requests').get().code_hash,null);
  }
 }finally{f.sql.close()}
});

test('shared identity accepts primary accounts without another portal login and preserves linked member subjects',async()=>{
 const f=fixture();try{
 f.env.PORTAL_SHARED_IDENTITY='true';
 const token=await signJwt(f.env,{sub:'owner',actor_type:'owner'});
 for(const linked of [false,true]){
  if(linked)f.sql.exec("INSERT INTO account_identity_links VALUES('website:site:member','owner','site','member','2026-10-09')");
  const started=await start(f);const url=new URL(started.authorize);
  const result=await f.request('id.example',url.pathname+url.search,{cookie:'pidp_session='+token});
  assert.equal(result.status,303);
  const complete=new URL(result.headers.get('location'));
  const finished=await f.request('one.example',complete.pathname.replace('/pidp','')+complete.search,{cookie:started.browser});
  assert.equal(finished.status,303);
  const cookie=finished.headers.getSetCookie().find(c=>c.startsWith('pidp_session='));const claims=await verifyJwt(f.env,decodeURIComponent(cookie.split(';')[0].slice('pidp_session='.length)));assert.equal(claims.sub,linked?'member':'owner');
 }
 const started=await start(f);const u=new URL(started.authorize);
 const login=await f.request('id.example',u.pathname+u.search);
 const target=new URL(login.headers.get('location'));
 assert.equal(target.pathname,'/app/login');assert.equal(target.searchParams.get('app'),'members');
 }finally{f.sql.close()}
});

test('path-mounted central identity preserves the browser-bound tenant handoff',async()=>{
 const f=fixture(true);
 f.env.PUBLIC_BASE_URL='https://orgportal.cc/pidp';
 f.env.PORTAL_AUTH_ORIGINS+=',https://orgportal.cc';
 try {
  const s=await start(f);
  const authorize=new URL(s.authorize);
  assert.equal(authorize.origin+authorize.pathname,'https://orgportal.cc/pidp/auth/sso/authorize');
  const login=await f.request('orgportal.cc',authorize.pathname.replace('/pidp','')+authorize.search);
  const target=new URL(login.headers.get('location'));
  assert.equal(target.pathname,'/pidp/app/login');
  assert.equal(new URL(target.searchParams.get('next')).pathname,'/pidp/auth/sso/authorize');
  const page=await f.request('orgportal.cc','/app/login?app=members&next='+encodeURIComponent(target.searchParams.get('next')));
  assert.match(await page.text(),/action="\/pidp\/app\/login"/);
  const session=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  const completed=await f.request('orgportal.cc',authorize.pathname.replace('/pidp','')+authorize.search,{cookie:'pidp_session='+session});
  const complete=new URL(completed.headers.get('location'));
  const result=await f.request('one.example',complete.pathname.replace('/pidp','')+complete.search,{cookie:s.browser});
  assert.equal(result.status,303);
  assert.equal(new URL(result.headers.get('location')).origin,'https://one.example');
  assert.equal((await f.request('orgportal.cc','/auth/session',{cookie:'pidp_session='+session})).status,200);
  assert.equal((await f.request('orgportal.cc','/auth/session',{cookie:'pidp_session=forged'})).status,401);
  assert.equal((await f.request('orgportal.cc',authorize.pathname.replace('/pidp','')+authorize.search,{'x-forwarded-host':'one.example'})).status,400);
 }finally{f.sql.close()}
});
test('member login offers explicit primary sign-in without reusing a primary cookie as member proof',async()=>{
 const f=fixture(true);
 try{
  const s=await start(f);
  const owner=await signJwt(f.env,{sub:'owner'});
  const response=await f.request('id.example','/app/login?app=members&next='+encodeURIComponent(s.authorize),{cookie:'pidp_session='+owner});
  assert.equal(response.status,200);
  const html=await response.text();
  assert.match(html,/Sign in with a PIdP account/);
  assert.match(html,/owner=1&amp;next=/);
  assert.match(html,/name="app" value="members"/);
  assert.match(html,/name="password"/);
  assert.equal(f.sql.prepare('SELECT count(*) AS n FROM account_identity_links').get().n,0);
 }finally{f.sql.close()}
});
test('example Google credentials never redirect a user to a nonfunctional OAuth client',async()=>{
 const f=fixture(true);
 try{
  f.env.GOOGLE_CLIENT_ID='google-client-id';f.env.GOOGLE_CLIENT_SECRET='google-client-secret';
  const response=await f.request('id.example','/auth/google/login?app=members&next=%2Fprofile');
  assert.equal(response.status,503);assert.equal(response.headers.get('location'),null);
  assert.match(await response.text(),/Google sign-in is not configured/);
  const login=await f.request('id.example','/app/login?app=members&next=%2Fprofile');
  assert.doesNotMatch(await login.text(),/Continue with Google/);
 }finally{f.sql.close()}
});

test('LifeTech account switching keeps branding and fresh sign-in with a surviving central session', async () => {
 const f=fixture(true);
 try {
  const clients=JSON.parse(f.env.PORTAL_CLIENTS_JSON);
  clients['https://one.example'].name='LifeTech';f.env.PORTAL_CLIENTS_JSON=JSON.stringify(clients);
  const session=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site'});
  for (const shared of ['false','true']) {
   f.env.PORTAL_SHARED_IDENTITY=shared;
   const started=await f.request('one.example','/auth/sso/start?prompt=select_account&next='+encodeURIComponent('https://one.example/auth/callback?next=%2Forgs%2Flifetech'));
   const chooser=await f.request('id.example',new URL(started.headers.get('location')).pathname+new URL(started.headers.get('location')).search,{cookie:'pidp_session='+session});
   assert.equal(chooser.status,200);
   const html=await chooser.text();
   assert.match(html,/Continue as member@example.test/);
   assert.match(html,/LifeTech logo/);
   const href=html.match(/href="([^"]+)">Use another portal account/)[1].replaceAll('&amp;','&');
   const login=new URL(href);
   assert.equal(login.searchParams.get('prompt'),'login');
   assert.equal(login.searchParams.get('app'),'members');
   const form=await f.request('id.example',login.pathname+login.search,{cookie:'pidp_session='+session});
   assert.equal(form.status,200);
   const body=await form.text();
   assert.match(body,/<h1>Sign in to LifeTech<\/h1>/);
   assert.match(body,/lifetech-logo-v2.png/);
   if(shared === "true") assert.doesNotMatch(body,/name="app"/);
   else assert.match(body,/name="app" value="members"/);
   assert.match(body,/<p>lifetech.fyi<\/p>/);
   assert.equal(f.sql.prepare('SELECT count(*) n FROM portal_sso_requests WHERE code_hash IS NOT NULL').get().n,0);
   // Validation errors must keep the same tenant and return ticket.
   const error=await fullApp.request('https://id.example/app/login',{method:'POST',body:new URLSearchParams({app:'members',next:login.searchParams.get('next')})},f.env);
   assert.equal(error.status,422);assert.match(await error.text(),/Sign in to LifeTech/);
  }
 } finally { f.sql.close() }
});

test('central registered portal uses the requesting tenant ticket for branded login',async()=>{
 const f=fixture(true);
 try{
  const clients=JSON.parse(f.env.PORTAL_CLIENTS_JSON);
  clients['https://one.example'].name='LifeTech';clients['https://orgportal.cc'].name='OrgPortal';
  f.env.PORTAL_CLIENTS_JSON=JSON.stringify(clients);f.env.PORTAL_AUTH_ORIGINS+=',https://orgportal.cc';f.env.PUBLIC_BASE_URL='https://orgportal.cc/pidp';
  const s=await start(f);const authorize=new URL(s.authorize);
  const response=await f.request('orgportal.cc',authorize.pathname.replace('/pidp','')+authorize.search);
  const target=new URL(response.headers.get('location'));
  const form=await f.request('orgportal.cc',target.pathname.replace('/pidp','')+target.search);
  assert.equal(form.status,200);assert.match(await form.text(),/<h1>Sign in to LifeTech on OrgPortal<\/h1>/);
 }finally{f.sql.close()}
});

test('expired sign-in offers a safe HTML retry without reusing the ticket',async()=>{
 const f=fixture();try{
  const started=await start(f);const authorize=new URL(started.authorize);
  f.sql.exec('UPDATE portal_sso_requests SET expires_at=0');
  const expired=await f.request('id.example',authorize.pathname+authorize.search);
  assert.equal(expired.status,400);assert.match(expired.headers.get('content-type'),/text\/html/);
  assert.match(expired.headers.get('content-security-policy'),/form-action https:\/\/orgportal.cc https:\/\/id.example https:\/\/one.example/);
  const html=await expired.text();assert.match(html,/<button type="submit">Try again<\/button>/);
  assert.match(html,/action="https:\/\/one.example\/pidp\/auth\/sso\/start"/);
  assert.match(html,/name="next" value="https:\/\/one.example\/auth\/callback\?next=%2Fpeople"/);
  assert.ok(!html.includes(authorize.searchParams.get('request')));
  const missing=await f.request('id.example','/auth/sso/authorize?request=missing&next=https://evil.example');
  const fallback=await missing.text();assert.match(fallback,/action="https:\/\/orgportal.cc\/users\/login"/);assert.ok(!fallback.includes('evil.example'));
 }finally{f.sql.close()}
});

test('tenant SSO preserves original authentication time rather than upgrading remembered login',async()=>{
 const f=fixture(true);try{
  const authTime=Math.floor(Date.now()/1000)-1800;
  const issuerSession=await signJwt(f.env,{sub:'member',actor_type:'website_user',website_id:'site',auth_time:authTime});
  const started=await start(f),authorize=new URL(started.authorize);
  const approved=await f.request('id.example',authorize.pathname+authorize.search,{cookie:'pidp_session='+issuerSession});
  const complete=new URL(approved.headers.get('location'));
  const result=await f.request('one.example',complete.pathname.replace('/pidp','')+complete.search,{cookie:started.browser});
  assert.equal(result.status,303);
  const cookie=result.headers.getSetCookie().find(c=>c.startsWith('pidp_session='));
  const claims=await verifyJwt(f.env,decodeURIComponent(cookie.split(';')[0].slice('pidp_session='.length)));
  assert.equal(claims.auth_time,authTime);
 }finally{f.sql.close()}
});

test('LifeTech login identifies tenant and central host on form and validation errors', async () => {
 const f=fixture(true);
 try {
  f.env.PORTAL_CLIENTS_JSON=JSON.stringify({'https://lifetech.fyi':{name:'LifeTech',accountApp:'members',callbacks:['/auth/callback']}});
  f.env.PORTAL_AUTH_ORIGINS='https://lifetech.fyi';
  const started=await start(f,'lifetech.fyi');
  const query=new URLSearchParams({app:'members',next:started.authorize});
  for(const [host,label,domain] of [['orgportal.cc','LifeTech on OrgPortal','orgportal.cc'],['lifetech.fyi','LifeTech','lifetech.fyi']]) {
   for(const method of ['GET','POST']) {
    const response=await fullApp.request('https://'+host+'/app/login'+(method==='GET'?'?'+query:''),{method,...(method==='POST'?{body:query}:{})},f.env);
    assert.equal(response.status,method==='GET'?200:422);
    const html=await response.text();
    assert.ok(html.includes('<h1>Sign in to '+label+'</h1>'));
    assert.ok(html.includes('<p>'+domain+'</p>'));
    assert.doesNotMatch(html,/Authentication provided by PIdP/);
    const visible=html.replace(/<style>[\s\S]*?<\/style>/g,'').replace(/<[^>]+>/g,'');
    assert.equal(visible.split('orgportal.cc').length-1,host==='orgportal.cc'?1:0);
   }
  }
 } finally {f.sql.close();}
});

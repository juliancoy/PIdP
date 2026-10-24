import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {getPlatformProxy} from 'wrangler';
import app from '../src/index.ts';
import {hashPassword, signJwt, verifyJwt} from '../src/crypto.ts';
import {migrateSharedCredentials} from '../scripts/migrate-shared-credentials.mjs';
const options={appSlug:'orgportal',configuredAppSlug:'orgportal',sharedIdentity:false,apply:true,writesPaused:true,backupVerified:true};
test('real local D1 batch migrates, rolls back late failure, and restores a backup', async()=>{
 const dir=await mkdtemp(join(tmpdir(),'pidp-migration-'));let proxy;
 try {
  const config=join(dir,'wrangler.json');
  await writeFile(config,JSON.stringify({name:'migration-rehearsal',compatibility_date:'2026-06-03',d1_databases:[{binding:'DB',database_name:'isolated',database_id:'00000000-0000-0000-0000-000000000001'}]}));
  proxy=await getPlatformProxy({configPath:config,persist:false,remoteBindings:false,envFiles:[]});const db=proxy.env.DB;
  for(const file of ['0001_initial.sql','0010_account_identity_links.sql','0009_portal_sso.sql','0013_browser_sessions.sql','0015_portal_desktop_auth.sql']){
   const sql=await readFile(new URL('../migrations/'+file,import.meta.url),'utf8');
   for(const statement of sql.replace(/^--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean)) await db.prepare(statement).run();
  }
  await db.batch([
   db.prepare("INSERT INTO users(id,email,hashed_password,is_active) VALUES('operator','operator@test',NULL,1),('primary','Same@test','primary-hash',1)"),
   db.prepare("INSERT INTO websites(id,owner_id,name,slug) VALUES('site','operator','Portal','orgportal')"),
   db.prepare("INSERT INTO website_users(id,website_id,email,hashed_password,is_active) VALUES('new','site','new@test','member-hash',1),('linked','site','same@test','different-salted-hash',1)"),
   db.prepare("INSERT INTO account_identity_links VALUES('website:site:linked','primary','site','linked','now')"),
  ]);
  const newHash=await hashPassword('new-password');
  const primaryHash=await hashPassword('primary-password');
  await db.prepare("UPDATE website_users SET hashed_password=? WHERE id='new'").bind(newHash).run();
  await db.prepare("UPDATE users SET hashed_password=? WHERE id='primary'").bind(primaryHash).run();
  const tables=['users','websites','website_users','account_identity_links'];
  const snapshot=async()=>Object.fromEntries(await Promise.all(tables.map(async name=>[name,(await db.prepare(`SELECT * FROM ${name} ORDER BY 1`).all()).results])));
  const before=await snapshot();
  assert.equal((await migrateSharedCredentials(db,{...options,apply:false})).accounts,2);assert.deepEqual(await snapshot(),before);
  await assert.rejects(migrateSharedCredentials(db,{...options,appSlug:'missing'}));
  await assert.rejects(migrateSharedCredentials(db,{...options,writesPaused:false}));
  await assert.rejects(migrateSharedCredentials(db,{...options,backupVerified:false}));
  await db.prepare("UPDATE website_users SET is_active=0 WHERE id='linked'").run();const conflicting=await snapshot();
  await assert.rejects(migrateSharedCredentials(db,options));assert.deepEqual(await snapshot(),conflicting);
  await db.prepare("UPDATE website_users SET is_active=1 WHERE id='linked'").run();await migrateSharedCredentials(db,options);
  assert.equal((await db.prepare("SELECT hashed_password FROM users WHERE id='primary'").first()).hashed_password,primaryHash);
  assert.equal((await db.prepare("SELECT hashed_password FROM users WHERE id='new'").first()).hashed_password,newHash);
  assert.equal((await db.prepare("SELECT hashed_password FROM website_users WHERE id='new'").first()).hashed_password,null);
  await migrateSharedCredentials(db,options);
  const env={DB:db,SECRET_KEY:'isolated-migration-key',PUBLIC_BASE_URL:'https://orgportal.cc/pidp',
   PORTAL_SHARED_IDENTITY:'true',PORTAL_SSO_APP_SLUG:'orgportal',EMAIL_VERIFICATION_REQUIRED:'false',
   PORTAL_AUTH_ORIGINS:'https://tenant.example',PORTAL_CLIENTS_JSON:JSON.stringify({'https://tenant.example':{name:'Tenant',accountApp:'orgportal',callbacks:['/auth/callback']}})};
  const login=(email,password)=>app.request('https://orgportal.cc/app/login',{method:'POST',body:new URLSearchParams({app:'orgportal',email,password,next:'/profile'})},env);
  const response=await login('new@test','new-password');assert.equal(response.status,303);
  assert.equal((await login('same@test','primary-password')).status,303);
  assert.equal((await login('same@test','different-salted-hash')).status,401);
  const cookie=response.headers.getSetCookie().find(c=>c.startsWith('pidp_session=')).split(';')[0];
  const oldSession=await signJwt(env,{sub:'new',actor_type:'website_user',website_id:'site'});
  assert.equal((await verifyJwt(env,oldSession)).sub,'new');
  const started=await app.request('https://tenant.example/auth/sso/start?app=orgportal&next='+encodeURIComponent('https://tenant.example/auth/callback'),{},env);
  assert.equal(started.status,303);
  const browser=started.headers.getSetCookie().find(c=>c.startsWith('__Host-pidp_sso_browser=')).split(';')[0];
  const authorize=new URL(started.headers.get('location'));authorize.pathname=authorize.pathname.replace(/^\/pidp/,'');
  const authorized=await app.request(authorize.toString(),{headers:{cookie}},env);assert.equal(authorized.status,303);
  const finish=new URL(authorized.headers.get('location'));finish.pathname=finish.pathname.replace(/^\/pidp/,'');
  const finished=await app.request(finish.toString(),{headers:{cookie:browser}},env);assert.equal(finished.status,303);
  const tenantToken=finished.headers.getSetCookie().find(c=>c.startsWith('pidp_session=')).split(';')[0].slice('pidp_session='.length);
  const claims=await verifyJwt(env,decodeURIComponent(tenantToken));assert.equal(claims.sub,'new');assert.equal(claims.actor_type,'website_user');assert.equal(claims.website_id,'site');
  await db.prepare("UPDATE users SET is_active=0 WHERE id='new'").run();assert.equal((await login('new@test','new-password')).status,401);
  const restore=tables.toReversed().map(name=>db.prepare(`DELETE FROM ${name}`));
  for(const name of tables) for(const row of before[name]) {
   const columns=Object.keys(row);restore.push(db.prepare(`INSERT INTO ${name} (${columns.join(',')}) VALUES (${columns.map(()=>'?').join(',')})`).bind(...Object.values(row)));
  }
  await db.batch(restore);assert.deepEqual(await snapshot(),before);
 } finally {if(proxy)await proxy.dispose();await rm(dir,{recursive:true,force:true});}
});

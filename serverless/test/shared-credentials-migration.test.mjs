import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync, backup} from 'node:sqlite';
import {mkdtempSync, writeFileSync, copyFileSync, rmSync, statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
const migration=readFileSync(new URL('../../docs/proposals/0012_shared_orgportal_credentials.sql',import.meta.url),'utf8');
function fixture(){
 const db=new DatabaseSync(':memory:');
 for(const name of ['0001_initial.sql','0010_account_identity_links.sql'])db.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
 db.exec(`INSERT INTO users(id,email,provider,provider_account_id) VALUES('operator','operator@test',NULL,NULL),('primary','same@test','google','verified-provider-subject');
 INSERT INTO websites(id,owner_id,name,slug) VALUES('shared','operator','OrgPortal','code-collective'),('other','operator','Other','other');`);
 return db;
}
function apply(db){db.exec('BEGIN');try{db.exec(migration.replaceAll("?1", "'code-collective'"));db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}}
test('migration preserves IDs and provider identities, moves passwords once and retains subject aliases',()=>{
 const db=fixture();try{
 db.exec(`INSERT INTO website_users(id,website_id,email,hashed_password,provider,provider_account_id) VALUES('new','shared','new@test','hash','github','new-subject'),('old','shared','same@test',NULL,'google','verified-provider-subject'),('unrelated','other','other@test','untouched',NULL,NULL);`);
 apply(db);apply(db);
 assert.equal(db.prepare("SELECT hashed_password FROM users WHERE id='new'").get().hashed_password,'hash');
 assert.equal(db.prepare("SELECT canonical_user_id FROM account_identity_links WHERE subject='website:shared:old'").get().canonical_user_id,'primary');
 assert.equal(db.prepare("SELECT canonical_user_id FROM account_identity_links WHERE subject='website:shared:new'").get().canonical_user_id,'new');
 assert.equal(db.prepare("SELECT hashed_password FROM website_users WHERE id='new'").get().hashed_password,null);
 assert.equal(db.prepare("SELECT hashed_password FROM website_users WHERE id='unrelated'").get().hashed_password,'untouched');
 assert.equal(db.prepare('SELECT count(*) n FROM account_identity_links').get().n,2);
 }finally{db.close()}
});
test('email-only collisions roll back every change',()=>{
 const db=fixture();try{
 db.exec(`INSERT INTO website_users(id,website_id,email,provider,provider_account_id) VALUES('collision','shared','same@test','google','different-subject'),('new','shared','new@test','github','new-subject')`);
 assert.throws(()=>apply(db));assert.equal(db.prepare("SELECT count(*) n FROM users WHERE id='new'").get().n,0);assert.equal(db.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
 }finally{db.close()}
});


test('a primary account without provider metadata is still an email-only collision',()=>{
 const db=fixture();try{
 db.exec("UPDATE users SET provider=NULL,provider_account_id=NULL WHERE id='primary'; INSERT INTO website_users(id,website_id,email,provider,provider_account_id) VALUES('collision','shared','same@test','google','subject')");
 assert.throws(()=>apply(db));assert.equal(db.prepare('SELECT count(*) n FROM account_identity_links').get().n,0);
 }finally{db.close()}
});


test('offline operator CLI creates a private restorable backup and rejects overwrites',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'identity-cli-'));const original=fixture();
 try {
  original.exec("INSERT INTO website_users(id,website_id,email,hashed_password) VALUES('new','shared','new@test','member-hash')");
  const database=join(dir,'copy.sqlite'),saved=join(dir,'backup.sqlite'),config=join(dir,'config.json');
  await backup(original,database);
  writeFileSync(config,JSON.stringify({vars:{PORTAL_SHARED_IDENTITY:'false',PORTAL_SSO_APP_SLUG:'code-collective'}}));
  const command=[fileURLToPath(new URL('../scripts/migrate-shared-credentials.mjs',import.meta.url)),'--config',config,'--database',database,'--app','code-collective'];
  const call=(extra=[])=>spawnSync(process.execPath,[...command,...extra],{encoding:'utf8',timeout:15000});
  const preview=call();assert.equal(preview.status,0,preview.stderr);assert.equal(JSON.parse(preview.stdout).applied,false);
  const flags=['--apply','--writes-paused','--backup',saved];
  const applied=call(flags);assert.equal(applied.status,0,applied.stderr);assert.equal(JSON.parse(applied.stdout).applied,true);
  assert.equal(statSync(saved).mode&0o777,0o600);
  const migrated=new DatabaseSync(database);
  try {assert.equal(migrated.prepare("SELECT hashed_password FROM website_users WHERE id='new'").get().hashed_password,null);} finally {migrated.close();}
  assert.notEqual(call(flags).status,0);
  copyFileSync(saved,database);
  const restored=new DatabaseSync(database);
  try {assert.equal(restored.prepare("SELECT hashed_password FROM website_users WHERE id='new'").get().hashed_password,'member-hash');assert.equal(restored.prepare("SELECT id FROM users WHERE id='new'").get(),undefined);}finally{restored.close();}
 } finally {original.close();rmSync(dir,{recursive:true,force:true});}
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
const migration=readFileSync(new URL('../../docs/proposals/0012_shared_orgportal_credentials.sql',import.meta.url),'utf8');
function fixture(){
 const db=new DatabaseSync(':memory:');
 for(const name of ['0001_initial.sql','0010_account_identity_links.sql'])db.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
 db.exec(`INSERT INTO users(id,email,provider,provider_account_id) VALUES('operator','operator@test',NULL,NULL),('primary','same@test','google','verified-provider-subject');
 INSERT INTO websites(id,owner_id,name,slug) VALUES('shared','operator','OrgPortal','code-collective'),('other','operator','Other','other');`);
 return db;
}
function apply(db){db.exec('BEGIN');try{db.exec(migration);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}}
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

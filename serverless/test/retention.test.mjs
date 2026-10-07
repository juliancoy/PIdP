import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { runRetention } from '../src/retention.ts';
function adapter(sql) { return {prepare(q){return {bind(...v){return {async first(){return sql.prepare(q).get(...v);},async run(){return {meta:sql.prepare(q).run(...v)};}};}};}}; }

test('bounded temporary expiry preserves live rows, grants and replay evidence',async()=>{
 const sql=new DatabaseSync(':memory:');
 const tables=['mcp_oauth_requests','mcp_oauth_codes','mcp_oauth_logins','oauth_states','portal_sso_requests','account_identity_link_previews','account_identity_link_requests'];
 for(const table of tables)sql.exec(`CREATE TABLE ${table}(id TEXT PRIMARY KEY,expires_at INTEGER)`);
 for(const table of ['portal_sso_limits','mcp_oauth_registration_limits'])sql.exec(`CREATE TABLE ${table}(id TEXT PRIMARY KEY,window_start INTEGER)`);
 sql.exec("CREATE TABLE mcp_oauth_grants(id TEXT);INSERT INTO mcp_oauth_grants VALUES('active');CREATE TABLE mcp_oauth_refresh(hash TEXT,used INTEGER);INSERT INTO mcp_oauth_refresh VALUES('replay-evidence',1)");
 const now=1800000000000,cutoff=Math.floor(now/1000)-23*3600;
 for(const table of tables){const put=sql.prepare(`INSERT INTO ${table} VALUES(?,?)`);put.run('old',cutoff-1);put.run('boundary',cutoff);put.run('future',cutoff+999999);}
 for(let i=0;i<501;i++)sql.prepare('INSERT INTO mcp_oauth_codes VALUES(?,?)').run(String(i),cutoff-1);
 const db=adapter(sql);
 assert.equal((await runRetention(db,now,true)).mcp_oauth_codes,502);
 assert.equal((await runRetention(db,now)).mcp_oauth_codes,500);
 assert.equal((await runRetention(db,now)).mcp_oauth_codes,2);
 assert.equal((await runRetention(db,now)).mcp_oauth_codes,0);
 assert.equal(sql.prepare('SELECT COUNT(*) n FROM mcp_oauth_grants').get().n,1);
 assert.equal(sql.prepare('SELECT COUNT(*) n FROM mcp_oauth_refresh').get().n,1);
 for(const table of tables)assert.equal(sql.prepare(`SELECT COUNT(*) n FROM ${table}`).get().n,2);
 await assert.rejects(runRetention(db,-1));sql.close();
});

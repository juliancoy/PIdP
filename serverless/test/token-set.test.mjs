import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import app from '../src/index.ts';
import { signJwt } from '../src/crypto.ts';
test('download creates four hashed owner tokens and rejects website identities', async () => {
 const sql = new DatabaseSync(':memory:');
 sql.exec(`CREATE TABLE users (id TEXT, email TEXT, full_name TEXT, identity_data TEXT, is_active INTEGER, created_at TEXT);
 CREATE TABLE user_api_tokens (id TEXT, owner_id TEXT, name TEXT, token_hash TEXT, scope TEXT, is_active INTEGER, last_used_at TEXT, created_at TEXT);
 INSERT INTO users VALUES ('owner','owner@example.test','Owner','{}',1,'2026-01-01');`);
 const DB = { prepare(q) { return { bind(...args) { return { async first() { return sql.prepare(q).get(...args) || null; }, async run() { return sql.prepare(q).run(...args); } }; } }; }, async batch(statements) { sql.exec('BEGIN'); try { for (const s of statements) await s.run(); sql.exec('COMMIT'); } catch(e) { sql.exec('ROLLBACK'); throw e; } } };
 const env = { DB, SECRET_KEY:'local-test-secret' };
 const request = async claims => app.request('https://id.example/auth/tokens/download', {method:'POST',headers:{Authorization:`Bearer ${await signJwt(env,claims)}`}},env);
 try {
 assert.equal((await request({sub:'owner',actor_type:'website_user',website_id:'site'})).status,403);
 const response = await request({sub:'owner',actor_type:'owner'});
 assert.equal(response.status,200);
 assert.equal(response.headers.get('cache-control'),'no-store');
 assert.match(response.headers.get('content-disposition'),/\.env\.pidp/);
 const values = Object.fromEntries((await response.text()).trim().split('\n').map(line=>line.split('=')));
 assert.deepEqual(Object.keys(values),['PIDP_PAT','PIDP_ORG_PORTAL_TOKEN','PIDP_ORG_MCP_TOKEN','PIDP_ORG_ADMIN_TOKEN']);
 const rows = sql.prepare('SELECT * FROM user_api_tokens').all();
 assert.equal(rows.length,4);
 assert.equal(new Set(Object.values(values)).size,4);
 for(const row of rows) { assert.equal(row.owner_id,'owner'); assert.equal(row.is_active,1); assert.ok(!Object.values(values).includes(row.token_hash)); }
 } finally {sql.close();}
});

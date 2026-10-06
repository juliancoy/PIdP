import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import app from '../src/index.ts';
import { signJwt } from '../src/crypto.ts';

function fixture() {
  const sql = new DatabaseSync(':memory:',{enableForeignKeyConstraints:false});
  sql.exec(`CREATE TABLE users (id TEXT, email TEXT, full_name TEXT, identity_data TEXT, is_active INTEGER, created_at TEXT);
    CREATE TABLE website_users (id TEXT, website_id TEXT, email TEXT, full_name TEXT, identity_data TEXT, is_active INTEGER, created_at TEXT);
    INSERT INTO users VALUES ('member', 'same@example.test', 'Owner', '{}', 1, '2026-01-01');
    INSERT INTO website_users VALUES ('member', 'site', 'same@example.test', 'Member', '{"bio":"Keep me","roles":["member"]}', 1, '2026-01-01');
    INSERT INTO website_users VALUES ('member', 'other', 'same@example.test', 'Other tenant', '{}', 1, '2026-01-01');`);
  sql.exec(readFileSync(new URL('../migrations/0010_account_identity_links.sql',import.meta.url),'utf8'));
  const DB = { prepare(query) {
    const statement = sql.prepare(query);
    return { bind(...args) { return {
      async run() { return statement.run(...args); },
      async first() { return statement.get(...args) || null; },
    }; } };
  } };
  const env = { DB, SECRET_KEY: 'profile-local-test', ADMIN_EMAILS: 'same@example.test' };
  const request = async (claims, body, path = '/auth/me') => {
    const token = await signJwt(env, claims);
    return app.request(`https://id.example${path}`, {
      method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }, env);
  };
  return { sql, request, env };
}

test('website members save only their own profile and retain the account namespace', async () => {
  const f = fixture();
  try {
    const response = await f.request({ sub: 'member', actor_type: 'website_user', website_id: 'site' }, {
      full_name: 'New Name', display_name: 'New Name', avatar_url: 'https://example.test/avatar.png',
      id: 'owner', website_id: 'other', email: 'admin@example.test', is_active: false, is_sysadmin: true, roles: ['admin'],
    });
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.full_name, 'New Name');
    assert.equal(data.is_sysadmin, false);
    assert.equal(data.email, 'same@example.test');
    assert.equal(data.is_active, true);
    assert.deepEqual(data.identity_data, { bio: 'Keep me', roles: ['member'], display_name: 'New Name', avatar_url: 'https://example.test/avatar.png' });
    assert.equal(f.sql.prepare('SELECT full_name FROM users').get().full_name, 'Owner');
    assert.equal(f.sql.prepare("SELECT full_name FROM website_users WHERE website_id = 'other'").get().full_name, 'Other tenant');
    assert.equal((await f.request({ sub: 'member', actor_type: 'website_user', website_id: 'site' }, {}, '/websites/site/auth-config')).status, 403);
  } finally { f.sql.close(); }
});

test('wrong or missing website namespaces cannot save a profile', async () => {
  const f = fixture();
  try {
    for (const website_id of ['missing', undefined]) {
      const response = await f.request({ sub: 'member', actor_type: 'website_user', website_id }, { full_name: 'No' });
      assert.ok([401, 403, 404].includes(response.status));
    }
    assert.equal(f.sql.prepare("SELECT full_name FROM website_users WHERE website_id = 'site'").get().full_name, 'Member');
  } finally { f.sql.close(); }
});

test('owner profile saving still updates the owner account', async () => {
  const f = fixture();
  try {
    const response = await f.request({ sub: 'member' }, { full_name: 'Updated owner', display_name: 'Owner name' });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).full_name, 'Updated owner');
    assert.equal(f.sql.prepare("SELECT full_name FROM website_users WHERE website_id = 'site'").get().full_name, 'Member');
  } finally { f.sql.close(); }
});


test('admin authority uses owner IDs and cannot cross account namespaces', async () => {
  const f = fixture();
  try {
    f.env.ADMIN_USER_IDS = 'member';
    f.sql.prepare("UPDATE website_users SET identity_data = ? WHERE website_id = 'site'").run(JSON.stringify({roles: ['admin'], is_sysadmin: true}));
    for (const [claims, expected] of [
      [{sub: 'member', actor_type: 'website_user', website_id: 'site'}, false],
      [{sub: 'member'}, true],
    ]) {
      const token = await signJwt(f.env, claims);
      const response = await app.request('https://id.example/auth/me', {headers: {Authorization: `Bearer ${token}`}}, f.env);
      assert.equal(response.status, 200);
      assert.equal((await response.json()).is_sysadmin, expected);
    }
    f.env.ADMIN_USER_IDS = '';
    f.sql.prepare('UPDATE users SET identity_data = ?').run(JSON.stringify({roles: ['admin'], is_sysadmin: true}));
    const token = await signJwt(f.env, {sub: 'member'});
    const response = await app.request('https://id.example/auth/me', {headers: {Authorization: `Bearer ${token}`}}, f.env);
    assert.equal((await response.json()).is_sysadmin, false);
  } finally { f.sql.close(); }
});


test('explicit central identity link shares personal data without changing session permissions', async () => {
  const f = fixture();
  try {
    for (const table of ['users', 'website_users']) {
      f.sql.exec(`ALTER TABLE ${table} ADD COLUMN provider TEXT; ALTER TABLE ${table} ADD COLUMN provider_account_id TEXT`);
    }
    f.sql.prepare("UPDATE users SET id='owner', provider='google', provider_account_id='verified-google-sub'").run();
    f.sql.prepare("UPDATE website_users SET provider='google',provider_account_id='verified-google-sub' WHERE website_id='site'").run();
    f.sql.prepare("INSERT INTO account_identity_links VALUES('website:site:member','owner','site','member','2026-10-05')").run();
    f.env.ADMIN_USER_IDS = 'owner';
    const token = await signJwt(f.env, {sub:'member',actor_type:'website_user',website_id:'site'});
    const read = async () => {
      const r = await app.request('https://id.example/auth/me', {headers:{Authorization:`Bearer ${token}`}}, f.env);
      assert.equal(r.status,200);return r.json();
    };
    const linked = await read();
    assert.equal(linked.id,'owner');assert.equal(linked.account_id,'member');assert.equal(linked.canonical_user_id,'owner');assert.equal(linked.is_sysadmin,false);
    assert.equal((await app.request('https://id.example/websites',{headers:{Authorization:`Bearer ${token}`}},f.env)).status,403);
    f.sql.prepare("UPDATE users SET identity_data=?").run(JSON.stringify({roles:['owner'],theme_mode:'dark',avatar_url:'https://example.test/owner.png'}));
    assert.equal((await read()).identity_data.theme_mode,'dark');
    assert.deepEqual((await read()).identity_data.roles,['member']);
    const saved = await f.request({sub:'member',actor_type:'website_user',website_id:'site'}, {
      full_name:'Shared name',avatar_url:'https://example.test/shared.png',theme_mode:'light',
      roles:['admin'],is_sysadmin:true,canonical_user_id:'other',provider:'github',provider_account_id:'other',
    });
    assert.equal(saved.status,200);
    const member = await saved.json();assert.equal(member.id,'owner');assert.equal(member.account_id,'member');assert.equal(member.canonical_user_id,'owner');assert.equal(member.is_sysadmin,false);
    assert.equal(member.full_name,'Shared name');assert.deepEqual(member.identity_data.roles,['member']);
    const ownerToken = await signJwt(f.env,{sub:'owner'});
    const ownerResponse = await app.request('https://id.example/auth/me',{headers:{Authorization:`Bearer ${ownerToken}`}},f.env);
    const owner = await ownerResponse.json();
    assert.equal(owner.full_name,'Shared name');assert.equal(owner.identity_data.theme_mode,'light');
    assert.equal(owner.identity_data.avatar_url,'https://example.test/shared.png');assert.deepEqual(owner.identity_data.roles,['owner']);
    assert.equal(f.sql.prepare("SELECT provider_account_id FROM users").get().provider_account_id,'verified-google-sub');
    const updatedOwner = await f.request({sub:'owner'},{full_name:'Owner edit',theme_mode:'dark'});
    assert.equal(updatedOwner.status,200);assert.equal((await read()).full_name,'Owner edit');assert.equal((await read()).identity_data.theme_mode,'dark');
    assert.equal((await f.request({sub:'member',actor_type:'website_user',website_id:'site'},{theme_mode:'invalid'})).status,422);

    f.sql.prepare("UPDATE website_users SET provider_account_id='different-sub',identity_data=? WHERE website_id='site'").run(JSON.stringify({sub:'verified-google-sub',canonical_user_id:'owner'}));
    assert.equal((await read()).canonical_user_id,'owner');
    f.sql.prepare("UPDATE website_users SET provider_account_id='verified-google-sub',provider='github' WHERE website_id='site'").run();
    assert.equal((await read()).canonical_user_id,'owner');
    f.sql.prepare("UPDATE website_users SET provider='google' WHERE website_id='site'").run();
    f.sql.prepare('UPDATE users SET is_active=0').run();
    const disabled = await app.request('https://id.example/auth/me',{headers:{Authorization:`Bearer ${token}`}},f.env);
    assert.equal(disabled.status,401);
  } finally {f.sql.close();}
});

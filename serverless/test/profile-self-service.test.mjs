import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import app from '../src/index.ts';
import { signJwt } from '../src/crypto.ts';

function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE users (id TEXT, email TEXT, full_name TEXT, identity_data TEXT, is_active INTEGER, created_at TEXT);
    CREATE TABLE website_users (id TEXT, website_id TEXT, email TEXT, full_name TEXT, identity_data TEXT, is_active INTEGER, created_at TEXT);
    INSERT INTO users VALUES ('member', 'same@example.test', 'Owner', '{}', 1, '2026-01-01');
    INSERT INTO website_users VALUES ('member', 'site', 'same@example.test', 'Member', '{"bio":"Keep me","roles":["member"]}', 1, '2026-01-01');
    INSERT INTO website_users VALUES ('member', 'other', 'same@example.test', 'Other tenant', '{}', 1, '2026-01-01');`);
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
  return { sql, request };
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
      assert.ok([403, 404].includes(response.status));
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

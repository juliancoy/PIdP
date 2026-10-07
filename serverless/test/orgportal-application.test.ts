import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

test('neutral application branding preserves namespace and existing login origins', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(`CREATE TABLE websites (id TEXT PRIMARY KEY, slug TEXT, name TEXT, description TEXT,
      login_hosts TEXT, allowed_redirect_origins TEXT);
      INSERT INTO websites VALUES ('existing-namespace', 'code-collective', 'Code Collective', '',
        '["codecollective.us","medtech.social"]', '["https://codecollective.us","https://medtech.social"]');`);
    const migration = readFileSync(new URL('../migrations/0011_orgportal_application.sql', import.meta.url), 'utf8');
    db.exec(migration); db.exec(migration);
    const row = db.prepare('SELECT * FROM websites').get()!;
    assert.equal(row.id, 'existing-namespace');
    assert.equal(row.slug, 'code-collective');
    assert.equal(row.name, 'OrgPortal');
    assert.deepEqual(JSON.parse(String(row.login_hosts)), ['codecollective.us', 'medtech.social', 'orgportal.cc']);
    assert.deepEqual(JSON.parse(String(row.allowed_redirect_origins)), ['https://codecollective.us', 'https://medtech.social', 'https://orgportal.cc']);
  } finally { db.close(); }
});

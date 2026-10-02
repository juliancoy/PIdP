import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pbkdf2Sync } from 'node:crypto';
import { hashPassword, verifyPassword } from '../src/crypto.ts';

test('password hashing works when Workers reject native PBKDF2 above 100,000 iterations', async () => {
  const deriveBits = crypto.subtle.deriveBits;
  crypto.subtle.deriveBits = async () => { throw new DOMException('iteration counts above 100000 are not supported', 'NotSupportedError'); };
  try {
    const password = 'Test password with unicode 🔐';
    const stored = await hashPassword(password);
    const [scheme, iterations, salt, digest] = stored.split('$');
    assert.equal(scheme, 'pbkdf2_sha256');
    assert.equal(iterations, '210000');
    assert.equal(digest, pbkdf2Sync(password, Buffer.from(salt, 'base64url'), 210000, 32, 'sha256').toString('base64url'));
    assert.equal(await verifyPassword(password, stored), true);
    assert.equal(await verifyPassword('wrong password', stored), false);
    assert.notEqual(await hashPassword(password), stored);
  } finally {
    crypto.subtle.deriveBits = deriveBits;
  }
});

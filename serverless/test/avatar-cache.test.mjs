import test from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/index.ts';
import { storeSocialAvatar } from '../src/oauth.ts';

const policy = 'public, max-age=31536000, immutable';
test('social avatars are copied to versioned PIdP storage with cache metadata', async t => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async () => { fetches++; return new Response('image-bytes', { headers: { 'content-type': 'image/jpeg' } }); };
  t.after(() => { globalThis.fetch = originalFetch; });
  const stored = [];
  const env = { AVATARS: { put: async (key, body, options) => stored.push({ key, bytes: await new Response(body).text(), options }) } };
  const first = await storeSocialAvatar(env, 'member', 'google', 'https://google.example/avatar', 'https://id.example');
  const second = await storeSocialAvatar(env, 'member', 'github', 'https://github.example/avatar', 'https://id.example');
  assert.equal(fetches, 2);
  assert.equal(first.avatar_source, 'google');
  assert.ok(first.avatar_url.startsWith('https://id.example/avatars/member/'));
  assert.notEqual(first.avatar_url, second.avatar_url);
  for (const object of stored) {
    assert.equal(object.bytes, 'image-bytes');
    assert.equal(object.options.httpMetadata.cacheControl, policy);
    assert.equal(object.options.httpMetadata.contentType, 'image/jpeg');
  }
});

test('stored avatars cache publicly and revalidate without downloading their body', async () => {
  const metadata = { httpEtag: '"avatar-v1"', uploaded: new Date('2026-01-01'), writeHttpMetadata: headers => headers.set('content-type', 'image/jpeg') };
  const env = { AVATARS: { get: async key => key.endsWith('missing.jpg') ? null : { ...metadata, body: new Response('image-bytes').body }, head: async () => metadata } };
  const get = await app.request('https://id.example/avatars/member/photo.jpg', {}, env);
  assert.equal(get.status, 200);
  assert.equal(get.headers.get('cache-control'), policy);
  assert.equal(get.headers.get('etag'), '"avatar-v1"');
  assert.equal(await get.text(), 'image-bytes');
  const conditional = await app.request('https://id.example/avatars/member/photo.jpg', { headers: { 'if-none-match': '"other", W/"avatar-v1"' } }, env);
  assert.equal(conditional.status, 304);
  assert.equal(await conditional.text(), '');
  assert.equal(conditional.headers.get('cache-control'), policy);
  const head = await app.request('https://id.example/avatars/member/photo.jpg', { method: 'HEAD' }, env);
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  const missing = await app.request('https://id.example/avatars/member/missing.jpg', {}, env);
  assert.equal(missing.status, 404);
  assert.notEqual(missing.headers.get('cache-control'), policy);
});

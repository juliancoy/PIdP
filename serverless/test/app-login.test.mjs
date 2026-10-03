import test from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/index.ts';

const env = { PUBLIC_BASE_URL: 'https://id.codecollective.us', SECRET_KEY: 'fixture', GOOGLE_CLIENT_ID: 'fixture', GOOGLE_CLIENT_SECRET: 'fixture', PORTAL_AUTH_ORIGINS: 'https://medtech.social' };
function googleLink(html) {
  const href = html.match(/href="([^"]+)">Continue with Google/)[1].replaceAll('&amp;', '&');
  return new URL(href);
}

test('social login preserves member app and return context', async () => {
  const response = await app.request('https://id.codecollective.us/app/login?app=medtech&next=%2Fcommunity', {}, env);
  assert.equal(response.status, 200);
  const url = googleLink(await response.text());
  assert.equal(url.pathname, '/auth/google/login');
  assert.equal(url.searchParams.get('app'), 'medtech');
  assert.equal(url.searchParams.get('next'), '/community');
  assert.equal(url.searchParams.has('owner'), false);
});

test('portal owner login uses the portal proxy and explicit owner namespace', async () => {
  const response = await app.request('https://id.codecollective.us/app/login?app=medtech&owner=1&next=%2Fcommunity', { headers: { 'x-forwarded-host': 'medtech.social', 'x-forwarded-proto': 'https' } }, env);
  const url = googleLink(await response.text());
  assert.equal(url.origin, 'https://medtech.social');
  assert.equal(url.pathname, '/pidp/auth/google/login');
  assert.equal(url.searchParams.get('owner'), '1');
  assert.equal(url.searchParams.has('app'), false);
});

test('unconfigured providers are hidden', async () => {
  const response = await app.request('https://id.codecollective.us/app/login', {}, { ...env, GOOGLE_CLIENT_SECRET: '' });
  assert.doesNotMatch(await response.text(), /Continue with Google|Continue with GitHub/);
});

test('social login remains available after a password validation error', async () => {
  const response = await app.request('https://id.codecollective.us/app/login', { method: 'POST', body: new URLSearchParams({ app: 'medtech', next: '/community' }) }, env);
  assert.equal(response.status, 422);
  assert.equal(googleLink(await response.text()).searchParams.get('app'), 'medtech');
});

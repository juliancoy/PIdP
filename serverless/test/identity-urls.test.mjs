import test from 'node:test';
import assert from 'node:assert/strict';
import {identityUrl,identityPath,mountedIdentityPath} from '../src/identityUrls.ts';

test('identity URLs default to the OrgPortal mount and respect explicit local configuration',()=>{
  assert.equal(identityUrl({},'/app/login').href,'https://orgportal.cc/pidp/app/login');
  assert.equal(identityPath({},'/pidp/auth/google/callback'),'/auth/google/callback');
  assert.equal(identityUrl({PUBLIC_BASE_URL:'https://localhost:8443/pidp'},'/app/login').href,'https://localhost:8443/pidp/app/login');
  assert.equal(identityUrl({},'/auth/account-links/finish','https://local.example/auth/account-links/connect?app=site').href,'https://local.example/auth/account-links/finish');
});
test('identity pages mount login links while MCP OAuth stays at the canonical root',()=>{
  assert.equal(mountedIdentityPath('/app/login','/pidp'),'/pidp/app/login');
  assert.equal(mountedIdentityPath('/oauth/mcp/authorize','/pidp'),'/oauth/mcp/authorize');
});

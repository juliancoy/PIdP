import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {compilePortalDomains,replaceVariable} from '../../scripts/sync-portal-domains.mjs';
const registry=JSON.parse(readFileSync(new URL('../../shared/portal-clients.json',import.meta.url)));
test('one registry derives routing, identity clients, and website login origins for every domain',()=>{
 const generated=compilePortalDomains(registry);
 for(const [origin,client] of Object.entries(registry)) {
  assert.ok(generated.pidp.PORTAL_AUTH_ORIGINS.split(',').includes(origin));
  assert.equal(generated.orgportal.ORGPORTAL_SITE_HOSTS.split(',').includes(new URL(origin).hostname),client.deployment.orgPortalSite);
  assert.equal(generated.websites[client.accountApp]?.allowed_redirect_origins.includes(origin)||false,client.deployment.websiteLogin);
  assert.equal(JSON.parse(generated.pidp.PORTAL_CLIENTS_JSON)[origin].deployment,undefined);
 }
 assert.equal(JSON.parse(generated.pidp.PORTAL_CLIENTS_JSON)['https://techparty.us'].name,'Tech Party');
});
test('registry rejects unsafe origins, callbacks, implicit policy, and redirect chains',()=>{
 const base=registry['https://techparty.us'];
 for(const origin of ['http://example.com','https://example.com/path','https://user@example.com','https://example.com:8443']) assert.throws(()=>compilePortalDomains({[origin]:base}));
 for(const callback of ['//evil.example','/\\evil.example','/auth/callback?next=x']) assert.throws(()=>compilePortalDomains({'https://example.com':{...base,callbacks:[callback]}}));
 assert.throws(()=>compilePortalDomains({'https://example.com':{...base,deployment:undefined}}));
 assert.throws(()=>compilePortalDomains({'https://example.com':{...base,restartOrigin:'https://unregistered.example'}}));
});
test('sync changes only the named variable and fails on missing or duplicate bindings',()=>{
 const text='// Keep this comment\n{"vars":{"ORIGINS":"old","OTHER":"preserve"}}';
 assert.equal(replaceVariable(text,'ORIGINS','new'),text.replace('"old"','"new"'));
 assert.throws(()=>replaceVariable(text,'MISSING','new'));
 assert.throws(()=>replaceVariable('{"X":"a","X":"b"}','X','new'));
});

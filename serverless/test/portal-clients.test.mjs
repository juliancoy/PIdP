import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {portalClient,ssoReturn,browserReturn,localDestination} from '../src/portalClients.ts';
const defaults=JSON.parse(readFileSync(new URL('../../shared/portal-clients.json',import.meta.url),'utf8'));
const cases=JSON.parse(readFileSync(new URL('../../shared/portal-return-cases.json',import.meta.url),'utf8'));
const env={PORTAL_AUTH_ORIGINS:Object.keys(defaults).join(','),PUBLIC_BASE_URL:'https://id.example'};

test('product origins own their name, callbacks and account namespace independently of hosting',()=>{
 for(const [origin,client] of Object.entries(defaults)){
  assert.equal(portalClient(env,origin).name,client.name);assert.equal(portalClient(env,origin).accountApp,'code-collective');
  assert.equal(ssoReturn(env,origin,'wrong','/auth/callback'),null);
  if(!client.restartOrigin)for(const c of cases)assert.equal(!!ssoReturn(env,origin,client.accountApp,c.value),c.valid,origin+' '+c.value);
 }
 assert.equal(portalClient(env,'https://unregistered.example'),null);
 assert.equal(portalClient({...env,PORTAL_AUTH_ORIGINS:''},'https://orgportal.cc'),null);
 assert.equal(portalClient({...env,PORTAL_CLIENTS_JSON:'invalid'},'https://orgportal.cc'),null);
});
test('the shared browser destination policy rejects redirect tricks and preserves explicit native returns',()=>{
 for(const value of ['//evil.example','/\\evil.example','https://user:password@orgportal.cc/auth/callback','javascript:alert(1)','https://evil.example'])assert.equal(browserReturn(env,value),null);
 assert.equal(browserReturn(env,'https://id.example/auth/sso/authorize?request=ticket'),'https://id.example/auth/sso/authorize?request=ticket');
 assert.equal(browserReturn({...env,NATIVE_REDIRECT_SCHEMES:'org.arkavo.portal'},'org.arkavo.portal://auth/callback'),'org.arkavo.portal://auth/callback');
 assert.equal(localDestination('/chat'),true);
});

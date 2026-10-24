// Exercises the running local nginx/FastAPI stack using owned synthetic fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import {chromium} from '@playwright/test';
const container=process.env.IDENTITY_CONTAINER||'lifetech-identity-api';
const python=(body)=>execFileSync('docker',['exec','-i',container,'/venv/bin/python','-'],{input:"import sys\nsys.path.insert(0,'/app')\n"+body,encoding:'utf8'});
test('local identity origin isolates authenticated responses while tenant SSO works',{timeout:90000},async()=>{
 let browser,fixture;
 try {
 const contextHost=JSON.parse(execFileSync('docker',['context','inspect','--format','{{json .Endpoints.docker.Host}}'],{encoding:'utf8'}));
 assert.ok((process.env.DOCKER_HOST||contextHost).startsWith('unix://'),'Rehearsal requires a local Docker socket');
 const config=JSON.parse(execFileSync('docker',['inspect',container,'--format','{{json .Config.Env}}'],{encoding:'utf8'}));
 const environment=Object.fromEntries(config.map(value=>{const at=value.indexOf('=');return [value.slice(0,at),value.slice(at+1)];}));
 assert.equal(environment.ENV,'dev','Rehearsal requires a development identity service');
 assert.equal(environment.PORTAL_SHARED_IDENTITY,'true','Shared account identity must be enabled');
 assert.equal(environment.PUBLIC_BASE_URL,'https://id.localhost:8443','Rehearsal requires the isolated local identity origin');

 fixture=JSON.parse(python(`import asyncio,json,uuid
from datetime import datetime,timezone
from sqlalchemy import select
from db import SessionLocal,engine
from models import User,Website,WebsiteUser,AccountIdentityLink
async def main():
 async with SessionLocal() as s:
  site=(await s.execute(select(Website).where(Website.slug=='orgportal'))).scalar_one()
  owner,member=uuid.uuid4(),uuid.uuid4();email='origin-'+owner.hex+'@example.com'
  s.add(User(id=owner,email=email,hashed_password='pbkdf2_sha256$210000$efQSdVLVMvIxidzzHSLpXA$4mwDckrnGHdzvix9cXdz7N5TBJ-N1JcfDceuLVPGCyE',identity_data={'email_verified':True}))
  await s.flush()
  s.add(WebsiteUser(id=member,website_id=site.id,email=email,hashed_password=None,identity_data={'email_verified':True}))
  await s.flush()
  s.add(AccountIdentityLink(subject=f'website:{site.id}:{member}',canonical_user_id=owner,website_id=site.id,website_user_id=member,linked_at=datetime.now(timezone.utc).isoformat()))
  await s.commit();print(json.dumps({'owner':str(owner),'member':str(member),'site':str(site.id),'email':email}))
 await engine.dispose()
asyncio.run(main())
`));
 browser=await chromium.launch({headless:true,args:['--no-proxy-server','--host-resolver-rules=MAP id.localhost 127.0.0.1']});
 const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();page.setDefaultTimeout(20000);
 const login=await context.request.post('https://id.localhost:8443/session/login',{headers:{Origin:'https://id.localhost:8443'},form:{email:fixture.email,password:'imported-password-✓',app:'orgportal',next:'/profile'}});
 assert.ok(login.ok(),'Synthetic primary sign-in failed');
 await page.goto('https://id.localhost:8443/profile');assert.equal(new URL(page.url()).origin,'https://id.localhost:8443');
 const identityCookies=await context.cookies('https://id.localhost:8443');const identityCookie=identityCookies.find(c=>c.name==='pidp_token');
 assert.ok(identityCookie&&identityCookie.domain==='id.localhost'&&identityCookie.httpOnly&&identityCookie.secure);
 assert.equal((await context.request.get('https://id.localhost:8443/auth/session')).status(),200);
 const primaryClaims=JSON.parse(Buffer.from(identityCookie.value.split('.')[1],'base64url'));assert.equal(primaryClaims.sub,fixture.owner);assert.notEqual(primaryClaims.actor_type,'website_user');
 assert.equal((await context.request.post('https://id.localhost:8443/auth/session/logout',{headers:{Origin:'https://localhost:8443'}})).status(),403);
 assert.equal((await context.request.get('https://id.localhost:8443/auth/session')).status(),200,'Rejected cross-origin logout must not revoke the identity session');
 await page.goto('https://localhost:8443/pidp/health');
 const blocked=await page.evaluate(async()=>{try{await fetch('https://id.localhost:8443/auth/session',{credentials:'include'});return false;}catch{return true;}});assert.equal(blocked,true,'Portal must not read an authenticated identity response');
 const pageBlocked=await page.evaluate(async()=>{try{await fetch('/pidp/profile',{credentials:'include'});return false;}catch{return true;}});assert.equal(pageBlocked,true,'Account pages must not be proxied on the portal origin');
 const start='https://localhost:8443/pidp/auth/sso/start?app=orgportal&next='+encodeURIComponent('https://localhost:8443/auth/callback?next=/');
 await page.goto(start);await page.waitForFunction(()=>location.hostname==='localhost'&&!location.pathname.startsWith('/pidp/auth/sso')).catch(async error=>{throw new Error(JSON.stringify({url:new URL(page.url()).origin+new URL(page.url()).pathname,body:(await page.locator('body').innerText()).slice(0,1500)}),{cause:error});});
 assert.equal((await context.request.get('https://localhost:8443/pidp/auth/session')).status(),200);
 const portalCookie=(await context.cookies('https://localhost:8443')).find(c=>c.name==='pidp_token');assert.ok(portalCookie&&portalCookie.domain==='localhost');assert.notEqual(portalCookie.value,identityCookie.value);
 const claims=JSON.parse(Buffer.from(portalCookie.value.split('.')[1],'base64url'));assert.equal(claims.actor_type,'website_user');assert.equal(claims.sub,fixture.member);
 await page.waitForLoadState('networkidle');
 const access=await context.request.get('https://localhost:8443/pidp/auth/session-token');assert.equal(access.status(),200);const apiToken=(await access.json()).access_token;
 const role=await context.request.get('https://localhost:8443/api/org/admin/me',{headers:{Authorization:'Bearer '+apiToken}});assert.equal(role.status(),200);assert.equal((await role.json()).is_sysadmin,false);
 assert.equal((await context.request.get('https://localhost:8443/api/org/admin/mcp/status',{headers:{Authorization:'Bearer '+apiToken}})).status(),403);
 const report=process.env.IDENTITY_ORIGIN_REPORT;if(report){mkdirSync(report,{recursive:true});writeFileSync(report+'/browser.json',JSON.stringify({status:'passed',portal:'https://localhost:8443',identity:'https://id.localhost:8443',identity_cookie_host_only:true,portal_cookie_host_only:true,portal_cannot_read_identity:true,portal_cannot_proxy_account_pages:true,tenant_sso:true,tenant_subject_preserved:true,shared_primary_login:true,administrator_access_denied:true},null,2));}
 }finally{
 await browser?.close();
 if(fixture)python(`import asyncio
from uuid import UUID
from sqlalchemy import delete,or_
from db import SessionLocal,engine
from models import User,WebsiteUser,AccountIdentityLink,BrowserSession,PortalSsoRequest
async def main():
 async with SessionLocal() as s:
  owner=UUID('${fixture.owner}');member=UUID('${fixture.member}')
  await s.execute(delete(BrowserSession).where(or_(BrowserSession.owner_id==owner,BrowserSession.website_user_id==member)))
  await s.execute(delete(AccountIdentityLink).where(AccountIdentityLink.website_user_id==member))
  await s.execute(delete(PortalSsoRequest).where(PortalSsoRequest.subject=='website:${fixture.site}:${fixture.member}'))
  await s.execute(delete(WebsiteUser).where(WebsiteUser.id==member));await s.execute(delete(User).where(User.id==owner));await s.commit()
 await engine.dispose()
asyncio.run(main())
`);
 }
});

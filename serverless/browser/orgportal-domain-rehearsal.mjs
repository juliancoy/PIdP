// All browser requests terminate in the actual local edge/identity modules.
// Synthetic accounts only; no external DNS, provider calls or live databases.
import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync,mkdirSync,writeFileSync,mkdtempSync,rmSync,readdirSync} from 'node:fs';
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {chromium} from '@playwright/test';
import {generateKeyPair,exportJWK} from 'jose';
import identity from '../src/index.ts';
import edgeModule from '../../../OrgPortal/cloudflare/worker.js';
const edge=edgeModule.default || edgeModule;
import {hashPassword,sha256Hex,verifyJwt} from '../src/crypto.ts';
import {migrateSharedCredentials} from '../scripts/migrate-shared-credentials.mjs';

test('OrgPortal domain: migrated login, account pages, tenant SSO and protocol routing',{timeout:45000},async t=>{
 const sql=new DatabaseSync(':memory:');let browser,server;const tls=mkdtempSync(join(tmpdir(),'orgportal-domain-'));
 const report=process.env.IDENTITY_DOMAIN_REPORT;
 const visits=[],upstreams=[];
 const DB={prepare(query){
  const statement=sql.prepare(query.replaceAll('?1','?'));
  return {bind(...args){const values=query.includes('?1')?Array((query.match(/\?1/g)||[]).length).fill(args[0]):args;
   return {async first(){return statement.get(...values)||null;},async all(){return {results:statement.all(...values)};},async run(){return {meta:statement.run(...values)};},async execute(){return statement.all(...values);}};
  }};
 },async batch(statements){sql.exec('BEGIN');try{for(const s of statements)await s.execute();sql.exec('COMMIT');}catch(e){sql.exec('ROLLBACK');throw e;}}};
 try {
  for(const file of readdirSync(new URL('../migrations/',import.meta.url)).filter(name=>name.endsWith('.sql')).sort())sql.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
  sql.exec("INSERT INTO users(id,email) VALUES('operator','operator@example.test'); INSERT INTO websites(id,owner_id,name,slug) VALUES('site','operator','OrgPortal','orgportal')");
  sql.prepare('INSERT INTO website_users(id,website_id,email,hashed_password) VALUES(?,?,?,?)').run('member','site','member@example.test',await hashPassword('isolated-password'));
  await migrateSharedCredentials(DB,{appSlug:'orgportal',configuredAppSlug:'orgportal',sharedIdentity:false,apply:true,writesPaused:true,backupVerified:true});
  const key={...await exportJWK((await generateKeyPair('ES256',{extractable:true})).privateKey),kid:'isolated-key'};
  const env={DB,SECRET_KEY:'isolated-domain-secret',APP_NAME:'OrgPortal',PUBLIC_BASE_URL:'https://orgportal.cc/pidp',PORTAL_SHARED_IDENTITY:'true',PORTAL_SSO_APP_SLUG:'orgportal',EMAIL_VERIFICATION_REQUIRED:'false',
   PORTAL_AUTH_ORIGINS:'https://orgportal.cc,https://lifetech.fyi',PORTAL_CLIENTS_JSON:JSON.stringify(Object.fromEntries(['https://orgportal.cc','https://lifetech.fyi'].map(origin=>[origin,{name:'OrgPortal',accountApp:'orgportal',callbacks:['/auth/callback']}]))),
   GOOGLE_CLIENT_ID:'isolated-google',GOOGLE_CLIENT_SECRET:'isolated-google-secret',GOOGLE_REDIRECT_URI:'https://orgportal.cc/pidp/auth/google/callback',
   GITHUB_CLIENT_ID:'isolated-github',GITHUB_CLIENT_SECRET:'isolated-github-secret',GITHUB_REDIRECT_URI:'https://orgportal.cc/pidp/auth/github/callback',
   MCP_OAUTH_ISSUER:'https://orgportal.cc',MCP_OAUTH_PRIVATE_JWK:JSON.stringify(key),MCP_OAUTH_CLIENTS_JSON:JSON.stringify({fixture:{name:'Fixture',redirectUris:['https://client.example/callback'],secretHash:await sha256Hex('isolated-client-secret'),resources:['https://orgportal.cc/mcp'],scopes:['org:portal.read']}}),MCP_OAUTH_RESOURCES_JSON:JSON.stringify({'https://orgportal.cc/mcp':{secretHash:await sha256Hex('isolated-resource-secret')}})};
  const edgeEnv={ASSETS:{fetch:async()=>new Response('',{status:404})},PIDP:{fetch:(url,init)=>identity.request(url,{...init,duplex:'half'},env)},ORG_API_ORIGIN:'https://organization.internal',CHAT_API_ORIGIN:'https://chat.internal',ORGPORTAL_SITE_HOSTS:'orgportal.cc,lifetech.fyi'};
  t.mock.method(globalThis,'fetch',async(url,init)=>{
   const target=new URL(url);assert.ok(['organization.internal','chat.internal'].includes(target.hostname),'Unexpected external fetch');
   upstreams.push({host:target.hostname,path:target.pathname,publicHost:init.headers.get('x-forwarded-host')});
   return Response.json({route:target.pathname},{status:target.pathname==='/mcp'?401:200});
  });
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(tls,'key.pem'),'-out',join(tls,'cert.pem'),'-days','1','-subj','/CN=orgportal.cc','-addext','subjectAltName=DNS:orgportal.cc,DNS:lifetech.fyi'],{stdio:'ignore'});
  server=createServer({key:readFileSync(join(tls,'key.pem')),cert:readFileSync(join(tls,'cert.pem'))},async(incoming,outgoing)=>{
   try {
    const url=new URL(incoming.url,'https://'+incoming.headers.host);visits.push(url.origin+url.pathname);
    assert.ok(['orgportal.cc','lifetech.fyi'].includes(url.hostname),'Unexpected hostname');
    if(url.pathname==='/auth/callback'){outgoing.writeHead(200,{'content-type':'text/html'});outgoing.end('<h1>Tenant return complete</h1>');return;}
    const chunks=[];for await(const chunk of incoming)chunks.push(chunk);
    const init={method:incoming.method,headers:incoming.headers};if(chunks.length)init.body=Buffer.concat(chunks);
    const response=await edge.fetch(new Request(url,init),edgeEnv);
    for(const [name,value]of response.headers)if(name!=='set-cookie')outgoing.setHeader(name,value);
    const cookies=response.headers.getSetCookie();if(cookies.length)outgoing.setHeader('set-cookie',cookies);
    outgoing.writeHead(response.status);outgoing.end(Buffer.from(await response.arrayBuffer()));
   }catch(error){outgoing.writeHead(500,{'content-type':'text/plain'});outgoing.end(String(error));}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  browser=await chromium.launch({headless:true,args:['--no-proxy-server',`--host-resolver-rules=MAP orgportal.cc 127.0.0.1:${port}, MAP lifetech.fyi 127.0.0.1:${port}, MAP * ~NOTFOUND`],...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
  await page.goto('https://orgportal.cc/pidp/app/login?app=orgportal&next=%2Fpidp%2Fprofile');
  await page.locator('input[name=email]').first().fill('member@example.test');await page.locator('input[name=password]').fill('isolated-password');
  await page.locator('form').filter({has:page.locator('input[name=password]')}).locator('button[type=submit]').click();
  await page.waitForURL('https://orgportal.cc/pidp/u/member').catch(async error=>{throw new Error(JSON.stringify({url:page.url(),body:(await page.locator('body').innerText()).slice(0,1800),visits}),{cause:error});});
  await page.reload();assert.equal(new URL(page.url()).hostname,'orgportal.cc');
  const canonicalCookies=await context.cookies('https://orgportal.cc');
  assert.ok(canonicalCookies.some(c=>c.name==='pidp_session'&&c.domain==='orgportal.cc'&&c.secure&&c.httpOnly));
  await page.goto('https://lifetech.fyi/pidp/auth/sso/start?app=orgportal&next='+encodeURIComponent('https://lifetech.fyi/auth/callback?next=/chat'));
  await page.waitForURL('https://lifetech.fyi/auth/callback?next=/chat');
  const tenantCookie=(await context.cookies('https://lifetech.fyi')).find(c=>c.name==='pidp_session');assert.ok(tenantCookie&&tenantCookie.domain==='lifetech.fyi');
  const claims=await verifyJwt(env,tenantCookie.value);assert.equal(claims.actor_type,'website_user');assert.equal(claims.sub,'member');assert.equal(claims.website_id,'site');
  for(const provider of ['google','github']){
   const response=await edge.fetch(new Request('https://orgportal.cc/pidp/auth/'+provider+'/login?next=%2Fpidp%2Fprofile'),edgeEnv);
   assert.equal(new URL(response.headers.get('location')).searchParams.get('redirect_uri'),'https://orgportal.cc/pidp/auth/'+provider+'/callback');
  }
  const discovery=await(await edge.fetch(new Request('https://orgportal.cc/.well-known/oauth-authorization-server'),edgeEnv)).json();
  assert.equal(discovery.issuer,'https://orgportal.cc');assert.equal(discovery.token_endpoint,'https://orgportal.cc/oauth/mcp/token');
  for(const path of ['/api/org/api/accounts/me','/api/chat/health','/mcp'])await edge.fetch(new Request('https://orgportal.cc'+path),edgeEnv);
  assert.deepEqual(upstreams.map(r=>[r.host,r.path,r.publicHost]),[['organization.internal','/api/accounts/me','orgportal.cc'],['chat.internal','/health','orgportal.cc'],['organization.internal','/mcp','orgportal.cc']]);
  assert.ok(visits.every(url=>!url.includes('id.orgportal.cc')&&!url.includes('id.codecollective.us')));
  if(report){mkdirSync(report,{recursive:true});await page.screenshot({path:report+'/tenant-return.png'});writeFileSync(report+'/browser-summary.json',JSON.stringify({status:'passed',network:'loopback HTTPS; canonical hosts mapped to 127.0.0.1, other DNS blocked',visits,upstreams,provider_callbacks:'canonical redirect URLs verified; real provider console/exchange not exercised',backend_apis:'edge forwarding verified with synthetic upstreams'},null,2));}
 }finally{await browser?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}sql.close();rmSync(tls,{recursive:true,force:true});}
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { chromium } from '@playwright/test';
import { generateKeyPair, exportJWK } from 'jose';
import { mcpAuthorization } from '../src/mcpAuthorization.ts';
import { sha256Hex, signJwt } from '../src/crypto.ts';

test('isolated Chrome profiles pair an account and keep OAuth in the original profile', async () => {
 assert.ok(process.env.WEBDRIVER_URL, 'Set WEBDRIVER_URL to the local Docker Selenium service.');
 const sql=new DatabaseSync(':memory:');
 sql.exec("CREATE TABLE users(id TEXT PRIMARY KEY,is_active INTEGER); INSERT INTO users VALUES('alice',1),('bob',1); CREATE TABLE website_users(id TEXT,website_id TEXT,is_active INTEGER)");
 for(const name of ['0006_mcp_authorization.sql','0007_mcp_client_registration.sql','0008_mcp_login_handoff.sql','0010_account_identity_links.sql'])sql.exec(readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8'));
 const db={prepare(query){const stmt=sql.prepare(query);return{bind(...args){return{async first(){return stmt.get(...args)??null},async all(){return{results:stmt.all(...args)}},async run(){return{meta:stmt.run(...args)}}}}}}};
 let issuer,portal,env;
 const certDir=process.env.BRIDGE_TEST_CERT_DIR||'/tmp';
 const options={key:readFileSync(certDir+'/test-key.pem'),cert:readFileSync(certDir+'/test-cert.pem')};
 const serve=async(request,response)=>{
  try{
   const base=request.headers.host===new URL(portal).host?portal:issuer;
   const headers={...request.headers};if(base===portal)headers['x-forwarded-host']=new URL(portal).host;
   const chunks=[];for await(const chunk of request)chunks.push(chunk);
   const path=request.url.replace(/^\/pidp(?=\/)/,'');
   const result=await mcpAuthorization.request(issuer+path,{method:request.method,headers,body:chunks.length?Buffer.concat(chunks):undefined},env);
   const output=Object.fromEntries(result.headers);if(result.headers.getSetCookie().length)output['set-cookie']=result.headers.getSetCookie();
   response.writeHead(result.status,output);response.end(await result.text());
  }catch{response.writeHead(500);response.end('Fixture failed')}
 };
 const originalServer=createServer(options,serve),portalServer=createServer(options,serve);
 for(const server of [originalServer,portalServer])await new Promise(resolve=>server.listen(0,'0.0.0.0',resolve));
 const browserHost=process.env.BROWSER_TEST_HOST || 'host.docker.internal';
 issuer=`https://${browserHost}:${originalServer.address().port}`;portal=`https://${browserHost}:${portalServer.address().port}`;const resource=portal+'/api/org/mcp';
 const {privateKey}=await generateKeyPair('ES256',{extractable:true});
 env={DB:db,SECRET_KEY:'isolated-browser-fixture-key',MCP_OAUTH_ISSUER:issuer,MCP_OAUTH_PRIVATE_JWK:JSON.stringify({...await exportJWK(privateKey),kid:'test'}),MCP_OAUTH_CLIENTS_JSON:JSON.stringify({client:{name:'ChatGPT',secretHash:await sha256Hex('client-secret-at-least-32-characters'),redirectUris:['https://chatgpt.example/callback'],resources:[resource],scopes:['org:events.read','org:portal.read']}}),MCP_OAUTH_RESOURCES_JSON:JSON.stringify({[resource]:{secretHash:await sha256Hex('resource-secret-at-least-32-characters')}}),MCP_OAUTH_PORTALS_JSON:JSON.stringify({[resource]:{name:'OrgPortal',loginUrl:portal+'/users/mcp-connect'}}),PORTAL_SSO_APP_SLUG:'members'};
 let driverSession;
 let browser;
 {
  const result=await (await fetch(process.env.WEBDRIVER_URL+'/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capabilities:{alwaysMatch:{browserName:'chrome',acceptInsecureCerts:true,'goog:chromeOptions':{args:['--headless=new','--no-sandbox','--disable-dev-shm-usage']}}}})})).json();
  assert.ok(result.value.sessionId,JSON.stringify(result));driverSession=result.value.sessionId;
  const endpoint=new URL(result.value.capabilities['se:cdp']),driver=new URL(process.env.WEBDRIVER_URL);endpoint.hostname=driver.hostname;endpoint.port=driver.port;
  browser=await chromium.connectOverCDP(endpoint.toString(),{timeout:10000});
 }
 try{
  const primary=await browser.newContext({ignoreHTTPSErrors:true}),secondary=await browser.newContext({ignoreHTTPSErrors:true});
  await secondary.addCookies([{name:'pidp_session',value:await signJwt(env,{sub:'bob',email:'work@example.test'}),url:portal,httpOnly:true,secure:true,sameSite:'Lax'}]);
  const original=await primary.newPage(),other=await secondary.newPage();original.setDefaultTimeout(10000);other.setDefaultTimeout(10000);
  const params=new URLSearchParams({response_type:'code',client_id:'client',redirect_uri:'https://chatgpt.example/callback',resource,scope:'org:events.read org:portal.read',code_challenge_method:'S256',code_challenge:Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('v'.repeat(43)))).toString('base64url'),state:'preserved-chatgpt-state'});
  await original.bringToFront();
  await original.goto(issuer+'/oauth/mcp/authorize?'+params,{waitUntil:'domcontentloaded'});
  await original.getByRole('heading',{name:'Connect using another Chrome profile'}).waitFor();
  const link=await original.locator('#link').inputValue(),code=await original.locator('code').textContent();
  await original.getByRole('button',{name:'Copy sign-in link',exact:true}).click();
  assert.equal(await original.locator('#link').evaluate(input=>input.selectionEnd-input.selectionStart),link.length);
  for(const width of [390,1440]){await original.setViewportSize({width,height:900});assert.equal(await original.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await original.screenshot({path:`/tmp/orgportal-browser-handoff-${width}.png`,fullPage:true})}
  await other.goto(link,{waitUntil:'domcontentloaded'});
  await other.getByRole('heading',{name:'Confirm your account',exact:true}).waitFor();
  assert.match(await other.textContent('body'),/work@example.test/);assert.ok(!(await other.textContent('body')).includes(code));
  await other.getByLabel('Matching code').fill(code);
  await other.getByRole('button',{name:'Confirm this account'}).click();
  await other.getByRole('heading',{name:'Account confirmed',exact:true}).waitFor();
  await original.bringToFront();
  await original.getByRole('button',{name:'Continue to permissions'}).waitFor({timeout:15000});
  assert.match(await original.locator('#account').textContent(),/work@example.test/);
  await original.getByRole('button',{name:'Continue to permissions'}).click();
  await original.getByRole('button',{name:'Allow access',exact:true}).waitFor();
  assert.match(await original.textContent('body'),/work@example.test/);
  assert.equal(new URL(original.url()).searchParams.get('state'),'preserved-chatgpt-state');
  assert.equal(sql.prepare('SELECT COUNT(*) AS count FROM mcp_oauth_logins').get().count,0);
  assert.equal((await secondary.cookies(issuer)).some(c=>c.name==='__Host-pidp_mcp_session'),false);
  assert.equal((await primary.cookies(portal)).some(c=>c.name==='pidp_session'),false);
 }finally{
  await browser.close();if(driverSession)await fetch(process.env.WEBDRIVER_URL+'/session/'+driverSession,{method:'DELETE'});for(const server of [originalServer,portalServer]){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}sql.close();
 }
});

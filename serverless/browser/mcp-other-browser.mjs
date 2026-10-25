import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { chromium, expect } from '@playwright/test';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { mcpAuthorization as app } from '../src/mcpAuthorization.ts';
import { signJwt, sha256Hex } from '../src/crypto.ts';
import { assessOutcome, userModel } from './fixtures/user-model/review.mjs';

for (const mode of ['poll', 'return-to-tab']) test(`other-browser heuristic: automatic handoff on ${mode}`, {timeout:30000}, async () => {
  const sql=new DatabaseSync(':memory:');
  sql.exec("CREATE TABLE users(id TEXT, is_active INTEGER); INSERT INTO users VALUES ('alice',1)");
  for(const name of ['0006_mcp_authorization.sql','0007_mcp_client_registration.sql','0008_mcp_login_handoff.sql']) sql.exec(readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8'));
  const db={prepare(query){const stmt=sql.prepare(query);return {bind(...p){return {async first(){return stmt.get(...p)??null},async all(){return {results:stmt.all(...p)}},async run(){return {meta:stmt.run(...p)}}}}}}};
  const issuer='https://id.example', portal='https://portal.example', resource=portal+'/api/org/mcp', callback='https://client.example/callback', verifier='v'.repeat(43);
  const {privateKey}=await generateKeyPair('ES256',{extractable:true});
  const secret=crypto.randomUUID(),clientSecret=crypto.randomUUID();
  const testClientSecret=crypto.randomUUID()+crypto.randomUUID();
  const env={DB:db,SECRET_KEY:crypto.randomUUID(),MCP_OAUTH_ISSUER:issuer,
    MCP_OAUTH_PRIVATE_JWK:JSON.stringify({...await exportJWK(privateKey),kid:'test'}),
    MCP_OAUTH_CLIENTS_JSON:JSON.stringify({client:{name:'Test assistant',dynamic:true,secretHash:await sha256Hex(testClientSecret),redirectUris:[callback],resources:[resource],scopes:['org:events.read']}}),
    MCP_OAUTH_RESOURCES_JSON:JSON.stringify({[resource]:{secretHash:await sha256Hex(secret)}}),
    MCP_OAUTH_PORTALS_JSON:JSON.stringify({[resource]:{name:'Portal',loginUrl:portal+'/users/mcp-connect'}})};
  const browser=await chromium.launch({headless:true});
  try {
    const receiving=await browser.newContext(), authorizing=await browser.newContext();
    let finishPosts=0,statusGets=0,failNextStatus=false;
    for(const context of [receiving,authorizing]) await context.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());
      if(url.origin==='https://client.example')return route.fulfill({contentType:'text/html',body:'<h1>Connected</h1>'});
      if(![issuer,portal].includes(url.origin))return route.abort();
      if(url.pathname.endsWith('/browser/status')){statusGets++;if(failNextStatus){failNextStatus=false;return route.abort('connectionreset')}}
      if(url.pathname.endsWith('/browser/finish'))finishPosts++;
      const headers={...req.headers()};if(url.origin===portal)headers['x-forwarded-host']=url.host;
      const response=await app.request(issuer+url.pathname.replace(/^\/pidp/,'')+url.search,{method:req.method(),headers,body:req.postDataBuffer()||undefined},env);
      // Preserve separate Set-Cookie headers when adapting Fetch responses to Playwright.
      for(const cookie of response.headers.getSetCookie()){
        const [pair]=cookie.split(';'),index=pair.indexOf('='),name=pair.slice(0,index),value=pair.slice(index+1);
        if(/max-age=0/i.test(cookie))await context.clearCookies({name,domain:url.hostname});
        else await context.addCookies([{name,value,url:url.origin,httpOnly:true,secure:true,sameSite:'Lax'}]);
      }
      // Playwright does not route subsequent requests in an HTTP redirect chain.
      // A fresh navigation keeps every fixture request in the real OAuth handlers.
      if(response.status===303){
        const headers=Object.fromEntries(response.headers);delete headers['content-security-policy'];delete headers['set-cookie'];
        headers['content-type']='text/html';
        const target=new URL(response.headers.get('location'),req.url()).toString().replaceAll('&','&amp;').replaceAll('"','&quot;');
        return route.fulfill({status:200,headers,body:'<meta http-equiv="refresh" content="0;url='+target+'">'});
      }
      const headersOut=Object.fromEntries(response.headers);delete headersOut['set-cookie'];
      await route.fulfill({status:response.status,headers:headersOut,body:await response.text()});
    });
    for(const [context,url] of [[receiving,issuer],[authorizing,portal]])await context.addCookies([{name:'pidp_session',value:await signJwt(env,{sub:'alice',email:'member@example.test'}),url,httpOnly:true,secure:true,sameSite:'Lax'}]);
    await receiving.addCookies([{name:'__Host-pidp_mcp_session',value:await new SignJWT({resource,display:'member@example.test'}).setProtectedHeader({alg:'ES256',kid:'test',typ:'mcp-session+jwt'}).setSubject('owner:alice').setIssuer(issuer).setAudience(issuer).setIssuedAt().setExpirationTime('10m').setJti('fixture-session').sign(privateKey),url:issuer,httpOnly:true,secure:true,sameSite:'Lax'}]);
    const page=await receiving.newPage(),other=await authorizing.newPage();
    page.setDefaultTimeout(5000);other.setDefaultTimeout(5000);
    const pageErrors=[];page.on('pageerror',e=>pageErrors.push(e.message));
    const challenge=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))).toString('base64url');
    await page.goto(issuer+'/oauth/mcp/authorize?'+new URLSearchParams({response_type:'code',client_id:'client',redirect_uri:callback,resource,scope:'org:events.read',code_challenge_method:'S256',code_challenge:challenge,state:'original-task'}));
    await page.getByRole('link',{name:'Use another browser',exact:true}).click();
    await expect(page.getByRole('heading',{name:'Use another browser',exact:true})).toBeVisible();
    await expect.poll(()=>statusGets).toBeGreaterThan(0);assert.equal(finishPosts,0);
    const pairing=await page.locator('code').innerText(),link=await page.getByLabel('Sign-in link').inputValue();
    assert.equal((await authorizing.cookies()).some(c=>c.name==='__Host-pidp_mcp_browser'),false);
    await other.goto(link);
    await expect(other.getByText('member@example.test',{exact:true})).toBeVisible();
    await other.getByLabel('Matching code').fill('BAD-CODE');
    await other.getByRole('button',{name:'Confirm this account',exact:true}).click();
    await expect(other.getByRole('heading',{name:'Matching code incorrect',exact:true})).toBeVisible();assert.equal(finishPosts,0);
    await other.goto(link);await other.getByLabel('Matching code').fill(pairing);
    if(mode==='return-to-tab'){
      // Stop interval timers; returning to the tab must initiate its own check.
      await page.clock.install();
      await page.evaluate(()=>Object.defineProperty(document,'hidden',{configurable:true,get:()=>true}));
    }else failNextStatus=true;
    await other.getByRole('button',{name:'Confirm this account',exact:true}).click();
    await expect(other.getByRole('heading',{name:'Account confirmed',exact:true})).toBeVisible();
    if(mode==='return-to-tab')await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});document.dispatchEvent(new Event('visibilitychange'))});
    // No receiving-browser click or reload after confirmation in the other browser.
    await expect(page.getByRole('button',{name:'Allow access',exact:true})).toBeVisible({timeout:5000});
    await expect(page.getByText('member@example.test',{exact:true})).toBeVisible();assert.equal(finishPosts,1);
    assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM mcp_oauth_grants').get().n,0);
    assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM mcp_oauth_logins').get().n,0);
    await page.getByRole('button',{name:'Allow access',exact:true}).click();
    await expect(page.getByRole('heading',{name:'Connected',exact:true})).toBeVisible();
    const result=new URL(page.url());assert.equal(result.searchParams.get('state'),'original-task');
    const post=(path,body,headers={})=>app.request(issuer+path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams(body)},env);
    const exchange=await post('/oauth/mcp/token',{grant_type:'authorization_code',client_id:'client',client_secret:testClientSecret,code:result.searchParams.get('code'),redirect_uri:callback,resource,code_verifier:verifier});assert.equal(exchange.status,200);
    const tokens=await exchange.json(),identity=await (await post('/oauth/mcp/introspect',{token:tokens.access_token,resource},{authorization:'Bearer '+secret})).json();
    assert.equal(identity.active,true);assert.equal(identity.sub,'owner:alice');
    assert.deepEqual(pageErrors,[]);
    const task=userModel.tasks.find(t=>t.id==='mcp-other-browser');
    const outcome=assessOutcome(task,['visible other-browser choice','isolated browser sessions','incorrect pairing rejected','automatic receiving-browser advance','OAuth request retained','explicit consent required','live confirmed identity']);assert.equal(outcome.status,'verified');
    const dir=process.env.MCP_OTHER_BROWSER_ARTIFACTS||'/tmp/pidp-other-browser';mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/'+mode+'-user-heuristics.json',JSON.stringify({task:task.id,condition:mode,outcome,humanReview:'pending',limitations:'Synthetic identity cookies; real OAuth handlers with isolated SQLite; no production writes or external ChatGPT UI.'},null,2));
  }finally{await browser.close();sql.close()}
});

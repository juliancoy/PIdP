// Read-only local render checks. No credentials, sessions, or production requests.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import {chromium} from '@playwright/test';
import app from '../src/index.ts';
const clients=JSON.parse(readFileSync(new URL('../../shared/portal-clients.json',import.meta.url),'utf8'));
test('portal sign-in branding renders on mobile and desktop without exposing the account namespace as a product',async()=>{
 const pages=new Map();
 for(const [origin,client] of Object.entries(clients).filter(([,c])=>!c.restartOrigin)){
  const row={origin,app:client.accountApp,next:origin+'/auth/callback?next=%2Fchat'};
  const env={PUBLIC_BASE_URL:'https://id.example',PORTAL_AUTH_ORIGINS:Object.keys(clients).join(','),
   DB:{prepare(){return{bind(){return{async first(){return row}}}}}},GOOGLE_CLIENT_ID:'fixture',GOOGLE_CLIENT_SECRET:'fixture'};
  const response=await app.request('https://id.example/app/login?'+new URLSearchParams({app:client.accountApp,next:'https://id.example/auth/sso/authorize?request=local-ticket'}),{},env);
  assert.equal(response.status,200);pages.set('/'+new URL(origin).host,{html:await response.text(),client});
 }
 const server=createServer((request,response)=>{const page=pages.get(request.url);response.setHeader('Content-Type','text/html');response.end(page?.html||'Missing fixture')});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
  for(const width of [390,1280]){
   const page=await browser.newPage({viewport:{width,height:900}});
   for(const [path,{client}] of pages){
    await page.goto('http://127.0.0.1:'+server.address().port+path);
    assert.equal(await page.locator('h1').textContent(),'Sign in to '+client.name);
    assert.equal(await page.locator('input[name=app]').getAttribute('value'),client.accountApp);
    assert.equal(await page.getByText('Authentication provided by PIdP.').count(),1);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   }
   await page.close();
  }
 }finally{await browser?.close();await new Promise(resolve=>server.close(resolve))}
});

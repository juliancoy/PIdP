import test from 'node:test';
import assert from 'node:assert/strict';
import {chromium,expect} from '@playwright/test';
const issuer='https://pidp.identity.test:8891',portal='https://lifetech.identity.test:8891';
const password='Local-test-password-42';
test('isolated LifeTech account-link clickthrough: account changes, confirmation, cancellation, and handoff',async()=>{
 const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP *.identity.test 127.0.0.1, MAP * ~NOTFOUND'],executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||'/usr/bin/google-chrome'});
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 await context.route('**/*',async route=>{
  const url=new URL(route.request().url());
  if(url.hostname==='pidp.identity.test' && url.pathname==='/auth/google/login'){
   const response=await route.fetch({url:'https://127.0.0.1:8891'+url.pathname+url.search,headers:{...route.request().headers(),host:'pidp.identity.test:8891'},maxRedirects:0});
   const authorize=new URL(response.headers().location);
   assert.equal(authorize.hostname,'accounts.google.com');assert.equal(authorize.searchParams.get('prompt'),'select_account');
   assert.equal(authorize.searchParams.get('redirect_uri'),issuer+'/auth/google/callback');
   return route.fulfill({response,headers:{...response.headers(),location:issuer+'/__fixture/google?'+new URLSearchParams({state:authorize.searchParams.get('state')}).toString()}});
  }
  return ['pidp.identity.test','lifetech.identity.test','orgportal.identity.test','medtech.identity.test'].includes(new URL(route.request().url()).hostname)?route.continue():route.abort()});
 const page=await context.newPage();
 async function login(email){await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 const start=portal+'/pidp/auth/sso/start?next='+encodeURIComponent(portal+'/auth/callback?next=%2Fpeople');
 try{
  await page.goto(issuer+'/app/login?owner=true&next='+encodeURIComponent(start));await login('owner@example.test');
  await expect(page.getByRole('heading',{name:'Connect your LifeTech account'})).toBeVisible();
  await expect(page.getByText('Continue to LifeTech at lifetech.identity.test:8891.')).toBeVisible();
  const primaryCookie=(await context.cookies(issuer)).find(c=>c.name==='pidp_session');
  await context.addCookies([{name:'pidp_session',value:primaryCookie.value,domain:'.identity.test',path:'/',secure:true,httpOnly:true,sameSite:'Lax'}]);
  assert.equal((await context.cookies(issuer)).filter(c=>c.name==='pidp_session').length,2);

  assert.ok(!(await page.locator('body').innerText()).includes('codecollective'));
  await page.getByRole('button',{name:'Use another PIdP account',exact:true}).click();
  await expect(page).toHaveURL(/app\/login\?.*owner=true/);assert.equal(new URL(page.url()).searchParams.get('owner'),'true');await login('other@example.test');
  await expect(page.getByText('Primary account: other (other@example.test)')).toBeVisible();
  await page.getByRole('button',{name:'Authenticate the portal account'}).click();await expect(page.getByRole('heading',{name:'Sign in to LifeTech'})).toBeVisible();await login('missing@example.test');await expect(page.getByText('Invalid credentials.',{exact:true})).toBeVisible();
  const beforeGoogle=(await context.cookies(issuer)).find(c=>c.name==='pidp_session'&&c.domain==='pidp.identity.test');
  await context.addCookies([{name:'pidp_session',value:beforeGoogle.value,domain:'.identity.test',path:'/',secure:true,httpOnly:true,sameSite:'Lax'}]);
  assert.equal((await context.cookies(issuer)).filter(c=>c.name==='pidp_session').length,2);
  await page.getByRole('link',{name:'Continue with Google'}).click();await expect(page.getByRole('heading',{name:'Local Google account chooser'})).toBeVisible();await page.getByRole('link',{name:'member@example.test',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Confirm account link'})).toBeVisible();
  assert.equal((await context.cookies(issuer)).filter(c=>c.name==='pidp_session').length,1,JSON.stringify((await context.cookies(issuer)).map(c=>({name:c.name,domain:c.domain,path:c.path}))));
  await page.getByRole('button',{name:'Use another portal account'}).click();await login('alternate@example.test');
  await expect(page.getByText('Portal account: alternate@example.test',{exact:true})).toBeVisible();
  // Switching the primary account invalidates the earlier proof and restarts confirmation.
  await page.getByRole('button',{name:'Use another PIdP account',exact:true}).click();await login('owner@example.test');
  await page.getByRole('button',{name:'Authenticate the portal account'}).click();await login('alternate@example.test');
  await page.getByRole('button',{name:'Link these accounts'}).click();
  await expect(page.getByRole('heading',{name:'Returned to LifeTech'})).toBeVisible();
  assert.equal(new URL(page.url()).origin,portal);assert.equal(new URL(page.url()).searchParams.get('next'),'/people');
  await page.getByRole('link',{name:'Continue',exact:true}).click();await expect(page.getByRole('heading',{name:'People'})).toBeVisible();
  console.log('PASS: recovery, primary switch, member switch, renewed confirmation, LifeTech return');
  // A separate identity remains unlinked and can cancel without creating a handoff.
  const fresh=await browser.newContext({ignoreHTTPSErrors:true});
  await fresh.route('**/*',route=>new URL(route.request().url()).hostname.endsWith('.identity.test')?route.continue():route.abort());
  const cancel=await fresh.newPage();await cancel.goto(issuer+'/app/login?owner=true&next='+encodeURIComponent(start));
  await cancel.getByLabel('Email',{exact:true}).fill('other@example.test');await cancel.getByLabel('Password',{exact:true}).fill(password);await cancel.getByRole('button',{name:'Sign in',exact:true}).click();
  await cancel.getByRole('link',{name:'Cancel and return to LifeTech'}).click();await expect(cancel).toHaveURL(portal+'/');assert.equal(new URL(cancel.url()).origin,portal);
  await cancel.goto(start);await cancel.getByRole('link',{name:'Link my portal account'}).click();await cancel.getByRole('button',{name:'Authenticate the portal account'}).click();
  await cancel.getByLabel('Email',{exact:true}).fill('alternate@example.test');await cancel.getByLabel('Password',{exact:true}).fill(password);await cancel.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(cancel.getByRole('heading',{name:'Choose a different account'})).toBeVisible();
  await cancel.getByRole('button',{name:'Use another portal account'}).click();await cancel.getByLabel('Email',{exact:true}).fill('member@example.test');await cancel.getByLabel('Password',{exact:true}).fill(password);await cancel.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(cancel.getByRole('heading',{name:'Confirm account link'})).toBeVisible();await cancel.getByRole('button',{name:'Link these accounts'}).click();await expect(cancel.getByRole('heading',{name:'Returned to LifeTech'})).toBeVisible();
  await fresh.close();console.log('PASS: conflicting link recovers through explicit account switching');
  // Reuse the central member session across registered products and explicitly
  // choose it on both phone and desktop before each browser-bound handoff.
  for(const width of [390,1280]){
   await page.setViewportSize({width,height:900});
   for(const [host,name] of [['lifetech','LifeTech'],['orgportal','OrgPortal'],['medtech','MedTech']]){
    const origin=`https://${host}.identity.test:8891`;
    await page.goto(origin+'/pidp/auth/sso/start?prompt=select_account&next='+encodeURIComponent(origin+'/auth/callback?next=%2Fpeople'));
    await expect(page.getByRole('heading',{name:'Choose an account'})).toBeVisible();
    await expect(page.getByText(`Continue to ${name} at ${host}.identity.test:8891.`)).toBeVisible();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.getByRole('link',{name:'Continue as alternate@example.test'}).click();
    await expect(page.getByRole('heading',{name:'Returned to '+name})).toBeVisible();
    assert.equal(new URL(page.url()).origin,origin);
   }
  }
  console.log('PASS: LifeTech, OrgPortal, MedTech chooser and handoff at mobile and desktop widths');
  for(const url of [portal+'/pidp/auth/sso/start?next=https://evil.example/auth/callback',issuer+'/auth/sso/authorize?request=expired',portal+'/pidp/auth/sso/complete?request=missing&code=wrong']){
   const target=new URL(url);const response=await context.request.get('https://127.0.0.1:8891'+target.pathname+target.search,{headers:{host:target.host},maxRedirects:0});assert.equal(response.status(),400);
  }
  console.log('PASS: cancellation, invalid return, expired request, invalid handoff');
 }catch(error){await page.screenshot({path:'/tmp/pidp-identity-lab-failure.png',fullPage:true});console.error('Failed at',page.url(),await page.locator('body').innerText());throw error}
 finally{await context.close();await browser.close()}
});

test('tenant logout then login can switch the surviving central account and keeps LifeTech branding',async()=>{
 const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP *.identity.test 127.0.0.1, MAP * ~NOTFOUND'],executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||'/usr/bin/google-chrome'});
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 await context.route('**/*',route=>['pidp.identity.test','lifetech.identity.test'].includes(new URL(route.request().url()).hostname)?route.continue():route.abort());
 const page=await context.newPage();
 const start=portal+'/pidp/auth/sso/start?prompt=select_account&next='+encodeURIComponent(portal+'/auth/callback?next=%2Forgs%2Flifetech');
 async function passwordLogin(email){
  await expect(page.getByRole('heading',{name:'Sign in to LifeTech',exact:true})).toBeVisible();
  await expect(page.getByAltText('LifeTech logo')).toHaveAttribute('src','https://lifetech.fyi/assets/images/lifetech-logo-v2.png');
  await page.getByLabel('Email',{exact:true}).fill(email);
  await page.getByLabel('Password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Returned to LifeTech',exact:true})).toBeVisible();
  assert.equal(new URL(page.url()).searchParams.get('next'),'/orgs/lifetech');
 }
 async function subject(){return page.evaluate(async()=>{const response=await fetch('/pidp/auth/session-token');if(!response.ok)throw new Error('No tenant session');const data=await response.json();return JSON.parse(atob(data.access_token.split('.')[1].replaceAll('-','+').replaceAll('_','/'))).sub})}
 try{
  await page.goto(start);
  await passwordLogin('member@example.test');
  const firstSubject=await subject();
  const central=(await context.cookies(issuer)).find(cookie=>cookie.name==='pidp_session');assert.ok(central);
  assert.equal(await page.evaluate(async()=>(await fetch('/pidp/auth/session/logout',{method:'POST'})).status),200);
  assert.equal(await page.evaluate(async()=>(await fetch('/pidp/auth/session-token')).status),401);
  assert.equal((await context.cookies(issuer)).find(cookie=>cookie.name==='pidp_session').value,central.value);
  await page.goto(start);
  await expect(page.getByRole('link',{name:'Continue as member@example.test',exact:true})).toBeVisible();
  await expect(page.getByAltText('LifeTech logo')).toBeVisible();
  await page.getByRole('link',{name:'Use another portal account',exact:true}).click();
  assert.equal(new URL(page.url()).searchParams.get('prompt'),'login');
  await passwordLogin('alternate@example.test');
  assert.notEqual(await subject(),firstSubject);
  console.log('PASS: tenant logout clears tenant session; surviving central session offers a choice; alternate account signs in with LifeTech branding and original return context');
 }finally{await context.close();await browser.close()}
});

test('signed-out browser reaches the LifeTech login form without an empty account chooser',async()=>{
 const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP *.identity.test 127.0.0.1, MAP * ~NOTFOUND'],executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||'/usr/bin/google-chrome'});
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 await context.route('**/*',route=>['pidp.identity.test','lifetech.identity.test'].includes(new URL(route.request().url()).hostname)?route.continue():route.abort());
 try{
  const page=await context.newPage();
  const destination=portal+'/auth/callback?next=%2Fevents%2Fdemo%23apply';
  for(const invalid of [false,true]){
   if(invalid)await context.addCookies([{name:'pidp_session',value:'expired-or-invalid',url:issuer}]);
   await page.goto(portal+'/pidp/auth/sso/start?'+new URLSearchParams({prompt:'select_account',next:destination}));
   await expect(page.getByRole('heading',{name:'Sign in to LifeTech',exact:true})).toBeVisible();
   await expect(page.getByLabel('Email',{exact:true})).toBeVisible();
   await expect(page.getByLabel('Password',{exact:true})).toBeVisible();
   await expect(page.getByRole('heading',{name:'Choose an account'})).toHaveCount(0);
   assert.equal(new URL(page.url()).pathname,'/app/login');
  }
 }finally{await context.close();await browser.close()}
});

test('expired request retry button opens a fresh sign-in',async()=>{
 const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP *.identity.test 127.0.0.1, MAP * ~NOTFOUND'],executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||'/usr/bin/google-chrome'});
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 try{
  const page=await context.newPage();
  // Keep the production fallback entirely inside the isolated identity lab.
  await page.route('https://orgportal.cc/users/login**',route=>route.fulfill({contentType:'text/html',body:'<h1>Fresh login</h1>'}));
  await page.goto(issuer+'/auth/sso/authorize?request=expired');
  await expect(page.getByRole('heading',{name:'Expired request',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Try again',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Fresh login',exact:true})).toBeVisible();
 }finally{await context.close();await browser.close()}
});

test('mobile login succeeds once; repeated completion shows invalid_browser while session remains valid',async()=>{
 const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP *.identity.test 127.0.0.1, MAP * ~NOTFOUND'],executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||'/usr/bin/google-chrome'});
 const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true});
 await context.route('**/*',route=>['pidp.identity.test','lifetech.identity.test'].includes(new URL(route.request().url()).hostname)?route.continue():route.abort());
 try{
  const page=await context.newPage();let completion='';let completions=0;
  page.on('response',response=>{if(new URL(response.url()).pathname==='/pidp/auth/sso/complete'){completion=response.url();completions++}});
  await page.goto(portal+'/pidp/auth/sso/start?'+new URLSearchParams({prompt:'select_account',next:portal+'/auth/callback?next=%2Fpeople'}));
  await page.getByLabel('Email',{exact:true}).fill('member@example.test');
  await page.getByLabel('Password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Returned to LifeTech',exact:true})).toBeVisible();
  assert.equal(completions,1,'Normal login must complete only once');assert.ok(completion);
  const sessionBefore=await page.evaluate(async()=>(await fetch('/pidp/auth/session-token')).status);assert.equal(sessionBefore,200);
  const replay=await page.goto(completion);assert.equal(replay.status(),400);
  await expect(page.locator('body')).toContainText('invalid_browser');
  assert.equal(await page.evaluate(async()=>(await fetch('/pidp/auth/session-token')).status),200,'Successful login session survives repeated completion');
  await page.screenshot({path:'/tmp/pidp-mobile-repeated-callback.png',fullPage:true});
  console.log('PASS: normal mobile login completes once; deliberate repeat returns invalid_browser; authenticated session remains valid');
 }finally{await context.close();await browser.close()}
});

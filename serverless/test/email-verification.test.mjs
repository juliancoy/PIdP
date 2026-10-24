import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import app from '../src/index.ts';
import { hashPassword } from '../src/crypto.ts';
import { sendVerification, consumeVerification } from '../src/emailVerification.ts';
async function fixture() {
 const sql=new DatabaseSync(':memory:');
 sql.exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT,hashed_password TEXT,full_name TEXT,provider TEXT,provider_account_id TEXT,identity_data TEXT DEFAULT '{}',is_active INTEGER,created_at TEXT);
 CREATE TABLE websites(id TEXT PRIMARY KEY,slug TEXT);CREATE TABLE website_users(id TEXT,website_id TEXT,email TEXT,identity_data TEXT,is_active INTEGER);`);
 sql.prepare("INSERT INTO users VALUES('u','member@example.test',?,NULL,NULL,NULL,'{}',1,'2026-01-01')").run(await hashPassword('password123'));
 const mail=[];
 const DB = {prepare(query) {
   return {bind(...args) {
     return {async first() {return sql.prepare(query).get(...args) || null},
       async run() {return {meta:{changes:sql.prepare(query).run(...args).changes}}}};
   }};
 }};
 const env={SECRET_KEY:'test',PUBLIC_BASE_URL:'https://id.example',EMAIL_FROM:'identity@example.test',EMAIL:{async send(message){mail.push(message);return {messageId:'test'}}},DB};
 return {sql,env,mail,user:()=>sql.prepare("SELECT * FROM users WHERE id='u'").get(),request:(path,body)=>app.request('https://id.example'+path,body?{method:'POST',body:new URLSearchParams(body)}:{},env)};
}
test('password verification, resend cooldown, return context and single-use completion',async()=>{
 const f=await fixture();try{
 assert.equal((await f.request('/auth/token',{username:'member@example.test',password:'password123'})).status,403);
 const browser=await f.request('/app/login',{email:'member@example.test',password:'password123',next:'/profile'});assert.match(browser.headers.get('location'),/Verify/);assert.equal(browser.headers.get('set-cookie'),null);
 for(let i=0;i<2;i++)assert.equal((await f.request('/auth/resend-verification',{email:'member@example.test',next:'/profile'})).status,303);
 assert.equal(f.mail.length,1);
 const link=new URL(f.mail[0].text.match(/https:\/\/\S+/)[0]);assert.equal(f.user().identity_data.includes(link.searchParams.get('token')),false);
 assert.equal((await f.request('/auth/resend-verification',{email:'unknown@example.test',next:'/profile'})).status,303);assert.equal(f.mail.length,1);
 const wrong=new URL(link);wrong.searchParams.set('token','wrong');assert.match((await f.request(wrong.pathname+wrong.search)).headers.get('location'),/invalid/);
 const verified=await f.request(link.pathname+link.search);assert.match(verified.headers.get('location'),/Email\+verified/);assert.equal(new URL(verified.headers.get('location')).searchParams.get('next'),'/profile');
 assert.match((await f.request(link.pathname+link.search)).headers.get('location'),/invalid/);
 assert.equal((await f.request('/auth/token',{username:'member@example.test',password:'password123'})).status,200);
 }finally{f.sql.close()}
});
test('expiry, tenant isolation, unsafe returns and failed delivery fail closed',async()=>{
 const f=await fixture();try{
 assert.equal((await f.request('/auth/resend-verification',{email:'member@example.test',next:'https://evil.example'})).status,400);
 await sendVerification(f.env,f.user());const link=new URL(f.mail[0].text.match(/https:\/\/\S+/)[0]);
 link.searchParams.set('app','missing');assert.match((await f.request(link.pathname+link.search)).headers.get('location'),/invalid/);
 const identity=JSON.parse(f.user().identity_data);identity.email_verification.expires_at='2000-01-01';f.sql.prepare('UPDATE users SET identity_data=?').run(JSON.stringify(identity));
 assert.equal(await consumeVerification(f.env,f.user(),link.searchParams.get('token')),null);
 f.sql.exec("UPDATE users SET identity_data='{}'");f.env.EMAIL.send=async()=>{throw new Error('private delivery failure')};
 assert.equal((await f.request('/auth/resend-verification',{email:'member@example.test',next:'/profile'})).status,503);assert.equal(f.user().identity_data,'{}');
 }finally{f.sql.close()}
});

test('headless browser can request a replacement email and return to sign-in after verification',async()=>{
 const {chromium}=await import('@playwright/test');
 const {createServer}=await import('node:http');
 const f=await fixture();
 const server=createServer(async(req,res)=>{
  try {
   const chunks=[];for await(const chunk of req)chunks.push(chunk);
   const response=await app.request('https://id.example'+req.url,{method:req.method,headers:req.headers,...(chunks.length?{body:Buffer.concat(chunks)}:{})},f.env);
   const headers=Object.fromEntries(response.headers);
   if(headers.location) headers.location=headers.location.replace('https://id.example','');
   res.writeHead(response.status,headers);res.end(await response.text());
  }catch(error){res.writeHead(500);res.end('Local test bridge failed')}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const origin='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage();page.setDefaultTimeout(5000);
  await page.goto(origin+'/app/login?next=%2Fprofile');
  await page.getByText('Resend verification email',{exact:true}).click();
  const resend=page.locator('form[action="/auth/resend-verification"]');
  await resend.getByLabel('Email').fill('member@example.test');
  await resend.getByRole('button',{name:'Send verification email'}).click();
  await page.getByRole('status').waitFor();assert.match(await page.getByRole('status').innerText(),/Check your inbox/);
  const link=new URL(f.mail[0].text.match(/https:\/\/\S+/)[0]);
  await page.goto(origin+link.pathname+link.search);
  await page.getByRole('status').waitFor();assert.match(await page.getByRole('status').innerText(),/Email verified/);
  assert.equal(new URL(page.url()).searchParams.get('next'),'/profile');
  assert.equal(await page.getByRole('button',{name:'Sign in',exact:true}).isVisible(),true);
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));f.sql.close()}
});

test('shared registration sends verification without issuing a browser session',async()=>{
 const f=await fixture();try{
 f.env.PORTAL_SHARED_IDENTITY='true';
 const result=await app.request('https://id.example/app/register',{method:'POST',headers:{origin:'https://id.example'},body:new URLSearchParams({email:'new@example.test',password:'password123',next:'/profile'})},f.env);
 assert.equal(result.status,303);assert.match(result.headers.get('location'),/Check\+your\+email/);assert.equal(result.headers.get('set-cookie'),null);assert.equal(f.mail.length,1);
 assert.equal((await f.request('/auth/token',{username:'new@example.test',password:'password123'})).status,403);
 }finally{f.sql.close()}
});

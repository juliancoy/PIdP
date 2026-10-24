import test from 'node:test';import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';import {readFileSync} from 'node:fs';
import {browserSession,BROWSER_IDLE_SECONDS,BROWSER_ABSOLUTE_SECONDS} from '../src/browserSessions.ts';
import {signJwt,verifyJwt,sha256Hex} from '../src/crypto.ts';import app from '../src/index.ts';
function fixture(){
 const sql=new DatabaseSync(':memory:');for(const migration of ['0001_initial.sql','0009_portal_sso.sql','0013_browser_sessions.sql'])sql.exec(readFileSync(new URL('../migrations/'+migration,import.meta.url),'utf8'));
 sql.exec("INSERT INTO users(id,email,is_active) VALUES('owner','owner@example.test',1),('other','other@example.test',1)");
 const DB={prepare(query){const s=sql.prepare(query);return{bind(...args){return{async first(){return s.get(...args)||null},async run(){return{meta:s.run(...args)}}}}}}};
 return{sql,env:{DB,SECRET_KEY:'session-fixture-only',ACCESS_TOKEN_EXPIRE_MINUTES:'60'}};
}
const cookie=r=>decodeURIComponent(r.headers.getSetCookie().find(c=>c.startsWith('pidp_session=')).split(';')[0].slice('pidp_session='.length));
test('30-day remembered login restores a short token after the old access token expires',async()=>{
 const f=fixture(),clock=Date.now;let now=clock();Date.now=()=>now;
 try{
  const original=await signJwt(f.env,{sub:'owner'}),remembered=await browserSession(f.env,original);
  assert.equal(remembered.maxAge,BROWSER_IDLE_SECONDS);const session=await verifyJwt(f.env,remembered.token);
  assert.equal(session.token_use,'browser_session');assert.ok(session.sid);
  assert.equal(f.sql.prepare('SELECT id_hash FROM browser_sessions').get().id_hash,await sha256Hex(session.sid));
  now+=8*86400000;await assert.rejects(verifyJwt(f.env,original));
  const response=await app.request('https://id.example/auth/session-token',{headers:{cookie:'pidp_session='+remembered.token}},f.env);
  assert.equal(response.status,200);assert.match(response.headers.get('cache-control'),/no-store/);
  const body=await response.json(),access=await verifyJwt(f.env,body.access_token);
  assert.equal(access.sid,session.sid);assert.equal(access.token_use,undefined);assert.ok(access.exp-Math.floor(now/1000)<=3600);
  assert.notEqual(body.access_token,cookie(response));
  assert.equal((await verifyJwt(f.env,cookie(response))).exp-Math.floor(now/1000),BROWSER_IDLE_SECONDS);
  const value=response.headers.getSetCookie().find(c=>c.startsWith('pidp_session='));
  for(const attribute of ['HttpOnly','Secure','SameSite=Lax','Max-Age=2592000'])assert.ok(value.includes(attribute));assert.ok(!value.includes('Domain='));
 }finally{Date.now=clock;f.sql.close()}
});
test('renewal is bounded by 90 days and inactivity expires after 30 days',async()=>{
 const f=fixture(),clock=Date.now;const initial=clock();let now=initial;Date.now=()=>now;
 try{
  const access=await signJwt(f.env,{sub:'owner'});let remembered=await browserSession(f.env,access);
  const idle=await browserSession(f.env,access);now=initial+31*86400000;await assert.rejects(verifyJwt(f.env,idle.token));now=initial;
  for(const day of [29,58,87]){now=initial+day*86400000;const claims=await verifyJwt(f.env,remembered.token);remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner',sid:claims.sid}),remembered.token)}
  assert.equal((await verifyJwt(f.env,remembered.token)).exp,Math.floor(initial/1000)+BROWSER_ABSOLUTE_SECONDS);
  now=initial+91*86400000;await assert.rejects(verifyJwt(f.env,remembered.token));
 }finally{Date.now=clock;f.sql.close()}
});
test('logout revokes captured cookies and linked access tokens server-side',async()=>{
 const f=fixture();try{
  const remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner'}));
  const response=await app.request('https://id.example/auth/session-token',{headers:{cookie:'pidp_session='+remembered.token}},f.env),access=(await response.json()).access_token;
  const logout=await app.request('https://id.example/auth/session/logout',{method:'POST',headers:{cookie:'pidp_session='+remembered.token}},f.env);
  assert.equal(logout.status,200);await assert.rejects(verifyJwt(f.env,remembered.token));await assert.rejects(verifyJwt(f.env,access));assert.equal(f.sql.prepare('SELECT count(*) AS n FROM browser_sessions').get().n,0);
 }finally{f.sql.close()}
});
test('sessions cannot move accounts or be API bearers; account deletion cascades',async()=>{
 const f=fixture();try{
  const remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner'})),claims=await verifyJwt(f.env,remembered.token);
  await assert.rejects(verifyJwt(f.env,await signJwt(f.env,{sub:'other',sid:claims.sid})));
  assert.equal((await app.request('https://id.example/auth/me',{headers:{authorization:'Bearer '+remembered.token}},f.env)).status,401);
  f.sql.exec("DELETE FROM users WHERE id='owner'");assert.equal(f.sql.prepare('SELECT count(*) AS n FROM browser_sessions').get().n,0);
 }finally{f.sql.close()}
});

test('remembered login does not authorize API credential changes without recent sign-in',async()=>{
 const f=fixture();try{
  const remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner'}));
  const claims=await verifyJwt(f.env,remembered.token);
  const stale=await signJwt(f.env,{sub:'owner',sid:claims.sid,auth_time:Math.floor(Date.now()/1000)-901});
  const r=await app.request('https://id.example/auth/tokens',{method:'POST',headers:{authorization:'Bearer '+stale,'content-type':'application/json'},body:'{}'},f.env);
  assert.equal(r.status,401);assert.match(await r.text(),/Sign in again/);
 }finally{f.sql.close()}
});

test('logout surfaces storage failure so the browser can retry revocation',async()=>{
 const f=fixture();try{
  const remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner'}));
  const {revokeBrowserSession}=await import('../src/browserSessions.ts');
  const failed={...f.env,DB:{prepare(){throw new Error('storage unavailable')}}};
  await assert.rejects(revokeBrowserSession(failed,remembered.token),/storage unavailable/);
  await revokeBrowserSession(f.env,remembered.token);
  await revokeBrowserSession(f.env,remembered.token);
 }finally{f.sql.close()}
});


test('a portal-origin logout cannot revoke the separate identity session',async()=>{
 const f=fixture();try {
  const remembered=await browserSession(f.env,await signJwt(f.env,{sub:'owner'}));
  const result=await app.request('https://id.example/auth/session/logout',{method:'POST',headers:{cookie:'pidp_session='+remembered.token,origin:'https://portal.example'}},f.env);
  assert.equal(result.status,403);
  assert.equal((await verifyJwt(f.env,remembered.token)).sub,'owner');
 }finally{f.sql.close();}
});

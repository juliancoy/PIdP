// Isolated real PIdP Worker routes backed by a disposable local SQLite fixture.
import {createServer} from 'node:https';
import {readFileSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import app from '../src/index.ts';
import {hashPassword} from '../src/crypto.ts';
const port=Number(process.env.LAB_PORT||8891),issuer=`https://pidp.localhost:${port}`;
const clients=Object.fromEntries(['lifetech','orgportal','medtech'].map(name=>[`https://${name}.localhost:${port}`,{name:{lifetech:'LifeTech',orgportal:'OrgPortal',medtech:'MedTech'}[name],accountApp:'members',callbacks:['/auth/callback']}]));
const sql=new DatabaseSync(':memory:');
for(const file of ['0001_initial.sql','0009_portal_sso.sql','0010_account_identity_links.sql'])sql.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
const password=await hashPassword('Local-test-password-42');
for(const [id,email] of [['owner','owner@example.test'],['other','other@example.test']])sql.prepare('INSERT INTO users(id,email,hashed_password,full_name) VALUES(?,?,?,?)').run(id,email,password,id);
sql.prepare("INSERT INTO websites(id,owner_id,name,slug) VALUES('site','owner','Shared credential namespace','members')").run();
for(const id of ['member','alternate'])sql.prepare('INSERT INTO website_users(id,website_id,email,hashed_password,full_name) VALUES(?,?,?,?,?)').run(id,'site',id+'@example.test',password,id);
function prepare(query,params=[]){return {bind(...p){return prepare(query,p)},async first(){return sql.prepare(query).get(...params)||null},async all(){return{results:sql.prepare(query).all(...params)}},async run(){return{meta:sql.prepare(query).run(...params)}}}}
const DB={prepare,async batch(statements){sql.exec('BEGIN');try{const results=[];for(const s of statements)results.push(await s.run());sql.exec('COMMIT');return results}catch(e){sql.exec('ROLLBACK');throw e}}};
const env={DB,SECRET_KEY:'identity-lab-only-not-a-production-key',PUBLIC_BASE_URL:issuer,PORTAL_AUTH_ORIGINS:Object.keys(clients).join(','),PORTAL_CLIENTS_JSON:JSON.stringify(clients),FRONTEND_REDIRECT_URL:`https://orgportal.localhost:${port}/auth/callback`};
createServer({key:readFileSync('/certs/key.pem'),cert:readFileSync('/certs/cert.pem')},async(req,res)=>{
 try{
 const origin='https://'+req.headers.host,url=new URL(req.url,origin);
 if(url.pathname==='/' && clients[origin]){res.end('<h1>'+clients[origin].name+'</h1>');return}
 if(url.pathname==='/health'){res.end('identity-lab');return}
 if(url.pathname==='/auth/callback'){res.end('<h1>Returned to '+clients[origin]?.name+'</h1><a href="'+(url.searchParams.get('next')||'/')+'">Continue</a>');return}
 if(url.pathname==='/people'){res.end('<h1>People</h1>');return}
 if(url.pathname.startsWith('/pidp/'))url.pathname=url.pathname.slice(5);
 const headers=new Headers(Object.entries(req.headers).filter(([,v])=>typeof v==='string'));
 if(origin!==issuer){headers.set('x-forwarded-host',req.headers.host);headers.set('x-forwarded-proto','https')}
 const chunks=[];for await(const c of req)chunks.push(c);
 const response=await app.fetch(new Request(url,{method:req.method,headers,...(chunks.length?{body:Buffer.concat(chunks)}:{})}),env);
 res.statusCode=response.status;response.headers.forEach((v,k)=>{if(k!=='set-cookie')res.setHeader(k,v)});const cookies=response.headers.getSetCookie();if(cookies.length)res.setHeader('set-cookie',cookies);res.end(Buffer.from(await response.arrayBuffer()));
 }catch(e){console.error(e.message);res.statusCode=500;res.end('Local fixture failed')}
}).listen(8443,'0.0.0.0',()=>console.log('Isolated identity lab ready on '+issuer));

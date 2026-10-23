import {fail, HttpError} from './http';
import type { Env } from './types';
import { sha256Hex, signJwt, verifyJwt } from './crypto';
export const BROWSER_IDLE_SECONDS = 30 * 86400;
export const BROWSER_ABSOLUTE_SECONDS = 90 * 86400;

export async function browserSession(env: Env, accessToken: string, previous?: string) {
 const claims=await verifyJwt(env,accessToken),now=Math.floor(Date.now()/1000);
 let sid:string=crypto.randomUUID(),authTime=claims.auth_time||now,absolute=authTime+BROWSER_ABSOLUTE_SECONDS;
 if(!previous && claims.sid)previous=accessToken;
 if(previous){
  const old=await verifyJwt(env,previous);
  if(old.sub!==claims.sub || old.website_id!==claims.website_id || (old.actor_type||'owner')!==(claims.actor_type||'owner'))fail(401,'Session account changed');
  if(!old.sid)fail(401,'Missing browser session');
  sid=old.sid;authTime=old.auth_time||now;
  const row=await env.DB.prepare('SELECT absolute_expires_at FROM browser_sessions WHERE id_hash=?').bind(await sha256Hex(sid)).first<{absolute_expires_at:number}>();
  if(!row)fail(401,'Session revoked');
  absolute=row.absolute_expires_at;
 }
 const expires=Math.min(now+BROWSER_IDLE_SECONDS,absolute);
 const hash=await sha256Hex(sid);
 if(previous){
  const renewed=await env.DB.prepare('UPDATE browser_sessions SET expires_at=? WHERE id_hash=? AND expires_at>? AND absolute_expires_at>? RETURNING id_hash').bind(expires,hash,now,now).first();
  if(!renewed)fail(401,'Session expired');
 }else{
  const member=claims.actor_type==='website_user';
  await env.DB.prepare('INSERT INTO browser_sessions(id_hash,owner_id,website_user_id,website_id,created_at,expires_at,absolute_expires_at) VALUES(?,?,?,?,?,?,?)').bind(hash,member?null:claims.sub,member?claims.sub:null,member?claims.website_id:null,now,expires,absolute).run();
 }
 const {exp:_,jti:__,sid:___,token_use:____,...identity}=claims;
 return {token:await signJwt(env,{...identity,sid,auth_time:authTime,token_use:'browser_session',exp:expires}),maxAge:expires-now};
}
export async function revokeBrowserSession(env: Env, token: string) {
 try {const claims=await verifyJwt(env,token);if(claims.sid)await env.DB.prepare('DELETE FROM browser_sessions WHERE id_hash=?').bind(await sha256Hex(claims.sid)).run()}
 catch(error) {
  // Only an authentication rejection proves the session is already unusable.
  // Storage failures must reach the caller so offline logout can retry.
  if(!(error instanceof HttpError && error.status===401))throw error;
 }
}

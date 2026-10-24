const routes:Record<string,string>={
 '/oauth/mcp/register':'registration','/oauth/mcp/authorize':'authorization','/oauth/mcp/consent':'consent',
 '/oauth/mcp/token':'token_exchange_or_refresh','/oauth/mcp/revoke':'revocation','/oauth/mcp/introspect':'introspection',
 '/oauth/mcp/link':'browser_pairing','/oauth/mcp/browser/cancel':'browser_cancel','/oauth/mcp/connections':'connection_revocation','/oauth/mcp/resume':'resume','/oauth/mcp/handoff':'handoff','/oauth/mcp/browser/finish':'browser_link',
 '/auth/google/login':'google_login','/auth/google/callback':'google_callback',
 '/auth/github/login':'github_login','/auth/github/callback':'github_callback',
 '/auth/google-calendar/connect':'google_calendar_connect','/auth/google-calendar/callback':'google_calendar_callback',
};
export function oauthStatisticsStage(path:string,method='GET'){return !['GET','POST'].includes(method)?null:path==='/oauth/mcp/authorize'&&method==='POST'?'consent':routes[path]||null}
export async function recordOauthStatistics(db:D1Database,stage:string,status:number,location:string|null,duration:number){
 let redirectedError=false,denied=false;
 if(location){try{const q=new URL(location,'https://identity.invalid').searchParams;redirectedError=q.has('error');denied=q.get('error')==='access_denied'}catch{/* Never retain the destination. */}}
 const outcome=denied?'consent_denied':status===429?'rate_limited':status>=500?'server_error':status===401||status===403?'rejected':status>=400||redirectedError?'client_error':status>=300?'redirect':'ok';
 const ms=Math.max(0,Math.min(3600000,Math.round(duration)));
 await db.prepare(`INSERT INTO oauth_live_statistics(day,stage,outcome,requests,total_ms,max_ms) VALUES(?,?,?,1,?,?)
  ON CONFLICT(day,stage,outcome) DO UPDATE SET requests=requests+1,total_ms=total_ms+excluded.total_ms,max_ms=MAX(max_ms,excluded.max_ms)`).bind(new Date().toISOString().slice(0,10),stage,outcome,ms,ms).run();
}
export async function oauthStatistics(db:D1Database,days:number){
 const start=new Date(Date.now()-(days-1)*86400000).toISOString().slice(0,10);
 const rows=await db.prepare('SELECT day,stage,outcome,requests,total_ms,max_ms FROM oauth_live_statistics WHERE day>=? AND day<=? ORDER BY day,stage,outcome').bind(start,new Date().toISOString().slice(0,10)).all();
 return {source:'PIdP OAuth',days,start,asOf:new Date().toISOString(),rows:rows.results};
}

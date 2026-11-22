import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

// The registry is the only hand-edited list of alternate portal domains.
export function compilePortalDomains(registry) {
  const clients = {}, siteHosts = [], websites = {};
  for (const [origin, entry] of Object.entries(registry)) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password || url.port) throw Error(`Expected an exact HTTPS origin: ${origin}`);
    if (!entry.name?.trim() || !/^[a-z0-9][a-z0-9-]*$/.test(entry.accountApp || '')) throw Error(`Invalid client: ${origin}`);
    if (!Array.isArray(entry.callbacks) || !entry.callbacks.length || entry.callbacks.some(p => typeof p !== 'string' || !p.startsWith('/') || p.startsWith('//') || /[\\\s?#]/.test(p))) throw Error(`Invalid callbacks: ${origin}`);
    if (typeof entry.deployment?.orgPortalSite !== 'boolean' || typeof entry.deployment?.websiteLogin !== 'boolean') throw Error(`Explicit deployment policy required: ${origin}`);
    const { deployment, ...client } = entry;
    clients[origin] = client;
    if (deployment.orgPortalSite) siteHosts.push(url.hostname);
    if (deployment.websiteLogin) {
      const website = websites[entry.accountApp] ||= {login_hosts:[], allowed_redirect_origins:[]};
      website.login_hosts.push(url.hostname);
      website.allowed_redirect_origins.push(origin);
    }
  }
  for (const [origin, client] of Object.entries(clients)) {
    if (client.restartOrigin && (!clients[client.restartOrigin] || clients[client.restartOrigin].restartOrigin || origin === client.restartOrigin)) throw Error(`Invalid restart origin: ${origin}`);
  }
  return {pidp:{PORTAL_AUTH_ORIGINS:Object.keys(clients).join(','),PORTAL_CLIENTS_JSON:JSON.stringify(clients)},orgportal:{ORGPORTAL_SITE_HOSTS:siteHosts.join(',')},websites};
}

export function replaceVariable(text, name, value) {
  const pattern = new RegExp(`("${name}"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"`, 'g');
  let count=0;
  const result=text.replace(pattern,(_,prefix)=>{count++;return prefix+JSON.stringify(value)});
  if (count!==1) throw Error(`Expected exactly one ${name} binding; found ${count}`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const root=fileURLToPath(new URL('../',import.meta.url));
  const compiled=compilePortalDomains(JSON.parse(readFileSync(path.join(root,'shared/portal-clients.json'),'utf8')));
  const mode=process.argv[2] || '--check';
  if (mode==='--json') console.log(JSON.stringify(compiled,null,2));
  else {
    if (!['--check','--write'].includes(mode)) throw Error('Use --check, --write, or --json');
    const targets=[['serverless/wrangler.jsonc','PORTAL_AUTH_ORIGINS',compiled.pidp.PORTAL_AUTH_ORIGINS],['../OrgPortal/cloudflare/wrangler.jsonc','ORGPORTAL_SITE_HOSTS',compiled.orgportal.ORGPORTAL_SITE_HOSTS]];
    for (const [relative,name,value] of targets) {
      const file=path.join(root,relative);
      if (!existsSync(file) && relative.startsWith('../OrgPortal/')) {console.log('Sibling OrgPortal checkout absent; skipped its generated config.');continue;}
      const current=readFileSync(file,'utf8'),next=replaceVariable(current,name,value);
      if (next===current) continue;
      if (mode==='--check') throw Error(`${relative} is stale; run node scripts/sync-portal-domains.mjs --write from PIdP`);
      writeFileSync(file,next);console.log(`Updated ${relative}: ${name}`);
    }
    console.log('Portal domain configuration matches shared/portal-clients.json.');
  }
}

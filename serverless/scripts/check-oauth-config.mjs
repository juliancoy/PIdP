import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { generateKeyPair, exportJWK } from 'jose';
import { mcpAuthorization } from '../src/mcpAuthorization.ts';
import { readWranglerConfig } from './deploy.mjs';

// Exercise the real discovery handler with public deployment configuration and
// synthetic credentials. Never read production keys or create OAuth grants.
export async function checkOAuthConfiguration(vars, handler = mcpAuthorization) {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const resource = 'https://release-check.invalid/mcp';
  const env = {
    MCP_OAUTH_ISSUER: 'https://release-check.invalid',
    MCP_OAUTH_PRIVATE_JWK: JSON.stringify({ ...await exportJWK(privateKey), kid: 'release-check' }),
    MCP_OAUTH_CLIENTS_JSON: JSON.stringify({ check: {
      name: 'Release check', tokenEndpointAuthMethod: 'none',
      redirectUris: ['http://[::1]/callback'], resources: [resource], scopes: ['org:portal.read'],
    } }),
    MCP_OAUTH_RESOURCES_JSON: JSON.stringify({ [resource]: { secretHash: 'a'.repeat(64) } }),
    MCP_OAUTH_RESOURCE_CONFIG_JSON: vars.MCP_OAUTH_RESOURCE_CONFIG_JSON || '{}',
    MCP_OAUTH_RESOURCE_ADDITIONS_JSON: vars.MCP_OAUTH_RESOURCE_ADDITIONS_JSON || '{}',
  };
  const response = await handler.fetch(new Request(env.MCP_OAUTH_ISSUER + '/.well-known/oauth-authorization-server'), env);
  if (response.status !== 200) throw new Error('OAuth release check failed: configured resources are incompatible with this Worker.');
  const metadata = await response.json();
  if (metadata.issuer !== env.MCP_OAUTH_ISSUER || !metadata.code_challenge_methods_supported?.includes('S256')) {
    throw new Error('OAuth release check failed: invalid discovery response.');
  }
  return { status: response.status, scopes: metadata.scopes_supported };
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const args = process.argv.slice(2);
  const value = name => { const i = args.indexOf(name); return i < 0 ? null : args[i + 1]; };
  const configPath = value('--config');
  const vars = configPath ? JSON.parse(readFileSync(configPath, 'utf8')).vars : readWranglerConfig().vars;
  const bundle = value('--bundle');
  const handler = bundle ? (await import(pathToFileURL(resolve(bundle)).href)).default : mcpAuthorization;
  console.log(JSON.stringify(await checkOAuthConfiguration(vars || {}, handler)));
}

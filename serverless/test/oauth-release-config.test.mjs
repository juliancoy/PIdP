import test from 'node:test';
import assert from 'node:assert/strict';
import { checkOAuthConfiguration } from '../scripts/check-oauth-config.mjs';
import { readWranglerConfig } from '../scripts/deploy.mjs';

test('production resource configuration serves OAuth discovery', async () => {
  const result = await checkOAuthConfiguration(readWranglerConfig().vars);
  assert.equal(result.status, 200);
  assert.ok(result.scopes.includes('genomics:data'));
  assert.ok(result.scopes.includes('swarm:control'));
});

test('release check rejects a resource scope the Worker does not implement', async () => {
  await assert.rejects(checkOAuthConfiguration({ MCP_OAUTH_RESOURCE_CONFIG_JSON: JSON.stringify({
    'https://resource.invalid/mcp': { secretHash: 'a'.repeat(64), scopes: ['not:implemented'] },
  }) }), /configured resources are incompatible/);
});

test('release check rejects duplicate resource configuration', async () => {
  const config = JSON.stringify({ 'https://resource.invalid/mcp': { secretHash: 'a'.repeat(64), scopes: ['genomics:data'] } });
  await assert.rejects(checkOAuthConfiguration({ MCP_OAUTH_RESOURCE_CONFIG_JSON: config, MCP_OAUTH_RESOURCE_ADDITIONS_JSON: config }), /configured resources are incompatible/);
});

import { generateKeyPair, exportJWK } from 'jose';
import { writeFileSync } from 'node:fs';

const destination = process.argv[2];
if (!destination) throw new Error('Usage: node scripts/generate-mcp-key.mjs /secure/path/mcp-private.key');
const { privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...await exportJWK(privateKey), kid: crypto.randomUUID(), alg: 'ES256', use: 'sig' };
// Refuse overwrite; never print private key material into logs.
writeFileSync(destination, JSON.stringify(jwk), { mode: 0o600, flag: 'wx' });
console.log('Private signing key saved. Load it into MCP_OAUTH_PRIVATE_JWK through your secret manager.');

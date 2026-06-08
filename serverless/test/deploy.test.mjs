import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  loadCloudflareEnv,
  missingRequiredSecrets,
  parseArgs,
  parseEnvFile,
  parseSecretNames,
  plannedCommands,
  readWranglerConfig,
  stripJsoncComments,
  validateConfig,
} from "../scripts/deploy.mjs";

test("parseArgs recognizes status and dry-run flags", () => {
  assert.deepEqual(parseArgs(["--check-only", "--dry-run", "--skip-status"]), {
    checkOnly: true,
    skipMigrations: false,
    skipStatus: true,
    dryRun: true,
  });
});

test("check-only plan only runs status commands", () => {
  const commands = plannedCommands({ checkOnly: true, skipMigrations: false, skipStatus: false, dryRun: false }).map((item) => item[1]);
  assert.deepEqual(commands, [
    "wrangler whoami",
    "wrangler d1 list",
    "wrangler r2 bucket list",
    "wrangler deployments list",
  ]);
});

test("deploy plan typechecks, checks status, migrates, and deploys", () => {
  const commands = plannedCommands({ checkOnly: false, skipMigrations: false, skipStatus: false, dryRun: false }).map((item) => item[1]);
  assert.equal(commands[0], "npm run typecheck");
  assert.ok(commands.includes("wrangler d1 migrations apply pidp --remote"));
  assert.equal(commands.at(-1), "wrangler deploy");
});

test("deploy plan supports dry-run and skipping migrations", () => {
  const commands = plannedCommands({ checkOnly: false, skipMigrations: true, skipStatus: false, dryRun: true }).map((item) => item[1]);
  assert.equal(commands.at(-1), "wrangler deploy --dry-run");
  assert.equal(commands.includes("wrangler d1 migrations apply pidp --remote"), false);
});

test("deploy plan can skip Cloudflare status checks", () => {
  const commands = plannedCommands({ checkOnly: false, skipMigrations: true, skipStatus: true, dryRun: true }).map((item) => item[1]);
  assert.deepEqual(commands, ["npm run typecheck", "wrangler deploy --dry-run"]);
});

test("validateConfig catches placeholder D1 ids", () => {
  const problems = validateConfig({
    d1_databases: [{ database_id: "replace-with-cloudflare-d1-database-id" }],
    r2_buckets: [{ bucket_name: "pidp-avatars" }],
  });
  assert.deepEqual(problems, ["Set d1_databases[0].database_id in wrangler.jsonc."]);
});

test("readWranglerConfig preserves URLs while removing comments", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pidp-config-"));
  try {
    writeFileSync(path.join(root, "wrangler.jsonc"), `{
      // comments should be ignored
      "vars": {
        "ALLOWED_ORIGINS": "https://app.example.com,https://www.example.com",
        "FRONTEND_REDIRECT_URL": "https://app.example.com/p/auth/callback"
      },
      "d1_databases": [{ "binding": "DB", "database_name": "pidp", "database_id": "abc" }],
      "r2_buckets": [{ "binding": "AVATARS", "bucket_name": "pidp-avatars" }]
    }`);
    const config = readWranglerConfig(root);
    assert.equal(config.vars.ALLOWED_ORIGINS, "https://app.example.com,https://www.example.com");
    assert.equal(config.vars.FRONTEND_REDIRECT_URL, "https://app.example.com/p/auth/callback");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("stripJsoncComments keeps comment markers inside strings", () => {
  const raw = `{"url":"https://id.example.com/*","value":"literal /* marker */"} // remove`;
  assert.deepEqual(JSON.parse(stripJsoncComments(raw)), {
    url: "https://id.example.com/*",
    value: "literal /* marker */",
  });
});

test("parseEnvFile reads CLOUDFLARE_API_TOKEN without surrounding quotes", () => {
  assert.deepEqual(parseEnvFile("CLOUDFLARE_API_TOKEN='secret-token'\nOTHER=value\n"), {
    CLOUDFLARE_API_TOKEN: "secret-token",
    OTHER: "value",
  });
});

test("loadCloudflareEnv reads .env.cloudflare when token is not exported", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pidp-serverless-"));
  try {
    writeFileSync(path.join(root, ".env.cloudflare"), "CLOUDFLARE_API_TOKEN=test-token\n");
    const result = loadCloudflareEnv({}, root);
    assert.equal(result.env.CLOUDFLARE_API_TOKEN, "test-token");
    assert.equal(result.source, path.join(root, ".env.cloudflare"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("parseSecretNames reads Wrangler JSON secret list output", () => {
  const output = JSON.stringify([
    { name: "SECRET_KEY", type: "secret_text" },
    { name: "GOOGLE_CLIENT_SECRET", type: "secret_text" },
  ]);
  assert.deepEqual(parseSecretNames(output), ["SECRET_KEY", "GOOGLE_CLIENT_SECRET"]);
});

test("parseSecretNames tolerates human-readable secret list output", () => {
  const output = "Name\nSECRET_KEY\nGOOGLE_CLIENT_SECRET\n";
  assert.deepEqual(parseSecretNames(output), ["SECRET_KEY", "GOOGLE_CLIENT_SECRET"]);
});

test("missingRequiredSecrets requires SECRET_KEY by default", () => {
  assert.deepEqual(missingRequiredSecrets(["GOOGLE_CLIENT_SECRET"]), ["SECRET_KEY"]);
  assert.deepEqual(missingRequiredSecrets(["SECRET_KEY"]), []);
});

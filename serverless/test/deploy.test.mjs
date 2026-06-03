import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadCloudflareEnv, parseArgs, parseEnvFile, plannedCommands, validateConfig } from "../scripts/deploy.mjs";

test("parseArgs recognizes status and dry-run flags", () => {
  assert.deepEqual(parseArgs(["--check-only", "--dry-run"]), {
    checkOnly: true,
    skipMigrations: false,
    dryRun: true,
  });
});

test("check-only plan only runs status commands", () => {
  const commands = plannedCommands({ checkOnly: true, skipMigrations: false, dryRun: false }).map((item) => item[1]);
  assert.deepEqual(commands, [
    "wrangler whoami",
    "wrangler d1 list",
    "wrangler r2 bucket list",
    "wrangler deployments list",
  ]);
});

test("deploy plan typechecks, checks status, migrates, and deploys", () => {
  const commands = plannedCommands({ checkOnly: false, skipMigrations: false, dryRun: false }).map((item) => item[1]);
  assert.equal(commands[0], "npm run typecheck");
  assert.ok(commands.includes("wrangler d1 migrations apply pidp --remote"));
  assert.equal(commands.at(-1), "wrangler deploy");
});

test("deploy plan supports dry-run and skipping migrations", () => {
  const commands = plannedCommands({ checkOnly: false, skipMigrations: true, dryRun: true }).map((item) => item[1]);
  assert.equal(commands.at(-1), "wrangler deploy --dry-run");
  assert.equal(commands.includes("wrangler d1 migrations apply pidp --remote"), false);
});

test("validateConfig catches placeholder D1 ids", () => {
  const problems = validateConfig({
    d1_databases: [{ database_id: "replace-with-cloudflare-d1-database-id" }],
    r2_buckets: [{ bucket_name: "pidp-avatars" }],
  });
  assert.deepEqual(problems, ["Set d1_databases[0].database_id in wrangler.jsonc."]);
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

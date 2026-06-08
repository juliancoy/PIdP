#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WRANGLER = process.platform === "win32" ? "npx.cmd" : "npx";
const REQUIRED_SECRETS = ["SECRET_KEY"];

export function parseArgs(argv) {
  return {
    checkOnly: argv.includes("--check-only"),
    skipMigrations: argv.includes("--skip-migrations"),
    skipStatus: argv.includes("--skip-status"),
    dryRun: argv.includes("--dry-run"),
  };
}

export function readWranglerConfig(root = ROOT) {
  const configPath = path.join(root, "wrangler.jsonc");
  const raw = stripJsoncComments(readFileSync(configPath, "utf8"));
  return JSON.parse(raw);
}

export function stripJsoncComments(raw) {
  let output = "";
  let inString = false;
  let escaped = false;

  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    const next = raw[index + 1];

    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === "\"") {
        inString = false;
      }
      continue;
    }

    if (char === "\"") {
      inString = true;
      output += char;
      continue;
    }

    if (char === "/" && next === "/") {
      while (index < raw.length && raw[index] !== "\n") index += 1;
      output += "\n";
      continue;
    }

    if (char === "/" && next === "*") {
      index += 2;
      while (index < raw.length && !(raw[index] === "*" && raw[index + 1] === "/")) index += 1;
      index += 1;
      continue;
    }

    output += char;
  }

  return output;
}

export function parseEnvFile(raw) {
  const values = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values[match[1]] = value;
  }
  return values;
}

export function loadCloudflareEnv(baseEnv = process.env, root = ROOT) {
  const env = { ...baseEnv };
  if (env.CLOUDFLARE_API_TOKEN) return { env, source: "environment" };

  const candidates = [
    path.join(root, ".env.cloudflare"),
    path.join(root, "..", ".env.cloudflare"),
  ];
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    const values = parseEnvFile(readFileSync(candidate, "utf8"));
    if (values.CLOUDFLARE_API_TOKEN) {
      env.CLOUDFLARE_API_TOKEN = values.CLOUDFLARE_API_TOKEN;
      return { env, source: candidate };
    }
  }
  return { env, source: null };
}

export function validateConfig(config) {
  const problems = [];
  const d1 = config.d1_databases?.[0];
  if (!d1?.database_id || d1.database_id === "replace-with-cloudflare-d1-database-id") {
    problems.push("Set d1_databases[0].database_id in wrangler.jsonc.");
  }
  if (!config.r2_buckets?.[0]?.bucket_name) {
    problems.push("Set r2_buckets[0].bucket_name in wrangler.jsonc.");
  }
  return problems;
}

export function parseSecretNames(raw) {
  const text = String(raw || "").trim();
  if (!text) return [];

  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object" && typeof item.name === "string") return item.name;
          return "";
        })
        .filter(Boolean);
    }
    if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.secrets)) return parseSecretNames(JSON.stringify(parsed.secrets));
      return Object.keys(parsed);
    }
  } catch {
    // Fall through to loose parsing for human-readable Wrangler output.
  }

  return [...new Set(text.split(/[^A-Za-z0-9_]+/).filter((item) => /^[A-Z][A-Z0-9_]*$/.test(item)))];
}

export function missingRequiredSecrets(secretNames, required = REQUIRED_SECRETS) {
  const available = new Set(secretNames);
  return required.filter((name) => !available.has(name));
}

export function checkRequiredSecrets(env = process.env, required = REQUIRED_SECRETS) {
  const result = spawnSync(
    WRANGLER,
    ["wrangler", "secret", "list", "--format", "json"],
    { cwd: ROOT, env, encoding: "utf8" },
  );

  if (result.status !== 0) {
    return {
      ok: false,
      status: result.status || 1,
      error: result.stderr || result.stdout || "Unable to inspect Worker secrets.",
      missing: required,
    };
  }

  const secretNames = parseSecretNames(result.stdout);
  const missing = missingRequiredSecrets(secretNames, required);
  return {
    ok: missing.length === 0,
    status: missing.length === 0 ? 0 : 2,
    missing,
    secretNames,
  };
}

export function plannedCommands(options) {
  const status = [
    ["whoami", "wrangler whoami"],
    ["d1-list", "wrangler d1 list"],
    ["r2-list", "wrangler r2 bucket list"],
    ["deployments", "wrangler deployments list"],
  ];
  if (options.checkOnly) return status;

  const commands = [["typecheck", "npm run typecheck"]];
  if (!options.skipStatus) commands.push(...status);
  if (!options.skipMigrations) commands.push(["d1-migrate", "wrangler d1 migrations apply pidp --remote"]);
  commands.push(["deploy", options.dryRun ? "wrangler deploy --dry-run" : "wrangler deploy"]);
  return commands;
}

function runShell(command, env = process.env) {
  if (command.startsWith("wrangler ")) {
    const args = ["wrangler", ...command.slice("wrangler ".length).split(" ")];
    return spawnSync(WRANGLER, args, { cwd: ROOT, env, stdio: "inherit" });
  }
  return spawnSync(command, { cwd: ROOT, env, stdio: "inherit", shell: true });
}

function printAuthHint(envSource) {
  if (envSource) {
    console.log(`Using CLOUDFLARE_API_TOKEN from ${envSource === "environment" ? "environment" : path.relative(ROOT, envSource)}.`);
    return;
  }
  console.log("No CLOUDFLARE_API_TOKEN is set. The status check may still pass if Wrangler is already logged in.");
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const config = readWranglerConfig();
  const problems = validateConfig(config);
  const { env, source: envSource } = loadCloudflareEnv();

  console.log(`PIdP serverless deployment helper`);
  console.log(`Worker: ${config.name}`);
  console.log(`Mode: ${options.checkOnly ? "status check" : options.dryRun ? "dry-run deploy" : "deploy"}`);
  printAuthHint(envSource);

  if (!options.checkOnly && problems.length) {
    console.error("\nConfiguration is not ready for deployment:");
    for (const problem of problems) console.error(`- ${problem}`);
    return 2;
  }

  if (!options.checkOnly) {
    console.log("\n==> secret-preflight: wrangler secret list");
    const secretCheck = checkRequiredSecrets(env);
    if (!secretCheck.ok) {
      console.error("\nRequired Worker secrets are not ready for deployment:");
      for (const secretName of secretCheck.missing || REQUIRED_SECRETS) {
        console.error(`- Missing Worker secret: ${secretName}`);
      }
      if (secretCheck.error) console.error(String(secretCheck.error).trim());
      console.error("Set missing secrets with: npx wrangler secret put SECRET_KEY");
      return secretCheck.status || 1;
    }
  }

  for (const [label, command] of plannedCommands(options)) {
    console.log(`\n==> ${label}: ${command}`);
    const result = runShell(command, env);
    if (result.status !== 0) {
      if (label === "deployments") {
        console.warn("Deployment history is unavailable; continuing because this may be the first deployment for this Worker.");
        continue;
      }
      console.error(`Command failed: ${command}`);
      return result.status || 1;
    }
  }

  console.log(options.checkOnly ? "\nStatus check complete." : "\nDeployment flow complete.");
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = main();
}

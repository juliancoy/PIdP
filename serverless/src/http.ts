import type { Context } from "hono";

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function fail(status: number, detail: string): never {
  throw new HttpError(status, detail);
}

export function jsonError(c: Context, error: unknown): Response {
  if (error instanceof HttpError) {
    return c.json({ detail: error.message }, error.status as never);
  }
  console.error(error);
  return c.json({ detail: "Internal server error" }, 500);
}

export async function readJson<T = Record<string, unknown>>(c: Context): Promise<T> {
  try {
    return await c.req.json<T>();
  } catch {
    fail(400, "Invalid JSON body");
  }
}

export function bearerToken(c: Context): string {
  const header = c.req.header("Authorization") || "";
  if (!header.toLowerCase().startsWith("bearer ")) {
    fail(401, "Bearer token required");
  }
  const token=header.slice(7).trim();
  try {const encoded=token.split('.')[1];if(encoded && JSON.parse(atob(encoded.replaceAll('-','+').replaceAll('_','/'))).token_use==='browser_session')fail(401,'Browser session cookies cannot be used as bearer tokens')}
  catch(error){if(error instanceof HttpError)throw error}
  return token;
}

export async function formCredentials(c: Context): Promise<{ username: string; password: string }> {
  const form = await c.req.parseBody();
  const username = String(form.username || "").trim();
  const password = String(form.password || "");
  if (!username || !password) {
    fail(422, "username and password are required");
  }
  return { username, password };
}

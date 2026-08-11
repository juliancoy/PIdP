import type { Env, JwtPayload } from "./types";
import { fail } from "./http";

const enc = new TextEncoder();
const dec = new TextDecoder();

function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value: string): ArrayBuffer {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function signJwt(env: Env, payload: Omit<JwtPayload, "exp"> & { exp?: number }): Promise<string> {
  const ttlMinutes = Number(env.ACCESS_TOKEN_EXPIRE_MINUTES || "525600");
  const body: JwtPayload = {
    ...payload,
    exp: payload.exp ?? Math.floor(Date.now() / 1000) + ttlMinutes * 60,
  };
  const header = { alg: "HS256", typ: "JWT" };
  const signingInput = `${base64Url(enc.encode(JSON.stringify(header)))}.${base64Url(enc.encode(JSON.stringify(body)))}`;
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(env.SECRET_KEY), enc.encode(signingInput));
  return `${signingInput}.${base64Url(signature)}`;
}

export async function verifyJwt(env: Env, token: string): Promise<JwtPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) fail(401, "Invalid token");
  const signingInput = `${parts[0]}.${parts[1]}`;
  const ok = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.SECRET_KEY),
    fromBase64Url(parts[2]),
    enc.encode(signingInput),
  );
  if (!ok) fail(401, "Invalid token");
  let payload: JwtPayload;
  try {
    payload = JSON.parse(dec.decode(fromBase64Url(parts[1]))) as JwtPayload;
  } catch {
    fail(401, "Invalid token");
  }
  if (!payload.sub || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    fail(401, "Invalid token");
  }
  return payload;
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 210_000 },
    key,
    256,
  );
  return `pbkdf2_sha256$210000$${base64Url(salt)}$${base64Url(bits)}`;
}

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  const [scheme, iterationsRaw, saltRaw, hashRaw] = stored.split("$");
  if (scheme !== "pbkdf2_sha256") return false;
  const iterations = Number(iterationsRaw);
  if (!Number.isFinite(iterations) || iterations < 100_000) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromBase64Url(saltRaw), iterations },
    key,
    256,
  );
  return base64Url(bits) === hashRaw;
}

export function randomToken(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(40));
  return `${prefix}${base64Url(bytes)}`;
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptString(env: Env, value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env.SECRET_KEY), enc.encode(value));
  return `${base64Url(iv)}.${base64Url(ciphertext)}`;
}

export async function decryptString(env: Env, value: string): Promise<string> {
  const [ivRaw, bodyRaw] = String(value || "").split(".");
  if (!ivRaw || !bodyRaw) fail(400, "Encrypted value is invalid");
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(fromBase64Url(ivRaw)) },
      await aesKey(env.SECRET_KEY),
      fromBase64Url(bodyRaw),
    );
    return dec.decode(plaintext);
  } catch {
    fail(400, "Encrypted value is invalid");
  }
}

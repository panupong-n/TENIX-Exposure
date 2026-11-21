import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { secretKey } from "./config.ts";

const scryptAsync = (pw: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> =>
  new Promise((ok, fail) => scrypt(pw, salt, 64, { N: n, r, p, maxmem: 128 * 1024 * 1024 }, (e, k) => (e ? fail(e) : ok(k))));

const N = 32768;
export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scryptAsync(pw, salt, N, 8, 1);
  return `scrypt$${N}$8$1$${salt.toString("base64")}$${key.toString("base64")}`;
}
export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, n, r, p, salt, key] = stored.split("$");
  if (alg !== "scrypt" || !salt || !key) return false;
  const want = Buffer.from(key, "base64");
  const got = await scryptAsync(pw, Buffer.from(salt, "base64"), Number(n), Number(r), Number(p));
  return got.length === want.length && timingSafeEqual(got, want);
}
const dummyHash = hashPassword("dummy-password-for-timing");
/** Burn the same time as a real check when the account does not exist. */
export const burnPasswordCheck = async () => verifyPassword("x", await dummyHash);

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const uuid = () => crypto.randomUUID();

/** AES-256-GCM. Output: base64(iv | tag | ciphertext). */
export function seal(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", secretKey, iv);
  const enc = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64");
}
export function unseal(blob: string): string {
  const b = Buffer.from(blob, "base64");
  const d = createDecipheriv("aes-256-gcm", secretKey, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
}

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function unbase32(s: string): Buffer {
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("bad base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export const newTotpSecret = () => base32(randomBytes(20));

export function hotp(secret: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", unbase32(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const code = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 1_000_000).padStart(6, "0");
}
/** Returns the matching time-step (so the caller can refuse a replay) or null. */
export function totpMatch(secret: string, code: string, now = Date.now(), window = 1): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const step = Math.floor(now / 30000);
  let hit: number | null = null;
  for (let d = -window; d <= window; d++) {
    if (timingSafeEqual(Buffer.from(hotp(secret, step + d)), Buffer.from(code))) hit = step + d;
  }
  return hit;
}
export const totpUri = (secret: string, account: string) =>
  `otpauth://totp/${encodeURIComponent("10CYBER Exposure")}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent("10CYBER Exposure")}&algorithm=SHA1&digits=6&period=30`;

process.env.TENIX_DB_PATH = ":memory:";
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 9).toString("base64");
import assert from "node:assert/strict";
import { test } from "node:test";
const c = await import("../src/crypto.ts");

// RFC 6238 appendix B, SHA-1, secret "12345678901234567890" (8-digit values truncated to 6 digits)
const SECRET = c.base32(Buffer.from("12345678901234567890"));
test("TOTP matches the RFC 6238 test vectors", () => {
  assert.equal(SECRET, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  for (const [t, code] of [[59, "287082"], [1111111109, "081804"], [1111111111, "050471"], [1234567890, "005924"], [2000000000, "279037"]] as const) {
    assert.equal(c.hotp(SECRET, Math.floor(t / 30)), code, `T=${t}`);
  }
});

test("totpMatch accepts the +-1 step window, rejects outside it and non-digits", () => {
  const now = 1234567890_000;
  const step = Math.floor(now / 30000);
  assert.equal(c.totpMatch(SECRET, "005924", now), step);
  assert.equal(c.totpMatch(SECRET, c.hotp(SECRET, step - 1), now), step - 1);
  assert.equal(c.totpMatch(SECRET, c.hotp(SECRET, step + 1), now), step + 1);
  assert.equal(c.totpMatch(SECRET, c.hotp(SECRET, step + 2), now), null);
  assert.equal(c.totpMatch(SECRET, "12345", now), null);
  assert.equal(c.totpMatch(SECRET, "abcdef", now), null);
});

test("base32 round trips", () => {
  const b = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  assert.deepEqual(c.unbase32(c.base32(b)), b);
});

test("seal/unseal round trip; tampering is detected", () => {
  const sealed = c.seal("client-secret-value");
  assert.notEqual(sealed, "client-secret-value");
  assert.equal(c.unseal(sealed), "client-secret-value");
  const bad = Buffer.from(sealed, "base64");
  bad[bad.length - 1] ^= 1;
  assert.throws(() => c.unseal(bad.toString("base64")));
});

test("password hashing verifies only the right password", async () => {
  const h = await c.hashPassword("correct horse battery");
  assert.ok(await c.verifyPassword("correct horse battery", h));
  assert.ok(!(await c.verifyPassword("wrong horse battery", h)));
  assert.ok(!(await c.verifyPassword("x", "garbage")));
});

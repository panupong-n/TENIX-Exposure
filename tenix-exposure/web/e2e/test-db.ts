// Guard for every test that opens a database connection. Keep identical to server/test/test-db.ts (server/test/test-db.test.ts checks both).
// Only TENIX_TEST_DATABASE_URL is read, never TENIX_DATABASE_URL, and there is no default.
// Allowed: loopback host, port 5433, database exactly "tenix_test". Messages never echo the URL (it holds a password).
export function assertTestDatabaseUrl(raw: string | undefined): string {
  if (!raw) throw new Error("TENIX_TEST_DATABASE_URL is not set. Tests refuse to run without it (no default). Example: postgres://user:***@127.0.0.1:5433/tenix_test");
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error("TENIX_TEST_DATABASE_URL is not a valid URL"); }
  const bad = (why: string) => new Error(`TENIX_TEST_DATABASE_URL refused: ${why}. Tests may only use 127.0.0.1 or localhost, port 5433, database tenix_test`);
  if (u.protocol !== "postgres:" && u.protocol !== "postgresql:") throw bad("scheme must be postgres://");
  if (u.hostname !== "127.0.0.1" && u.hostname !== "localhost") throw bad("host is not loopback");
  if (u.port !== "5433") throw bad("port is not 5433"); // an empty port means 5432, so it is refused too
  if (decodeURIComponent(u.pathname.slice(1)) !== "tenix_test") throw bad("database name is not tenix_test");
  if (u.search) throw bad("query parameters are not allowed (pg lets ?host= override the host)");
  return raw;
}

export const testDatabaseUrl = () => assertTestDatabaseUrl(process.env.TENIX_TEST_DATABASE_URL);

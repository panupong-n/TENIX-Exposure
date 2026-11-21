import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const env = process.env;
const fail = (m: string): never => { throw new Error(m); };
export const isProd = env.NODE_ENV === "production";
export const port = Number(env.PORT ?? 8787);
/** Listen address. Loopback by default: the reverse proxy is the only way in. Set TENIX_HOST=0.0.0.0 only when something else protects the port. */
export const host = env.TENIX_HOST ?? "127.0.0.1";
/** Postgres connection string (required in production). Create the database first: createdb tenix_exposure. Outside production the default is port 5433, never 5432. */
export const databaseUrl = env.TENIX_DATABASE_URL ?? (isProd ? fail("TENIX_DATABASE_URL is required in production") : "postgres://localhost:5433/tenix_exposure");
/** Schema inside that database (tests use a throwaway one). */
export const dbSchema = env.TENIX_DB_SCHEMA ?? "public";
export const webDist = env.TENIX_WEB_DIST ?? resolve(import.meta.dirname, "../../web/dist");
/** Public URL used inside invite links. */
export const appUrl = (env.TENIX_APP_URL ?? `http://localhost:${isProd ? port : 5173}`).replace(/\/$/, "");
export const cookieSecure = env.TENIX_COOKIE_SECURE ? env.TENIX_COOKIE_SECURE === "1" : isProd;
/** Only for local development against the mock Falcon server. Never set in production. */
export const allowCustomFalconUrl = env.TENIX_DEV_FALCON_URL_OK === "1";

function loadKey(): Buffer {
  if (env.TENIX_SECRET_KEY) {
    const key = Buffer.from(env.TENIX_SECRET_KEY, "base64");
    if (key.length !== 32) throw new Error("TENIX_SECRET_KEY must be 32 bytes, base64 encoded");
    return key;
  }
  if (isProd) throw new Error("TENIX_SECRET_KEY is required in production (openssl rand -base64 32)");
  // shortcut: dev-only key file under server/.data, production must use the env var
  const file = resolve(import.meta.dirname, "../.data/dev-secret.key");
  if (!existsSync(file)) {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, randomBytes(32).toString("base64"), { mode: 0o600 });
  }
  return Buffer.from(readFileSync(file, "utf8"), "base64");
}
export const secretKey = loadKey();

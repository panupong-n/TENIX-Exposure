import assert from "node:assert/strict";
import { test } from "node:test";
import * as server from "./test-db.ts";
import * as e2e from "../../web/e2e/test-db.ts";

const OK = "postgres://u:p@127.0.0.1:5433/tenix_test";
for (const [name, g] of [["server", server], ["e2e", e2e]] as const) {
  test(`${name} guard refuses every database a test must never touch`, () => {
    assert.equal(g.assertTestDatabaseUrl(OK), OK);
    assert.equal(g.assertTestDatabaseUrl("postgres://u:p@localhost:5433/tenix_test"), "postgres://u:p@localhost:5433/tenix_test");
    for (const bad of [
      "postgres://u:p@127.0.0.1:5432/tenix_test",        // DeepSpace's port
      "postgres://u:p@127.0.0.1/tenix_test",             // no port = 5432
      "postgres://u:p@127.0.0.1:5433/tenix_exposure",    // the real database
      "postgres://u:p@127.0.0.1:5433/tenix_test_x",
      "postgres://u:p@192.168.70.109:5433/tenix_test",   // not loopback
      "postgres://u:p@db.example.com:5433/tenix_test",
      "postgres://u:p@127.0.0.1:5433/tenix_test?host=10.0.0.5",
      "mysql://u:p@127.0.0.1:5433/tenix_test",
      "not a url",
    ]) assert.throws(() => g.assertTestDatabaseUrl(bad), /TENIX_TEST_DATABASE_URL/, bad);
    assert.throws(() => g.assertTestDatabaseUrl(undefined), /not set/);
    assert.throws(() => g.assertTestDatabaseUrl(""), /not set/);
  });
}

test("refusal messages never contain the password", () => {
  assert.throws(() => server.assertTestDatabaseUrl("postgres://u:s3cretPW@127.0.0.1:5432/tenix_test"), (e: Error) => !e.message.includes("s3cretPW"));
});

test("testDatabaseUrl reads only TENIX_TEST_DATABASE_URL, never TENIX_DATABASE_URL", () => {
  const keep = { t: process.env.TENIX_TEST_DATABASE_URL, d: process.env.TENIX_DATABASE_URL };
  try {
    delete process.env.TENIX_TEST_DATABASE_URL;
    process.env.TENIX_DATABASE_URL = OK; // a perfectly valid value in the wrong variable must not be used
    assert.throws(() => server.testDatabaseUrl(), /not set/);
    assert.throws(() => e2e.testDatabaseUrl(), /not set/);
    process.env.TENIX_TEST_DATABASE_URL = OK;
    assert.equal(server.testDatabaseUrl(), OK);
  } finally {
    for (const [k, v] of [["TENIX_TEST_DATABASE_URL", keep.t], ["TENIX_DATABASE_URL", keep.d]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

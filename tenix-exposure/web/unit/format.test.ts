// Run with: npm run test:unit (node's built-in test runner, no extra dependency)
import assert from "node:assert/strict";
import { test } from "node:test";
import { formatCompact, formatMetric } from "../src/utils/format.ts";

test("formatCompact", () => {
  const cases: [number, string][] = [
    [0, "0"], [999, "999"], [1000, "1K"], [7790, "7.8K"], [34_122, "34.1K"], [99_949, "99.9K"], [111_025, "111K"], [858_001, "858K"],
    [999_499, "999K"], [999_950, "1M"], [999_999, "1M"], [1_000_000, "1M"], [9_999_999, "10M"], [16_693_578, "16.7M"], [301_274, "301K"],
    [1_234_567_890, "1.2B"], [999_999_999, "1B"], [-34_122, "-34.1K"],
  ];
  for (const [v, want] of cases) assert.equal(formatCompact(v), want, String(v));
});

test("formatMetric by context", () => {
  assert.deepEqual(formatMetric(999_999, "en", "tile"), { text: "999,999", compact: false });
  assert.deepEqual(formatMetric(1_000_000, "en", "tile"), { text: "1M", compact: true });
  assert.deepEqual(formatMetric(9_999_999, "en", "cell"), { text: "9,999,999", compact: false });
  assert.deepEqual(formatMetric(16_693_578, "en", "cell"), { text: "16.7M", compact: true });
  assert.deepEqual(formatMetric(9_999, "en", "chip"), { text: "9,999", compact: false });
  assert.deepEqual(formatMetric(34_122, "en", "chip"), { text: "34.1K", compact: true });
  assert.deepEqual(formatMetric(0, "en", "tile"), { text: "0", compact: false });
});

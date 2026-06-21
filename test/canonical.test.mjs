import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson, parseJsonStrict } from "../src/canonical.mjs";
import { normalizeTelemetryValue } from "../src/processor.mjs";

test("canonical JSON sorts keys and forces lowercase ASCII escapes", () => {
  const value = { z: "café-gpt", a: { quote: '"', line: "x\ny" } };
  assert.equal(
    canonicalJson(value).toString("ascii"),
    '{"a":{"line":"x\\ny","quote":"\\\""},"z":"caf\\u00e9-gpt"}',
  );
});

test("canonical JSON rejects floats, unsafe integers, non-ASCII keys, and cycles", () => {
  assert.throws(() => canonicalJson({ value: 1.5 }), /safe range/);
  assert.throws(() => canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 }), /safe range/);
  assert.throws(() => canonicalJson({ "café": 1 }), /ASCII/);
  const cycle = {};
  cycle.self = cycle;
  assert.throws(() => canonicalJson(cycle), /cyclic/);
});

test("strict parser rejects duplicate keys and non-integer numbers", () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}'), /duplicate/);
  assert.throws(() => parseJsonStrict('{"a":1.0}'), /floats/);
});

test("telemetry normalization tags exact large integers and binary64 floats", () => {
  assert.deepEqual(normalizeTelemetryValue(1_780_000_000_123_456_789n), {
    $int: "1780000000123456789",
  });
  assert.deepEqual(normalizeTelemetryValue(1.5), { $f64: "3ff8000000000000" });
  assert.deepEqual(normalizeTelemetryValue(Number.MAX_SAFE_INTEGER + 1), {
    $f64: "4340000000000000",
  });
});

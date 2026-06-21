import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  privateKeyFromSeed,
  signReceipt,
  verifyReceipt,
  verifyReceiptJson,
} from "../src/crypto.mjs";
import { validateReceiptProfile } from "../src/profile.mjs";
import { verifyChain, verifyCoherenceInputDisclosure } from "../src/derived.mjs";

const key = privateKeyFromSeed("1f".repeat(32));

test("signatures bind the canonical body and reject tampering", () => {
  const receipt = signReceipt({ a: 1, z: "café-gpt" }, key);
  assert.equal(verifyReceipt(receipt), true);
  assert.equal(verifyReceipt({ ...receipt, a: 2 }), false);
});

test("profile validation rejects signed unknown fields and silent trust upgrades", () => {
  const base = {
    kind: "amendment_receipt",
    receipt_version: "0.1",
    algorithm_id: "test",
    canonicalization_id: "olp-canonical-json-int-v1",
    spec_uri: "urn:test",
    trace_id: "00".repeat(16),
    attestation: "self",
    capture_status: "provisional",
    amendment_sequence: 1,
    previous_receipt_hash: "11".repeat(32),
    late_span_hash: "22".repeat(32),
    reason: "span_arrived_after_provisional_seal",
  };
  const unknown = signReceipt({ ...base, vendor_override: true }, key);
  const upgraded = signReceipt({ ...base, attestation: "independent" }, key);
  assert.equal(verifyReceipt(unknown), true, "envelope integrity remains separately observable");
  assert.equal(verifyReceipt(unknown, { validateProfile: validateReceiptProfile }), false);
  assert.equal(verifyReceipt(upgraded, { validateProfile: validateReceiptProfile }), false);
});

test("JSON verifier rejects duplicate keys before signature verification", () => {
  const receipt = signReceipt({ a: 1 }, key);
  const text = JSON.stringify(receipt).replace('"a":1', '"a":1,"a":1');
  assert.equal(verifyReceiptJson(text), false);
});

test("Node verifies every Python Canon receipt vector", async () => {
  const names = [
    "trace-receipt.json",
    "coherence-input-receipt.json",
    "amendment-receipt.json",
    "capture-loss-amendment.json",
    "openline-otel-conformance.json",
  ];
  for (const name of names) {
    const path = new URL(`../../olp-wire-canon/vectors/valid/${name}`, import.meta.url);
    const receipt = JSON.parse(await readFile(path, "utf8"));
    assert.equal(verifyReceipt(receipt, { validateProfile: validateReceiptProfile }), true, name);
  }
});

test("Node validates Python amendment chains and rejects broken chains", async () => {
  const load = async (group, name) => JSON.parse(await readFile(
    new URL(`../../olp-wire-canon/vectors/${group}/${name}`, import.meta.url),
    "utf8",
  ));
  const chain = [
    await load("valid", "trace-receipt.json"),
    await load("valid", "amendment-receipt.json"),
    await load("valid", "capture-loss-amendment.json"),
  ];
  assert.equal(verifyChain(chain), true);
  chain[2] = await load("invalid", "broken-chain-loss-amendment.json");
  assert.equal(verifyChain(chain), false);
});

test("Node validates Python disclosures and rejects altered disclosures", async () => {
  const receipt = JSON.parse(await readFile(
    new URL("../../olp-wire-canon/vectors/valid/coherence-input-receipt.json", import.meta.url),
    "utf8",
  ));
  const valid = JSON.parse(await readFile(
    new URL("../../olp-wire-canon/vectors/valid/coherence-input-disclosure.json", import.meta.url),
    "utf8",
  ));
  const altered = JSON.parse(await readFile(
    new URL("../../olp-wire-canon/vectors/invalid/altered-coherence-input-disclosure.json", import.meta.url),
    "utf8",
  ));
  assert.equal(verifyCoherenceInputDisclosure(receipt, valid), true);
  assert.equal(verifyCoherenceInputDisclosure(receipt, altered), false);
});

test("Node rejects the Python tampered receipt mutation", async () => {
  const receipt = JSON.parse(await readFile(
    new URL("../../olp-wire-canon/vectors/invalid/tampered-coherence-input-receipt.json", import.meta.url),
    "utf8",
  ));
  assert.equal(verifyReceipt(receipt, { validateProfile: validateReceiptProfile }), false);
});

import assert from "node:assert/strict";
import test from "node:test";
import { privateKeyFromSeed, sha256Canonical, verifyReceipt } from "../src/crypto.mjs";
import { validateReceiptProfile } from "../src/profile.mjs";
import { verifyChain, verifyCoherenceInputDisclosure } from "../src/derived.mjs";
import { OpenLineReceiptProcessor, ReceiptStore } from "../src/processor.mjs";
import { fakeSpan, TRACE_ID, typedEvents } from "../test-support/helpers.mjs";

test("processor emits coherence input, amendment, loss, and bound disclosure", async () => {
  const store = new ReceiptStore();
  const processor = new OpenLineReceiptProcessor(privateKeyFromSeed("42".repeat(32)), {
    graceIntervalMillis: 0,
    queueSize: 1,
    receiptStore: store,
  });

  processor.onEnd(fakeSpan({
    spanId: "0000000000000002",
    parentSpanId: "0000000000000001",
    name: "tool.call",
    events: typedEvents(),
  }));
  await processor.forceFlush();
  assert.equal(store.all().length, 0, "child completion does not seal the trace");

  processor.onEnd(fakeSpan({
    spanId: "0000000000000001",
    name: "agent.run",
    start: [1_780_000_000, 100],
    end: [1_780_000_001, 100],
  }));
  await processor.forceFlush();

  const initial = store.all()[0];
  assert.equal(initial.kind, "coherence_input_receipt");
  assert.equal(initial.trace_id, TRACE_ID);
  assert.equal(initial.observed_span_count, 2);
  assert.equal(verifyReceipt(initial, { validateProfile: validateReceiptProfile }), true);
  const disclosure = store.disclosureFor(initial);
  assert.ok(disclosure);
  assert.equal(sha256Canonical(disclosure.semantic_graph), initial.semantic_graph_hash);
  assert.deepEqual(disclosure.signals.map((signal) => signal.value_micros), initial.signal_points_micros);
  assert.equal(verifyCoherenceInputDisclosure(initial, disclosure), true);

  processor.onEnd(fakeSpan({
    spanId: "0000000000000003",
    parentSpanId: "0000000000000001",
    name: "late.one",
    start: [1_780_000_002, 100],
    end: [1_780_000_002, 200],
  }));
  processor.onEnd(fakeSpan({
    spanId: "0000000000000004",
    parentSpanId: "0000000000000001",
    name: "dropped.two",
    start: [1_780_000_003, 100],
    end: [1_780_000_003, 200],
  }));
  await processor.forceFlush();

  const receipts = store.all();
  assert.deepEqual(receipts.map((receipt) => receipt.kind), [
    "coherence_input_receipt",
    "amendment_receipt",
    "capture_loss_amendment",
  ]);
  assert.equal(receipts[1].previous_receipt_hash, receipts[0].payload_hash);
  assert.equal(receipts[2].previous_receipt_hash, receipts[1].payload_hash);
  assert.equal(receipts[2].new_dropped_span_count, 1);
  assert.equal(receipts[2].cumulative_dropped_span_count, 1);
  for (const receipt of receipts) {
    assert.equal(verifyReceipt(receipt, { validateProfile: validateReceiptProfile }), true);
  }
  assert.equal(verifyChain(receipts), true);
  await processor.shutdown();
});

test("ordinary spans remain structural trace receipts", async () => {
  const store = new ReceiptStore();
  const processor = new OpenLineReceiptProcessor(privateKeyFromSeed("43".repeat(32)), {
    graceIntervalMillis: 0,
    receiptStore: store,
  });
  processor.onEnd(fakeSpan({ spanId: "1000000000000001" }));
  await processor.forceFlush();
  const receipt = store.all()[0];
  assert.equal(receipt.kind, "trace_receipt");
  assert.equal(receipt.semantic_claims, false);
  assert.equal(verifyReceipt(receipt, { validateProfile: validateReceiptProfile }), true);
  await processor.shutdown();
});

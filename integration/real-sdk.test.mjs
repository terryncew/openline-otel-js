import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { ROOT_CONTEXT, trace } from "@opentelemetry/api";
import { BasicTracerProvider } from "@opentelemetry/sdk-trace-base";
import {
  OpenLineReceiptProcessor,
  ReceiptStore,
  validateReceiptProfile,
  verifyCoherenceInputDisclosure,
  verifyReceipt,
} from "../src/index.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("real OpenTelemetry JS spans produce a valid coherence receipt", async () => {
  const store = new ReceiptStore();
  const processor = new OpenLineReceiptProcessor(generateKeyPairSync("ed25519").privateKey, {
    graceIntervalMillis: 0,
    receiptStore: store,
  });

  const provider = new BasicTracerProvider({ spanProcessors: [processor] });
  if (typeof provider.addSpanProcessor === "function") {
    provider.addSpanProcessor(processor);
  }
  const tracer = provider.getTracer("openline-real-sdk", "0.1");
  const root = tracer.startSpan("agent.run");
  const rootContext = trace.setSpan(ROOT_CONTEXT, root);
  const child = tracer.startSpan("tool.call", {}, rootContext);
  child.addEvent("olp.claim", {
    id: "claim_1",
    content_hash: sha256("tool returned the requested record"),
    material: true,
  });
  child.addEvent("olp.evidence", {
    id: "evidence_1",
    content_hash: sha256("HTTP 200 with expected identifier"),
    observed: true,
  });
  child.addEvent("olp.relation", {
    src: "evidence_1",
    dst: "claim_1",
    relation_type: "supports",
  });
  child.addEvent("olp.signal", {
    sequence: 0,
    value_micros: 750_000,
    signal_schema_id: "cole-input-micros-v1",
  });
  child.end();
  root.end();
  await provider.forceFlush();
  await processor.forceFlush();

  const [receipt] = store.all();
  assert.equal(receipt.kind, "coherence_input_receipt");
  assert.equal(receipt.observed_span_count, 2);
  assert.equal(verifyReceipt(receipt, { validateProfile: validateReceiptProfile }), true);
  assert.equal(verifyCoherenceInputDisclosure(receipt, store.disclosureFor(receipt)), true);
  await provider.shutdown();
});

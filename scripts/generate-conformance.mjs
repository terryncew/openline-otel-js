import { mkdir, writeFile } from "node:fs/promises";
import { privateKeyFromSeed } from "../src/crypto.mjs";
import { OpenLineReceiptProcessor, ReceiptStore, snapshotSpan } from "../src/processor.mjs";
import { fakeSpan, typedEvents } from "../test-support/helpers.mjs";

const output = new URL("../artifacts/", import.meta.url);
await mkdir(output, { recursive: true });

async function write(name, value) {
  await writeFile(new URL(name, output), `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

const traceStore = new ReceiptStore();
const traceProcessor = new OpenLineReceiptProcessor(privateKeyFromSeed("43".repeat(32)), {
  graceIntervalMillis: 0,
  receiptStore: traceStore,
});
const traceSpan = fakeSpan({
  spanId: "1000000000000001",
  attributes: { z_last: 7, a_first: "café-gpt" },
});
traceProcessor.onEnd(traceSpan);
await traceProcessor.forceFlush();
await traceProcessor.shutdown();
await write("node-trace-receipt.json", traceStore.all()[0]);
await write("node-trace-span-records.json", [snapshotSpan(traceSpan).record]);

const chainStore = new ReceiptStore();
const chainProcessor = new OpenLineReceiptProcessor(privateKeyFromSeed("42".repeat(32)), {
  graceIntervalMillis: 0,
  queueSize: 1,
  receiptStore: chainStore,
});
chainProcessor.onEnd(fakeSpan({
  spanId: "0000000000000002",
  parentSpanId: "0000000000000001",
  name: "tool.call",
  events: typedEvents(),
}));
await chainProcessor.forceFlush();
chainProcessor.onEnd(fakeSpan({
  spanId: "0000000000000001",
  name: "agent.run",
  start: [1_780_000_000, 100],
  end: [1_780_000_001, 100],
}));
await chainProcessor.forceFlush();
const coherence = chainStore.all()[0];
await write("node-coherence-input-receipt.json", coherence);
await write("node-coherence-input-disclosure.json", chainStore.disclosureFor(coherence));

chainProcessor.onEnd(fakeSpan({
  spanId: "0000000000000003",
  parentSpanId: "0000000000000001",
  name: "late.one",
  start: [1_780_000_002, 100],
  end: [1_780_000_002, 200],
}));
chainProcessor.onEnd(fakeSpan({
  spanId: "0000000000000004",
  parentSpanId: "0000000000000001",
  name: "dropped.two",
  start: [1_780_000_003, 100],
  end: [1_780_000_003, 200],
}));
await chainProcessor.forceFlush();
await chainProcessor.shutdown();
const [, amendment, loss] = chainStore.all();
await write("node-amendment-receipt.json", amendment);
await write("node-capture-loss-amendment.json", loss);

console.log("generated 4 Node receipt kinds and 1 bound disclosure");

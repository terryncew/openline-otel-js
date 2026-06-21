# openline-otel-js

Portable signed OpenLine receipts from OpenTelemetry JavaScript spans.

`openline-otel-js` is the reciprocal implementation of the
[OLP Wire Canon 0.1](https://github.com/terryncew/olp-wire-canon). It implements
an OpenTelemetry-compatible span processor without replacing an application's
existing processors or exporters.

Ordinary spans produce a provisional `trace_receipt`. Explicit, valid
`olp.*` events produce a `coherence_input_receipt` and a hash-bound disclosure
that a COLE implementation can recompute. Late spans extend the record through
signed amendments. Queue overflow is attached to the affected trace as a
signed capture-loss amendment.

## Install

Until the package is published to npm, install it from GitHub with the OTel
packages used by your application:

```bash
npm install github:terryncew/openline-otel-js \
  @opentelemetry/api @opentelemetry/sdk-trace-base
```

Node.js 20 or newer is required.

## Attach the processor

```js
import { generateKeyPairSync } from "node:crypto";
import {
  OpenLineReceiptProcessor,
  ReceiptStore,
} from "@openline/otel-js";

const { privateKey } = generateKeyPairSync("ed25519");
const receipts = new ReceiptStore();
const openline = new OpenLineReceiptProcessor(privateKey, {
  receiptStore: receipts,
  graceIntervalMillis: 30_000,
});

// Register `openline` as an additional SpanProcessor using the configuration
// API supported by your installed OpenTelemetry JS SDK version.
```

The adapter has no runtime import from the OTel SDK. It implements the
`SpanProcessor` interface structurally, so the same processor can sit beside a
vendor exporter or another span processor.

After a trace seals:

```js
for (const receipt of receipts.all()) {
  console.log(receipt.kind, receipt.payload_hash);
}

const initial = receipts.all()[0];
const disclosure = receipts.disclosureFor(initial);
```

## Typed OpenLine events

Ordinary span names and attributes remain telemetry. The adapter never invents
claims, evidence, relations, or COLE inputs from them.

Applications may add four explicit event names:

```js
span.addEvent("olp.claim", {
  id: "claim_1",
  content_hash: sha256OfClaimText,
  material: true,
});

span.addEvent("olp.evidence", {
  id: "evidence_1",
  content_hash: sha256OfObservedRecord,
  observed: true,
});

span.addEvent("olp.relation", {
  src: "evidence_1",
  dst: "claim_1",
  relation_type: "supports",
});

span.addEvent("olp.signal", {
  sequence: 0,
  value_micros: 750000,
  signal_schema_id: "cole-input-micros-v1",
});
```

Typed events are strict. Invalid fields, duplicate IDs, missing relation
targets, semantically invalid relation directions, mixed schemas, sequence
gaps, malformed hashes, and floating-point signals keep the output at
`trace_receipt` with a signed validation error.

## Integer and byte rules

Receipt bodies contain only Canon-safe integers. OTel nanosecond timestamps are
assembled with `BigInt` from the SDK's `[seconds, nanoseconds]` tuple and
committed as `{"$int":"<decimal>"}`. Finite non-integer JavaScript numbers and
unsafe integer-valued `Number`s are preserved by exact binary64 bits as
`{"$f64":"<16 lowercase hex>"}`.

Canonical JSON sorts ASCII object keys, forces lowercase `\u` escapes for
non-ASCII values, rejects floats in signed bodies, and rejects duplicate keys
when verifying JSON text.

## Reciprocal conformance

```bash
npm test
npm run test:real-sdk
npm run generate
OLP_CANON_PATH=../olp-wire-canon npm run verify:python
```

The gate proves both directions:

- Node independently verifies the released Python Canon vectors.
- Python verifies all four Node-produced receipt kinds.
- Python recomputes Node's trace Merkle root from disclosed raw spans.
- Python validates the Node amendment chain and COLE disclosure commitment.

The friction vectors include shuffled insertion order, `café-gpt` to exercise
ASCII escaping, real epoch-nanosecond timestamps above JavaScript's safe
integer range, and an explicit one-past-safe-integer canonicalization failure.

## Trust boundary

Every 0.1 receipt remains:

```text
attestation: self
capture_status: provisional
```

The signature proves key possession and post-signing integrity. It does not
prove complete capture, truthful source events, signer independence, or COLE
measurement. Stronger attestation requires separately controlled capture,
keys, and routing.

## Scope status

The Canon and reciprocal byte-level gates pass. A live integration test is
included for the current OpenTelemetry JS packages, but the build environment
used for this draft could not access the npm registry. The repository's first
GitHub Actions run must pass before calling this adapter SDK-verified.

## License

MIT License. Copyright 2026 Terrynce White.

import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical.mjs";
import { sha256Canonical, signReceipt } from "./crypto.mjs";

export const ALGORITHM_ID = "olp-otel-js-receipt-0.1";
export const CANONICALIZATION_ID = "olp-canonical-json-int-v1";
export const SPEC_URI = "https://github.com/terryncew/olp-wire-canon";
const OLP_EVENTS = new Set(["olp.claim", "olp.evidence", "olp.relation", "olp.signal"]);
const SAFE_ID = /^[A-Za-z0-9._:-]+$/;
const HASH = /^[0-9a-f]{64}$/;

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function f64Hex(value) {
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeDoubleBE(value);
  return buffer.toString("hex");
}

export function normalizeTelemetryValue(value, path = "$") {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return { $int: value.toString(10) };
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite telemetry number`);
    if (Number.isInteger(value)) {
      return Number.isSafeInteger(value) ? value : { $f64: f64Hex(value) };
    }
    return { $f64: f64Hex(value) };
  }
  if (Array.isArray(value)) return value.map((item, index) => normalizeTelemetryValue(item, `${path}[${index}]`));
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => compareAscii(left, right))
        .map(([key, item]) => [key, normalizeTelemetryValue(item, `${path}.${key}`)]),
    );
  }
  throw new TypeError(`${path}: unsupported telemetry value`);
}

function attributes(value) {
  return Object.fromEntries(
    Object.entries(value ?? {})
      .sort(([left], [right]) => compareAscii(left, right))
      .map(([key, item]) => [key, normalizeTelemetryValue(item, `attributes.${key}`)]),
  );
}

export function hrTimeToNanos(time) {
  if (!Array.isArray(time) || time.length !== 2) throw new TypeError("OTel HrTime must be [seconds, nanoseconds]");
  const [seconds, nanos] = time;
  if (!Number.isSafeInteger(seconds) || !Number.isSafeInteger(nanos) || seconds < 0 || nanos < 0 || nanos >= 1_000_000_000) {
    throw new TypeError("invalid OTel HrTime");
  }
  return BigInt(seconds) * 1_000_000_000n + BigInt(nanos);
}

function spanContext(span) {
  const context = typeof span.spanContext === "function" ? span.spanContext() : span.spanContext;
  if (!context || !/^[0-9a-f]{32}$/.test(context.traceId) || !/^[0-9a-f]{16}$/.test(context.spanId)) {
    throw new TypeError("ended span has invalid trace or span context");
  }
  return context;
}

function parentSpanId(span) {
  const parent = span.parentSpanContext ?? span.parentSpanId ?? null;
  const value = typeof parent === "string" ? parent : parent?.spanId;
  if (value == null || value === "") return null;
  if (!/^[0-9a-f]{16}$/.test(value)) throw new TypeError("invalid parent span id");
  return value;
}

export function snapshotSpan(span) {
  const context = spanContext(span);
  const startNanos = hrTimeToNanos(span.startTime);
  const endNanos = hrTimeToNanos(span.endTime);
  const scope = span.instrumentationScope ?? span.instrumentationLibrary ?? {};
  return {
    traceId: context.traceId,
    spanId: context.spanId,
    parentSpanId: parentSpanId(span),
    startNanos,
    record: {
      trace_id: context.traceId,
      span_id: context.spanId,
      parent_span_id: parentSpanId(span),
      name: span.name,
      kind: Number(span.kind ?? 0),
      start_time_unix_nano: normalizeTelemetryValue(startNanos),
      end_time_unix_nano: normalizeTelemetryValue(endNanos),
      status: {
        code: Number(span.status?.code ?? 0),
        description: span.status?.message ?? span.status?.description ?? null,
      },
      attributes: attributes(span.attributes),
      events: (span.events ?? []).map((event) => ({
        name: event.name,
        timestamp_unix_nano: normalizeTelemetryValue(hrTimeToNanos(event.time ?? event.timestamp)),
        attributes: attributes(event.attributes),
      })),
      links: (span.links ?? []).map((link) => ({
        trace_id: link.context.traceId,
        span_id: link.context.spanId,
        attributes: attributes(link.attributes),
      })),
      resource: attributes(span.resource?.attributes),
      instrumentation_scope: {
        name: scope.name ?? "",
        version: scope.version ?? null,
        schema_url: scope.schemaUrl ?? scope.schema_url ?? null,
        attributes: attributes(scope.attributes),
      },
    },
  };
}

export function merkleRoot(records) {
  if (!records.length) return createHash("sha256").update(Buffer.alloc(0)).digest("hex");
  let level = records.map((record) => createHash("sha256")
    .update(Buffer.concat([Buffer.from([0]), canonicalJson(record)]))
    .digest());
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      if (index + 1 === level.length) next.push(level[index]);
      else next.push(createHash("sha256")
        .update(Buffer.concat([Buffer.from([1]), level[index], level[index + 1]]))
        .digest());
    }
    level = next;
  }
  return level[0].toString("hex");
}

function exact(attributesValue, required) {
  const actual = Object.keys(attributesValue).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`typed event fields mismatch: expected ${expected.join(",")}`);
  }
}

function validateTypedEvents(events) {
  const claims = new Map();
  const evidence = new Map();
  const relations = [];
  const signals = new Map();
  const schemas = new Set();

  for (const event of events) {
    const value = event.attributes;
    if (event.name === "olp.claim") {
      exact(value, ["id", "content_hash", "material"]);
      if (!SAFE_ID.test(value.id) || !HASH.test(value.content_hash) || typeof value.material !== "boolean") throw new TypeError("invalid claim event");
      if (claims.has(value.id)) throw new TypeError("duplicate claim id");
      claims.set(value.id, value);
    } else if (event.name === "olp.evidence") {
      exact(value, ["id", "content_hash", "observed"]);
      if (!SAFE_ID.test(value.id) || !HASH.test(value.content_hash) || value.observed !== true) throw new TypeError("invalid evidence event");
      if (evidence.has(value.id)) throw new TypeError("duplicate evidence id");
      evidence.set(value.id, value);
    } else if (event.name === "olp.relation") {
      exact(value, ["src", "dst", "relation_type"]);
      if (!["supports", "contradicts", "depends_on"].includes(value.relation_type)) throw new TypeError("invalid relation type");
      relations.push(value);
    } else if (event.name === "olp.signal") {
      exact(value, ["sequence", "signal_schema_id", "value_micros"]);
      if (!Number.isSafeInteger(value.sequence) || value.sequence < 0 || !Number.isSafeInteger(value.value_micros)) throw new TypeError("invalid signal event");
      if (typeof value.signal_schema_id !== "string" || !value.signal_schema_id) throw new TypeError("signal schema is required");
      if (signals.has(value.sequence)) throw new TypeError("duplicate signal sequence");
      signals.set(value.sequence, value);
      schemas.add(value.signal_schema_id);
    }
  }
  if ([...claims.keys()].some((id) => evidence.has(id))) throw new TypeError("node ids must be globally unique");
  if (schemas.size > 1) throw new TypeError("signal schema must be uniform");
  const nodeType = new Map([
    ...[...claims.keys()].map((id) => [id, "Claim"]),
    ...[...evidence.keys()].map((id) => [id, "Evidence"]),
  ]);
  for (const relation of relations) {
    const src = nodeType.get(relation.src);
    const dst = nodeType.get(relation.dst);
    if (!src || !dst) throw new TypeError("relation references missing node");
    if (relation.relation_type === "supports" && !(src === "Evidence" && dst === "Claim")) throw new TypeError("supports must point Evidence to Claim");
    if (relation.relation_type === "contradicts" && !(src === "Claim" && dst === "Claim")) throw new TypeError("contradicts must point Claim to Claim");
    if (relation.relation_type === "depends_on" && dst !== "Claim") throw new TypeError("depends_on must target Claim");
  }
  const orderedSignals = [...signals.keys()].sort((left, right) => left - right);
  if (orderedSignals.some((sequence, index) => sequence !== index)) throw new TypeError("signal sequence must be zero-based without gaps");
  return {
    graph: {
      claims: [...claims.keys()].sort().map((id) => claims.get(id)),
      evidence: [...evidence.keys()].sort().map((id) => evidence.get(id)),
      relations: relations.sort((left, right) => compareAscii(
        `${left.src}\0${left.dst}\0${left.relation_type}`,
        `${right.src}\0${right.dst}\0${right.relation_type}`,
      )),
    },
    signals: orderedSignals.map((sequence) => signals.get(sequence)),
  };
}

export class ReceiptStore {
  #receipts = [];
  #disclosures = new Map();

  emit(receipt, disclosure = null) {
    this.#receipts.push(receipt);
    if (disclosure) this.#disclosures.set(receipt.payload_hash, disclosure);
  }

  all() { return [...this.#receipts]; }
  disclosureFor(receiptOrHash) {
    const hash = typeof receiptOrHash === "string" ? receiptOrHash : receiptOrHash.payload_hash;
    return this.#disclosures.get(hash) ?? null;
  }
}

function newState() {
  return {
    spans: new Map(),
    rootClosedAt: null,
    droppedSpanCount: 0,
    receipt: null,
    amendmentCount: 0,
    lastAmendmentHash: null,
    pendingReportedLoss: 0,
    timer: null,
  };
}

export class OpenLineReceiptProcessor {
  #key;
  #graceMillis;
  #queueSize;
  #store;
  #semconvSchemaId;
  #states = new Map();
  #queue = [];
  #pendingLoss = new Map();
  #drainScheduled = false;
  #shutdown = false;

  constructor(signingKey, {
    graceIntervalMillis = 30_000,
    queueSize = 2048,
    receiptStore = new ReceiptStore(),
    semconvSchemaId = "otel-genai-development-2026-06",
  } = {}) {
    if (!Number.isSafeInteger(graceIntervalMillis) || graceIntervalMillis < 0) throw new TypeError("grace interval must be a non-negative integer");
    if (!Number.isSafeInteger(queueSize) || queueSize < 1) throw new TypeError("queue size must be positive");
    this.#key = signingKey;
    this.#graceMillis = graceIntervalMillis;
    this.#queueSize = queueSize;
    this.#store = receiptStore;
    this.#semconvSchemaId = semconvSchemaId;
  }

  get receiptStore() { return this.#store; }
  onStart(_span, _parentContext) {}
  onEnding(_span) {}

  onEnd(span) {
    if (this.#shutdown) return;
    const snapshot = snapshotSpan(span);
    if (this.#queue.length >= this.#queueSize) {
      this.#pendingLoss.set(snapshot.traceId, (this.#pendingLoss.get(snapshot.traceId) ?? 0) + 1);
      return;
    }
    this.#queue.push(snapshot);
    if (!this.#drainScheduled) {
      this.#drainScheduled = true;
      queueMicrotask(() => this.#drain());
    }
  }

  #state(traceId) {
    if (!this.#states.has(traceId)) this.#states.set(traceId, newState());
    return this.#states.get(traceId);
  }

  #consume(snapshot) {
    const state = this.#state(snapshot.traceId);
    if (state.spans.has(snapshot.spanId)) {
      if (JSON.stringify(state.spans.get(snapshot.spanId).record) !== JSON.stringify(snapshot.record)) state.droppedSpanCount += 1;
      return;
    }
    if (state.receipt) {
      this.#emitAmendment(state, snapshot);
      return;
    }
    state.spans.set(snapshot.spanId, snapshot);
    if (snapshot.parentSpanId === null) {
      state.rootClosedAt = Date.now();
      state.timer = setTimeout(() => this.#finalize(snapshot.traceId, state, "grace_elapsed"), this.#graceMillis);
      state.timer.unref?.();
    }
  }

  #applyLosses() {
    const losses = this.#pendingLoss;
    this.#pendingLoss = new Map();
    for (const [traceId, count] of losses) {
      const state = this.#state(traceId);
      state.droppedSpanCount += count;
      if (state.receipt) {
        state.pendingReportedLoss += count;
        this.#emitLoss(state, traceId);
      }
    }
  }

  #drain() {
    this.#drainScheduled = false;
    while (this.#queue.length) this.#consume(this.#queue.shift());
    this.#applyLosses();
    const now = Date.now();
    for (const [traceId, state] of this.#states) {
      if (!state.receipt && state.rootClosedAt !== null && now - state.rootClosedAt >= this.#graceMillis) {
        this.#finalize(traceId, state, "grace_elapsed");
      }
    }
  }

  #base(traceId, state, spans) {
    return {
      kind: "trace_receipt",
      receipt_version: "0.1",
      algorithm_id: ALGORITHM_ID,
      canonicalization_id: CANONICALIZATION_ID,
      spec_uri: SPEC_URI,
      trace_id: traceId,
      attestation: "self",
      capture_status: "provisional",
      capture_loss: state.droppedSpanCount > 0,
      dropped_span_count: state.droppedSpanCount,
      observed_span_count: spans.length,
      trace_root: merkleRoot(spans.map((span) => span.record)),
      tree_algorithm: "rfc6962-mth-sha256-promote-odd-v1",
      completion_policy: {
        type: "root_close_plus_grace",
        grace_millis: this.#graceMillis,
        semconv_schema_id: this.#semconvSchemaId,
      },
    };
  }

  #finalize(traceId, state, reason) {
    if (state.receipt || !state.spans.size) return;
    if (state.timer) clearTimeout(state.timer);
    const spans = [...state.spans.values()].sort((left, right) =>
      left.startNanos < right.startNanos ? -1 : left.startNanos > right.startNanos ? 1 : compareAscii(left.spanId, right.spanId));
    const body = { ...this.#base(traceId, state, spans), seal_reason: reason };
    const typedEvents = spans.flatMap((span) => span.record.events).filter((event) => OLP_EVENTS.has(event.name));
    let disclosure = null;
    if (!typedEvents.length) {
      body.semantic_claims = false;
    } else {
      try {
        const typed = validateTypedEvents(typedEvents);
        body.kind = "coherence_input_receipt";
        body.semantic_claims = true;
        body.typed_event_status = "valid";
        body.semantic_graph_hash = sha256Canonical(typed.graph);
        body.signal_schema_id = typed.signals.length ? typed.signals[0].signal_schema_id : null;
        body.signal_points_micros = typed.signals.map((signal) => signal.value_micros);
        body.state_cap = "white";
        disclosure = {
          kind: "coherence_input_disclosure",
          disclosure_version: "0.1",
          trace_id: traceId,
          semantic_graph: typed.graph,
          signal_schema_id: body.signal_schema_id,
          signals: typed.signals.map(({ sequence, value_micros }) => ({ sequence, value_micros })),
        };
      } catch (error) {
        body.typed_event_status = "invalid";
        body.typed_event_error = error.message;
      }
    }
    state.receipt = signReceipt(body, this.#key);
    this.#store.emit(state.receipt, disclosure);
  }

  #emitAmendment(state, snapshot) {
    state.amendmentCount += 1;
    const body = {
      kind: "amendment_receipt",
      receipt_version: "0.1",
      algorithm_id: ALGORITHM_ID,
      canonicalization_id: CANONICALIZATION_ID,
      spec_uri: SPEC_URI,
      trace_id: snapshot.traceId,
      attestation: "self",
      capture_status: "provisional",
      amendment_sequence: state.amendmentCount,
      previous_receipt_hash: state.lastAmendmentHash ?? state.receipt.payload_hash,
      late_span_hash: sha256Canonical(snapshot.record),
      reason: "span_arrived_after_provisional_seal",
    };
    const receipt = signReceipt(body, this.#key);
    state.lastAmendmentHash = receipt.payload_hash;
    this.#store.emit(receipt);
  }

  #emitLoss(state, traceId) {
    if (!state.receipt || !state.pendingReportedLoss) return;
    state.amendmentCount += 1;
    const body = {
      kind: "capture_loss_amendment",
      receipt_version: "0.1",
      algorithm_id: ALGORITHM_ID,
      canonicalization_id: CANONICALIZATION_ID,
      spec_uri: SPEC_URI,
      trace_id: traceId,
      attestation: "self",
      capture_status: "provisional",
      amendment_sequence: state.amendmentCount,
      previous_receipt_hash: state.lastAmendmentHash ?? state.receipt.payload_hash,
      new_dropped_span_count: state.pendingReportedLoss,
      cumulative_dropped_span_count: state.droppedSpanCount,
      reason: "processor_queue_overflow_after_provisional_seal",
    };
    const receipt = signReceipt(body, this.#key);
    state.pendingReportedLoss = 0;
    state.lastAmendmentHash = receipt.payload_hash;
    this.#store.emit(receipt);
  }

  async forceFlush() {
    this.#drain();
  }

  async shutdown() {
    if (this.#shutdown) return;
    this.#shutdown = true;
    this.#drain();
    for (const [traceId, state] of this.#states) {
      if (!state.receipt && state.spans.size) this.#finalize(traceId, state, "shutdown_before_grace_elapsed");
      if (state.timer) clearTimeout(state.timer);
    }
  }
}

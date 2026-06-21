import { validateCanonicalValue } from "./canonical.mjs";

const HASH = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;
const TRACE_ID = /^[0-9a-f]{32}$/;
const COMMON = new Set([
  "kind", "receipt_version", "algorithm_id", "canonicalization_id", "spec_uri",
  "attestation", "capture_status", "payload_hash", "signature",
]);
const TRACE = new Set([
  "trace_id", "capture_loss", "dropped_span_count", "observed_span_count",
  "trace_root", "tree_algorithm", "completion_policy", "seal_reason",
]);
const TRACE_OPTIONAL = new Set(["semantic_claims", "typed_event_status", "typed_event_error"]);
const COHERENCE = new Set([
  ...TRACE, "semantic_claims", "typed_event_status", "semantic_graph_hash",
  "signal_schema_id", "signal_points_micros", "state_cap",
]);
const AMENDMENT = new Set([
  "trace_id", "amendment_sequence", "previous_receipt_hash", "late_span_hash", "reason",
]);
const LOSS = new Set([
  "trace_id", "amendment_sequence", "previous_receipt_hash", "new_dropped_span_count",
  "cumulative_dropped_span_count", "reason",
]);

function exact(value, required, allowed = required) {
  const keys = new Set(Object.keys(value));
  const missing = [...required].filter((key) => !keys.has(key));
  const unknown = [...keys].filter((key) => !allowed.has(key));
  if (missing.length || unknown.length) {
    throw new TypeError(`field mismatch: missing=${missing.sort()} unknown=${unknown.sort()}`);
  }
}

function union(...sets) {
  return new Set(sets.flatMap((set) => [...set]));
}

function integer(value, field, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new TypeError(`${field} must be a safe integer >= ${minimum}`);
  }
}

function hash(value, field) {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new TypeError(`${field} must be lowercase SHA-256 hex`);
  }
}

function traceFields(receipt) {
  if (!TRACE_ID.test(receipt.trace_id)) throw new TypeError("trace_id must be lowercase 16-byte hex");
  integer(receipt.dropped_span_count, "dropped_span_count");
  integer(receipt.observed_span_count, "observed_span_count");
  if (typeof receipt.capture_loss !== "boolean" || receipt.capture_loss !== (receipt.dropped_span_count > 0)) {
    throw new TypeError("capture_loss must agree with dropped_span_count");
  }
  hash(receipt.trace_root, "trace_root");
  if (receipt.tree_algorithm !== "rfc6962-mth-sha256-promote-odd-v1") throw new TypeError("unsupported tree algorithm");
  exact(receipt.completion_policy, new Set(["type", "grace_millis", "semconv_schema_id"]));
  if (receipt.completion_policy.type !== "root_close_plus_grace") throw new TypeError("unsupported completion policy");
  integer(receipt.completion_policy.grace_millis, "grace_millis");
  if (typeof receipt.completion_policy.semconv_schema_id !== "string" || !receipt.completion_policy.semconv_schema_id) {
    throw new TypeError("semconv_schema_id is required");
  }
  if (!["grace_elapsed", "shutdown_before_grace_elapsed"].includes(receipt.seal_reason)) {
    throw new TypeError("unsupported seal reason");
  }
}

export function validateReceiptProfile(receipt) {
  validateCanonicalValue(receipt);
  if (receipt.receipt_version !== "0.1") throw new TypeError("unsupported receipt version");
  if (receipt.canonicalization_id !== "olp-canonical-json-int-v1") throw new TypeError("unsupported canonicalization");
  if (receipt.attestation !== "self" || receipt.capture_status !== "provisional") throw new TypeError("unsupported trust labels");
  if (typeof receipt.algorithm_id !== "string" || !/^[\x20-\x7e]+$/.test(receipt.algorithm_id)) throw new TypeError("algorithm_id must be printable ASCII");
  if (typeof receipt.spec_uri !== "string" || !/^(https:\/\/|urn:)/.test(receipt.spec_uri)) throw new TypeError("spec_uri must be HTTPS or URN");
  hash(receipt.payload_hash, "payload_hash");
  exact(receipt.signature, new Set(["algorithm", "public_key", "value"]));
  if (receipt.signature.algorithm !== "Ed25519" || !HASH.test(receipt.signature.public_key) || !SIGNATURE.test(receipt.signature.value)) {
    throw new TypeError("invalid signature profile");
  }

  if (receipt.kind === "trace_receipt") {
    exact(receipt, union(COMMON, TRACE), union(COMMON, TRACE, TRACE_OPTIONAL));
    if (Object.hasOwn(receipt, "semantic_claims") && receipt.semantic_claims !== false) throw new TypeError("trace receipt cannot assert semantics");
    if (Object.hasOwn(receipt, "typed_event_status") || Object.hasOwn(receipt, "typed_event_error")) {
      if (receipt.typed_event_status !== "invalid" || !receipt.typed_event_error) throw new TypeError("invalid typed events require signed error");
    }
    traceFields(receipt);
  } else if (receipt.kind === "coherence_input_receipt") {
    exact(receipt, union(COMMON, COHERENCE));
    if (receipt.semantic_claims !== true || receipt.typed_event_status !== "valid") throw new TypeError("coherence input requires valid semantics");
    hash(receipt.semantic_graph_hash, "semantic_graph_hash");
    if (!Array.isArray(receipt.signal_points_micros) || !receipt.signal_points_micros.every(Number.isSafeInteger)) throw new TypeError("invalid signal points");
    if (receipt.signal_points_micros.length) {
      if (typeof receipt.signal_schema_id !== "string" || !receipt.signal_schema_id) throw new TypeError("signal schema mismatch");
    } else if (receipt.signal_schema_id !== null) throw new TypeError("signal schema mismatch");
    if (receipt.state_cap !== "white") throw new TypeError("state_cap must remain white");
    traceFields(receipt);
  } else if (receipt.kind === "amendment_receipt") {
    exact(receipt, union(COMMON, AMENDMENT));
    if (!TRACE_ID.test(receipt.trace_id)) throw new TypeError("invalid trace_id");
    integer(receipt.amendment_sequence, "amendment_sequence", 1);
    hash(receipt.previous_receipt_hash, "previous_receipt_hash");
    hash(receipt.late_span_hash, "late_span_hash");
    if (receipt.reason !== "span_arrived_after_provisional_seal") throw new TypeError("invalid amendment reason");
  } else if (receipt.kind === "capture_loss_amendment") {
    exact(receipt, union(COMMON, LOSS));
    if (!TRACE_ID.test(receipt.trace_id)) throw new TypeError("invalid trace_id");
    integer(receipt.amendment_sequence, "amendment_sequence", 1);
    hash(receipt.previous_receipt_hash, "previous_receipt_hash");
    integer(receipt.new_dropped_span_count, "new_dropped_span_count", 1);
    integer(receipt.cumulative_dropped_span_count, "cumulative_dropped_span_count", 1);
    if (receipt.cumulative_dropped_span_count < receipt.new_dropped_span_count) throw new TypeError("invalid cumulative loss");
    if (receipt.reason !== "processor_queue_overflow_after_provisional_seal") throw new TypeError("invalid loss reason");
  } else {
    throw new TypeError("unknown receipt kind");
  }
  return true;
}

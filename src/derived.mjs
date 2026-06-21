import { sha256Canonical, verifyReceipt } from "./crypto.mjs";
import { validateReceiptProfile } from "./profile.mjs";

const SAFE_ID = /^[A-Za-z0-9._:-]+$/;
const HASH = /^[0-9a-f]{64}$/;

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("expected object");
  const actual = Object.keys(value).sort(compareAscii);
  const expected = [...fields].sort(compareAscii);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError("field mismatch");
  }
}

export function verifyChain(receipts) {
  try {
    if (!Array.isArray(receipts) || !receipts.length) return false;
    const initial = receipts[0];
    if (!["trace_receipt", "coherence_input_receipt"].includes(initial.kind)) return false;
    if (!verifyReceipt(initial, { validateProfile: validateReceiptProfile })) return false;
    let previousHash = initial.payload_hash;
    for (let index = 1; index < receipts.length; index += 1) {
      const receipt = receipts[index];
      if (!["amendment_receipt", "capture_loss_amendment"].includes(receipt.kind)) return false;
      if (!verifyReceipt(receipt, { validateProfile: validateReceiptProfile })) return false;
      if (receipt.trace_id !== initial.trace_id) return false;
      if (receipt.amendment_sequence !== index) return false;
      if (receipt.previous_receipt_hash !== previousHash) return false;
      previousHash = receipt.payload_hash;
    }
    return true;
  } catch {
    return false;
  }
}

function validateGraph(graph) {
  exact(graph, ["claims", "evidence", "relations"]);
  if (![graph.claims, graph.evidence, graph.relations].every(Array.isArray)) throw new TypeError("graph groups must be arrays");
  const nodeTypes = new Map();
  const claimIds = [];
  const evidenceIds = [];
  for (const claim of graph.claims) {
    exact(claim, ["id", "content_hash", "material"]);
    if (!SAFE_ID.test(claim.id) || !HASH.test(claim.content_hash) || typeof claim.material !== "boolean" || nodeTypes.has(claim.id)) {
      throw new TypeError("invalid claim");
    }
    nodeTypes.set(claim.id, "Claim");
    claimIds.push(claim.id);
  }
  for (const evidence of graph.evidence) {
    exact(evidence, ["id", "content_hash", "observed"]);
    if (!SAFE_ID.test(evidence.id) || !HASH.test(evidence.content_hash) || evidence.observed !== true || nodeTypes.has(evidence.id)) {
      throw new TypeError("invalid evidence");
    }
    nodeTypes.set(evidence.id, "Evidence");
    evidenceIds.push(evidence.id);
  }
  if (claimIds.some((id, index) => id !== [...claimIds].sort(compareAscii)[index])) throw new TypeError("claims must be sorted");
  if (evidenceIds.some((id, index) => id !== [...evidenceIds].sort(compareAscii)[index])) throw new TypeError("evidence must be sorted");
  const relationKeys = [];
  for (const relation of graph.relations) {
    exact(relation, ["src", "dst", "relation_type"]);
    const src = nodeTypes.get(relation.src);
    const dst = nodeTypes.get(relation.dst);
    if (!src || !dst) throw new TypeError("relation references missing node");
    if (relation.relation_type === "supports" && !(src === "Evidence" && dst === "Claim")) throw new TypeError("invalid supports relation");
    if (relation.relation_type === "contradicts" && !(src === "Claim" && dst === "Claim")) throw new TypeError("invalid contradicts relation");
    if (relation.relation_type === "depends_on" && dst !== "Claim") throw new TypeError("invalid depends_on relation");
    if (!["supports", "contradicts", "depends_on"].includes(relation.relation_type)) throw new TypeError("unsupported relation");
    relationKeys.push(`${relation.src}\0${relation.dst}\0${relation.relation_type}`);
  }
  if (new Set(relationKeys).size !== relationKeys.length) throw new TypeError("duplicate relation");
  if (relationKeys.some((key, index) => key !== [...relationKeys].sort(compareAscii)[index])) throw new TypeError("relations must be sorted");
}

export function verifyCoherenceInputDisclosure(receipt, disclosure) {
  try {
    if (receipt.kind !== "coherence_input_receipt") return false;
    if (!verifyReceipt(receipt, { validateProfile: validateReceiptProfile })) return false;
    exact(disclosure, ["kind", "disclosure_version", "trace_id", "semantic_graph", "signal_schema_id", "signals"]);
    if (disclosure.kind !== "coherence_input_disclosure" || disclosure.disclosure_version !== "0.1") return false;
    if (disclosure.trace_id !== receipt.trace_id) return false;
    validateGraph(disclosure.semantic_graph);
    if (sha256Canonical(disclosure.semantic_graph) !== receipt.semantic_graph_hash) return false;
    if (disclosure.signal_schema_id !== receipt.signal_schema_id || !Array.isArray(disclosure.signals)) return false;
    const values = [];
    for (let index = 0; index < disclosure.signals.length; index += 1) {
      const signal = disclosure.signals[index];
      exact(signal, ["sequence", "value_micros"]);
      if (signal.sequence !== index || !Number.isSafeInteger(signal.value_micros)) return false;
      values.push(signal.value_micros);
    }
    return values.length === receipt.signal_points_micros.length
      && values.every((value, index) => value === receipt.signal_points_micros[index]);
  } catch {
    return false;
  }
}

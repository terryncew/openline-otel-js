import type { Context, Span } from "@opentelemetry/api";
import type { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import type { KeyObject } from "node:crypto";

export type CanonValue = null | boolean | string | number | CanonValue[] | { [key: string]: CanonValue };
export type ReceiptKind =
  | "trace_receipt"
  | "coherence_input_receipt"
  | "amendment_receipt"
  | "capture_loss_amendment";

export interface Signature {
  algorithm: "Ed25519";
  public_key: string;
  value: string;
}

export interface Receipt {
  kind: ReceiptKind;
  receipt_version: "0.1";
  algorithm_id: string;
  canonicalization_id: "olp-canonical-json-int-v1";
  spec_uri: string;
  attestation: "self";
  capture_status: "provisional";
  payload_hash: string;
  signature: Signature;
  [key: string]: CanonValue | Signature;
}

export interface CoherenceInputDisclosure {
  kind: "coherence_input_disclosure";
  disclosure_version: "0.1";
  trace_id: string;
  semantic_graph: CanonValue;
  signal_schema_id: string | null;
  signals: CanonValue[];
}

export interface ProcessorOptions {
  graceIntervalMillis?: number;
  queueSize?: number;
  receiptStore?: ReceiptStore;
  semconvSchemaId?: string;
}

export class ReceiptStore {
  emit(receipt: Receipt, disclosure?: CoherenceInputDisclosure | null): void;
  all(): Receipt[];
  disclosureFor(receiptOrHash: Receipt | string): CoherenceInputDisclosure | null;
}

export class OpenLineReceiptProcessor {
  constructor(signingKey: KeyObject, options?: ProcessorOptions);
  get receiptStore(): ReceiptStore;
  onStart(span: Span, parentContext: Context): void;
  onEnding(span: Span): void;
  onEnd(span: ReadableSpan): void;
  forceFlush(): Promise<void>;
  shutdown(): Promise<void>;
}

export function canonicalJson(value: CanonValue): Buffer;
export function parseJsonStrict(text: string): CanonValue;
export function validateCanonicalValue(value: unknown, path?: string): void;
export function privateKeyFromSeed(seed: Buffer | string): KeyObject;
export function publicKeyFromHex(value: string): KeyObject;
export function publicKeyHex(key: KeyObject): string;
export function sha256Bytes(value: Uint8Array): Buffer;
export function sha256Canonical(value: CanonValue): string;
export function signReceipt(body: Record<string, CanonValue>, privateKey: KeyObject): Receipt;
export function verifyReceipt(receipt: Receipt, options?: { validateProfile?: typeof validateReceiptProfile }): boolean;
export function verifyReceiptJson(text: string, options?: { validateProfile?: typeof validateReceiptProfile }): boolean;
export function validateReceiptProfile(receipt: Receipt): true;
export function verifyChain(receipts: Receipt[]): boolean;
export function verifyCoherenceInputDisclosure(receipt: Receipt, disclosure: CoherenceInputDisclosure): boolean;
export function normalizeTelemetryValue(value: unknown, path?: string): CanonValue;
export function hrTimeToNanos(value: [number, number]): bigint;
export function merkleRoot(records: CanonValue[]): string;
export function snapshotSpan(span: ReadableSpan): { traceId: string; spanId: string; parentSpanId: string | null; startNanos: bigint; record: CanonValue };

export const ALGORITHM_ID: "olp-otel-js-receipt-0.1";
export const CANONICALIZATION_ID: "olp-canonical-json-int-v1";
export const SPEC_URI: "https://github.com/terryncew/olp-wire-canon";

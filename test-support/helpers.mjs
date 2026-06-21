import { createHash } from "node:crypto";

export const TRACE_ID = "0123456789abcdef0123456789abcdef";

export function contentHash(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function fakeSpan({
  spanId,
  parentSpanId = null,
  name = "agent.run",
  start = [1_780_000_000, 123_456_789],
  end = [1_780_000_000, 223_456_789],
  attributes = {},
  events = [],
} = {}) {
  return {
    name,
    kind: 1,
    startTime: start,
    endTime: end,
    status: { code: 1 },
    attributes,
    events: events.map((event, index) => ({
      time: [start[0], start[1] + index + 1],
      attributes: {},
      ...event,
    })),
    links: [],
    resource: { attributes: { "service.name": "café-gpt" } },
    instrumentationScope: {
      name: "openline-test",
      version: "0.1",
      schemaUrl: null,
      attributes: {},
    },
    parentSpanContext: parentSpanId ? { traceId: TRACE_ID, spanId: parentSpanId } : undefined,
    spanContext() { return { traceId: TRACE_ID, spanId }; },
  };
}

export function typedEvents() {
  return [
    {
      name: "olp.claim",
      attributes: {
        material: true,
        content_hash: contentHash("tool returned requested record"),
        id: "claim_1",
      },
    },
    {
      name: "olp.evidence",
      attributes: {
        observed: true,
        id: "evidence_1",
        content_hash: contentHash("HTTP 200 with expected identifier"),
      },
    },
    {
      name: "olp.relation",
      attributes: { relation_type: "supports", dst: "claim_1", src: "evidence_1" },
    },
    {
      name: "olp.signal",
      attributes: { value_micros: 750_000, signal_schema_id: "cole-input-micros-v1", sequence: 0 },
    },
  ];
}

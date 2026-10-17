import test from "node:test";
import assert from "node:assert/strict";
import {
  createWorkflowEventEnvelope,
  validateWorkflowEvent,
  verifyWorkflowEventChain,
  workflowProvenanceInternals
} from "../src/workflow-provenance.js";

function event(overrides = {}) {
  return {
    schema_version: "0.1.0",
    event_id: "evt-1",
    workflow_id: "wf-1",
    transition_id: "transition-1",
    sequence: 1,
    occurred_at: "2026-10-16T20:00:00Z",
    recorded_at: "2026-10-16T20:00:01Z",
    actor: {
      kind: "service",
      subject: "issuer.example/workload/test",
      identity_evidence: { state: "verified", reference_id: "identity-ref-1" }
    },
    action: "workflow.test",
    resource: { type: "test-resource", id: "resource-1" },
    policy: { id: "test-policy", version: "sha256:policy-placeholder" },
    evidence: [{ type: "test-report", reference_id: "evidence-1", digest_algorithm: "sha256", digest: "abc123", state: "verified" }],
    artifacts: [],
    causation_ids: [],
    correlation_id: "trace-1",
    outcome: "succeeded",
    failure: null,
    integrity: null,
    ...overrides
  };
}

function chain(events) {
  let previous = workflowProvenanceInternals.ZERO_DIGEST;
  return events.map((item) => {
    const envelope = createWorkflowEventEnvelope(item, previous);
    previous = envelope.event_digest;
    return envelope;
  });
}

test("accepts a complete event matching the proposed contract", () => {
  assert.deepEqual(validateWorkflowEvent(event()), { valid: true, errors: [] });
});

test("rejects missing identity, policy, outcome, and evidence fields", () => {
  const invalid = event({ actor: null, policy: undefined, outcome: "maybe", evidence: "none" });
  const result = validateWorkflowEvent(invalid);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes("actor")));
  assert.ok(result.errors.some((error) => error.includes("policy")));
  assert.ok(result.errors.some((error) => error.includes("outcome")));
  assert.ok(result.errors.some((error) => error.includes("evidence")));
});

test("verifies an ordered digest chain with causal links", () => {
  const first = event();
  const second = event({
    event_id: "evt-2",
    transition_id: "transition-2",
    sequence: 2,
    causation_ids: ["evt-1"]
  });
  const result = verifyWorkflowEventChain(chain([first, second]));
  assert.equal(result.status, "verified");
  assert.equal(result.valid, true);
  assert.equal(result.record_count, 2);
  assert.deepEqual(result.gaps, []);
});

test("detects payload tampering", () => {
  const envelopes = chain([event()]);
  envelopes[0].event.action = "workflow.tampered";
  const result = verifyWorkflowEventChain(envelopes);
  assert.equal(result.status, "invalid");
  assert.ok(result.errors.some((error) => error.includes("digest mismatch")));
});

test("detects reordered envelopes", () => {
  const first = event();
  const second = event({ event_id: "evt-2", sequence: 2, causation_ids: ["evt-1"] });
  const envelopes = chain([first, second]).reverse();
  const result = verifyWorkflowEventChain(envelopes);
  assert.equal(result.status, "invalid");
  assert.ok(result.errors.some((error) => error.includes("chain link mismatch")));
});

test("detects truncation or missing sequence numbers", () => {
  const first = event();
  const third = event({ event_id: "evt-3", sequence: 3, causation_ids: ["evt-2"] });
  const result = verifyWorkflowEventChain(chain([first, third]));
  assert.equal(result.status, "partially_verified");
  assert.ok(result.gaps.some((gap) => gap.expected_sequence === 2));
  assert.ok(result.gaps.some((gap) => gap.missing_causation_event_id === "evt-2"));
});

test("detects duplicate event IDs as replay or identifier reuse", () => {
  const first = event();
  const duplicate = event({ sequence: 2 });
  const result = verifyWorkflowEventChain(chain([first, duplicate]));
  assert.equal(result.status, "invalid");
  assert.ok(result.errors.some((error) => error.includes("duplicate event_id")));
});

test("preserves reconstructed evidence as a distinct status", () => {
  const result = verifyWorkflowEventChain(chain([
    event({ evidence: [{ type: "legacy-log", reference_id: "legacy-1", state: "reconstructed" }] })
  ]));
  assert.equal(result.status, "reconstructed");
  assert.ok(result.warnings.some((warning) => warning.includes("Reconstructed evidence")));
});

test("unavailable evidence cannot be reported as fully verified", () => {
  const result = verifyWorkflowEventChain(chain([
    event({ evidence: [{ type: "source-record", reference_id: "missing-1", state: "unavailable" }] })
  ]));
  assert.equal(result.status, "partially_verified");
});

test("invalid evidence forces an invalid verification result", () => {
  const result = verifyWorkflowEventChain(chain([
    event({ evidence: [{ type: "source-record", reference_id: "bad-1", state: "invalid" }] })
  ]));
  assert.equal(result.status, "invalid");
});

test("rejects a non-finite value before creating an envelope", () => {
  assert.throws(() => createWorkflowEventEnvelope(event({ resource: { type: "x", id: NaN } })), /Canonical JSON/);
});

test("does not claim full verification when actor identity evidence is unverified", () => {
  const result = verifyWorkflowEventChain(chain([event({ actor: { kind: "service", subject: "issuer.example/workload/test", identity_evidence: { state: "unverified", reference_id: "identity-ref-1" } })]));
  assert.equal(result.status, "unverified");
  assert.ok(result.warnings.some((warning) => warning.includes("identity evidence")));
});

test("does not crash when a malformed envelope has a non-object event", () => {
  const result = verifyWorkflowEventChain([{ event: null, previous_event_digest: "0".repeat(64), event_digest: "bad" }]);
  assert.equal(result.status, "invalid");
  assert.ok(result.errors.some((error) => error.includes("event must be an object")));
});

test("unverified evidence cannot be reported as fully verified", () => {
  const result = verifyWorkflowEventChain(chain([
    event({ evidence: [{ type: "source-record", reference_id: "unknown-1", state: "unverified" }] })
  ]));
  assert.equal(result.status, "unverified");
});

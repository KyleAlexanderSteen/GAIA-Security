import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditLedger } from "../src/audit-ledger.js";
import { createWorkflowProvenanceStore } from "../src/workflow-provenance-store.js";

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "gaia-provenance-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const ledger = createAuditLedger({
    ledgerPath: join(directory, "ledger.jsonl"),
    anchorPath: join(directory, "anchors.jsonl"),
    writerId: "test-writer",
    privateKey,
    publicKey
  });
  return { directory, ledger };
}

function event(overrides = {}) {
  return {
    schema_version: "0.1.0",
    event_id: "evt-1",
    workflow_id: "wf-1",
    transition_id: "transition-1",
    sequence: 1,
    occurred_at: "2026-10-16T20:00:00Z",
    recorded_at: "2026-10-16T20:00:01Z",
    actor: { kind: "service", subject: "test/workload", identity_evidence: { state: "verified", reference_id: "identity-1" } },
    action: "workflow.test",
    resource: { type: "test-resource", id: "resource-1" },
    policy: { id: "test-policy", version: "policy-v1" },
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

test("persists provenance inside the signed audit ledger and verifies after reopening", async (t) => {
  const { ledger } = await fixture(t);
  const store = createWorkflowProvenanceStore({ ledger });
  const result = await store.append(event());
  assert.equal(result.record.eventType, "workflow.provenance");
  assert.equal(result.verification.status, "verified");
  assert.equal((await store.verify()).record_count, 1);
});

test("serializes concurrent appends and enforces per-workflow sequence", async (t) => {
  const { ledger } = await fixture(t);
  const store = createWorkflowProvenanceStore({ ledger });
  const first = event();
  const second = event({ event_id: "evt-2", transition_id: "transition-2", sequence: 2, causation_ids: ["evt-1"] });
  const results = await Promise.all([store.append(first), store.append(second)]);
  assert.deepEqual(results.map((result) => result.envelope.event.sequence), [1, 2]);
  assert.equal((await store.verify()).status, "verified");
});

test("rejects an unexpected sequence without writing it", async (t) => {
  const { ledger } = await fixture(t);
  const store = createWorkflowProvenanceStore({ ledger });
  await assert.rejects(store.append(event({ sequence: 3 })), /Expected sequence 1/);
  assert.equal((await ledger.verify()).recordCount, 0);
});

test("rejects tampered signed ledger records before treating provenance as evidence", async (t) => {
  const { directory, ledger } = await fixture(t);
  const store = createWorkflowProvenanceStore({ ledger });
  await store.append(event());
  const path = join(directory, "ledger.jsonl");
  const { readFile } = await import("node:fs/promises");
  const records = (await readFile(path, "utf8")).trimEnd().split("\n").map(JSON.parse);
  records[0].payload.envelope.event.action = "tampered";
  await writeFile(path, records.map((record) => JSON.stringify(record)).join("\n") + "\n");
  await assert.rejects(store.verify(), /Ledger integrity failure/);
});

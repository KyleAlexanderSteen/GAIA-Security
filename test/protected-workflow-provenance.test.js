import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditLedger } from "../src/audit-ledger.js";
import { createProtectedWorkflow } from "../src/protected-workflow.js";
import { createWorkflowProvenanceStore } from "../src/workflow-provenance-store.js";

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "gaia-protected-provenance-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const ledger = createAuditLedger({
    ledgerPath: join(directory, "ledger.jsonl"),
    anchorPath: join(directory, "anchors.jsonl"),
    writerId: "protected-workflow-test",
    privateKey,
    publicKey
  });
  const heads = new Map();
  const actions = new Map();
  const key = (namespace, actionId) => `${namespace}\\0${actionId}`;
  const checkpoint = {
    async readHead(namespace) {
      return heads.get(namespace) ?? { version: 0, hash: "0".repeat(64) };
    },
    async readAction(namespace, actionId) {
      return actions.get(key(namespace, actionId)) ?? null;
    },
    async compareAndSet({ namespace, expectedVersion, entry }) {
      const current = heads.get(namespace) ?? { version: 0, hash: "0".repeat(64) };
      if (current.version !== expectedVersion) return { acknowledged: false };
      const head = { version: current.version + 1, hash: entry.entryHash };
      actions.set(key(namespace, entry.actionId), { ...entry, head });
      heads.set(namespace, head);
      return { acknowledged: true, head };
    }
  };
  return { ledger, checkpoint, provenanceStore: createWorkflowProvenanceStore({ ledger }) };
}

test("protected workflow persists provenance before execution and for the outcome", async (t) => {
  const { ledger, checkpoint, provenanceStore } = await fixture(t);
  let sawIntentProvenance = false;
  const workflow = createProtectedWorkflow({
    ledger, checkpoint, provenanceStore,
    async executeAction() {
      const events = (await ledger.listRecords())
        .filter((record) => record.eventType === "workflow.provenance")
        .map((record) => record.payload.envelope.event);
      sawIntentProvenance = events.some((event) => event.action === "protected-action.intent-recorded");
      assert.equal(sawIntentProvenance, true, "intent provenance must exist before execution");
      return { committed: true };
    }
  });

  const result = await workflow.run({
    namespace: "tenant-provenance/workflow-a",
    actionId: "action-provenance-001",
    actionType: "test.write",
    payload: { safe: true }
  });
  assert.equal(result.status, "completed");

  const records = await ledger.listRecords();
  const events = records
    .filter((record) => record.eventType === "workflow.provenance")
    .map((record) => record.payload.envelope.event);
  assert.equal(events.length, 2);
  assert.deepEqual(events.map((event) => event.sequence), [1, 2]);
  assert.deepEqual(events.map((event) => event.outcome), ["succeeded", "succeeded"]);
  assert.deepEqual(events[1].causation_ids, [events[0].event_id]);
  const verification = await provenanceStore.verify();
  assert.equal(verification.valid, true);
  // The chain remains explicitly unverified because runtime identity is not attested.
  assert.equal(verification.status, "unverified");
});

test("action failure is recorded as a failed provenance outcome", async (t) => {
  const { ledger, checkpoint, provenanceStore } = await fixture(t);
  const workflow = createProtectedWorkflow({
    ledger, checkpoint, provenanceStore,
    async executeAction() { throw new Error("expected test failure"); }
  });
  await assert.rejects(workflow.run({
    namespace: "tenant-provenance/workflow-b",
    actionId: "action-provenance-002",
    actionType: "test.write",
    payload: {}
  }), /expected test failure/);

  const events = (await ledger.listRecords())
    .filter((record) => record.eventType === "workflow.provenance")
    .map((record) => record.payload.envelope.event);
  assert.equal(events.length, 2);
  assert.equal(events[1].outcome, "failed");
  assert.equal(events[1].failure.code, "PROTECTED_ACTION_FAILED");
  assert.equal((await realStore.verify()).valid, true);
});


test("fails closed when intent provenance persistence fails", async (t) => {
  const { ledger, checkpoint, provenanceStore: realStore } = await fixture(t);
  const provenanceStore = {
    async append(event) {
      if (event.action === "protected-action.intent-recorded") throw new Error("provenance store unavailable");
      return realStore.append(event);
    }
  };
  let executed = false;
  const workflow = createProtectedWorkflow({
    ledger, checkpoint, provenanceStore,
    async executeAction() { executed = true; return "must-not-run"; }
  });
  await assert.rejects(workflow.run({
    namespace: "tenant-provenance/fail-intent",
    actionId: "action-provenance-fail-intent",
    actionType: "test.write",
    payload: {}
  }), /provenance could not be persisted/);
  assert.equal(executed, false);
  assert.equal(workflow.isBlocked("tenant-provenance/fail-intent"), true);
});

test("blocks namespace when outcome provenance persistence fails after execution", async (t) => {
  const { ledger, checkpoint, provenanceStore: realStore } = await fixture(t);
  let appendCount = 0;
  const provenanceStore = {
    async append(event) {
      appendCount += 1;
      if (appendCount === 2) throw new Error("outcome provenance unavailable");
      return realStore.append(event);
    }
  };
  let executions = 0;
  const workflow = createProtectedWorkflow({
    ledger, checkpoint, provenanceStore,
    async executeAction() { executions += 1; return { mayHaveCompleted: true }; }
  });
  await assert.rejects(workflow.run({
    namespace: "tenant-provenance/fail-outcome",
    actionId: "action-provenance-fail-outcome",
    actionType: "test.write",
    payload: {}
  }), /provenance could not be persisted/);
  assert.equal(executions, 1);
  assert.equal(workflow.isBlocked("tenant-provenance/fail-outcome"), true);

  // Recovery must close the missing provenance event without re-running the action.
  const recovered = await workflow.recover({
    namespace: "tenant-provenance/fail-outcome",
    actionId: "action-provenance-fail-outcome"
  });
  assert.equal(recovered.status, "recovered");
  assert.equal(executions, 1);
  assert.equal(workflow.isBlocked("tenant-provenance/fail-outcome"), false);
  const events = (await ledger.listRecords())
    .filter((record) => record.eventType === "workflow.provenance")
    .map((record) => record.payload.envelope.event);
  assert.deepEqual(events.map((event) => event.action), [
    "protected-action.intent-recorded",
    "protected-action.outcome-reconciled"
  ]);
  assert.equal((await provenanceStore.verify()).valid, true);
});

import test from "node:test";
import assert from "node:assert/strict";
import { createProtectedWorkflow, ProtectedActionBlockedError } from "../src/protected-workflow.js";

function fakeLedger() {
  const records = [];
  return {
    records,
    async append(record) {
      const item = { ...record, recordHash: `local-${records.length + 1}` };
      records.push(item);
      return item;
    },
    async verify() {
      return { valid: true, recordCount: records.length, headHash: records.at(-1)?.recordHash ?? "0".repeat(64) };
    }
  };
}

function fakeCheckpoint({ failIntent = false, loseFirstAck = false, failOutcome = false } = {}) {
  const heads = new Map();
  const actions = new Map();
  let calls = 0;
  const key = (namespace, actionId) => `${namespace}\0${actionId}`;
  return {
    actions,
    async readHead(namespace) { return heads.get(namespace) ?? { version: 0, hash: "0".repeat(64) }; },
    async readAction(namespace, actionId) { return actions.get(key(namespace, actionId)) ?? null; },
    async compareAndSet({ namespace, expectedVersion, entry }) {
      calls += 1;
      if (entry.kind === "intent" && failIntent) throw new Error("checkpoint unavailable");
      if (entry.kind === "outcome" && failOutcome) throw new Error("outcome checkpoint unavailable");
      const head = heads.get(namespace) ?? { version: 0, hash: "0".repeat(64) };
      if (head.version !== expectedVersion) return { acknowledged: false };
      const next = { ...entry, head: { version: head.version + 1, hash: entry.entryHash } };
      actions.set(key(namespace, entry.actionId), next);
      heads.set(namespace, next.head);
      if (loseFirstAck && calls === 1) throw new Error("simulated lost acknowledgement");
      return { acknowledged: true, head: next.head };
    }
  };
}

test("persists and verifies intent before running action, then checkpoints outcome", async () => {
  const ledger = fakeLedger();
  const checkpoint = fakeCheckpoint();
  let ran = false;
  const workflow = createProtectedWorkflow({
    ledger, checkpoint,
    async executeAction() {
      assert.equal(ledger.records.length, 1);
      assert.equal(ledger.records[0].eventType, "protected-action.intent");
      assert.equal(checkpoint.actions.size, 1);
      ran = true;
      return { simulated: true };
    }
  });
  const result = await workflow.run({
    namespace: "tenant-a/ledger-a", actionId: "action-001",
    actionType: "containment.simulation", payload: { target: "sandbox" }
  });
  assert.equal(ran, true);
  assert.equal(result.status, "completed");
  assert.equal(ledger.records.length, 2);
  assert.equal(checkpoint.actions.get("tenant-a/ledger-a\0action-001").kind, "outcome");
});

test("fails closed and never executes when independent intent checkpoint is unavailable", async () => {
  const ledger = fakeLedger();
  const checkpoint = fakeCheckpoint({ failIntent: true });
  let ran = false;
  const workflow = createProtectedWorkflow({ ledger, checkpoint, async executeAction() { ran = true; } });
  await assert.rejects(
    workflow.run({ namespace: "tenant-a/ledger-a", actionId: "action-002", actionType: "privileged.write", payload: {} }),
    ProtectedActionBlockedError
  );
  assert.equal(ran, false);
});

test("reconciles a lost intent acknowledgement before executing", async () => {
  const ledger = fakeLedger();
  const checkpoint = fakeCheckpoint({ loseFirstAck: true });
  let calls = 0;
  const workflow = createProtectedWorkflow({ ledger, checkpoint, async executeAction() { calls += 1; return "ok"; } });
  const result = await workflow.run({
    namespace: "tenant-a/ledger-a", actionId: "action-003", actionType: "protected.write", payload: { n: 1 }
  });
  assert.equal(result.status, "completed");
  assert.equal(calls, 1);
});

test("does not automatically repeat a previously checkpointed action ID", async () => {
  const ledger = fakeLedger();
  const checkpoint = fakeCheckpoint();
  let calls = 0;
  const workflow = createProtectedWorkflow({ ledger, checkpoint, async executeAction() { calls += 1; return "ok"; } });
  const input = { namespace: "tenant-a/ledger-a", actionId: "action-004", actionType: "protected.write", payload: {} };
  await workflow.run(input);
  const retry = await workflow.run(input);
  assert.equal(retry.status, "already-completed");
  assert.equal(calls, 1);
});

test("blocks the namespace if the action ran but outcome checkpoint is uncertain", async () => {
  const ledger = fakeLedger();
  const checkpoint = fakeCheckpoint({ failOutcome: true });
  let calls = 0;
  const workflow = createProtectedWorkflow({ ledger, checkpoint, async executeAction() { calls += 1; return "may-have-run"; } });
  await assert.rejects(
    workflow.run({ namespace: "tenant-a/ledger-a", actionId: "action-005", actionType: "protected.write", payload: {} }),
    /namespace blocked for reconciliation/
  );
  assert.equal(calls, 1);
  assert.equal(workflow.isBlocked("tenant-a/ledger-a"), true);
  assert.throws(
    () => workflow.clearBlockAfterVerifiedReconciliation("tenant-a/ledger-a", { verified: true, reference: "incident-123" }),
    // Synchronous method should clear only after evidence; this call is valid.
  );
});

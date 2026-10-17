/**
 * Fail-closed protected-action workflow.
 *
 * The checkpoint dependency MUST be an independently administered, durable service
 * with authenticated reads and atomic monotonic compare-and-set semantics. This
 * module deliberately does not pretend a local file is an independent checkpoint.
 *
 * Required checkpoint API:
 *   readHead(namespace) -> { version: non-negative integer, hash: string } | null
 *   readAction(namespace, actionId) -> checkpoint entry | null
 *   compareAndSet({ namespace, expectedVersion, entry }) ->
 *      { acknowledged: true, head: { version, hash } } | { acknowledged: false }
 *
 * readAction must be authoritative and reflect an entry only after its durable CAS
 * has committed. A lost acknowledgement is reconciled by reading the action ID.
 */
import { createHash } from "node:crypto";

const DOMAIN = "GAIA:PROTECTED-WORKFLOW:v1:";
const MAX_CAS_ATTEMPTS = 5;

function stableJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Payload numbers must be finite.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new TypeError("Payload must contain plain JSON objects only.");
    }
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("Payload contains a value that cannot be represented as JSON.");
}

function digest(value) {
  return createHash("sha256").update(DOMAIN).update(stableJson(value)).digest("hex");
}

export class ProtectedActionBlockedError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "ProtectedActionBlockedError";
    this.details = details;
  }
}

export function createProtectedWorkflow({ ledger, checkpoint, executeAction }) {
  if (!ledger?.append || !ledger?.verify) throw new TypeError("ledger.append and ledger.verify are required.");
  if (!checkpoint?.readHead || !checkpoint?.readAction || !checkpoint?.compareAndSet) {
    throw new TypeError("checkpoint.readHead, checkpoint.readAction, and checkpoint.compareAndSet are required.");
  }
  if (typeof executeAction !== "function") throw new TypeError("executeAction must be a function.");

  const blockedNamespaces = new Set();
  const namespaceQueues = new Map();

  async function serialized(namespace, task) {
    const previous = namespaceQueues.get(namespace) ?? Promise.resolve();
    const current = previous.catch(() => {}).then(task);
    namespaceQueues.set(namespace, current);
    try {
      return await current;
    } finally {
      if (namespaceQueues.get(namespace) === current) namespaceQueues.delete(namespace);
    }
  }

  async function commitEntry(namespace, entry) {
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const existing = await checkpoint.readAction(namespace, entry.actionId);
      if (existing) {
        if (existing.entryHash === entry.entryHash && existing.kind === entry.kind) {
          return { acknowledged: true, reconciled: true, head: existing.head ?? null };
        }
        // A single action advances monotonically from intent to outcome. The
        // checkpoint service must enforce that transition atomically.
        if (entry.kind === "outcome" && existing.kind === "intent"
          && existing.intentHash === entry.intentHash) {
          // Continue to CAS the outcome against the current authoritative head.
        } else {
          throw new ProtectedActionBlockedError("Action ID already exists with conflicting checkpoint content.", {
          namespace, actionId: entry.actionId, kind: entry.kind
          });
        }
      }

      const head = await checkpoint.readHead(namespace);
      const expectedVersion = head?.version ?? 0;
      let result;
      try {
        result = await checkpoint.compareAndSet({ namespace, expectedVersion, entry });
      } catch (error) {
        // A timeout can mean the CAS committed but its acknowledgement was lost.
        const reconciled = await checkpoint.readAction(namespace, entry.actionId).catch(() => null);
        if (reconciled?.entryHash === entry.entryHash && reconciled?.kind === entry.kind) {
          return { acknowledged: true, reconciled: true, head: reconciled.head ?? null };
        }
        throw new ProtectedActionBlockedError("Checkpoint acknowledgement is uncertain; protected action is blocked.", {
          namespace, actionId: entry.actionId, kind: entry.kind, cause: String(error)
        });
      }

      if (result?.acknowledged === true) return { ...result, reconciled: false };
      // CAS lost to a concurrent writer. Re-read the authoritative head and retry.
    }
    throw new ProtectedActionBlockedError("Checkpoint CAS retry limit exceeded; protected action is blocked.", {
      namespace, actionId: entry.actionId, kind: entry.kind
    });
  }

  async function run({ namespace, actionId, actionType, payload }) {
    if (typeof namespace !== "string" || !namespace.trim()) throw new TypeError("namespace is required.");
    if (typeof actionId !== "string" || !actionId.trim()) throw new TypeError("actionId is required and must be stable across retries.");
    if (typeof actionType !== "string" || !actionType.trim()) throw new TypeError("actionType is required.");
    // Validate that the complete intent is deterministic JSON before any write.
    const intent = { namespace, actionId, actionType, payload };
    const intentHash = digest(intent);

    return serialized(namespace, async () => {
      if (blockedNamespaces.has(namespace)) {
        throw new ProtectedActionBlockedError("Namespace is blocked pending reconciliation of a prior uncertain outcome.", {
          namespace
        });
      }

      const prior = await checkpoint.readAction(namespace, actionId);
      if (prior) {
        if (prior.kind === "outcome" && prior.intentHash === intentHash && prior.status === "completed") {
          return { actionId, status: "already-completed", checkpoint: prior };
        }
        throw new ProtectedActionBlockedError("Action ID already exists; automatic re-execution is forbidden.", {
          namespace, actionId, existingKind: prior.kind, existingStatus: prior.status
        });
      }

      const intentRecord = await ledger.append({
        epochId: namespace,
        eventType: "protected-action.intent",
        payload: { actionId, actionType, intentHash, payload }
      });
      const localState = await ledger.verify();
      if (!localState?.valid || localState.recordCount < 1 || localState.headHash !== intentRecord.recordHash) {
        throw new ProtectedActionBlockedError("Local intent could not be verified as the current ledger head.", {
          namespace, actionId
        });
      }

      const intentEntry = {
        schemaVersion: 1,
        kind: "intent",
        namespace,
        actionId,
        actionType,
        intentHash,
        ledgerRecordHash: intentRecord.recordHash,
        createdAt: new Date().toISOString()
      };
      intentEntry.entryHash = digest(intentEntry);
      const intentAck = await commitEntry(namespace, intentEntry);
      if (!intentAck.acknowledged) {
        throw new ProtectedActionBlockedError("Independent checkpoint did not acknowledge durable intent.", {
          namespace, actionId
        });
      }

      let actionResult;
      try {
        actionResult = await executeAction({ namespace, actionId, actionType, payload });
      } catch (error) {
        const failure = { name: error?.name ?? "Error", message: String(error?.message ?? error) };
        let outcomeRecord;
        try {
          outcomeRecord = await ledger.append({
            epochId: namespace,
            eventType: "protected-action.outcome",
            payload: { actionId, actionType, status: "failed", intentHash, error: failure }
          });
        } catch (ledgerError) {
          blockedNamespaces.add(namespace);
          throw new ProtectedActionBlockedError("Action failed, but its outcome could not be durably recorded; namespace blocked.", {
            namespace, actionId, cause: String(ledgerError)
          });
        }
        const outcomeEntry = {
          schemaVersion: 1, kind: "outcome", namespace, actionId, actionType,
          intentHash, status: "failed", ledgerRecordHash: outcomeRecord.recordHash,
          error: failure, createdAt: new Date().toISOString()
        };
        outcomeEntry.entryHash = digest(outcomeEntry);
        try {
          await commitEntry(namespace, outcomeEntry);
        } catch (checkpointError) {
          blockedNamespaces.add(namespace);
          throw new ProtectedActionBlockedError("Action failed and its outcome could not be checkpointed; namespace blocked.", {
            namespace, actionId, cause: String(checkpointError)
          });
        }
        throw error;
      }

      let outcomeRecord;
      try {
        outcomeRecord = await ledger.append({
          epochId: namespace,
          eventType: "protected-action.outcome",
          payload: { actionId, actionType, status: "completed", intentHash, result: actionResult }
        });
      } catch (ledgerError) {
        blockedNamespaces.add(namespace);
        throw new ProtectedActionBlockedError("Action may have completed, but its outcome could not be durably recorded; namespace blocked.", {
          namespace, actionId, actionMayHaveCompleted: true, cause: String(ledgerError)
        });
      }
      const outcomeEntry = {
        schemaVersion: 1, kind: "outcome", namespace, actionId, actionType,
        intentHash, status: "completed", ledgerRecordHash: outcomeRecord.recordHash,
        result: actionResult, createdAt: new Date().toISOString()
      };
      outcomeEntry.entryHash = digest(outcomeEntry);
      try {
        const outcomeAck = await commitEntry(namespace, outcomeEntry);
        if (!outcomeAck.acknowledged) throw new Error("Checkpoint outcome acknowledgement missing.");
      } catch (error) {
        blockedNamespaces.add(namespace);
        throw new ProtectedActionBlockedError("Action ran, but durable outcome acknowledgement is uncertain; namespace blocked for reconciliation.", {
          namespace, actionId, actionMayHaveCompleted: true, cause: String(error)
        });
      }
      return { actionId, status: "completed", result: actionResult, intentCheckpoint: intentAck };
    });
  }

  function isBlocked(namespace) {
    return blockedNamespaces.has(namespace);
  }

  // Deliberately does not clear a block merely because a read succeeds. An operator
  // must reconcile the action with the real target system before explicitly clearing.
  function clearBlockAfterVerifiedReconciliation(namespace, evidence) {
    if (!blockedNamespaces.has(namespace)) return false;
    if (!evidence || evidence.verified !== true || typeof evidence.reference !== "string" || !evidence.reference.trim()) {
      throw new TypeError("Verified reconciliation evidence with a non-empty reference is required.");
    }
    blockedNamespaces.delete(namespace);
    return true;
  }

  return Object.freeze({ run, isBlocked, clearBlockAfterVerifiedReconciliation });
}

export const protectedWorkflowInternals = Object.freeze({ stableJson, digest, MAX_CAS_ATTEMPTS });

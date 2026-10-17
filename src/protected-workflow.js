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

export function createProtectedWorkflow({ ledger, checkpoint, executeAction, provenanceStore = null }) {
  if (!ledger?.append || !ledger?.verify || !ledger?.listRecords) throw new TypeError("ledger.append, ledger.verify, and ledger.listRecords are required.");
  if (!checkpoint?.readHead || !checkpoint?.readAction || !checkpoint?.compareAndSet) {
    throw new TypeError("checkpoint.readHead, checkpoint.readAction, and checkpoint.compareAndSet are required.");
  }
  if (typeof executeAction !== "function") throw new TypeError("executeAction must be a function.");

  if (provenanceStore !== null && typeof provenanceStore.append !== "function") {
    throw new TypeError("provenanceStore.append must be a function when provenanceStore is supplied.");
  }

  const blockedNamespaces = new Set();
  const namespaceQueues = new Map();

  // Provenance is emitted only after the corresponding local audit record exists.
  // The actor identity is deliberately marked unverified: this runtime does not
  // independently attest its own workload identity.
  async function appendProvenance({ namespace, actionId, actionType, phase, outcome, ledgerRecord, error = null }) {
    if (!provenanceStore) return null;
    const records = await ledger.listRecords();
    const priorEvents = records
      .filter((record) => record.eventType === "workflow.provenance")
      .map((record) => record.payload?.envelope?.event)
      .filter((event) => event?.workflow_id === namespace);
    const previous = priorEvents.at(-1);
    const event = {
      schema_version: "0.1.0",
      event_id: `${namespace}:${actionId}:${phase}`,
      workflow_id: namespace,
      transition_id: `${actionId}:${phase}`,
      sequence: priorEvents.length + 1,
      occurred_at: new Date().toISOString(),
      recorded_at: new Date().toISOString(),
      actor: {
        kind: "service",
        subject: "gaia-security/protected-workflow",
        identity_evidence: { state: "unverified", reference_id: "runtime-identity-not-attested" }
      },
      action: phase === "intent" ? "protected-action.intent-recorded" : "protected-action.outcome-recorded",
      resource: { type: "protected-action", id: actionId },
      policy: null,
      evidence: [{
        type: "signed-audit-ledger-record",
        reference_id: ledgerRecord.recordHash,
        digest_algorithm: "sha256",
        digest: ledgerRecord.recordHash,
        state: "verified"
      }],
      artifacts: [],
      causation_ids: previous ? [previous.event_id] : [],
      correlation_id: actionId,
      outcome,
      failure: error ? { code: "PROTECTED_ACTION_FAILED", message: error.message } : null,
      integrity: null
    };
    return provenanceStore.append(event);
  }

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
      try {
        await appendProvenance({
          namespace, actionId, actionType, phase: "intent", outcome: "succeeded",
          ledgerRecord: intentRecord
        });
      } catch (provenanceError) {
        blockedNamespaces.add(namespace);
        throw new ProtectedActionBlockedError("Intent was checkpointed, but workflow provenance could not be persisted; namespace blocked.", {
          namespace, actionId, cause: String(provenanceError)
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
        try {
          await appendProvenance({
            namespace, actionId, actionType, phase: "outcome", outcome: "failed",
            ledgerRecord: outcomeRecord, error: failure
          });
        } catch (provenanceError) {
          blockedNamespaces.add(namespace);
          throw new ProtectedActionBlockedError("Action failed and its provenance could not be persisted; namespace blocked.", {
            namespace, actionId, cause: String(provenanceError)
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
      try {
        await appendProvenance({
          namespace, actionId, actionType, phase: "outcome", outcome: "succeeded",
          ledgerRecord: outcomeRecord
        });
      } catch (provenanceError) {
        blockedNamespaces.add(namespace);
        throw new ProtectedActionBlockedError("Action may have completed, but its provenance could not be persisted; namespace blocked.", {
          namespace, actionId, actionMayHaveCompleted: true, cause: String(provenanceError)
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

  async function recover({ namespace, actionId, reconcileAction }) {
    if (typeof namespace !== "string" || !namespace.trim()) throw new TypeError("namespace is required.");
    if (typeof actionId !== "string" || !actionId.trim()) throw new TypeError("actionId is required.");

    return serialized(namespace, async () => {
      const checkpointEntry = await checkpoint.readAction(namespace, actionId);
      if (!checkpointEntry) {
        throw new ProtectedActionBlockedError("No authoritative checkpoint intent exists; recovery cannot safely infer or execute an action.", {
          namespace, actionId
        });
      }
      if (checkpointEntry.kind === "outcome") {
        if (checkpointEntry.status !== "completed" && checkpointEntry.status !== "failed") {
          throw new ProtectedActionBlockedError("Checkpoint outcome has an unsupported state.", { namespace, actionId });
        }
        blockedNamespaces.delete(namespace);
        return { actionId, status: "already-reconciled", outcome: checkpointEntry.status };
      }
      if (checkpointEntry.kind !== "intent") {
        throw new ProtectedActionBlockedError("Checkpoint entry has an unsupported lifecycle state.", { namespace, actionId });
      }

      const ledgerState = await ledger.verify();
      if (!ledgerState?.valid) throw new ProtectedActionBlockedError("Local ledger failed verification; recovery is blocked.", { namespace, actionId });
      const records = await ledger.listRecords();
      const matching = records.filter((record) => record.epochId === namespace
        && record.payload?.actionId === actionId);
      const intentRecord = matching.find((record) => record.eventType === "protected-action.intent");
      if (!intentRecord || intentRecord.payload?.intentHash !== checkpointEntry.intentHash) {
        throw new ProtectedActionBlockedError("Verified local intent is missing or conflicts with the independent checkpoint.", {
          namespace, actionId
        });
      }

      const existingOutcome = matching.find((record) => record.eventType === "protected-action.outcome");
      let outcomePayload;
      if (existingOutcome) {
        // Prefer the durable, verified local outcome over re-querying or re-executing.
        outcomePayload = existingOutcome.payload;
      } else {
        if (typeof reconcileAction !== "function") {
          throw new ProtectedActionBlockedError("Action outcome is unknown. Supply an authoritative target-system reconciliation callback; execution will not be repeated.", {
            namespace, actionId
          });
        }
        const result = await reconcileAction({
          namespace, actionId, actionType: checkpointEntry.actionType,
          intentHash: checkpointEntry.intentHash, payload: intentRecord.payload.payload
        });
        if (!result || !["completed", "failed", "unknown"].includes(result.status)) {
          throw new TypeError("reconcileAction must return status completed, failed, or unknown.");
        }
        if (result.status === "unknown") {
          blockedNamespaces.add(namespace);
          throw new ProtectedActionBlockedError("Target system cannot establish the action outcome; namespace remains blocked.", {
            namespace, actionId, evidenceReference: result.evidence?.reference ?? null
          });
        }
        if (result.evidence?.verified !== true
          || typeof result.evidence.reference !== "string"
          || !result.evidence.reference.trim()) {
          throw new ProtectedActionBlockedError("Target-system reconciliation requires verified evidence and a reference.", {
            namespace, actionId
          });
        }
        outcomePayload = {
          actionId, actionType: checkpointEntry.actionType,
          status: result.status, intentHash: checkpointEntry.intentHash,
          ...(result.status === "completed" ? { result: result.result } : { error: result.error ?? { name: "ReconciledFailure", message: "Target system confirms failure." } }),
          reconciliation: { reference: result.evidence.reference }
        };
        try {
          await ledger.append({ epochId: namespace, eventType: "protected-action.outcome", payload: outcomePayload });
        } catch (error) {
          blockedNamespaces.add(namespace);
          throw new ProtectedActionBlockedError("Reconciled outcome could not be durably recorded in the local ledger.", {
            namespace, actionId, cause: String(error)
          });
        }
      }

      if (outcomePayload.intentHash !== checkpointEntry.intentHash
        || !["completed", "failed"].includes(outcomePayload.status)) {
        throw new ProtectedActionBlockedError("Local outcome does not match the checkpointed intent or has an invalid status.", {
          namespace, actionId
        });
      }
      const outcomeRecord = (await ledger.listRecords()).find((record) => record.epochId === namespace
        && record.eventType === "protected-action.outcome"
        && record.payload?.actionId === actionId);
      if (!outcomeRecord) throw new ProtectedActionBlockedError("Outcome record is missing after recovery.", { namespace, actionId });

      const outcomeEntry = {
        schemaVersion: 1, kind: "outcome", namespace, actionId,
        actionType: checkpointEntry.actionType, intentHash: checkpointEntry.intentHash,
        status: outcomePayload.status, ledgerRecordHash: outcomeRecord.recordHash,
        ...(outcomePayload.status === "completed" ? { result: outcomePayload.result } : { error: outcomePayload.error }),
        ...(outcomePayload.reconciliation ? { reconciliation: outcomePayload.reconciliation } : {}),
        createdAt: outcomeRecord.timestamp ?? new Date().toISOString()
      };
      outcomeEntry.entryHash = digest(outcomeEntry);
      const acknowledgement = await commitEntry(namespace, outcomeEntry);
      if (!acknowledgement.acknowledged) {
        blockedNamespaces.add(namespace);
        throw new ProtectedActionBlockedError("Recovered outcome is not durably checkpointed; namespace remains blocked.", {
          namespace, actionId
        });
      }
      blockedNamespaces.delete(namespace);
      return { actionId, status: "recovered", outcome: outcomePayload.status, checkpoint: acknowledgement };
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

  return Object.freeze({ run, recover, isBlocked, clearBlockAfterVerifiedReconciliation });
}

export const protectedWorkflowInternals = Object.freeze({ stableJson, digest, MAX_CAS_ATTEMPTS });

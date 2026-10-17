import {
  createWorkflowEventEnvelope,
  verifyWorkflowEventChain
} from "./workflow-provenance.js";

const EVENT_TYPE = "workflow.provenance";

/**
 * Persists provenance envelopes inside GAIA's existing signed audit ledger.
 * One store instance serializes its own appends; the underlying ledger is still
 * documented as single-process-writer. Do not share this as a multi-writer store.
 */
export function createWorkflowProvenanceStore({ ledger }) {
  if (!ledger?.append || !ledger?.listRecords || !ledger?.verify) {
    throw new TypeError("ledger.append, ledger.listRecords, and ledger.verify are required.");
  }
  let queue = Promise.resolve();

  async function readChain() {
    const integrity = await ledger.verify();
    if (!integrity?.valid) throw new Error("Audit ledger integrity verification failed.");
    const records = await ledger.listRecords();
    return records
      .filter((record) => record.eventType === EVENT_TYPE)
      .map((record) => record.payload?.envelope);
  }

  async function verify() {
    const envelopes = await readChain();
    return verifyWorkflowEventChain(envelopes);
  }

  function append(event) {
    const operation = queue.then(async () => {
      const envelopes = await readChain();
      const previous = envelopes.at(-1)?.event_digest;
      const expectedSequence = envelopes.reduce((max, envelope) => {
        return envelope?.event?.workflow_id === event?.workflow_id
          ? Math.max(max, envelope.event.sequence)
          : max;
      }, 0) + 1;
      if (event?.sequence !== expectedSequence) {
        throw new TypeError(`Expected sequence ${expectedSequence} for workflow ${event?.workflow_id ?? "(missing id)"}.`);
      }
      const envelope = createWorkflowEventEnvelope(event, previous);
      const record = await ledger.append({
        epochId: event.workflow_id,
        eventType: EVENT_TYPE,
        payload: { envelope }
      });
      // Re-verify the ledger after the durable write. A failed check rejects the
      // append result so callers must not treat the event as trusted evidence.
      const checked = await verify();
      // "unverified" is a valid explicit evidence state (for example, when the
      // event's actor identity is not independently attested). Persist it without
      // upgrading it to trusted evidence. Structural/digest failures and causal or
      // sequence gaps still reject the append.
      if (checked.status === "invalid" || checked.status === "partially_verified") {
        throw new Error(`Persisted workflow provenance failed integrity/completeness checks: ${checked.status}.`);
      }
      return { record, envelope, verification: checked };
    });
    queue = operation.catch(() => {});
    return operation;
  }

  return Object.freeze({ append, verify });
}

export const workflowProvenanceStoreInternals = Object.freeze({ EVENT_TYPE });

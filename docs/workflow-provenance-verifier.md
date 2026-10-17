# Workflow provenance verifier prototype

**Tracking:** [GAIA-Documentation #320](https://github.com/KyleAlexanderSteen/GAIA-Documentation/issues/320)  
**Status:** Experimental implementation; review required.  
**Target:** `GAIA-Security`

## What is implemented

- A versioned event-shape validator for the proposed workflow provenance contract.
- Deterministic JSON canonicalization and SHA-256 digest-linked event envelopes.
- Chain-link and digest verification.
- Detection of duplicate event IDs, ordering/sequence gaps, and missing causal references.
- Explicit outcomes that preserve reconstructed, unavailable, unverified, and invalid evidence states.
- Node built-in test coverage for valid events, malformed fields, tampering, reordering, truncation/gaps, replay/ID reuse, evidence-state preservation, and protected-workflow lifecycle integration.

## Security boundary and limitations

This prototype's digest chain is **not a digital signature or proof of actor identity**. It does not provide durable storage, an external trust anchor, independent checkpointing, key lifecycle management, concurrency control, or protection against an attacker who can rewrite the entire chain. It does not make a claim that all issue #320 acceptance criteria are complete.

The contract and implementation are provisional until the owner reviews the proposed schema/profile. The protected-workflow integration is a local prototype, not a production service integration. The tests must pass in CI before this PR is considered verified.


## Signed-ledger integration added

`src/workflow-provenance-store.js` now provides `createWorkflowProvenanceStore({ ledger })`. It stores validated provenance envelopes as `workflow.provenance` records in the existing signed audit ledger, verifies ledger integrity before reading, serializes appends within one store instance, enforces per-workflow sequence progression, and verifies after persistence.

`createProtectedWorkflow({ ..., provenanceStore })` now emits a provenance event after the intent has been written and independently checkpointed, before the protected action executes. It emits a corresponding success/failure outcome event after the local outcome record is written. If intent provenance cannot be persisted, the action is not executed; if outcome provenance cannot be persisted, the namespace is blocked for reconciliation.

Coverage in `test/workflow-provenance-store.test.js` includes signed-ledger persistence, concurrent calls within one store instance, sequence rejection, and detection of tampered ledger records. `test/protected-workflow-provenance.test.js` exercises intent-before-execution ordering, linked intent/outcome events, and failure-outcome recording against the real local signed ledger.

### Integration boundary

The underlying ledger remains a single-process-writer local-file prototype. The adapter serializes appends only within one store instance; there is no multi-process lock or independent external checkpoint. Runtime actor identity is deliberately recorded as `unverified` because the protected-workflow process does not independently attest its workload identity. Evidence references point to signed-ledger records, but external evidence sources are not independently fetched or verified. Recovery currently reconciles the protected action/checkpoint lifecycle; this integration does not yet emit a dedicated provenance event for every recovery path. These limits must remain visible.

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
- Node built-in test coverage for valid events, malformed fields, tampering, reordering, truncation/gaps, replay/ID reuse, and evidence-state preservation.

## Security boundary and limitations

This prototype's digest chain is **not a digital signature or proof of actor identity**. It does not provide durable storage, an external trust anchor, independent checkpointing, key lifecycle management, concurrency control, or protection against an attacker who can rewrite the entire chain. It does not make a claim that all issue #320 acceptance criteria are complete.

The contract and implementation are provisional until the owner reviews the proposed schema/profile. No production service integration or external side effect is included. The tests must pass in CI before this PR is considered verified.


## Signed-ledger integration added

`src/workflow-provenance-store.js` now provides `createWorkflowProvenanceStore({ ledger })`. It stores validated provenance envelopes as `workflow.provenance` records in the existing signed audit ledger, verifies ledger integrity before reading, serializes appends within one store instance, enforces per-workflow sequence progression, and verifies after persistence.

Coverage in `test/workflow-provenance-store.test.js` includes signed-ledger persistence, concurrent calls within one instance, sequence rejection, and detection of tampered ledger records.

### Integration boundary

The adapter is not yet wired into `createProtectedWorkflow`. The underlying ledger remains a single-process-writer local-file prototype, and the adapter does not provide multi-process locking or an independent external checkpoint. Identity states are declarations rather than authenticated identity proofs, and evidence source digests are not independently fetched or verified. These limits must remain visible until the corresponding controls are implemented and tested.

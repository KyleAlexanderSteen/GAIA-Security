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

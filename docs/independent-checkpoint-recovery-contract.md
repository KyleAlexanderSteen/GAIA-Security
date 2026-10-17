# Independent Checkpoint and Recovery Boundary

**Status:** Proposed security contract for review; not an approved production design.  
**Scope:** Extends the experimental local Stage 0 audit ledger without claiming that the current prototype is production-secure.  
**Related implementation:** `src/audit-ledger.js`, `test/audit-ledger.test.js`, and `docs/stage-0-audit-ledger-mvp.md`.  
**Traceability:** GAIA-Documentation issues [#320](https://github.com/KyleAlexanderSteen/GAIA-Documentation/issues/320) and [#321](https://github.com/KyleAlexanderSteen/GAIA-Documentation/issues/321); GAIA-Security issue [#1](https://github.com/KyleAlexanderSteen/GAIA-Security/issues/1).

## 1. Problem statement

The current prototype writes a signed hash-chained JSONL ledger and signed Merkle checkpoints to local files. Its verifier detects the tested record edits and anchored-record removal when the verifier's trusted key is retained independently. It does not provide an independent trust boundary if an attacker can replace both local ledger and local checkpoint files, nor does it implement remote monotonic state, rollback/fork detection, production key lifecycle, or disaster recovery.

A valid signature proves that a signature matches a particular key and message. It does not, by itself, prove that the message is the newest checkpoint, that the key is authorized, or that a history has not been rolled back to an older valid state.

## 2. Security objectives

The implementation SHALL:

1. Preserve an independently retained, authenticated statement of the latest accepted ledger checkpoint.
2. Detect a local ledger/checkpoint rollback relative to that statement.
3. Detect conflicting checkpoint histories (forks) for the same ledger identity.
4. Authenticate checkpoint signers through an explicit trust policy, not a caller-supplied display name alone.
5. Make checkpoint persistence, verification, and recovery outcomes explicit and auditable.
6. Fail safely when the independent checkpoint service or required audit write path is unavailable.
7. Preserve evidence during recovery; never silently rewrite, truncate, or bless a suspect history.
8. Expose guarantees and limitations accurately, including any availability trade-offs.

## 3. Threat model and assumptions

### In scope

- Local ledger or local checkpoint file is modified, deleted, truncated, or replaced.
- An attacker restores an older but internally valid copy of the local files.
- Two writers or replicas present different successors to the same accepted checkpoint.
- A checkpoint is signed by an unknown, revoked, expired, or incorrectly bound key.
- Remote checkpoint storage is unavailable, times out, returns malformed data, or rejects a conditional update.
- Process crash or host restart occurs between local append, checkpoint publication, and acknowledgement.
- Recovery media contains incomplete, stale, or conflicting state.

### Explicit assumptions and out-of-scope conditions

- The independent checkpoint boundary and its trust roots are not writable by the same principal that can rewrite the local ledger. If an attacker controls both boundaries or compromises the trusted signing authority, this contract alone cannot guarantee detection.
- A remote service is not considered independent merely because it uses a different URL. Its credentials, administration plane, retention controls, and recovery path must be assessed for shared compromise.
- If the checkpoint service or its administrator is in the threat model as potentially malicious, a single service's signed answer cannot prove that it has not equivocated to different clients. Evaluate an independently administered witness, transparency log, or cross-client checkpoint gossip as a separate mitigation; define its costs and availability impact before making it mandatory.
- If multiple GAIA instances, tenants, or environments share the service, ledger identity, authorization scope, and checkpoint namespace MUST be isolated and validated on every read and write. Cross-ledger substitution must be rejected.
- This document does not select a cloud provider, WORM product, HSM/KMS, consensus protocol, retention period, or key quorum. Those are owner-reviewed decisions.
- This is not a certification, proof of complete containment, or claim that the existing prototype meets these requirements.

## 4. Checkpoint contract

Each externally accepted checkpoint SHALL contain, at minimum:

- `schemaVersion` and a stable `ledgerId`;
- monotonically increasing `checkpointSequence` scoped to that ledger;
- `previousCheckpointDigest` (null only for the explicitly initialized genesis checkpoint);
- `recordCount`, `ledgerHeadHash`, and the anchored epoch/range plus Merkle root;
- a creation timestamp for diagnostics (not the sole anti-rollback mechanism);
- signer key identifier and signature over a canonical representation of all security-relevant fields.

The exact wire format and canonicalization rules must be versioned. The signature MUST cover the ledger identity, sequence, predecessor digest, record count, head hash, epoch/range, Merkle root, and signer key identifier.

Canonicalization MUST be deterministic and unambiguous: specify character encoding, field ordering, number representation, optional/null handling, and hash/signature algorithms in a versioned format. Signatures and hashes MUST use domain separation so that a value valid for one purpose (for example, a writer record) cannot be reinterpreted as a checkpoint or a different protocol message. Reject duplicate fields, unknown critical fields, invalid encodings, and non-canonical representations rather than guessing how to parse them. Algorithm identifiers MUST be policy-checked; an input record must not be allowed to downgrade verification to a weaker algorithm.

The verifier MUST enforce an explicit freshness policy for the remote checkpoint response. A correctly signed but stale cached response is not proof of the latest head. The service interface must define how the client establishes freshness (for example, an authenticated uncached read or a challenge-bound response) and what happens when freshness cannot be established. Wall-clock timestamps may support diagnostics or bounded-age policies, but cannot replace monotonic state and predecessor checks.

The independent store SHALL provide an authenticated read and a durable monotonic update primitive. Updates MUST be conditional on the expected current checkpoint sequence/digest (compare-and-swap or an equivalent serialization guarantee). It MUST reject stale writers and conflicting successors instead of silently overwriting the accepted checkpoint. The store's acknowledged durability and retention guarantees must be documented and tested.

A checkpoint is not considered independently anchored merely because it has been signed or copied to a second path under the same local administrative boundary.

## 5. Verification and rollback/fork rules

On startup, before protected work is authorized, the verifier SHALL:

1. Load the configured trust policy and obtain the latest checkpoint from the independent boundary.
2. Authenticate the checkpoint response and verify its signature, schema, ledger identity, key status, and predecessor linkage as required by the configured trust policy.
3. Verify the local ledger's complete schema, sequence, hash chain, record digests, and writer signatures.
4. Verify that the local ledger contains the exact checkpointed prefix: its record count, head hash, and anchored Merkle ranges/root must match the externally accepted checkpoint.
5. Compare local and external checkpoint positions.

The verifier MUST treat any of the following as an integrity incident: local state older than the external accepted checkpoint; a different digest at an already accepted sequence; an invalid predecessor link; two different proposed successors to one accepted checkpoint; or a local history that cannot reproduce the accepted checkpoint. It MUST NOT automatically reset the external checkpoint to match local state.

If local state is newer than the latest remote checkpoint, it may represent a crash after local append but before external acknowledgement. Such records are **unanchored**, not automatically trusted as committed history. The system MUST apply the explicit recovery procedure below and MUST NOT perform protected side effects based solely on those records.

Wall-clock timestamps are diagnostic and cannot replace monotonic sequence/predecessor checks.

## 6. Key trust and lifecycle requirements

- Trust anchors and the mapping from key ID to authorized principal/purpose MUST be provisioned through a separately authenticated configuration or trust store.
- A key identifier or `writerId` string alone is not identity proof.
- Checkpoint-signing and record-writer keys SHOULD be distinct; their permissions and rotation procedures MUST be documented.
- Private signing keys MUST NOT be stored in the ledger, checkpoint record, source repository, or ordinary application logs.
- Key rotation MUST define an authenticated transition from old to new key, effective sequence/time semantics, and handling of checkpoints signed before and after transition.
- Revocation MUST define behavior for previously accepted checkpoints and for records signed by a key later revoked. Revocation must not silently erase historical evidence.
- Unknown, revoked, malformed, or policy-ineligible signing keys MUST be rejected for new checkpoint acceptance.
- Emergency key recovery and trust-root replacement require a separately authenticated, auditable procedure and owner approval. No automatic trust-on-first-use fallback is permitted for production.

The key-management implementation and trust-root distribution are open decisions, not features delivered by this document.

## 7. Audit-write availability and fail-safe policy

The system MUST classify operations by risk and define the required audit durability before execution. The default proposal is:

- **High-impact or privileged side effects:** fail closed if the required intent record cannot be durably appended and the required checkpoint policy cannot be satisfied. Do not execute first and log later.
- **Read-only or explicitly low-risk work:** may continue only under a documented degraded mode that does not claim a fresh independent checkpoint and does not cross into privileged side effects.
- **Remote checkpoint unavailable:** preserve locally synced records as pending/unanchored, report degraded health, and prevent actions whose policy requires independent acknowledgement.
- **Local audit append unavailable or corrupt:** do not execute protected side effects. Do not swallow the failure or report success.
- **Buffering/queueing:** permitted only if the loss, ordering, capacity, replay, duplicate, and side-effect semantics are defined. A local queue is not equivalent to independent durable acknowledgement.
- **Emergency override:** if later approved, it must be narrowly scoped, time-bounded, attributable to an authorized human, independently recorded when possible, and visible in the final audit history. No override is implemented or approved by this document.

The product owner must decide which operation classes require local durable intent only versus independent checkpoint acknowledgement before execution. Until then, the conservative default applies to privileged/high-impact actions.

## 8. Recovery protocol

Recovery SHALL be an explicit state machine, not an automatic file repair:

1. **Quarantine:** stop protected side effects and preserve the suspect local ledger, checkpoint files, remote response, and diagnostic metadata as read-only evidence where feasible.
2. **Re-establish trust:** authenticate the independent checkpoint service and load the approved trust/key policy.
3. **Classify:** determine whether the local state is behind, ahead-but-unacknowledged, corrupted, or forked relative to the external checkpoint.
4. **Restore/verify:** retrieve a trusted ledger snapshot or replay from a known-good checkpoint using authenticated records. Verify every record and checkpoint before accepting restored state.
5. **Resolve divergence:** never choose a branch based only on local recency or timestamps. Conflicting histories require a deterministic policy and, for unresolved conflicts, authorized human review.
6. **Resume cautiously:** resume protected actions only after integrity is re-established and the system emits an auditable recovery decision. Any discarded or superseded records remain preserved as incident evidence.

If the independent boundary cannot be reached, recovery cannot establish the latest accepted state; the system remains in a degraded/blocked state for protected operations.

## 9. Proposed acceptance and adversarial tests

These are required test cases for a future implementation; this contract PR does not claim that the external service or these tests already exist.

| ID | Scenario | Required result |
|---|---|---|
| CP-01 | Change a local record payload after checkpointing | Verification rejects the record/checkpoint mismatch; no protected action runs. |
| CP-02 | Delete a record covered by the externally accepted checkpoint | Verification detects the missing anchored prefix and enters integrity-incident state. |
| CP-03 | Restore both local files to an older, internally valid snapshot | External monotonic checkpoint detects rollback; no automatic reset occurs. |
| CP-04 | Present a different checkpoint digest at an already accepted sequence | Reject as conflicting history/fork and preserve evidence. |
| CP-05 | Two writers submit different successors to the same checkpoint | At most one conditional update is accepted; the loser must reread and reconcile, not overwrite. |
| CP-06 | Submit checkpoint signed by unknown or revoked key | Reject; do not advance external checkpoint. |
| CP-07 | Rotate keys using an authenticated transition | Valid pre-transition history remains verifiable; unauthorized transition fails. |
| CP-08 | Remote store times out before acknowledgement | Mark new records unanchored/pending; protected action follows the approved fail-safe policy. |
| CP-09 | Remote write succeeds but acknowledgement is lost | Retry is idempotent or resolves by reading the accepted checkpoint; no duplicate/fork is silently created. |
| CP-10 | Local append fails before a protected action | Action does not execute; failure is surfaced. |
| CP-11 | Crash after local append but before remote checkpoint | Restart identifies pending records and runs recovery; it does not treat them as independently anchored. |
| CP-12 | Restore from a trusted snapshot and replay authenticated records | Recovered head and checkpoint digest match the external trust state before resuming. |
| CP-13 | External service returns malformed, stale, or wrong-ledger checkpoint | Reject response and fail closed for protected actions. |
| CP-14 | Independent store unavailable during recovery | Preserve evidence and remain blocked for protected actions; never silently trust local state. |
| CP-15 | Attempt to overwrite an accepted checkpoint with a stale conditional token | Store rejects the write; accepted state remains unchanged. |

Tests MUST also assert that failure paths do not invoke protected side effects, not merely that an error is thrown.

The action lifecycle MUST also be tested across partial failures. Each protected action should have a stable operation/correlation identifier and explicit states such as `intent-durable`, `checkpoint-acknowledged` (where required), `action-attempted`, `outcome-recorded`, and `reconciliation-required`. The implementation must define which transitions are durable, which may be retried, and how duplicate execution is prevented or detected. An audit record is evidence of a recorded claim; it is not, by itself, proof that an external side effect occurred exactly once.

| ID | Scenario | Required result |
|---|---|---|
| CP-16 | Retry the same protected operation after a lost acknowledgement | Stable operation ID and idempotency policy prevent duplicate execution or make the duplicate detectable and reconcilable. |
| CP-17 | Protected action may have succeeded, but outcome append fails | Block subsequent protected actions, mark reconciliation required, preserve evidence, and do not claim a known outcome. |
| CP-18 | Two requests submit the same operation ID concurrently | The operation is serialized or deduplicated according to the documented idempotency contract; conflicting payloads for one ID are rejected. |
| CP-19 | Checkpoint service administrator or signing service is suspected compromised | Follow a separately authorized incident/trust-root recovery path; do not silently trust a new key or rewrite accepted history. |
| CP-20 | Clock skew or timestamp rollback occurs | Sequence, predecessor, and authenticated state determine freshness; wall-clock time alone cannot authorize rollback or advancement. |
| CP-21 | Two different clients receive conflicting signed checkpoints from a compromised or equivocating service | Detect through the selected witness/transparency/gossip control where configured; otherwise document that this threat is not covered by a single-service design. |
| CP-22 | A valid but stale signed checkpoint response is replayed | Freshness policy rejects it or prevents protected work until the current head is established. |
| CP-23 | A checkpoint for another ledger or tenant is substituted | Ledger identity and authorization scope checks reject it; no state advances. |
| CP-24 | Equivalent data is encoded in multiple ambiguous forms or a weaker algorithm is requested | Non-canonical/duplicate-field input and disallowed algorithm downgrade are rejected deterministically. |

## 10. Observability and evidence

Every checkpoint publication, acknowledgement, rejection, rollback/fork detection, key-policy rejection, recovery transition, and fail-safe block SHOULD produce a structured audit event containing a correlation ID, ledger ID, expected/observed checkpoint sequence and digest (where safe), reason code, outcome, and actor/service identity. Secrets, private keys, credentials, and sensitive payloads MUST be excluded.

Acceptance evidence should include test output, the selected store's documented consistency/durability semantics, a threat-model review, key lifecycle procedures, and a recovery tabletop or fault-injection record. A green unit-test suite alone is insufficient to claim operational independence.

## 11. Owner-reviewed design baseline

**Owner decision:** The following three choices are approved as the design baseline for implementation planning. This approval does not select a vendor, authorize production deployment, or certify the prototype as production-secure.

### 11.1 Independent checkpoint service

- Use a separately administered service with durable, authenticated reads and a monotonic conditional-update primitive (compare-and-swap or a demonstrably equivalent serialization guarantee).
- Keep the backend interface provider-neutral and define conformance tests before selecting a provider.
- Treat immutable/WORM retention as an additional evidence-retention control, not as a substitute for atomic sequencing, fork prevention, or an independently protected trust boundary.
- Document the actual administrative principals, credentials, recovery path, replication, consistency, retention, and compromise assumptions before calling the service independent.

### 11.2 Checkpoint-signing trust

- Use a dedicated checkpoint-signing identity controlled by the independent service; keep it distinct from record-writer identities.
- Prefer a managed KMS/HSM-backed signing service only after its key isolation, authorization, audit, availability, and recovery guarantees are verified. The label “KMS” or “HSM” alone is not proof of those guarantees.
- Distribute the public verification key and authorization policy through authenticated configuration with a trust root independent of the checkpoint ledger itself.
- Define authenticated rotation, revocation, and emergency trust-root replacement. Routine rotation should prove the new key's possession and authorization through a trusted transition. If compromise is suspected, the possibly compromised old key MUST NOT be the sole authority for approving its replacement.
- Never place private keys, credentials, or recovery secrets in Git, ledger records, checkpoints, or ordinary logs.

### 11.3 Fail-safe policy

- Fail closed for privileged or high-impact side effects whenever required local durable intent or independent checkpoint acknowledgement is missing.
- If local intent persistence fails, do not execute the protected action.
- If a remote acknowledgement is lost, query the authoritative checkpoint head and retry idempotently; do not assume failure, blindly advance, or create a competing history.
- If the action may have succeeded but its outcome cannot be durably recorded, stop subsequent protected actions, raise an integrity incident, and reconcile the real-world outcome before resuming.
- Permit read-only or explicitly low-risk degraded operation only under a documented policy that cannot cross into protected side effects.
- Do not implement an emergency bypass until its authority, scope, duration, evidence requirements, and post-incident review are separately approved.

## 12. Decisions required before implementation

The following remain explicitly **unapproved**:

1. Concrete backend/provider and its administrative/security boundary.
2. Exact consistency, durability, retention/WORM, replication, and behavior under administrator compromise.
3. Actual signing-key custody product, key policy, rotation/revocation runbooks, and emergency trust-root procedure.
4. The operation-class matrix specifying which actions require local durable intent and which require independent acknowledgement before execution.
5. Retention, privacy minimization, backup, legal hold, and incident-evidence policy.
6. Human escalation/approval path for unresolved forks and emergency overrides.
7. Availability and recovery objectives (RPO/RTO) and acceptable degraded-mode behavior.
8. Idempotency strategy for each protected action and the reconciliation mechanism for actions whose real-world outcome is uncertain.
9. Whether the threat model requires an independent witness/transparency mechanism to detect a checkpoint service that equivocates to different clients.
10. Freshness requirements, maximum acceptable checkpoint response age, and the concrete protocol used to establish a current authoritative head.

## 13. Definition of done

This contract is ready for implementation planning only after owner review of the unresolved decisions. Implementation acceptance requires CP-01–CP-24 (or reviewed equivalents), documented threat-model coverage, deterministic encoding/signature conformance vectors, tested failure ordering, freshness and cross-ledger isolation tests, recovery evidence, and an updated Stage 0 gate report. If independent witnessing is not selected, the documented residual risk must explicitly state that a single checkpoint service may be unable to detect its own equivocation. Passing tests does not alone establish security against compromise of the independent store, trust roots, or signing authority.

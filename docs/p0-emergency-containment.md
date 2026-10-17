# P0 Emergency Containment Vertical Slice

**Tracking issue:** [GAIA-Documentation #319](https://github.com/KyleAlexanderSteen/GAIA-Documentation/issues/319)  
**Status:** Experimental orchestration contract; not a production control  
**Change type:** implementation + tests + documentation  
**Risk:** high; no live target adapter is included

## What this adds

`src/emergency-containment.js` defines a small coordinator for three explicitly allowlisted actions:

- `SEVER_EGRESS`
- `REVOKE_ACCESS`
- `ISOLATE_SUBJECT`

The caller must provide an authorization adapter, a target-system execution adapter, and optionally an independent emergency-journal adapter. Authorization is checked for each exact actor/action/target and must return a non-empty capability ID with a future expiry. Invalid, expired, denied, or unavailable authorization fails closed. The executor receives the request ID as an idempotency key.

Normal policy, provenance, telemetry, and audit services are deliberately not constructor dependencies. If the emergency journal is unavailable, the coordinator reports `journalStatus: "unavailable"` but does not suppress an otherwise authorized containment action. This makes the degraded audit state visible rather than silently claiming a durable record.

## Guarantees and non-guarantees

- The module enforces action allowlisting, request validation, capability-result shape/expiry, in-process duplicate suppression, and explicit journal degradation status.
- The authorization adapter must independently enforce identity, scope, authority, and expiry; this module does not authenticate an actor or implement the adapter.
- The executor must enforce the action safely at the actual target and honor idempotency. No real egress, credential, or workload adapter is included.
- Request deduplication is in-memory only and does not survive process restart or coordinate multiple processes.
- The optional journal is not a durable ledger implementation. A `written` result means only that the injected adapter resolved successfully; durability must be established by that adapter's own contract and tests.
- No PET, differential-privacy mechanism, TEE, policy engine, signer, operator roster, or production emergency bypass is selected.
- No production deployment or experiment is part of this change.

## Validation plan

Run `npm run check` and CI. Follow-up work must add independent adapter contract tests, restart/concurrency recovery tests, a threat model, and reconciliation semantics for missing emergency records. Test results must be reported separately from implementation status.

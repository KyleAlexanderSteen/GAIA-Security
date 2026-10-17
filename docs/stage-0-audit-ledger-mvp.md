# Stage 0 Audit Ledger MVP: Scope and Threat Notes

**Status:** Experimental implementation accompanying the Stage 0 build PR. Not a production approval.

## Implemented in this slice

- Canonical JSON serialization for the record body.
- Per-record SHA-256 digest linked to the previous record.
- Ed25519 signature over the record digest; key material is supplied by the caller and is never generated or stored by this module.
- Append-and-sync write path to a local JSON Lines file.
- Verification of schema version, sequence, chain links, digest, and writer signature.
- Signed Merkle checkpoints over records in an epoch.
- Tests for append/verify, intent-before-simulated-action ordering, reopen/recovery, tampering, truncation, and checkpoint verification.

## Explicit limits

- **Not tamper-proof storage:** a privileged filesystem administrator can rewrite the ledger and its local checkpoint file. Production needs independently protected keys and an external/remote checkpoint or WORM retention boundary.
- **Single-process writer only:** the in-process queue serializes writes within one instance; there is no cross-process lock, consensus, or fork resolution.
- **No identity provider integration:** `writerId` is an asserted identifier supplied by the caller. Key-to-principal binding, key rotation/revocation, hardware-backed signing, and independent verification-key distribution remain unimplemented.
- **No production containment integration:** tests simulate the intent-before-action ordering. No network egress switch, credential revocation, substrate isolation, or privileged action is invoked.
- **No retention/deletion policy:** retention, legal hold, privacy minimization, backup, disaster recovery, and external anchoring policy require decisions.
- **Merkle anchoring is local:** the signed root is stored alongside the local ledger, not independently published. This detects accidental/local edits when trusted key material is retained separately, but does not stop a privileged attacker from replacing both files.
- **Filesystem durability depends on the underlying filesystem and platform.** `fsync` is called on the file after each append; this is not a guarantee against every storage/controller/power-loss scenario.
- **Epoch scope:** an anchor covers all records with the named epoch as present when anchoring. The record interval is recorded; later records in the same epoch are not covered by an earlier anchor.

## Stage 0 gate status

This prototype can demonstrate a signed, hash-chained local append and a simulated intent-before-action ordering. It does **not** by itself pass the complete Stage 0 gate. Shadow egress-control, tabletop containment, independent anchoring, operator roster, key lifecycle, and halt/restart scenarios still require separate evidence and owner decisions.

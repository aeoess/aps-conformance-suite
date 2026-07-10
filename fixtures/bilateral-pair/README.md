# Bilateral pair reconciliation fixtures

A bilateral receipt exists as two copies, one per co-signer. Reconciliation
compares the relying party's copy with the counterparty's copy (or its
absence) and emits reason-coded mismatch classes: payload_changed,
recipient_changed, wrong_audience, unilateral_success, action_ref_mismatch.

Six vectors: one reconciled pair plus one per class. Every receipt is
genuinely Ed25519 co-signed (public keys included); reconciliation itself is
structural and presumes per-copy signature verification already passed.
Expected fields are the verdict status and the mismatch list.

These vectors carry pair inputs and expected verdicts rather than the
canonical-bytes contract fields; implementations verify by running their
reconciliation over each pair and comparing status plus mismatches.

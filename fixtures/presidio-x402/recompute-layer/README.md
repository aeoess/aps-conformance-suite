# recompute-layer — integrity is not derivation

A proposal, not part of the APS accountability-record negative suite.

## The gap

APS's three native record checks — schema, Ed25519 signature over `JCS(record
minus sig)`, and `action_digest = sha256(JCS(action))` — prove two things and only
two things: the record was not tampered with, and it was signed by the key
`signer_did` resolves to. They say nothing about whether the *recorded decision
re-derives from the record's own controls*. A recorder can sign a well-formed,
untampered `decision: "allow"` over an action whose controls actually mandate a
deny, and every APS check will pass.

`presidio-x402-verdict-not-recomputable.record.json` is exactly that record. It is
deliberately built to be **APS-native-valid**:

- schema-valid (Draft 2020-12);
- signature valid over `JCS(record minus sig)`, signed by the policy-recorder key
  that `signer_did` resolves to (`keypair.publicKeyHex`) — **not** a wrong key;
- `action_digest` binds: `sha256(JCS(action)) == action_digest.sha256`. The
  `action` is honest — `scope` is the screen_ref scope only
  (`presidio:x402.screen:PII_REDACTED:EMAIL_ADDRESS`), nothing tampered;
- `decision: "allow"`, `executed: true`.

Run `fixtures/presidio-x402/recompute-layer/verify-recompute-record.ts` from the
suite (`npm run verify:presidio-x402-recompute`): it verifies TRUE. That is the point.

## What the record cannot show, and what closes the gap

The controls that produced the decision are carried in
`presidio_x402_ext.controls` (order `[pii, trusted_wallet, policy, replay, mpa]`),
with `policy.verdict = "VIOLATION"`. The proposed recompute layer applies

```
verdict = f(controls)   # precedence-combinator, first-failure-wins
                        # PII_BLOCKED / UNTRUSTED / VIOLATION / DUPLICATE / DENIED -> DENY
                        # mpa PENDING | TIMEOUT                                    -> REFER
                        # otherwise                                               -> ALLOW
                        # DENY->deny, REFER->halt, ALLOW->allow
```

For this record, `f(controls) = deny`, which contradicts the recorded
`decision: "allow"`. The record carries `presidio_recompute_expected: "deny"`
alongside `decision: "allow"` to make the contradiction explicit and gradeable.

`recompute_check.py` is a **discriminator, not an always-fail**:

- the PART-1 positive record (`presidio-x402-allow-pii-redacted`, clean controls)
  -> `f = allow == decision` -> **AGREES** (trusted);
- this record -> `f = deny != allow` -> **DISAGREES / FLAGGED**.

It exits nonzero only on an *unexpected* result (an agreement where a
disagreement was expected, or vice-versa), never merely because a record is
flagged.

## Connection to autogen#7353

This is the `receipt completeness != transition-verification completeness`
distinction raised on the autogen#7353 AAR thread (Tuttotorna / babyblueviper1,
2026-07-04). A complete, well-signed receipt attests that a decision was recorded;
it does not attest that the decision was the *right* function of its inputs.
`verdict = f(controls)` is one concrete transition-verification instance layered on
top of an intact receipt: APS certifies the receipt, the recompute layer certifies
the transition.

## The `recompute_mismatch` rejection class (proposed)

A record whose decision does not re-derive from its controls fails under a named
class, `recompute_mismatch`, carried at the envelope level in
`recompute_rejection_kind`. The name was proposed and agreed on x402-foundation/x402#2332
(babyblueviper1, Tuttotorna, vstantch, 2026-07-04): it parallels APS's own lowercase
`digest_mismatch`, and it is the honest name because nothing was tampered with — the
decision simply does not follow from its own controls.

It sits in a four-layer stack, and the boundaries are load-bearing:

- **integrity** — the record was preserved (`digest_mismatch` / `schema` on failure);
- **signature** — who signed it (`signature` on failure);
- **recompute** — the verdict follows from the *declared* controls (`recompute_mismatch`);
- **attestation** — the declared controls are the *real* controls (separate, not here).

Two rules hold this honest. `recompute_mismatch` is **never a substitute for a native
APS verdict**: APS says the receipt is intact, `recompute_mismatch` says the decision
does not re-derive, and both fire independently. And the recompute layer **stops at the
declared controls** — it cannot say the controls are truthful; a recorder who lies about
`policy.verdict` gets a clean recompute over a false premise, which is an *attestation*
failure, not a recompute one.

`recompute_check.py` re-derives the declared `recompute_rejection_kind` rather than
trusting it: a flagged record must carry the class recompute yields, and an agreeing
record must carry none.

**Placement and adoption are aeoess's call** as schema owner — whether this lives as an
envelope field beside the record (as here), as its own layer, or as a native APS
`rejection_kind`. This directory ships the working instance; the shape follows wherever
the boundary is drawn.

## Scope — what this proves and does not prove

- It **does** prove: given the recorded controls, the recorded decision does not
  equal `f(controls)`. The signed decision does not re-derive from its own
  recorded inputs.
- It **does not** prove: that the *controls themselves* are truthful. If a
  recorder lies about `policy.verdict`, recompute will happily agree with a false
  decision. Recompute checks derivation, not the honesty of the control record;
  control-record integrity is a separate concern (attestation of each control's
  own evidence).
- It **does not** change any APS verdict. APS still says the record is intact and
  correctly signed. Recompute is an *additional* layer, not a replacement for the
  native checks.
- The control vocabulary and the `f` precedence order are Presidio's
  (`[pii, trusted_wallet, policy, replay, mpa]`, first-failure-wins, MPA
  timeout -> REFER). A general recompute layer would parameterize `f`; this
  directory ships the x402 instance.

## Files

- `presidio-x402-verdict-not-recomputable.record.json` — the APS-valid record plus
  `presidio_x402_ext.controls`, the `presidio_recompute_expected` / recorded `decision`
  pair, and the proposed `recompute_rejection_kind: recompute_mismatch` envelope field.
- `recompute_check.py` — standalone (stdlib only) implementation of `f(controls)`;
  loads both this record and the PART-1 positive and shows the discriminator
  behavior.
- `README.md` — this file.

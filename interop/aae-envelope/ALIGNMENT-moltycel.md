# Alignment: APS AAE-envelope vectors ↔ MoltyCel signed-JWS vectors

**APS's canonical vectors (`V1` to `V4` in this directory) are the source of truth.**
The files under [`moltycel-format/`](./moltycel-format/) are a **one-time
cross-encoding** of those four scenarios into MoltyCel's published signed-JWS
conformance-vector format (`draft-kroehl-agentic-trust-aae-00`), produced once to
demonstrate that the APS verifier and MoltyCel's reference verifier agree on the
four overlapping scenarios. The cross-encoding is **not** a maintained parallel
set and is not kept in sync; if the canonical vectors change, the canonical
vectors win and the cross-encoding is regenerated or discarded.

## What was run

- **APS canonical (source of truth):** `interop/aae-envelope/verify.ts` →
  `V1 ACCEPT, V2 REJECT (SCOPE_WIDENING), V3 REJECT (DELEGATION_EXPIRED),
  V4 REJECT (DELEGATION_REVOKED)`. All four pass.
- **APS scenarios in MoltyCel format:** `moltycel-format/` signed JWS, schema-validated
  against `schema/vector-schema.json` and run through MoltyCel's reference verifier
  `examples/python-verify.py`. 4/4 valid + decided as expected.
- **MoltyCel's own overlapping vectors (02/06/07/11):** run through their reference
  verifier: all behave exactly as their rationales state (their full suite: 15/15).

## Mapping (four overlapping scenarios, outcomes agree)

| APS canonical | APS reason code | APS verdict | Cross-encoded (ours, JWS) | MoltyCel vector | MoltyCel verdict (their verifier) | AAE section |
|---|---|---|---|---|---|---|
| `V1-narrowing-valid` | n/a | ACCEPT | `aae-vector-91` ACCEPT @9 | `06-delegation-valid-depth-2` | ACCEPT @ step 9 | §3, §5 step 9 |
| `V2-widened-scope-reject` | `SCOPE_WIDENING` | REJECT | `aae-vector-92` REJECT @9 `delegated_actions_not_subset` | `07-delegation-action-superset` | REJECT @ step 9 `delegated_actions_not_subset` | §3 (actions subset), §5 step 9 |
| `V3-expired-parent-reject` | `DELEGATION_EXPIRED` | REJECT | `aae-vector-93` REJECT @9 `expired_not_after` | `02-expired-not-after` | REJECT @ step 3 `expired_not_after` | §2.4 (not_after), §5 step 3/9 |
| `V4-revoked-parent-cascade-reject` | `DELEGATION_REVOKED` | REJECT | `aae-vector-94` REJECT @9 `ancestor_revoked` | `11-delegation-cascade-revocation` | REJECT @ step 9 `ancestor_revoked` | §6.5 (delegation revocation), §5 step 9 |

**The four overlapping outcomes agree:** ACCEPT/REJECT matches in every row, and the
rejection causes line up (scope-widening, expiry, revocation). **Both treat cascade
revocation at check time**: a revoked parent invalidates the descendant *when the
chain is verified* (APS: `verifyDelegation` consults revocation state during the pass;
MoltyCel: §5 step 9 applies the revocation check to each ancestor). Neither defers to a
later lookup.

> Step-number nuance (not a disagreement): MoltyCel's `02-expired-not-after` rejects at
> **step 3** because the *presented root* AAE is itself expired, whereas APS `V3` (and its
> cross-encoding `aae-vector-93`) rejects at **step 9 `expired_not_after`** because the
> *parent* is expired while the presented child is still current (a cascade). Same expiry
> outcome; the step differs only because of where the expired credential sits in the chain.

## Three differences

1. **Format: signed JWS vs unsigned envelope.** MoltyCel's vectors are EdDSA-signed
   JWS in compact serialization, with signing keys resolved from DID documents
   (`testkeys/did-documents/`) and a per-step signature/signing-authority check
   (§5 step 1). APS's canonical `V1` to `V4` are unsigned AAE-shape JSON
   (`{"chain":[parent,child]}`); APS's `verify.ts` adapter maps them onto APS
   delegations and signs internally with ephemeral keys before running the shipped
   verifier. The cross-encoding bridges this by signing our four scenarios with
   MoltyCel's committed public test keys.

2. **Cascade normative strength: AAE SHOULD vs APS enforced.** AAE §6.5 states a
   relying party that determines a parent AAE is revoked **SHOULD** treat all
   descendants as invalid (MoltyCel's reference verifier implements that SHOULD as a
   step-9 reject). APS **enforces** the cascade: the verifier rejects the chain when an
   ancestor is revoked or expired. It is not optional. The outcomes coincide here, but
   APS's requirement is stronger than the AAE draft's normative language.

3. **Constraint-monotonicity coverage: AAE has it (08/15), our four do not.** AAE
   covers delegated-constraint monotonicity with dedicated vectors:
   `08-delegation-constraint-relaxation` (a child relaxing a numeric cap) and
   `15-currency-mismatch-delegation` (a child changing currency). APS's four canonical
   vectors exercise only action-narrowing, expiry, and revocation; they do **not** cover
   constraint monotonicity, so the cross-encoded files carry empty `constraints`. This is
   a coverage gap in our four relative to AAE, not a disagreement, a candidate for a
   future APS vector, tracked separately from this one-time artifact.

## Reproduce

Prerequisite: `verify.ts` loads the shipped APS SDK from `$HOME/agent-passport-system/dist/src/index.js` by default. Build the SDK there, or set `APS_SDK_PATH` to your built `dist/src/index.js`. The cross-encoding steps expect MoltyCel's repo at `/tmp/aae-moltycel` (override with `AAE_MOLTYCEL_REPO`).

```
# APS canonical (source of truth)
cd aps-conformance-suite && npx tsx interop/aae-envelope/verify.ts

# cross-encoding: rebuild + schema-validate + run through MoltyCel's verifier
cd interop/aae-envelope/moltycel-format
python3 build_moltycel_format.py
python3 crossverify.py

# MoltyCel's own suite (overlapping 02/06/07/11)
cd /tmp/aae-moltycel && python3 examples/python-verify.py
```

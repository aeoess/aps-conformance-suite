# constraint-monotonicity/ (ONE-TIME cross-encoding, NOT a maintained set)

Two APS constraint-monotonicity scenarios, cross-encoded into MoltyCel's signed-JWS
conformance-vector format and verified against his reference verifier. These parallel
MoltyCel's vectors 08 (numeric cap relaxation) and 15 (currency change), closing the
constraint-monotonicity gap that the parent `ALIGNMENT-moltycel.md` recorded.

APS's canonical vectors remain the source of truth. This directory is a one-time
alignment artifact, not a maintained parallel set.

## Vectors

| File | id | Scenario | MoltyCel parallel | Verifier result |
|---|---|---|---|---|
| `A-cap-relaxing-reject.json` | aae-vector-95 | child raises a numeric cap (1000 USD vs parent 500 USD) | `08-delegation-constraint-relaxation` | REJECT @ step 9 `delegated_constraint_relaxed` |
| `B-currency-change-reject.json` | aae-vector-96 | child changes the cap currency (300 EUR vs parent 500 USD) | `15-currency-mismatch-delegation` | REJECT @ step 9 `delegation_currency_mismatch` |

Both schema-validate against `schema/vector-schema.json` and are REJECTED by
`examples/python-verify.py` with the reasons above (`crossverify.py`: 2/2).

## How APS grounds these (run `node aps_grounding.mjs`)

The cross-encoded vectors are grounded in the shipped APS SDK, not just copied from
MoltyCel. The two scenarios ground differently, and the difference is reported here
rather than hidden.

### A, cap-relaxing: enforced natively by APS core narrowing

APS core `subDelegate` enforces numeric cap monotonicity at sub-delegation time:

```
A relax 500->1000 (same unit):   REJECTED -> Spend limit 1000 exceeds parent remaining 500
A tighten 500->300 (same unit):  ACCEPTED (valid narrowing); child limit=300
```

This is a direct, sub-delegation-time match to MoltyCel 08: a child may tighten a
numeric cap, never raise it. APS rejects (throws); MoltyCel rejects at step 9
`delegated_constraint_relaxed`. Strong alignment.

### B, currency-change: APS rejects, but at a different layer and reason code

This is the honest caveat. APS core `subDelegate` does NOT model fiat currency. Its
`spendLimitUnit` is a unit tag (`currency` or `invocations`), and a unit change is
accepted, not rejected:

```
B core subDelegate unit change:  ACCEPTED (no throw); child unit=invocations   <-- core gap
```

APS does enforce currency, but in the v2 payment-rails layer at enforcement time
(`preAuthorize`), comparing the delegation currency against the request currency:

```
B payment-rails EUR vs USD deleg:  {"ok":false,"denial_reason":"spend_limit_exceeded","reason_detail":"currency mismatch: delegation=USD request=EUR"}
B payment-rails USD vs USD deleg:  {"ok":true}
```

So the OUTCOME agrees (a currency that does not match the parent bound is rejected),
but three things differ from MoltyCel 15, and none are papered over:

1. Layer: MoltyCel rejects at sub-delegation link check (step 9). APS rejects at
   enforcement time (`preAuthorize`), not in `subDelegate`.
2. Reason code: MoltyCel uses `delegation_currency_mismatch`. APS folds currency
   mismatch into `spend_limit_exceeded` (with a `reason_detail` string).
3. Primitive: MoltyCel treats currency as a first-class constraint dimension on the
   delegation. APS core narrowing has no fiat-currency dimension; the v2 payment-rails
   hook supplies it.

The cross-encoded B vector still REJECTS under MoltyCel's verifier (it is a valid AAE
scenario), and APS would also reject the equivalent spend, so the conformance outcome
holds. The mechanism divergence is the finding to carry forward (a candidate for a
dedicated APS currency-monotonicity check at the narrowing layer).

UPDATE 2026-06-19: that check shipped. Core `subDelegate` now rejects a spend-unit
change once the parent carries a spend dimension (a spend limit or an explicit unit),
so the "core gap" shown above is closed; see agent-passport-system commit 938bdfb. The
grounding block above is retained as the pre-fix historical record. With the check in
place, B core now REJECTS the unit change at the narrowing layer (throws), which tightens
the layer alignment with MoltyCel 15 (both reject at the link check). Point 2 still holds:
APS reports this through the spend-unit guard, not a dedicated `delegation_currency_mismatch`
token. A unitless, unconstrained parent is unaffected; a child may still introduce a unit
there, which is narrowing rather than conversion.

## verification_mode (issue #2)

The MoltyCel clone used (`github.com/MoltyCel/aae-conformance-vectors`, HEAD c8dcce8,
post v1.0.0) carries no `verification_mode` field (enforced vs asserted) in its schema,
vectors, or verifier. There was nothing to mirror; if it lands upstream, these vectors
should be revisited.

## Reproduce

Requires the MoltyCel clone (default `/tmp/aae-moltycel`, override `AAE_MOLTYCEL_REPO`);
needs `cryptography` and `jsonschema`. APS grounding needs the built APS SDK
(`$HOME/agent-passport-system/dist`, override `APS_SDK_PATH`).

```
python3 build_constraint_vectors.py   # re-emit A and B (deterministic, MoltyCel public test keys)
python3 crossverify.py                # schema + MoltyCel reference verifier
node aps_grounding.mjs                # what the shipped APS SDK actually does
```

# action-ref-v1 recomputation negatives

Cross-stack fixtures for the action-ref-v1 **recomputation property**: a
verifier recomputes `action_ref` from the invocation payload's
`{action_type, agent_id, scope, timestamp}` tuple and MUST fail closed,
before invocation, when the claimed `action_ref` does not match. The verifier
never retries alternative preimages, never coerces field types, and never
normalizes field values to force a match.

Provenance: see [`SOURCE.md`](./SOURCE.md). The set was authored for the
argentum-core `examples/conformance/` shape conventions and mirrored here.

## Contents

| Section | Vectors | What it holds |
|---------|---------|---------------|
| `positive_fixture` | 5 | Tuples that recompute byte-identical: basic, unicode fields, empty scope, `.000` and `.999` millisecond edges. Each digest byte-checked across the shipping SDK path and a stdlib-only path. |
| `negative_fixture` | 9 | Drifted claims that MUST fail closed. Every `claimed_action_ref` is a real SHA-256 digest of a stated drifted byte form carried in the vector. |

## Negative drift families

| Family | Vectors | Drift behind the claim | Forbidden recovery move |
|--------|---------|------------------------|-------------------------|
| `field_order_drift` | `neg-a01`, `neg-a02` | Serialization in received field order, no JCS key sort | Rehashing the drifted byte order (preimage retry) |
| `timestamp_form_drift` | `neg-b01`, `neg-b02`, `neg-b03` | Epoch-ms integer, second-precision RFC 3339, six-digit-microsecond forms of the same instant | Converting between timestamp forms and rehashing (normalization retry) |
| `casing_drift` | `neg-c01`, `neg-c02` | `agent_id` letter casing changed between payload and claim preimage | Case folding before comparison |
| `payload_drift` | `neg-d01`, `neg-d02` | Payload `scope` / `action_type` differs from the tuple behind the claim | Substituting the claim's original tuple for the payload tuple |

`neg-b01` carries the drifted form in the invocation payload itself: the
claim matches the payload bytes verbatim, and only the timestamp grammar gate
rejects it. The other eight fail on canonical digest mismatch.

## Run

```
node run.mjs
```

Exit `0` when every positive is `MATCH` on both paths and every negative is
`FAIL-CLOSED` at the expected stage (grammar reject or recompute mismatch).
Exit `1` otherwise. Output is written to `results.json`. The verifier under
test has a single code path: grammar gate, one canonical recomputation, one
comparison. The fixture-integrity block recomputes the drifted digests only
to check the fixture data itself; it never feeds the verifier verdict.

## What these fixtures do NOT cover

Recomputation agreement only. Passing this set does not establish:

- **Policy correctness.** Nothing here checks that the action was permitted
  by any policy, or that a policy was evaluated at all.
- **Snapshot application.** Nothing here checks that any policy or state
  snapshot was applied at admission time.
- **Authorization.** A byte-identical recomputation says the claim binds to
  the stated tuple; it says nothing about whether the agent held authority
  to perform the action.
- **Occurrence.** A matching `action_ref` does not establish that the action
  happened, only that the identifier is consistent with the stated preimage.

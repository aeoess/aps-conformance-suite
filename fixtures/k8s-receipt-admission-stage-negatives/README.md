# Candidate stage negatives for kube-agentic-networking #298

Authored by AEOESS. These extend the receipt-admission stage family on kubernetes-sigs/kube-agentic-networking#298 (head `4055d9f173`) with negative directions it does not yet exercise. Same shape and bar as that set: every verdict reproduces from this file alone under the closed `stage_to_kind_to_verb` table. Self-checked, 5/5 reproduce.

## What each asserts

- `cand1` cross-stage, reverse of `st3`: a commitment at controller-observed-object checked at agent-declared. Object kind both sides, stages differ, so the divergence is the pipeline, not tamper: `cross_stage_digest_mismatch`.
- `cand2` / `cand3` stage-kind both directions anchored on agent-declared. `st5` and `st6` both anchor on controller-observed-object; these land the same two category errors on the agent-declared object stage: `stage_kind_mismatch`.
- `cand4` / `cand5` the `unknown_stage` verdict, which the enum defines but no `#298` vector exercises, from the required side and the commitment side.

## Coverage against #298

- cross_stage: `st3` covers agent-declared to controller-observed-object; `cand1` covers the reverse.
- stage_kind: `st5` and `st6` anchor on controller-observed-object; `cand2` and `cand3` anchor on agent-declared.
- unknown_stage: not exercised by `#298`; `cand4` and `cand5` cover both sides.

## Open design question, not authored as a vector

A cross-stage object case where the two object stages produce the same digest, no defaulting between agent-declared and controller-observed-object, is ambiguous under the current table. The stage difference points at `cross_stage_digest_mismatch`, but the digests are equal, which reads like `bound`. We did not author a vector for it, since the verdict is a table-design decision rather than something to assert unilaterally.

# Provenance: action-ref-v1 recompute-negative vectors

`vectors.json` in this directory mirrors a fixture set that was authored for
the shape conventions of the `argentum-core` repository
(`examples/conformance/`, giskard09/argentum-core): fixture JSON layout with
`fixture_id` / `preimage_format` / `jcs_payload` / `*_bytes_hex` fields,
vector id idioms (`0001-*` positives, `neg-x0N-*` negatives), a per-directory
README, and a standalone stdlib runner.

## Source

- Authored on: 2026-06-11
- Authored in: a local clone of `giskard09/argentum-core` at
  `examples/conformance/recompute-drift-v1/`
- Local branch: `fixtures/action-ref-v1-recompute`
- Local commit: `43223a658b6805c68a679f258a1dfb1a16964338`
- Base commit (upstream `main` at clone time):
  `6e6eaacd` ("fix: include conformance_source in get_payg_account SELECT")
- The branch exists only in the local clone. Nothing was pushed, so no
  upstream URL is claimed for the fixture files themselves. The argentum-core
  spec the vectors target is public:
  https://github.com/giskard09/argentum-core/blob/action-ref-v1.0/docs/spec/action-ref.md

## How the digests were produced

- Positive `action_ref` values: computed with the shipping
  `computeExternalActionRefV1` from the agent-passport-system build
  (`dist/src/core/external-action-ref.js`), then recomputed with a second,
  stdlib-only path (node:crypto SHA-256 over a minimal RFC 8785
  canonicalization for a flat four-string object) and byte-checked equal.
- Negative `claimed_action_ref` values: real SHA-256 digests of the stated
  drifted byte forms (non-canonical field order, non-canonical timestamp
  forms, recased agent_id, changed tuple field), computed with the stdlib
  path. No digest in this set is invented.

## What was changed relative to the authored fixture set

`vectors.json` wraps the two argentum-convention fixture objects
(`positive_fixture`, `negative_fixture`) verbatim under one top-level object
with schema metadata. The vector contents are byte-identical to the files on
the local branch.

## Companion files

- `README.md`: property under test, drift-family map, not-covered list.
- `run.mjs`: recomputation runner (SDK import plus stdlib-only recompute).
- `results.json`: machine-readable output of the last `run.mjs` run.

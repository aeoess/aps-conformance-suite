# moltycel-format/ — ONE-TIME cross-encoding (NOT a maintained set)

These four files are a **one-time cross-encoding** of APS's canonical AAE-envelope
vectors (`../V1-narrowing-valid.json` … `../V4-revoked-parent-cascade-reject.json`)
into MoltyCel's published **signed-JWS** conformance-vector format
(`draft-kroehl-agentic-trust-aae-00`).

**APS's canonical vectors in the parent directory remain the source of truth.**
This directory exists only to demonstrate that the APS verifier and MoltyCel's
reference verifier agree on the four overlapping scenarios. It is **not** kept in
sync with the canonical set and should not be treated as a parallel corpus.

See [`../ALIGNMENT-moltycel.md`](../ALIGNMENT-moltycel.md) for the mapping table
and the three documented differences.

## Contents

| File | id | APS canonical source | Expected (MoltyCel verifier) |
|---|---|---|---|
| `V1-narrowing-valid.json` | aae-vector-91 | `../V1-narrowing-valid.json` | ACCEPT @ step 9 |
| `V2-widened-scope-reject.json` | aae-vector-92 | `../V2-widened-scope-reject.json` | REJECT @ step 9 `delegated_actions_not_subset` |
| `V3-expired-parent-reject.json` | aae-vector-93 | `../V3-expired-parent-reject.json` | REJECT @ step 9 `expired_not_after` |
| `V4-revoked-parent-cascade-reject.json` | aae-vector-94 | `../V4-revoked-parent-cascade-reject.json` | REJECT @ step 9 `ancestor_revoked` |

## Reproduce

Requires the MoltyCel repo clone (default `/tmp/aae-moltycel`, override with
`AAE_MOLTYCEL_REPO`); needs `cryptography` and `jsonschema`.

```
python3 build_moltycel_format.py   # re-emit the four signed-JWS vectors (deterministic)
python3 crossverify.py             # schema-validate + run through MoltyCel's reference verifier
```

The JWS are signed with MoltyCel's committed **public test keys** (registry +
agent-a) and verify against their offline DID documents. Those keys are for
testing only.

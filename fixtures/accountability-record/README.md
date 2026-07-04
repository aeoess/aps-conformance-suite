# Accountability Record fixtures

A signed record that attests one thing: the enforcement-boundary decision over a
single agent action (allow, deny, or halt) and whether that action executed. The
record shape is derived from the agent-passport-system receipt primitives (the
decision-receipt predicate, the execution-envelope field convention, and the
content-addressed `action_ref` from draft-pidlisnyi-aps-00 §4.1), so an
accountability record reuses the same canonicalization and signing rules as the
rest of the corpus rather than defining its own. Canonicalization is RFC 8785
(JCS). The signing preimage is the RFC 8785 (JCS) canonicalization of the full
record with the `sig` field excluded; `sig` is the Ed25519 signature over those
bytes. The inline payload field is named `action`, matching the inline `action`
object on the SDK ActionReceipt/CommerceActionReceipt (though it is a different,
smaller shape here: type/scope/timestamp). That name also collides with the
ActivityStreams `action` verb-object, which this record does not use. `action_digest`
is the SHA-256 of the JCS of the `action` object.

## Files

- `accountability-record.schema.json`: JSON Schema (Draft 2020-12) for the record.
- `accountability-record-fixture-v1.json`: twelve deterministic test vectors.
- `generate-fixtures.ts`: regenerates the fixture from deterministic seeds.
- `verify.ts`: cold-clone verifier (byte-parity, Ed25519, digest binding).
- `validate.py`: schema validation (jsonschema Draft 2020-12) and cross-language byte-parity.
- `lib.ts`: shared primitives (vendored JCS, `computeActionRef`, digest, Ed25519).

## Vectors

| # | name | what it exercises | expected |
|---|------|-------------------|----------|
| 1 | `allow-executed-settled` | allow, executed, opaque `settlement_ref` + rail label | verifies |
| 2 | `deny-no-settlement` | deny, not executed, no settlement | verifies |
| 3 | `halt` | halt, not executed | verifies |
| 4 | `detached-payload` | `action_digest`/`action_ref` commit to a payload not inlined | verifies (payload unverified) |
| 5 | `negative-tampered-payload` | inline payload swapped so `sha256(JCS(action))` != `action_digest.sha256` | fails (digest) |
| 6 | `negative-wrong-key` | valid record signed by a different key than `signer_did` resolves to | fails (signature) |
| 7 | `negative-schema-decision` | `decision` is `permit` (decisionReceipt vocabulary), out of the boundary enum | fails (schema) |
| 8 | `negative-type-relabel` | `record_type` relabeled while keeping the original signature | fails (signature) |
| 9 | `positive-deny-executed` | `deny` with `executed:true` (recorded boundary violation); fields are independent | verifies |
| 10 | `positive-collision-same-second-a` | same second as B, so same `action_ref`, distinct `action_digest` | verifies |
| 11 | `positive-collision-same-second-b` | pair of A; proves `action_ref` is a correlation key, not a unique id | verifies |
| 12 | `negative-sig-alg-lowercase` | `sig_alg` is `ed25519` (lowercase), violating the `Ed25519` const | fails (schema) |

Two verification layers cover these. `verify.ts` (Ed25519 + digest + byte-parity) is
authoritative for the signature and digest negatives (5, 6, 8). `validate.py`
(jsonschema Draft 2020-12) is authoritative for the schema negatives (7, 12); those
records carry a valid signature over their own bytes and are rejected only by the
schema. Run both.

Vectors use synthetic test DIDs and deterministic test keypairs derived from a
published seed. No real agent identities and no private key material are in the
fixture; the private key is reproducible from `seed_input`, the public key is
published for verification.

## Verify from a cold clone

```
git clone https://github.com/aeoess/aps-conformance-suite
cd aps-conformance-suite
npm install

# TS verifier: byte-parity, Ed25519 signatures, digest binding; confirms the signature and digest negatives fail
npx tsx fixtures/accountability-record/verify.ts

# Python: schema validation (jsonschema Draft 2020-12) + cross-language JCS byte-parity; confirms the schema negatives fail
pip install jsonschema cryptography
python3 fixtures/accountability-record/validate.py

# Regenerate (deterministic; byte-stable across runs)
npx tsx fixtures/accountability-record/generate-fixtures.ts
```

`verify.ts` re-derives the signing input and canonical bytes from each record and
checks them against the stored bytes, verifies each Ed25519 signature, and checks
`action_digest` binding when the payload is inline. `validate.py` validates every
record against the schema and reproduces the canonical bytes in Python, which
confirms that two independent implementations agree on the RFC 8785 bytes.

## What the record proves, and what it does not

An accountability record attests exactly two facts about one action: the boundary
decision (allow, deny, or halt) and whether the action executed. Everything else
is outside its scope by construction.

- It does not attest that the action's outcome was correct, safe, or successful.
- It does not prove that a settlement occurred. `settlement_ref` and
  `settlement_rail` are opaque correlation hints carried for reconciliation, and
  the schema attaches no rail-specific meaning to either.
- It says nothing about the quality of the decision or the agent's behavior
  beyond the recorded verdict and the `executed` flag.

Absence of a claim in this record is not a denial of that claim; the record is
simply silent on it. What a verifier does learn: who recorded the decision
(`signer_did`), which agent acted (`agent_did`), under which delegation
(`delegation_ref`), for which beneficiary (`principal_ref`), plus a recomputable
`action_ref` and an `action_digest` it can check against the payload when it
holds one. That is the whole surface.

## Verifier notes

- **Past decision, not persisting authority.** A verified record attests that a
  boundary decision was made and signed at `issued_at`. It does not assert that the
  underlying delegation is still valid now. Checking whether the delegation is
  current (validity, expiry, revocation) is a verifier-side concern, resolved
  against live delegation and revocation state, not from this record.
- **Detached mode is a distinct status.** When `action` is absent, a
  verifier can check the signature and structure but cannot bind the payload to
  `action_digest`. It MUST report this as `payload-unverified`, distinct from a
  fully verified record, rather than treating a good signature as payload proof.
- **Key resolution is out of band.** The record carries `signer_did`, not a key.
  Resolving `signer_did` to the Ed25519 verification key (DID resolution, a key
  registry, or the fixture's published `keypair.publicKeyHex` here) happens outside
  the record. The signature says nothing until the resolver binds the DID to a key.
- **Which verifier is authoritative.** The dedicated `verify.ts` and `validate.py`
  are authoritative. The generic suite runner (`runners/ts/verify.ts`) skips these
  vectors by design (they are `record`-shaped, not canonicalization `input`
  vectors); its per-file SHA-256 gate still detects any tampering of the fixture.

## Non-goals

- **Multi-signer composition.** Each record carries one recorder signature.
  Countersignatures, threshold signing, and multi-party attestation are out of
  scope for v0.1.
- **Rail-specific settlement types.** `settlement_ref` and `settlement_rail` are
  opaque and rail-neutral. This family does not define typed settlement objects
  for any specific payment or clearing rail.
- **Outcome attestation.** The record fixes the boundary decision and execution
  status, not the result. Attesting what an action actually accomplished belongs
  to a separate receipt type.
- **Audience and tenant binding.** The record does not name an intended audience
  or bind to a tenant. It carries no `audience`/`tenant` field, and nothing here
  scopes who may rely on it or in which tenant it is valid. That binding, if
  needed, belongs to the transport or an enclosing envelope.
- **Scope-versus-delegation validation.** The record does not check that the
  action's scope is actually covered by `delegation_ref`. `action.scope`
  and `delegation_ref` are recorded as asserted; verifying that the delegation
  grants the scope (and the monotonic-narrowing chain behind it) is a verifier-side
  concern against delegation state, not part of this record.

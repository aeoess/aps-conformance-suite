# Read fidelity receipt fixtures

A read fidelity receipt proves sampled readback fidelity at the stated n under
the declared sampling assumptions. It does not prove every byte was read
correctly, does not prove perception or comprehension, does not prove which
channel was used, and carries no normative pass threshold: the consumer judges
k of n. Fidelity is evidenced at the sampled positions only; nothing is
claimed about unsampled bytes, and a model may reproduce spans from prior
knowledge of the content without reading the presentation.

A word_digest_handle MUST be resolved against a full digest or a
collision-checked set and MUST NOT serve as a sole record identifier, a
secret, or wallet material. Handles are never rendered in 12, 15, 18, 21, or
24 word groupings; those lengths read as seed phrases.

This family is about read fidelity of perceived content, a different question
from whether an action or verification pipeline executed correctly.

## Record and handle construction

The record is a signed commitment to a sampled readback challenge. A verifier
supplies a nonce, spans are drawn deterministically from a seed bound to that
nonce and to the exact content and presentation digests, and the record
carries sha256 commitments of the span texts plus the scored result (k of n).
Raw span texts and responses are never in the record. Canonicalization is
RFC 8785 (JCS); the signing preimage is the JCS of the record with the `sig`
field excluded entirely, and `sig` is the Ed25519 signature over those bytes.
The seed derivation is the replay binding:

```
seed = sha256hex( utf8( JCS({
         content_digest,
         presentation_digest,   // null when absent
         nonce,
         version
       }) ) )
```

RFC 8785 JCS preimage (keys sorted), so `presentation_digest` is a distinct
member (null when absent) rather than an empty string spliced against the
nonce. Verifiers recompute the derivation and reject a mismatch even when the
signature is valid, so replaying span commitments under a different nonce,
content, or presentation fails even after a re-sign.

Word handle vectors exercise the word_digest_handle codec over the pinned
lexicon `aps-handle-en-v1` (2048 words, lexicon_id
`sha256:2a9c4de3b5457154e6bde9d40af0da552c2556d8e80a2dec8b82dee4bca74510`,
profile `single-list-v1`). Data word i is bits [11i, 11i+11) of the digest,
MSB-first; the checksum words are drawn from
`sha256(BE16(prefixBits) || packedPrefix)`. The construction is
position-dependent: the hash runs over the ordered packed bits, so
substituting or transposing data words fails the checksum with probability
1 - 2^-11 per event for one checksum word (1 - 2^-22 for two).

## Files

- `read-fidelity-receipt.schema.json`: JSON Schema (Draft 2020-12) for the record.
- `read-fidelity-receipt-fixture-v1.json`: eight deterministic test vectors.
- `generate-fixtures.ts`: regenerates the fixture from deterministic seeds and a FIXTURE-ONLY key.
- `verify.ts`: cold-clone verifier (byte-parity, Ed25519, seed derivation, span commitments, handle codec).
- `validate.py`: schema validation (jsonschema Draft 2020-12), cross-language byte-parity, seed and checksum math.
- `lib.ts`: shared primitives (vendored JCS, Ed25519, word handle codec, sampler, record verification).
- `wordlist.ts`: the pinned lexicon, generated from the SDK lexicon data file (never hand-typed).

## Vectors

| # | name | what it exercises | expected |
|---|------|-------------------|----------|
| 1 | `v1-positive-full-readback` | valid signed record, k == n, optional lexicon fields | verifies |
| 2 | `v2-negative-handle-substitution` | one data word replaced with another lexicon word | fails (checksum) |
| 3 | `v3-negative-handle-out-of-lexicon` | two words outside the lexicon; indices reported | fails (out_of_lexicon) |
| 4 | `v4-negative-tampered-content-digest` | content_digest swapped after signing, stale sig kept | fails (signature) |
| 5 | `v5-positive-honest-partial` | recorded k=4 of n=6; no pass threshold in the format | verifies with recorded k |
| 6 | `v6-negative-replayed-nonce` | same commitments and responses, different nonce, RE-SIGNED | fails (seed) |
| 7 | `v7-negative-presentation-digest-mismatch` | presentation_digest swapped, RE-SIGNED | fails (seed) |
| 8 | `v8-negative-handle-transposition` | adjacent differing data words swapped | fails (checksum) |

Every negative fails for its STATED reason (`expected_reason`), and both
verifiers print the stated reason next to the actual one. The two re-signed
negatives (6, 7) carry signatures that ARE valid over their own bytes; they
are rejected only by the seed derivation recompute, which is the replay
binding doing its job. The tampered negative (4) is rejected by the
signature. The handle negatives (2, 3, 8) are rejected by the codec.

Both verifiers cover the family. `verify.ts` is authoritative for the
Ed25519 signatures, the span commitment recompute against the source text,
and the word-to-index mapping of the vendored lexicon. `validate.py` is
authoritative for the schema and independently reproduces the JCS bytes, the
seed derivation, and the handle checksum math in Python, which confirms that
two implementations agree. Run both.

The signing key is FIXTURE-ONLY: the private key is sha256 of the published
`seed_input` string, reproducible by anyone, and must never be used outside
this fixture. No real identities and no private key material are in the
fixture file.

## Verify from a cold clone

```
git clone https://github.com/aeoess/aps-conformance-suite
cd aps-conformance-suite
npm install

# TS verifier: byte-parity, Ed25519, seed derivation, span commitments, handle codec
npx tsx fixtures/read-fidelity-receipt/verify.ts

# Python: schema validation + cross-language JCS byte-parity + seed and checksum math
pip install jsonschema cryptography
python3 fixtures/read-fidelity-receipt/validate.py

# Regenerate (deterministic; byte-stable across runs)
npx tsx fixtures/read-fidelity-receipt/generate-fixtures.ts
```

## Verifier notes

- **The consumer judges k of n.** `expected_verification` is about record
  validity, not readback quality. Vector 5 verifies TRUE with k < n; whether
  4 of 6 is acceptable is a consumer policy question outside this family.
- **Signer versus executor.** `attester` is the SIGNING identity and may
  differ from the executing model. `model_claim` and `runtime_claim` are
  claims about the executor, and `verification_method` records whether they
  are merely `asserted` or backed by a `provider_attestation`. This fixture
  uses `asserted` throughout; nothing here proves which model produced the
  readback.
- **Nonces are single-use.** The record format cannot enforce nonce
  freshness across records; tracking nonce reuse over time is a
  verifier-side concern. What the seed derivation does enforce is that a
  given record's commitments are bound to its own nonce, content, and
  presentation.
- **Timestamps are caller-provided.** All three timestamps are asserted by
  the attester; the fixture pins fixed values and no library code reads a
  wall clock.

## Non-goals

- **Readback transcripts.** The record carries commitments and digests only.
  Publishing raw span texts or responses, when appropriate, happens outside
  the record.
- **Channel attestation.** The record cannot prove which input channel
  produced the readback; that limitation is stated in the lead paragraph and
  is a documented property of the format, not a fixture gap.
- **Handle registries.** Word handles here appear only as codec vectors. How
  a consumer maintains the collision-checked set that a handle resolves
  against is out of scope for this family.

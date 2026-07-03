# Two-wrapper attribution pair (Path B recording wrapper, vocab #36)

Two independent attribution wrappers over one shared base receipt. Fulfils the public commitment in
agent-governance-vocabulary issue #36 (github.com/aeoess/agent-governance-vocabulary/issues/36):
demonstrate that two emitters can each record an attribution wrapper over the SAME base receipt
digest, each independently verifiable, without either wrapper's authority leaking into the other.

## Base receipt

Source: the canonical public SAR-402 settlement receipt, resolved from the authoritative
DefaultVerifier endpoint:
  GET https://defaultverifier.com/v1/attest/receipt/sha256%3A91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9
Fetched 2026-07-02, HTTP 200, application/json. Raw served bytes hash to
sha256:298aacca59df797ccf2b142c7f6d270ac052b192bb41dca8501a918f80e1de5e. The same record also
resolves identically at https://sarexplorer.com/v1/attest/receipt/sha256%3A91e2... .

The served document self-declares its content address in two places, both equal to the value the
wrappers bind:
  receipt_id                = sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9
  receipt.integrity.digest  = sha256:91e2ae85...b8c9  (canonicalization "sorted_keys_compact_v0")
The full served document is embedded verbatim as `wrapper.receipt` in each wrapper (see
base-receipt.json for the provenance copy). Because the served document is itself shaped
`{receipt_id, ..., receipt:{...integrity:{digest}}}`, the embedded receipt carries the bound digest
at `receipt.integrity.digest` relative to itself, matching the vocab #36 schema.

## Verification boundary (read this before trusting the base digest)

The base digest `sha256:91e2ae85...` is an OPAQUE CONTENT ADDRESS. It is authoritatively resolvable
at the URLs above and self-declared by the emitter, but it is NOT independently recomputable from the
served record. Per the SAR-402 demo documentation (https://sarexplorer.com/demo/sar-402), the
receipt_id "is the inbound integrity.digest, a content hash the resource server computed, adopted
(not generated) by DefaultVerifier." The preimage is the resource server's original delivered object,
computed before DefaultVerifier wrapped and re-served it; it is not reconstructable from the composite
record now served. A 16-preimage reproduction attempt under the declared "sorted_keys_compact_v0"
canonicalization (inner receipt with/without integrity, whole document minus the self-referential
digest fields, null-dropped and compact/spaced separator variants) did not reproduce the target, as
expected for an adopted inbound hash.

What this means for this corpus: the wrappers BIND to the content address; they do not attest its
preimage. A preimage publication by the emitter would upgrade this fixture from "binds an authoritative
address" to "binds a recomputable digest"; that is pending on the emitter (vocab #36) and is not a flaw
of the emitter. It is stated here as the verification boundary of the fixture, not a defect.

## Wrapper schema

Path B recording wrapper, per nutstrut's schema description in vocab #36 (comment 2026-07-02T14:06:04Z).
No emitter code produces this shape yet; it is a proposed interop shape defined in the #36 thread, so
there is no emitter-vs-thread divergence to reconcile. Fields, all inside the signed body:
  wrapper_version, wrapped_receipt_digest, recorded_by, recording_service, recording_key_id,
  recording_event_id, recording_context ("ingestion"), source_evidence_created_by ("resource_server"),
  receipt (the embedded base document), recording_signature { kid, alg, sig }.
The signed body is the wrapper MINUS recording_signature. Both wrapped_receipt_digest and the embedded
receipt.integrity.digest are inside the signed body, so substituting the bound base breaks verification.

Deferred additive fields NOT included (per the thread, pending): an emitter-registry URI and an
authorization_basis field. When those are specified they extend this fixture; they are omitted here to
match the current thread schema exactly.

## Canonicalization and signatures

Signature convention matches the suite's existing fixtures (composition/envoys-rfc9421): the signed
preimage is `sha256(canonicalize(body))` signed as its UTF-8 hex string with Ed25519, where
canonicalize is the APS null-stripping, key-sorted canonical form ported from
agent-passport-system src/core/canonical.ts (the signObject convention in v2/bridge.ts).

Two FIXTURE-ONLY Ed25519 keypairs (emitter-a, emitter-b) derive deterministically from fixed synthetic
seeds in generate.ts (kept in keys/emitter-a.json, keys/emitter-b.json with a FIXTURE-ONLY note).
These are never production keys and are never reused. Run generate.ts to reproduce every byte.

## Layout

  base-receipt.json                     provenance copy of the fetched served document
  keys/emitter-a.json, emitter-b.json   FIXTURE-ONLY seeds + public keys
  keys/registry.json                    kid -> public-key-hex, used by the verifier
  wrapper-a.json, wrapper-b.json        the two positive wrappers (same base, distinct recording identity)
  negatives/neg-01-substituted-base.json    base digest swapped after signing -> fails
  negatives/neg-02-kid-cross-key.json       signature verified against the wrong emitter key -> fails
  negatives/neg-03-tampered-event-id.json   recording_event_id altered after signing -> fails
  lib.ts, generate.ts, verify.ts        helpers, deterministic generator, standalone verifier

Run: `npm run verify:two-wrapper-attribution` (also part of `npm test`).

## What this corpus does and does not cover

It covers: independent Path B recording-wrapper signatures over one shared base receipt digest, the
identity of that bound digest across both wrappers, cross-key isolation, and fail-closed behaviour on
digest substitution, kid mismatch, and post-signing tampering. It does NOT attest the base receipt's
digest preimage (an adopted inbound content address, see the verification boundary above), the base
receipt's settlement truth, or DefaultVerifier's own issuance signature (the demo receipt carries none:
"Recorded evidence only; no DefaultVerifier signature").

## Update: digest preimage pinned (Path A property)

The emitter published the original payload and the preimage rule
(`receipt_id = sha256(sorted_keys_compact_v0(payload minus integrity))`).
We verified the recompute independently: the payload at
https://github.com/nutstrut/attest-service/blob/main/reports/sar402/path-a-demo/sar402-canonical-public-demo-v2-20260623T234156Z.payload.json
hashes to `sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9`
under that rule. The digest is therefore independently recomputable from public data,
the full Path A property. The resolver response remains the lookup envelope; it was
never the preimage. Wrappers unchanged.

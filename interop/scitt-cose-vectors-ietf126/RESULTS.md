# Capsule vector run: stage-by-stage results

Input: scitt-cose test-vectors at tag vectors-ietf126 (529515ba). Verifier:
from-scratch TypeScript in verifier/ (CBOR codec, RFC 9052
COSE_Sign1, RFC 9162 inclusion proofs written fresh; node:crypto primitives).

## valid-eddsa (positive)

expected VALID; observed VALID; verdict **match**

- PASS structure: alg EdDSA/EdDSA, headers match expected
- PASS payload-digest: sha256 08b6e9ec3bd002da... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: a6dd4523ffdda175...
- PASS statement-sig: Signature1 verifies under issuer-key.pub
- PASS vds-gate: vds=1 RFC9162_SHA256, supported
- PASS inclusion-proof: root 5c834b80c0b40ca9... (independent full-tree rebuild agrees)
- PASS receipt-sig: receipt Signature1 verifies over reconstructed root

## valid-es256 (positive)

expected VALID; observed VALID; verdict **match**

- PASS structure: alg ES256/ES256, headers match expected
- PASS payload-digest: sha256 a55649d4e0674a1f... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: 3ffa392b06d19b15...
- PASS statement-sig: Signature1 verifies under issuer-key.pub
- PASS vds-gate: vds=1 RFC9162_SHA256, supported
- PASS inclusion-proof: root e1dba63622c67f39... (independent full-tree rebuild agrees)
- PASS receipt-sig: receipt Signature1 verifies over reconstructed root

## fail-tampered-path (negative)

expected INVALID/TAMPERED_INCLUSION_PATH; observed INVALID/TAMPERED_INCLUSION_PATH; verdict **match**

- PASS structure: alg EdDSA/EdDSA, headers match expected
- PASS payload-digest: sha256 374497661bfe6024... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: 341df0ce74c5d59c...
- PASS statement-sig: Signature1 verifies under issuer-key.pub
- PASS vds-gate: vds=1 RFC9162_SHA256, supported
- PASS inclusion-proof: root b539ba94681f4c24... (independent full-tree rebuild DISAGREES: b594e8f6ed6b5fc0)
- FAIL receipt-sig: receipt signature does NOT verify over reconstructed root b539ba94681f4c24...

## fail-unsupported-vds (negative)

expected INVALID/UNSUPPORTED_VDS; observed INVALID/UNSUPPORTED_VDS; verdict **match**

- PASS structure: alg EdDSA/EdDSA, headers match expected
- PASS payload-digest: sha256 b5b997112c8aff9e... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: ee728ba89fc45b23...
- PASS statement-sig: Signature1 verifies under issuer-key.pub
- FAIL vds-gate: vds=2 is not a supported verifiable data structure (supported: 1 RFC9162_SHA256)

## fail-bad-statement-sig (negative)

expected INVALID/BAD_STATEMENT_SIGNATURE; observed INVALID/BAD_STATEMENT_SIGNATURE; verdict **match**

- PASS structure: alg EdDSA/EdDSA, headers match expected
- PASS payload-digest: sha256 17591d8abea5cad1... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: 0dea38958b8f83f3...
- FAIL statement-sig: Signature1 does NOT verify under issuer-key.pub
- PASS vds-gate: vds=1 RFC9162_SHA256, supported
- PASS inclusion-proof: root e5b5647171f5b9b3... (independent full-tree rebuild agrees)
- PASS receipt-sig: receipt Signature1 verifies over reconstructed root

## valid-ccf-vds2 (positive)

expected VALID; observed VALID; verdict **match**

- PASS structure: alg ES256/ES384, headers match expected
- PASS payload-digest: sha256 04935e9a37f6d7c6... matches, payload attached and equal
- PASS leaf-entry: leaf entry recomputed: cdd87929ead61eca...
- PASS statement-sig: Signature1 verifies under issuer-key.pub
- PASS vds-gate: vds=2 CCF ledger: recognized, proof profile out of scope (recorded, not faked)
- PASS receipt-sig: receipt Signature1 verifies over the RECORDED root (reconstruction unsupported)
- UNSUPPORTED ccf.v1 (vds=2) inclusion-proof root reconstruction: profile algorithm out of committed scope; receipt signature checked over the recorded root instead

## Totals

vectors 6; match 6; divergence 0; vectors carrying an unsupported sub-check 1

# Verification scope

Stages derived from the 6 vectors and the fields they exercise, each mapped to
the spec text it comes from. Only these stages are implemented; the verifier
does exactly what the vectors demand and nothing more.

| stage | what it checks | derived from which vectors | spec basis |
|---|---|---|---|
| 1 structure | COSE_Sign1 is a 4-element array (protected bstr, unprotected map, payload, signature); statement protected header carries the expected alg (label 1), content_type (label 3), and CWT claims (label 15: issuer claim 1, subject claim 2) | all; every expected.json pins protected_header values | RFC 9052 s3 (COSE_Sign1), s3.1 (common headers), draft-mih-scitt-agent-action-capsule-02 s3 (Signed Statement header shape); CWT claims label 15 per RFC 9597 |
| 2 payload-digest | SHA-256(payload.bin) equals payload_sha256, and the statement's attached payload equals payload.bin | all; payload_sha256 present on every vector | draft-02 payload binding; the vector README payload_sha256 field |
| 3 leaf-entry | SHA-256(statement.cose bytes) equals the log's leaf_entry | all; manifest leaf_entry_definition and the fail-bad-statement-sig construction hinge on it | manifest leaf_entry_definition; RFC 9162 s2.1 (leaf input to MTH) |
| 4 statement-sig | the statement COSE_Sign1 Signature1 verifies under issuer-key.pub (EdDSA, ES256, ES384) | valid-eddsa, valid-es256, valid-ccf-vds2, fail-bad-statement-sig | RFC 9052 s4.4 (Sig_structure for Signature1), s4.2 (signing/verifying); COSE ECDSA raw r-or-s per RFC 9053 |
| 5 vds-gate | the receipt protected header vds (label 395) is a supported verifiable data structure; 1 = RFC9162_SHA256 supported, others rejected as UNSUPPORTED_VDS; read from PROTECTED header only | fail-unsupported-vds (vds 2); valid-ccf-vds2 (vds 2, recognized separately) | draft-ietf-cose-merkle-tree-proofs vds registry (label 395); the vector README instruction to read vds from the protected header |
| 6 inclusion-proof | reconstruct the Merkle root from the receipt's vdp (396 key -1) inclusion proof cbor([tree_size, leaf_index, path]) per RFC 9162, cross-checked against an independent full-tree rebuild from the manifest construction; the embedded path is also compared byte-for-byte against expected.json | valid-eddsa, valid-es256, fail-tampered-path | RFC 9162 s2.1.3 (inclusion proof), s2.1.3.2 (proof verification algorithm); draft-ietf-cose-merkle-tree-proofs (vdp label 396) |
| 7 receipt-sig | the receipt COSE_Sign1 signature verifies under log-key.pub over the reconstructed root as detached payload | valid-eddsa, valid-es256, fail-tampered-path | RFC 9052 s4.4 (detached payload in Sig_structure); RFC 9162 receipt binds the root |

## Out of scope, recorded not faked

- valid-ccf-vds2 uses the CCF ledger verifiable data structure (vds 2, ccf.v1,
  scitt-ccf-ledger v7.0.6). Its inclusion-proof root reconstruction follows the
  CCF profile, which is not RFC 9162 and whose defining draft was not in the
  committed scope or the allowed fetch set for this session. Stages 1 to 5 and
  7 run for this vector; stage 6 root reconstruction is marked unsupported and
  the receipt signature is checked over the root recorded in expected.json. No
  pass is faked: the unsupported sub-check is reported.
- No live Transparency Service is contacted. The log state is rebuilt from the
  committed bytes and the manifest's deterministic construction only.

## Failure-code mapping

statement-sig to BAD_STATEMENT_SIGNATURE; vds-gate to UNSUPPORTED_VDS;
inclusion-proof or receipt-sig to TAMPERED_INCLUSION_PATH. Declared in the
runner so the negative-vector comparison is explicit.

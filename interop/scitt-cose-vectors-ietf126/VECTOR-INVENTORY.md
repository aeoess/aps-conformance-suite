# Vector inventory

Source: github.com/action-state-group/scitt-cose, tag vectors-ietf126, commit
529515ba7445af0f07e5da578ad938e371e8c7a8. Manifest test-vectors/manifest.json,
version v1, stability append-only. SHA256SUMS verified: 36 files OK.

ACTUAL count: 6 vectors (2 positive, 3 negative, 1 positive out-of-band CCF).
The task expected around 32; the scitt-cose v1 suite is a focused 6-vector set,
not 32. Recorded as-is.

Each vector directory carries: statement.cose, receipt.cose, payload.bin,
issuer-key.pub (PEM), log-key.pub (PEM), expected.json. Input artifact bytes and
expected values were read only from these files plus the manifest and README.

| id | polarity | expected | failure_code | declared failing stage | notes |
|---|---|---|---|---|---|
| valid-eddsa | positive | VALID | none | none | EdDSA statement (alg -8) + RFC9162_SHA256 receipt (vds 1); everything verifies |
| valid-es256 | positive | VALID | none | none | ES256 statement (alg -7, P-256) + RFC9162_SHA256 receipt; everything verifies |
| valid-ccf-vds2 | positive | VALID | none | none | Real pyscitt did:x509 ES256 statement + real CCF ccf.v1 receipt (vds 2, ES384 P-384) from scitt-ccf-ledger v7.0.6; leaf_index/tree_size/inclusion_path all null (CCF proof, not RFC9162) |
| fail-tampered-path | negative | INVALID | TAMPERED_INCLUSION_PATH | receipt inclusion proof | first audit-path node has one flipped byte; statement is honest, only the receipt must reject; reconstructed_root null |
| fail-unsupported-vds | negative | INVALID | UNSUPPORTED_VDS | receipt vds gate | receipt protected vds (label 395) is 2 not 1; proof and signature otherwise honest; must reject on the unsupported VDS read from the PROTECTED header; reconstructed_root null |
| fail-bad-statement-sig | negative | INVALID | BAD_STATEMENT_SIGNATURE | statement signature | statement signature byte flipped; receipt is honestly minted over the digest of the tampered statement bytes (the log registered what it was given), so leaf entry and receipt verify; only the statement signature must reject |

## expected.json fields consumed

payload_sha256, protected_header.statement (alg, alg_code, content_type,
issuer, subject), protected_header.receipt (alg, alg_code, vds), leaf_entry,
leaf_index, tree_size, inclusion_path, reconstructed_root,
statement_signature_valid, receipt_valid, result, failure_code.

## Deterministic tree construction (from the manifest and README, not from code)

- leaf entry = SHA-256 of the complete COSE_Sign1 statement bytes, hex.
- RFC 9162 SHA-256 tree, tree_size 8, statement digest at leaf_index 2, every
  other leaf i = SHA-256("scitt-cose test vectors v1 :: <id> :: filler leaf <i>").
- receipt payload is the detached Merkle root; the inclusion proof lives in the
  receipt unprotected header at vdp (label 396) key -1 as
  cbor([tree_size, leaf_index, [audit_path]]).

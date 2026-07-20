# scitt-cose vectors-ietf126: independent verification run

A from-scratch TypeScript verifier for the SCITT COSE test vectors published by
Action State Group at github.com/action-state-group/scitt-cose, tag
`vectors-ietf126` (commit 529515ba7445af0f07e5da578ad938e371e8c7a8).

Context: bilateral conformance-vector exchange agreed on
mirjak/audit-bof-preparation#9. Result: all 6 v1 vectors reproduce their
declared verdicts; each negative fails at its declared stage; two full runs
produce byte-identical results.json. One profile-specific step is out of scope:
the CCF (vds=2) root reconstruction for valid-ccf-vds2. The receipt signature
is verified over the recorded root, and the boundary is recorded in RESULTS.md.

From-scratch: imports are Node builtins plus the local modules only. The CBOR
decoder is written from RFC 8949, COSE_Sign1 verification from RFC 9052
(EdDSA and ES256), the inclusion proof from RFC 9162. No third-party packages
and no code from the upstream implementation.

## Re-run

    git clone https://github.com/action-state-group/scitt-cose
    git -C scitt-cose checkout vectors-ietf126
    VECTORS_DIR=./scitt-cose/test-vectors OUT_DIR=. npx tsx verifier/run.ts
    VECTORS_DIR=./scitt-cose/test-vectors OUT_DIR=. npx tsx verifier/selfattack.ts

Reference run: sha256(results.json) =
2ed8738e9529faf5cdae5b51432ec065a6494e0a15b8e6f29733d8c2a7481db8

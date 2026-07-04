# presidio-x402 — payment-boundary accountability-record vectors

Boundary-decision records from [`presidio-hardened-x402`](https://github.com/presidio-v/presidio-hardened-x402),
a security middleware for the x402 agentic payment protocol. The recorded boundary
decision is a **PII screening + policy verdict** taken before an x402 payment is signed:
what PII the payment metadata carried, whether policy allowed the spend, and who signed
off. Records use the APS `accountability-record` shape (RFC 8785 JCS, Ed25519 over
`JCS(record minus sig)`, detached `action_digest`).

## Vectors (`presidio-x402-accountability-record-fixture-v1.json`)

Two vectors that map cleanly onto the native record checks:

- `presidio-x402-allow-pii-redacted` — positive. An x402 payment authorised after the
  EMAIL_ADDRESS in its metadata was redacted; `action.scope` carries the presidio
  screen_ref scope (`presidio:x402.screen:PII_REDACTED:EMAIL_ADDRESS`). Verifies TRUE.
- `presidio-x402-signer-equals-runtime` — negative, `rejection_kind: signature`. Identical
  decision content, but the record was signed by the actor's own payment wallet key rather
  than the policy-recorder key `signer_did` resolves to. Self-approval is not a second
  opinion; the signature is rejected against `ed25519_pubkey_hex`.

Run: `npm run verify:presidio-x402` (TS), or `python3 fixtures/presidio-x402/validate.py`
(schema + JCS byte-parity + digest binding + Ed25519, needs `jsonschema` + `cryptography`).

## `recompute-layer/` — a proposal, not a conformance fixture

`recompute-layer/` is a separate proposal (deliberately **not** registered as an APS
negative fixture). It carries one record that passes *every* native APS check yet whose
recorded `decision` does not re-derive from its own controls, motivating an optional
`recompute`/derivation verification layer. See `recompute-layer/README.md`.

## Provenance

The records recast presidio-hardened-x402's `decision_ref` / `screen_ref` conformance
vectors (merged at `giskard09/argentum-core` PR #29) into the APS accountability-record
shape. The fixture Ed25519 keys are test-only. Source discussion: x402-foundation/x402#2332,
microsoft/autogen#7353.

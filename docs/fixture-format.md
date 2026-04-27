# Fixture format

Every fixture file is a JSON document with these top-level fields:

```jsonc
{
  "version": "v1",                                  // fixture-format version
  "spec":    "JCS — RFC 8785",                       // canonicalization rule
  "spec_ref": "https://...",                         // human-readable spec link
  "seed_input":      "aps-canonicalize-fixture-v1",  // input to SHA-256 for keypair derivation
  "seed_sha256_hex": "<64-char hex>",                // sanity check on the derived seed
  "keypair":         { "publicKeyHex": "<64-char hex>" },
  "generated_at":    "2026-04-26",
  "vectors":         [ /* see below */ ]
}
```

## Per-vector fields

A vector has at minimum a `name`, `description`, and an `input`. Vectors
that participate in the canonicalization-and-signature contract carry the
full set:

```jsonc
{
  "name":        "nested-null-preservation",
  "description": "JCS preserves null values at every nesting depth.",
  "input":       { "a": null, "b": { "c": null } },
  "canonical_bytes_hex":               "<UTF-8 hex of canonical string>",
  "canonical_sha256":                  "<sha256 of canonical bytes>",
  "ed25519_pubkey_hex":                "<64-char hex>",
  "ed25519_signature_over_canonical_hex": "<128-char hex>",
  "expected_verification":             true
}
```

Negative vectors (expected-rejection) carry `expected_verification: false`
and a structured rejection identifier:

```jsonc
{
  "name":                "expected-rejection-trailing-slash",
  "description":         "Path with trailing slash; canonicalization rejects.",
  "rejection_kind":      "canonicalization",
  "expected_error_code": "TRAILING_SLASH",
  "canonicalize_input": {
    "raw":            "docs/CLAUDE.md/",
    "workingRoot":    "/Users/agent/workspace",
    "filesystemMode": "case-sensitive"
  },
  "expected_verification": false
}
```

## Deterministic keypairs

Every fixture that signs vectors derives its Ed25519 keypair from a
SHA-256 of `seed_input`:

```
seed = SHA-256(seed_input)               // 32 bytes
private key = seed                       // RFC 8032 Ed25519 seed
public key  = Ed25519 public derivation of seed
```

Implementations under test reproduce the keypair from `seed_input`,
which makes signature verification cross-language deterministic. No
secret material in the fixture; the public key is published, the
private key is reproducible from the seed.

## Categories in this suite

| Category | Format |
|---|---|
| `bilateral-delegation` | Generic JCS canonicalization vectors with `input` + `canonical_bytes_hex` + signature. |
| `inference-session` | CTEF v0.3.1 identity claims + validity windows; same canonicalization+signature shape. |
| `instruction-provenance` | IPR envelopes (positives carry `envelope`, negatives carry `rejection_kind`). |
| `aivss-scenarios` | AIVSS §3.6 structural scenarios (no canonicalization data — these are scenario specifications). |

The `aivss-scenarios` category is intentionally different — its files
describe attack scenarios with CVSS / AIVSS scores and APS-primitive
mappings, not byte-canonical inputs. Cross-implementation conformance for
these scenarios means: when run against the live APS test suite at
`agent-passport-system/tests/adversarial.ts`, every primitive named in
`aps_primitive_exercised` must produce the `expected_outcome`.

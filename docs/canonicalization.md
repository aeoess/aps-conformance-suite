# Canonicalization rules

The APS conformance suite uses **JCS canonicalization (RFC 8785)** for
every fixture vector. Implementations under test must produce
byte-identical canonical output for every vector's `input`.

## Reference algorithm

The reference TypeScript implementation lives at
`runners/ts/canonicalize.ts`. The algorithm:

1. `null` and `undefined` → `"null"`
2. Booleans → `"true"` or `"false"`
3. Numbers → `JSON.stringify(n)` (ES2015 number serialization). Reject
   `Infinity` and `NaN`.
4. Strings → `JSON.stringify(s)`
5. Arrays → `"[" + elements.map(canonicalize).join(",") + "]"`
6. Objects → sort keys by Unicode code-point ascending, emit
   `"{" + key.JSON.stringify + ":" + value.canonicalize + ","-joined + "}"`
7. `undefined` object values become `null` (RFC 8785).
8. `null` object values are **preserved** (RFC 8785; differs from APS's
   legacy canonicalizer which strips them).

## AIP-0001 adaptations

The APS SDK's JCS implementation adds these adaptations (also reflected in
the suite's runner):

- Object keys MUST be ASCII. Non-ASCII keys throw at canonicalization time.
- Whole-number floats collapse to integers (e.g., `2.0` → `"2"`).

External implementations targeting cross-implementation byte-parity should
mirror these adaptations or document where they diverge.

## Path canonicalization (IPR-specific)

The `instruction-provenance/` fixture category adds path canonicalization
on top of JCS. The algorithm is in InstructionProvenanceReceipt v0.2 §5.1.
Summary:

1. Reject empty path.
2. Reject percent-encoded paths.
3. Resolve to absolute, relative to declared `working_root`.
4. Reject if outside `working_root`.
5. Strip leading `./` and trailing `/`.
6. Reject any `..` segment.
7. Normalize Unicode to NFC.
8. Apply case mode (lowercase if `filesystem_mode` is `case-insensitive`).
9. Replace OS separators with forward slash.

Symlinks are preserved as separate entries with `is_symlink: true`; they
are NOT dereferenced.

## Determinism contract

Every fixture vector that includes `canonical_bytes_hex` and
`canonical_sha256` is a binding contract:

- An implementation that reads `vector.input` and produces canonical bytes
  whose UTF-8 hex differs from `canonical_bytes_hex` is non-conformant.
- An implementation whose Ed25519 verification of
  `ed25519_signature_over_canonical_hex` against `ed25519_pubkey_hex` and
  the canonical bytes returns `false` is non-conformant.

The reference TS runner verifies both for every applicable vector.

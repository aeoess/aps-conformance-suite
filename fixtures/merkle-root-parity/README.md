# merkle-root-parity

Cross-language byte-parity vectors for the attribution Merkle root
(receipt format v1.2, Day-145 audit). The TypeScript SDK
(`src/core/attribution.ts`), the Go SDK (`attribution` package), and the
Python SDK (`agent_passport.attribution`) must all produce the exact
`expected_root` hex for each vector. Runners recompute the root from the
leaf inputs; they do not merely check file shape.

## Construction

The tree is the hardened, domain-separated construction:

1. Sort the leaf hex strings ascending by code point.
2. Hash every leaf under the leaf tag: `sha256(0x00 || utf8(leaf_hex))`,
   lowercase hex output.
3. Fold adjacent pairs under the internal-node tag:
   `sha256(0x01 || utf8(left_hex) || utf8(right_hex))`.
4. A trailing odd node at any level is promoted unchanged. It is never
   duplicated. Duplication is the CVE-2012-2459 class defect: it lets the
   multiset `[a, b, c]` fold to the same root as `[a, b, c, c]`.
5. A single leaf yields `sha256(0x00 || leaf)`. The empty set yields
   `sha256("empty")` (no vector uses the empty set; the value is pinned in
   the SDK test suites).

All hashing operates on UTF-8 bytes of the hex strings, matching the
TypeScript reference, not on decoded raw bytes.

## Leaf derivation

`leaf[i] = lowercase_hex(sha256(utf8("aps-merkle-parity-" + i)))` with `i`
ascending from 0. Each vector also embeds the derived leaf hex values so a
runner can check its own derivation before folding.

## Vectors

Leaf-set sizes 1, 2, 3, 5, and 8 cover the single-leaf case, the fully
balanced case, and three odd-promotion shapes. The final vector pins both
the honest 3-leaf root and the root of the 4-leaf multiset that duplicates
the last leaf; a runner must recompute both and confirm they differ.

## Runner behavior

A conforming runner must, for every vector:

1. Recompute each leaf from `leaf_inputs` and compare with `leaves`.
2. Recompute the root and compare with `expected_root`.
3. If `duplicate_last_leaf_root` is present, recompute the root of
   `leaves + [last leaf]`, compare it with the pinned value, and confirm
   it differs from `expected_root`.

Any mismatch is a FAIL. Vectors in this category are never skipped.

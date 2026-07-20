// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// From-scratch RFC 9162 Section 2.1 Merkle tree machinery for the capsule
// vector verifier: leaf hash, interior node hash, and reconstruction of the
// root from an inclusion proof (audit path), written from the RFC text.
//
//   leaf hash:  MTH({d}) = SHA-256(0x00 || d)
//   node hash:  MTH = SHA-256(0x01 || left || right)
//
// Root reconstruction from (leaf_index, tree_size, path) follows the
// verification algorithm in RFC 9162 Section 2.1.3.2: walk fn = leaf_index,
// sn = tree_size - 1; for each node: if LSB(fn) set, or fn == sn, hash the
// path node on the left and right-shift both until fn has a zero LSB;
// otherwise hash it on the right; halve indices each step.

import { createHash } from 'node:crypto'

const sha256 = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

export const leafHash = (entry: Uint8Array): Uint8Array => sha256(Uint8Array.of(0), entry)
export const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array => sha256(Uint8Array.of(1), left, right)

/** RFC 9162 2.1.3.2 inclusion-proof verification, returning the reconstructed
 *  root (caller compares). Throws when the proof cannot be consumed exactly. */
export function rootFromInclusionProof(
  leafIndex: number,
  treeSize: number,
  leafEntry: Uint8Array,
  path: readonly Uint8Array[],
): Uint8Array {
  if (leafIndex >= treeSize) throw new Error('merkle: leaf_index out of range')
  let fn = leafIndex
  let sn = treeSize - 1
  let r = leafHash(leafEntry)
  for (const p of path) {
    if (sn === 0) throw new Error('merkle: path longer than needed')
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r)
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1 }
    } else {
      r = nodeHash(r, p)
    }
    fn >>= 1
    sn >>= 1
  }
  if (sn !== 0) throw new Error('merkle: path shorter than needed')
  return r
}

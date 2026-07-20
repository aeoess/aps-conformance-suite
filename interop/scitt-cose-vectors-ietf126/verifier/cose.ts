// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// From-scratch COSE_Sign1 handling per RFC 9052, for the capsule vector
// verifier. Parses the four-element COSE_Sign1 array, exposes protected header
// values, builds the Signature1 Sig_structure (RFC 9052 Section 4.4), and
// verifies EdDSA (Ed25519), ES256 (P-256) and ES384 (P-384) signatures with
// node:crypto. COSE ECDSA signatures are raw r||s, which node accepts via
// dsaEncoding 'ieee-p1363'.

import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto'
import { CborMap, CborTagged, cborDecode, cborEncode, type CborValue } from './cbor.js'

export interface CoseSign1 {
  protectedBytes: Uint8Array
  protectedMap: CborMap
  unprotectedMap: CborMap
  payload: Uint8Array | null
  signature: Uint8Array
}

export const HEADER_ALG = 1
export const HEADER_CONTENT_TYPE = 3
export const HEADER_CWT_CLAIMS = 15
export const HEADER_VDS = 395
export const HEADER_VDP = 396
export const CWT_ISS = 1
export const CWT_SUB = 2

export const ALG_NAMES: Record<number, string> = { [-8]: 'EdDSA', [-7]: 'ES256', [-35]: 'ES384' }

export function parseCoseSign1(raw: Uint8Array): CoseSign1 {
  let decoded = cborDecode(raw)
  if (decoded instanceof CborTagged) {
    if (decoded.tag !== 18) throw new Error(`cose: unexpected tag ${decoded.tag}`)
    decoded = decoded.value
  }
  if (!Array.isArray(decoded) || decoded.length !== 4) throw new Error('cose: not a 4-element COSE_Sign1 array')
  const [prot, unprot, payload, sig] = decoded
  if (!(prot instanceof Uint8Array)) throw new Error('cose: protected header must be a byte string')
  if (!(unprot instanceof CborMap)) throw new Error('cose: unprotected header must be a map')
  if (!(payload === null || payload instanceof Uint8Array)) throw new Error('cose: payload must be bstr or nil')
  if (!(sig instanceof Uint8Array)) throw new Error('cose: signature must be a byte string')
  const protectedMap = prot.length === 0 ? new CborMap() : cborDecode(prot)
  if (!(protectedMap instanceof CborMap)) throw new Error('cose: protected header must decode to a map')
  return { protectedBytes: prot, protectedMap, unprotectedMap: unprot, payload, signature: sig }
}

/** RFC 9052 Section 4.4 Sig_structure for Signature1, empty external AAD. */
export function sigStructure(cose: CoseSign1, detachedPayload?: Uint8Array): Uint8Array {
  const payload = cose.payload ?? detachedPayload
  if (payload === undefined) throw new Error('cose: detached payload required but not supplied')
  return cborEncode(['Signature1', cose.protectedBytes, new Uint8Array(0), payload])
}

export function loadPublicKeyPem(pem: string): KeyObject {
  return createPublicKey(pem)
}

/** Verify the COSE_Sign1 signature for the given algorithm code point. */
export function verifyCoseSignature(
  cose: CoseSign1,
  algCode: number,
  key: KeyObject,
  detachedPayload?: Uint8Array,
): boolean {
  const toBeSigned = sigStructure(cose, detachedPayload)
  if (algCode === -8) {
    return cryptoVerify(null, toBeSigned, key, cose.signature)
  }
  if (algCode === -7) {
    return cryptoVerify('sha256', toBeSigned, { key, dsaEncoding: 'ieee-p1363' }, cose.signature)
  }
  if (algCode === -35) {
    return cryptoVerify('sha384', toBeSigned, { key, dsaEncoding: 'ieee-p1363' }, cose.signature)
  }
  throw new Error(`cose: unsupported alg code ${algCode}`)
}

export function headerInt(map: CborMap, label: number): number | undefined {
  const v = map.get(label)
  return typeof v === 'number' ? v : undefined
}

export function cwtClaims(map: CborMap): { issuer?: string; subject?: string } {
  const claims = map.get(HEADER_CWT_CLAIMS)
  if (!(claims instanceof CborMap)) return {}
  const issuer = claims.get(CWT_ISS)
  const subject = claims.get(CWT_SUB)
  return {
    issuer: typeof issuer === 'string' ? issuer : undefined,
    subject: typeof subject === 'string' ? subject : undefined,
  }
}

export type { CborValue }

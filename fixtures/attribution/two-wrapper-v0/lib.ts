// Shared crypto + canonicalization helpers for the two-wrapper attribution
// fixture. Used by both generate.ts and verify.ts so signatures derive from one
// source of truth.
//
// No external dependencies. node:crypto provides Ed25519 sign/verify via PKCS8
// DER encoding (32-byte prefix + 32-byte seed) per RFC 8410. canonicalize() and
// signObjectHex() are ported verbatim from the same helpers the envoys-rfc9421
// fixture uses, which port agent-passport-system src/core/canonical.ts and the
// signObject convention in v2/bridge.ts (sign sha256(canonicalize(obj)) as UTF-8
// hex, null-stripping, alphabetical key sort).

import crypto from 'node:crypto'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export function privKeyObjFromSeedHex(seedHex: string): crypto.KeyObject {
  if (seedHex.length !== 64) throw new Error(`Seed must be 32 bytes hex (64 chars); got ${seedHex.length}`)
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')])
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
}

export function pubKeyHexFromSeedHex(seedHex: string): string {
  const pub = crypto.createPublicKey(privKeyObjFromSeedHex(seedHex))
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer
  return der.subarray(-32).toString('hex')
}

export function ed25519SignHexUtf8(messageStr: string, seedHex: string): string {
  return crypto.sign(null, Buffer.from(messageStr, 'utf-8'), privKeyObjFromSeedHex(seedHex)).toString('hex')
}

export function ed25519VerifyHexUtf8(messageStr: string, signatureHex: string, pubKeyHex: string): boolean {
  const pubDer = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pubKeyHex, 'hex')])
  const pub = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' })
  return crypto.verify(null, Buffer.from(messageStr, 'utf-8'), pub, Buffer.from(signatureHex, 'hex'))
}

export function sha256Hex(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input
  return crypto.createHash('sha256').update(buf).digest('hex')
}

// APS canonical form: sorts keys, drops null and undefined, recurses.
export function canonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null'
  if (obj instanceof Date) return JSON.stringify(obj)
  if (typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map((item) => canonicalize(item)).join(',') + ']'
  const o = obj as Record<string, unknown>
  const parts: string[] = []
  for (const key of Object.keys(o).sort()) {
    const val = o[key]
    if (val === null || val === undefined) continue
    parts.push(JSON.stringify(key) + ':' + canonicalize(val))
  }
  return '{' + parts.join(',') + '}'
}

// signObject per v2/bridge.ts: signs sha256(canonicalize(obj)) as UTF-8 hex.
export function signObjectHex(obj: Record<string, unknown>, seedHex: string): string {
  return ed25519SignHexUtf8(sha256Hex(canonicalize(obj)), seedHex)
}

export function verifyObjectHex(obj: Record<string, unknown>, signatureHex: string, pubKeyHex: string): boolean {
  return ed25519VerifyHexUtf8(sha256Hex(canonicalize(obj)), signatureHex, pubKeyHex)
}

// The Path B recording wrapper. The signed body is the wrapper MINUS
// recording_signature. wrapped_receipt_digest and the embedded
// receipt.integrity.digest are both inside the signed body, so any substitution
// of the bound base receipt breaks verification (nutstrut, vocab #36 2026-07-02).
export interface RecordingWrapper {
  wrapper_version: string
  wrapped_receipt_digest: string
  recorded_by: string
  recording_service: string
  recording_key_id: string
  recording_event_id: string
  recording_context: string
  source_evidence_created_by: string
  receipt: Record<string, unknown>
  recording_signature: { kid: string; alg: string; sig: string }
}

/** Signed preimage = wrapper without its recording_signature. */
export function wrapperSignedBody(w: RecordingWrapper): Record<string, unknown> {
  const { recording_signature, ...body } = w
  void recording_signature
  return body
}

/** Verify a wrapper against a kid->publicKeyHex registry. Fail closed. */
export function verifyWrapper(w: RecordingWrapper, registry: Record<string, string>): boolean {
  const kid = w.recording_signature?.kid
  const pub = kid ? registry[kid] : undefined
  if (!pub) return false
  return verifyObjectHex(wrapperSignedBody(w), w.recording_signature.sig, pub)
}

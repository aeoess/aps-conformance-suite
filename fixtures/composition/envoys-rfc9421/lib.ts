// Shared crypto + canonicalization helpers for the envoys-rfc9421 composition
// fixture. Used by both generate.ts and verify.ts so the two scripts derive
// signatures from a single source of truth.
//
// No external dependencies. node:crypto provides Ed25519 sign/verify via PKCS8
// DER encoding (32-byte prefix + 32-byte seed) per RFC 8410. The canonicalize()
// function ports `~/agent-passport-system/src/core/canonical.ts` verbatim
// (null-stripping, alphabetical key sort) so V2Delegation and BilateralReceipt
// signatures match what the SDK produces.

import crypto from 'node:crypto'

// PKCS8 DER prefix for Ed25519 raw 32-byte seed encoding. See RFC 8410.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export function seedBytesFromHex(seedHex: string): Buffer {
  if (seedHex.length !== 64) throw new Error(`Seed must be 32 bytes hex (64 chars); got ${seedHex.length}`)
  return Buffer.from(seedHex, 'hex')
}

export function privKeyObjFromSeedHex(seedHex: string): crypto.KeyObject {
  const seed = seedBytesFromHex(seedHex)
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
}

export function pubKeyHexFromSeedHex(seedHex: string): string {
  const priv = privKeyObjFromSeedHex(seedHex)
  const pub = crypto.createPublicKey(priv)
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer
  return der.subarray(-32).toString('hex')
}

export function ed25519SignBytes(message: Buffer, seedHex: string): Buffer {
  const priv = privKeyObjFromSeedHex(seedHex)
  return crypto.sign(null, message, priv)
}

export function ed25519SignHexUtf8(messageStr: string, seedHex: string): string {
  return ed25519SignBytes(Buffer.from(messageStr, 'utf-8'), seedHex).toString('hex')
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

// Ported verbatim from ~/agent-passport-system/src/core/canonical.ts (the
// node-stripping APS canonical form used by signObject in v2/bridge.ts and by
// createBilateralReceipt in core/bilateral-receipt.ts). Sorts keys, drops null
// and undefined values, recurses arrays/objects.
export function canonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null'
  if (obj instanceof Date) return JSON.stringify(obj)
  if (typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => canonicalize(item)).join(',') + ']'
  }
  const o = obj as Record<string, unknown>
  const parts: string[] = []
  for (const key of Object.keys(o).sort()) {
    const val = o[key]
    if (val === null || val === undefined) continue
    parts.push(JSON.stringify(key) + ':' + canonicalize(val))
  }
  return '{' + parts.join(',') + '}'
}

// signObject as per v2/bridge.ts: signs sha256(canonicalize(obj)) as UTF-8 hex.
export function signObjectHex(obj: Record<string, unknown>, seedHex: string): string {
  const hashHex = sha256Hex(canonicalize(obj))
  return ed25519SignHexUtf8(hashHex, seedHex)
}

// verifyObject mirror.
export function verifyObjectHex(
  obj: Record<string, unknown>,
  signatureHex: string,
  pubKeyHex: string,
): boolean {
  const hashHex = sha256Hex(canonicalize(obj))
  return ed25519VerifyHexUtf8(hashHex, signatureHex, pubKeyHex)
}

// BilateralReceipt sign path per core/bilateral-receipt.ts: signs the canonical
// JSON string directly (no extra sha256 wrap).
export function signCanonicalStringHex(
  obj: Record<string, unknown>,
  seedHex: string,
): string {
  const canonical = canonicalize(obj)
  return ed25519SignHexUtf8(canonical, seedHex)
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic seeds and inputs. Single source of truth for both generator
// and verifier. Editing anything here changes the fixture's signature bytes.
// ─────────────────────────────────────────────────────────────────────────────

// RFC 8032 §7.1 Test 1. Used by jschoemaker's v1.4.0 §13 vectors.
export const SEED_WIRE_AGENT_HEX =
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

// L2 serving-party key. Document seed: 32 bytes of 0x01.
export const SEED_SERVING_HEX = '01'.repeat(32)

// L3 delegation chain keys. Document seeds: 32 bytes of 0x02 / 0x03 / 0x04.
export const SEED_CHAIN_ROOT_HEX = '02'.repeat(32)
export const SEED_CHAIN_MIDDLE_HEX = '03'.repeat(32)
export const SEED_CHAIN_LEAF_HEX = '04'.repeat(32)

// Fixed clock values so every regeneration produces identical bytes.
export const FIXED_REQUESTED_AT = '2026-05-10T00:00:00.000Z'
export const FIXED_COMPLETED_AT = '2026-05-10T00:00:00.500Z'
export const FIXED_AGREED_AT = '2026-05-10T00:00:01.000Z'

export const POLICY_CTX_CREATED_AT = '2026-05-10T00:00:00.000Z'
export const POLICY_CTX_VALID_FROM = '2026-05-10T00:00:00.000Z'
export const POLICY_CTX_VALID_UNTIL = '2026-08-08T00:00:00.000Z' // 90 days, within 180-day max

// L1 fixed inputs: jschoemaker's v1.4.0 §13 Vector 2 (POST /api/task).
export const L1_KEYID = 'https://envoys.me/agents/test@rfc8032-vec1.example'
export const L1_METHOD = 'POST'
export const L1_PATH = '/api/task'
export const L1_BODY = '{"task":"summarize","url":"https://example.com/doc"}'
export const L1_CREATED = 1714000060
export const L1_NONCE = 'EBESExQVFhcYGRobHB0eHw'

// Fixed identifiers for L2/L3.
export const L2_RECEIPT_ID = 'recv-envoys-rfc9421-l2-v1'
export const L3_ROOT_DELEGATION_ID = 'delg-envoys-rfc9421-link-1-root'
export const L3_MIDDLE_DELEGATION_ID = 'delg-envoys-rfc9421-link-2-middle'
export const L3_LEAF_DELEGATION_ID = 'delg-envoys-rfc9421-link-3-leaf'

// ─────────────────────────────────────────────────────────────────────────────
// L1: RFC 9421 signature-base assembly. Covered components and order match
// jschoemaker's v1.4.0 §13 vectors.
// ─────────────────────────────────────────────────────────────────────────────

export interface L1Inputs {
  method: string
  path: string
  body: string
  keyid: string
  created: number
  nonce: string
}

export function l1ContentDigest(body: string): string {
  const digestB64 = crypto.createHash('sha256').update(body, 'utf-8').digest('base64')
  return `sha-256=:${digestB64}:`
}

export function l1SignatureBase(inp: L1Inputs): string {
  const cd = l1ContentDigest(inp.body)
  return [
    `"@method": ${inp.method}`,
    `"@path": ${inp.path}`,
    `"content-digest": ${cd}`,
    `"@signature-params": ("@method" "@path" "content-digest");keyid="${inp.keyid}";created=${inp.created};nonce="${inp.nonce}"`,
  ].join('\n')
}

export function l1SignatureValueBase64(sigBase: string, seedHex: string): string {
  return ed25519SignBytes(Buffer.from(sigBase, 'utf-8'), seedHex).toString('base64')
}

export function l1SignatureInputHeader(inp: L1Inputs): string {
  return `sig1=("@method" "@path" "content-digest");keyid="${inp.keyid}";created=${inp.created};nonce="${inp.nonce}"`
}

export function l1SignatureHeader(sigB64: string): string {
  return `sig1=:${sigB64}:`
}

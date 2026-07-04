// Shared primitives for the accountability-record fixture family.
//
// Derived from agent-passport-system (do not invent a parallel canonicalizer or
// action_ref rule):
//   - canonicalizeJCS : reused from the suite's vendored copy (runners/ts/canonicalize.ts),
//                       byte-identical to src/core/canonical-jcs.ts.
//   - normalizeTimestamp / computeActionRef : reimplemented to match
//                       src/core/canonical.ts + src/core/action-ref.ts exactly
//                       (draft-pidlisnyi-aps-00 §4.1).
//   - Ed25519 sign/verify + deterministic keypair : same Node-crypto pattern and
//                       PKCS8 prefix as src/crypto/keys.ts and the suite's
//                       fixtures/bilateral-delegation/generate-keypair.ts.
//
// No runtime dependency on agent-passport-system: the suite is self-contained so
// external implementations can verify from a cold clone.

import crypto from 'node:crypto'
import { canonicalizeJCS } from '../../runners/ts/canonicalize.js'

export { canonicalizeJCS }

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex')
}

/** SHA-256 (lowercase hex) of canonicalizeJCS(obj). Matches canonicalHashJCS. */
export function canonicalHashJCS(obj: unknown): string {
  return sha256Hex(canonicalizeJCS(obj))
}

/** Matches src/core/canonical.ts normalizeTimestamp: strip ms to second precision. */
export function normalizeTimestamp(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) throw new Error(`normalizeTimestamp: invalid timestamp "${ts}"`)
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

export interface RecordedAction {
  type: string
  scope: string[]
  timestamp: string
}

/** action_digest.sha256 = SHA-256(JCS(action)). Detached-payload commitment. */
export function actionDigestSha256(action: RecordedAction): string {
  return canonicalHashJCS(action)
}

/** action_ref = computeActionRef over the tuple {agentId, actionType, scopeRequired, timestamp}. */
export function computeActionRef(agentDid: string, action: RecordedAction): string {
  return canonicalHashJCS({
    agentId: agentDid,
    actionType: action.type,
    scopeRequired: action.scope,
    timestamp: normalizeTimestamp(action.timestamp),
  })
}

export interface Keypair {
  seedHex: string
  privateKeyHex: string
  publicKeyHex: string
}

/** Deterministic Ed25519 keypair from SHA-256(seedInput). Private key IS the seed. */
export function deriveKeypair(seedInput: string): Keypair {
  const seed = crypto.createHash('sha256').update(seedInput, 'utf-8').digest()
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubDer = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' }) as Buffer
  return {
    seedHex: seed.toString('hex'),
    privateKeyHex: seed.toString('hex'),
    publicKeyHex: Buffer.from(pubDer.subarray(-32)).toString('hex'),
  }
}

/** Ed25519 sign the UTF-8 bytes of `message`. Returns lowercase hex (128 chars). */
export function signUtf8(message: string, privateKeyHex: string): string {
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(privateKeyHex, 'hex')])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const sig = crypto.sign(null, Buffer.from(message, 'utf8'), keyObj)
  return Buffer.from(sig).toString('hex')
}

/** Ed25519 verify. Mirrors src/crypto/keys.ts: strict 64-hex pubkey / 128-hex sig. */
export function verifyUtf8(message: string, signatureHex: string, publicKeyHex: string): boolean {
  if (typeof publicKeyHex !== 'string' || publicKeyHex.length !== 64) return false
  if (typeof signatureHex !== 'string' || signatureHex.length !== 128) return false
  try {
    const derKey = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyHex, 'hex')])
    const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, Buffer.from(signatureHex, 'hex'))
  } catch {
    return false
  }
}

export const utf8Hex = (s: string): string => Buffer.from(s, 'utf8').toString('hex')

/** JCS of the record with `sig` omitted = the Ed25519 signing input. */
export function signingInput(record: Record<string, unknown>): string {
  const { sig, ...rest } = record
  return canonicalizeJCS(rest)
}

export interface AccountabilityRecord {
  spec_version: string
  record_type: 'accountability_record'
  action_ref: string
  action_digest: { sha256: string }
  action?: RecordedAction
  signer_did: string
  agent_did: string
  delegation_ref: string
  principal_ref: string
  decision: 'allow' | 'deny' | 'halt'
  executed: boolean
  issued_at: string
  settlement_ref?: string
  settlement_rail?: string
  sig: string
  sig_alg: 'Ed25519'
}

export interface VerifyResult {
  ok: boolean
  checks: Record<string, boolean | string>
}

/** Full verification: signature over signing-input, plus (when `action` is inline)
 *  action_digest binding and action_ref recomputation. verificationKeyHex is the
 *  key the signer_did is expected to resolve to. */
export function verifyRecord(record: AccountabilityRecord, verificationKeyHex: string): VerifyResult {
  const checks: Record<string, boolean | string> = {}
  const si = signingInput(record as unknown as Record<string, unknown>)
  checks.signature = verifyUtf8(si, record.sig, verificationKeyHex)
  if (record.action !== undefined) {
    const recomputedDigest = actionDigestSha256(record.action)
    checks.action_digest_binds = recomputedDigest === record.action_digest.sha256
    const recomputedRef = computeActionRef(record.agent_did, record.action)
    checks.action_ref_recomputes = recomputedRef === record.action_ref
  } else {
    checks.action_digest_binds = 'detached (no inline action)'
    checks.action_ref_recomputes = 'detached (no inline action)'
  }
  const ok = checks.signature === true &&
    (checks.action_digest_binds === true || checks.action_digest_binds === 'detached (no inline action)') &&
    (checks.action_ref_recomputes === true || checks.action_ref_recomputes === 'detached (no inline action)')
  return { ok, checks }
}

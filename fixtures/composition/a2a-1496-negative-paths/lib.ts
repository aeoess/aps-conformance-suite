// Shared validator + helpers for the a2a-1496-negative-paths fixture.
// Negative-path conformance asserts that running the APS delegation
// validator over a structurally invalid input throws a `NegativePathError`
// whose `code` field equals the fixture's `expected_error_code`.
//
// Convention follows fixtures/composition/envoys-rfc9421/lib.ts: no runtime
// dependency on agent-passport-system. Refusal-path semantics are taken
// from `~/agent-passport-system/src/v2/delegation-v2.ts`'s
// `validateV2Delegation()` and `isScopeExpansion()`, plus the chain-level
// depth check at `~/agent-passport-system/src/core/delegation.ts:128`,
// re-implemented here purpose-built for the four CTEF v0.3.2 §A error
// codes the fixtures pin against.

import crypto from 'node:crypto'

// ─────────────────────────────────────────────────────────────────────────
// Error surface
// ─────────────────────────────────────────────────────────────────────────

/** Closed taxonomy of error codes the fixtures pin against. Drawn from
 *  CTEF v0.3.2 §A Conformance Verification Appendix. */
export type NegativePathErrorCode =
  | 'INVALID_CLAIM_SCOPE'
  | 'DELEGATION_DEPTH_EXCEEDED'
  | 'INVALID_SIGNATURE'
  | 'VALIDITY_EXPIRED'

/** Error thrown by validateNegativePathInput() on a refused input. The
 *  `code` field carries the closed-taxonomy reason; verify.ts checks it
 *  against the fixture's expected_error_code. */
export class NegativePathError extends Error {
  readonly code: string
  constructor(code: string, message?: string) {
    super(message ?? code)
    this.name = 'NegativePathError'
    this.code = code
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Input shape
// ─────────────────────────────────────────────────────────────────────────

/** A single delegation link in a chain. JCS-canonical when serialized;
 *  the signature is over canonicalizeJCS(delegation minus signature). */
export interface NegativePathDelegation {
  /** Ed25519 public key of the delegator, hex (64 chars). The signature
   *  is verified against this key. */
  delegator: string
  /** Ed25519 public key of the delegatee, hex (64 chars). */
  delegatee: string
  /** Scope grant. `action_categories` is checked for monotonic narrowing
   *  against the parent link's scope. Other keys are preserved in the
   *  canonical-bytes form but not interpreted. */
  scope: { action_categories: string[]; [k: string]: unknown }
  /** Validity window. `not_after` is required and compared against the
   *  input's `now` (or real time). Both fields are ISO 8601 UTC strings. */
  validityWindow: { not_before?: string; not_after: string }
  /** Ed25519 hex signature over canonicalizeJCS(delegation minus signature). */
  signature: string
  /** Extra fields are preserved in canonical bytes (the signature covers
   *  them) but otherwise opaque to this validator. */
  [k: string]: unknown
}

/** The fixture's `input` shape. */
export interface NegativePathInput {
  /** Delegation chain, root first → leaf last. A single delegation ships
   *  as a one-element array. */
  chain: NegativePathDelegation[]
  /** Optional cap on chain length. When supplied, `chain.length > max_depth`
   *  triggers DELEGATION_DEPTH_EXCEEDED. When omitted, the depth check
   *  is skipped (chain length is unconstrained by this validator). */
  max_depth?: number
  /** Optional clock for the validity check, ISO 8601 UTC. Defaults to
   *  real time. Fixture authors pin this for deterministic VALIDITY_EXPIRED
   *  vectors. */
  now?: string
}

// ─────────────────────────────────────────────────────────────────────────
// JCS canonicalization (RFC 8785, minimal subset)
// ─────────────────────────────────────────────────────────────────────────
//
// Differs from envoys-rfc9421/lib.ts's canonicalize() in two ways: keys
// with null values are preserved (envoys' APS-legacy form drops them);
// numbers go through JSON.stringify which yields ES6 Number-to-String
// formatting (sufficient for the integer / simple-decimal values typical
// in delegation envelopes). Surface is intentionally small; if a fixture
// needs JCS rules this implementation doesn't cover (e.g. precise IEEE-754
// edge cases), surface them in a follow-up PR.

export function canonicalizeJCS(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`canonicalizeJCS: non-finite number ${value}`)
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalizeJCS(item)).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    const parts: string[] = []
    for (const k of keys) {
      const v = obj[k]
      if (v === undefined) continue
      parts.push(JSON.stringify(k) + ':' + canonicalizeJCS(v))
    }
    return '{' + parts.join(',') + '}'
  }
  throw new TypeError(`canonicalizeJCS: unsupported value type ${typeof value}`)
}

// ─────────────────────────────────────────────────────────────────────────
// Ed25519 verify (raw 32-byte pubkey hex → SPKI DER wrap → node:crypto)
// ─────────────────────────────────────────────────────────────────────────
// SPKI prefix per RFC 8410; mirrors fixtures/composition/envoys-rfc9421/lib.ts.

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function ed25519Verify(messageBytes: Buffer, signatureHex: string, pubKeyHex: string): boolean {
  if (pubKeyHex.length !== 64) return false
  let pub: crypto.KeyObject
  try {
    const pubDer = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pubKeyHex, 'hex')])
    pub = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' })
  } catch {
    return false
  }
  let sigBuf: Buffer
  try {
    sigBuf = Buffer.from(signatureHex, 'hex')
  } catch {
    return false
  }
  if (sigBuf.length !== 64) return false
  try {
    return crypto.verify(null, messageBytes, pub, sigBuf)
  } catch {
    return false
  }
}

/** Verify a delegation link's signature: strip `signature`, JCS-canonicalize
 *  the rest, ed25519 verify the signature against the link's `delegator`
 *  pubkey. Returns true on valid signature. */
function verifyDelegationSignature(d: NegativePathDelegation): boolean {
  const { signature: _sig, ...rest } = d
  const canonical = canonicalizeJCS(rest)
  return ed25519Verify(Buffer.from(canonical, 'utf-8'), d.signature, d.delegator)
}

// ─────────────────────────────────────────────────────────────────────────
// Refusal-path semantics
// ─────────────────────────────────────────────────────────────────────────

/** Mirrors `isScopeExpansion()` at delegation-v2.ts:73 — returns true when
 *  the child's `action_categories` contains a value not in the parent's. */
function isScopeExpansion(
  parent: NegativePathDelegation,
  child: NegativePathDelegation,
): boolean {
  const parentCats = new Set(parent.scope.action_categories ?? [])
  for (const cat of child.scope.action_categories ?? []) {
    if (!parentCats.has(cat)) return true
  }
  return false
}

// ─────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────

/**
 * Validate a delegation-chain input and throw on the first refusal
 * encountered. Check order:
 *
 *   1. Chain depth (if `input.max_depth` is set): chain.length > max_depth
 *      → DELEGATION_DEPTH_EXCEEDED.
 *   2. Per link, root → leaf:
 *      a. validityWindow.not_after < `input.now` (or real time)
 *         → VALIDITY_EXPIRED.
 *      b. Ed25519 verify of `signature` against canonicalizeJCS(link minus
 *         signature) under the link's `delegator` pubkey
 *         → INVALID_SIGNATURE.
 *      c. For non-root links: scope expansion vs parent
 *         → INVALID_CLAIM_SCOPE.
 *
 * Order matches V2's validateV2Delegation() (validity → signature) plus a
 * structural depth pre-check and a per-link narrowing post-check. A fixture
 * authors a single targeted violation per case; on overlap, the first
 * check above fires.
 */
export function validateNegativePathInput(input: NegativePathInput): void {
  if (!input || !Array.isArray(input.chain)) {
    throw new NegativePathError(
      'INVALID_SIGNATURE',
      'Negative-path input must carry a `chain` array of delegations.',
    )
  }
  const { chain, max_depth, now } = input

  // 1. Depth.
  if (typeof max_depth === 'number' && chain.length > max_depth) {
    throw new NegativePathError(
      'DELEGATION_DEPTH_EXCEEDED',
      `chain.length=${chain.length} exceeds max_depth=${max_depth}`,
    )
  }

  // Clock for validity check.
  const nowMs = now !== undefined ? Date.parse(now) : Date.now()
  if (Number.isNaN(nowMs)) {
    throw new NegativePathError(
      'VALIDITY_EXPIRED',
      `Negative-path input.now is not a parseable ISO 8601 date: ${now}`,
    )
  }

  // 2. Per-link checks.
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]

    // 2a. Validity.
    const notAfter = link?.validityWindow?.not_after
    const notAfterMs = typeof notAfter === 'string' ? Date.parse(notAfter) : NaN
    if (Number.isNaN(notAfterMs) || notAfterMs < nowMs) {
      throw new NegativePathError(
        'VALIDITY_EXPIRED',
        `chain[${i}].validityWindow.not_after=${notAfter} is at-or-before now=${new Date(nowMs).toISOString()}`,
      )
    }

    // 2b. Signature.
    if (!verifyDelegationSignature(link)) {
      throw new NegativePathError(
        'INVALID_SIGNATURE',
        `chain[${i}] signature does not verify against delegator pubkey`,
      )
    }

    // 2c. Scope narrowing (skip root).
    if (i > 0) {
      const parent = chain[i - 1]
      if (isScopeExpansion(parent, link)) {
        throw new NegativePathError(
          'INVALID_CLAIM_SCOPE',
          `chain[${i}].scope.action_categories expands beyond chain[${i - 1}]`,
        )
      }
    }
  }
}

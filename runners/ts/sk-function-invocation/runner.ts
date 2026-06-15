// Semantic Kernel function-invocation filter seam, modeled in TS.
//
// This runner does not define a new conformance schema or a new handle
// primitive. It imports portable fixture classes and asserts one property:
// the invocation path cannot bypass the verifier. The verifier recomputes the
// handle (action_ref) and, on any negative vector, the filter short-circuits
// before the function runs.
//
// Handle recompute reuses the suite's vendored JCS canonicalizer
// (runners/ts/canonicalize.ts, extracted from agent-passport-system
// src/core/canonical-jcs.ts) plus node crypto SHA-256. No canonicalization or
// hashing is reimplemented here.
//
// Maps to a Semantic Kernel IFunctionInvocationFilter: the filter runs the
// recompute check first and only calls next(context) when the handle is
// correct and bound. On a failure it does not call next(), so the kernel
// function never executes. See README.md for the .NET shape.

import crypto from 'node:crypto'
import { canonicalizeJCS } from '../canonicalize.js'

// ── Handle recompute (action_ref) ────────────────────────────────────
// action_ref = "sha256:" + hex(SHA-256(JCS({agent_id, action_type, scope, timestamp})))

export interface Preimage {
  agent_id: string
  action_type: string
  scope: string
  timestamp: string
}

export function recomputeActionRef(preimage: Preimage): string {
  const canonical = canonicalizeJCS(preimage)
  return 'sha256:' + crypto.createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

/** Compare two action_ref handles ignoring an optional "sha256:" prefix. */
function handlesEqual(a: string, b: string): boolean {
  const strip = (h: string) => (h.startsWith('sha256:') ? h.slice('sha256:'.length) : h)
  return strip(a) === strip(b)
}

/** Truncate a digest for a redacted reason string. */
function red(h: string): string {
  const s = h.startsWith('sha256:') ? h.slice('sha256:'.length) : h
  return s.slice(0, 8) + '...'
}

/** RFC 3339 UTC timestamp with exactly three fractional digits and a Z.
 *  The validation rule checks this grammar before recompute, so a non-string
 *  (for example an epoch integer) or a non-millisecond form is a terminal
 *  failure even when the claimed digest happens to match the same bytes. */
function validTimestampGrammar(ts: unknown): boolean {
  return typeof ts === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(ts)
}

// ── Verdict ──────────────────────────────────────────────────────────

export interface Verdict {
  allow: boolean
  fixtureId: string
  handleFamily: string
  reason: string
}

/**
 * Byte-level handle-correctness class.
 * Positive: recompute(preimage) equals the committed action_ref.
 * Negative: recompute(invocation_payload) does not equal the claimed_action_ref,
 * which is a terminal recompute mismatch.
 */
export function verifyHandleCorrectness(
  vector: any,
  opts: { positive: boolean; family: string },
): Verdict {
  const id = vector.id ?? vector.name
  if (opts.positive) {
    if (!validTimestampGrammar(vector.preimage.timestamp)) {
      return { allow: false, fixtureId: id, handleFamily: `${opts.family}:grammar_reject`,
        reason: 'timestamp_grammar_violation: not an RFC 3339 UTC string with three fractional digits' }
    }
    const recomputed = recomputeActionRef(vector.preimage)
    const claimed = vector.action_ref
    const allow = handlesEqual(recomputed, claimed)
    return {
      allow,
      fixtureId: id,
      handleFamily: `${opts.family}:recompute`,
      reason: allow ? 'recompute_match' : `recompute_mismatch: claimed ${red(claimed)} recomputed ${red(recomputed)}`,
    }
  }
  if (!validTimestampGrammar(vector.invocation_payload.timestamp)) {
    return { allow: false, fixtureId: id, handleFamily: `${opts.family}:${vector.failure_mode ?? 'grammar_reject'}`,
      reason: 'timestamp_grammar_violation: not an RFC 3339 UTC string with three fractional digits' }
  }
  const recomputed = recomputeActionRef(vector.invocation_payload)
  const claimed = vector.claimed_action_ref
  const allow = handlesEqual(recomputed, claimed)
  return {
    allow,
    fixtureId: id,
    handleFamily: `${opts.family}:${vector.failure_mode ?? 'recompute_drift'}`,
    reason: allow ? 'recompute_match' : `recompute_mismatch: claimed ${red(claimed)} recomputed ${red(recomputed)}`,
  }
}

/**
 * Issuer-binding and scope-replay class (near-miss). The recompute can be
 * correct, so the failure is at a higher layer:
 *   AMBIGUOUS_ISSUER_BINDING: one (action_ref, subject, claim_type, evidenceType)
 *     bound to more than one issuer with disjoint verdicts.
 *   RESCOPED_REPLAY: presented scope is not bound by the issued action_ref.
 *   SEMANTIC_DRIFT: verification fields differ from issuance fields.
 */
export function verifyNearMiss(vector: any): Verdict {
  const id = vector.id ?? vector.name
  const family = 'near-miss-v1'

  if (vector.failure_mode === 'AMBIGUOUS_ISSUER_BINDING' || vector.name === 'ambiguous_issuer_binding') {
    const envs = vector.envelopes ?? []
    const groups = new Map<string, Set<string>>()
    const verdicts = new Map<string, Set<string>>()
    for (const e of envs) {
      const actionRef = e.evidence_basis?.action_ref ?? vector.preimage_block?.action_ref
      const evidenceType = e.evidence_basis?.evidenceType ?? e.provider?.category
      const key = [actionRef, e.subject?.did, e.claim_type, evidenceType].join('|')
      if (!groups.has(key)) { groups.set(key, new Set()); verdicts.set(key, new Set()) }
      groups.get(key)!.add(e.provider?.id)
      verdicts.get(key)!.add(e.attestation?.admissibility_result ?? '')
    }
    let ambiguous = false
    for (const [key, providers] of groups) {
      if (providers.size > 1 && verdicts.get(key)!.size > 1) ambiguous = true
    }
    return {
      allow: !ambiguous,
      fixtureId: id,
      handleFamily: `${family}:AMBIGUOUS_ISSUER_BINDING`,
      reason: ambiguous
        ? 'ambiguous_issuer_binding: one (action_ref, subject, claim_type, evidenceType) maps to multiple issuers with disjoint verdicts'
        : 'binding_unique',
    }
  }

  if (vector.failure_mode === 'RESCOPED_REPLAY' || vector.name === 'rescoped_replay') {
    const issued = vector.issued_preimage_block.action_ref
    const presented = recomputeActionRef(vector.presented_preimage_block.preimage)
    const bound = handlesEqual(issued, presented)
    return {
      allow: bound,
      fixtureId: id,
      handleFamily: `${family}:RESCOPED_REPLAY`,
      reason: bound
        ? 'scope_bound'
        : `rescoped_replay: presented scope not bound by issued action_ref (issued ${red(issued)}, presented ${red(presented)})`,
    }
  }

  if (vector.failure_mode === 'SEMANTIC_DRIFT' || vector.name === 'semantic_drift') {
    const issuance = vector.issuance_preimage_block.action_ref
    const verification = recomputeActionRef(vector.verification_preimage_block.preimage)
    const bound = handlesEqual(issuance, verification)
    return {
      allow: bound,
      fixtureId: id,
      handleFamily: `${family}:SEMANTIC_DRIFT`,
      reason: bound
        ? 'semantics_bound'
        : `semantic_drift: verification fields differ from issuance (issuance ${red(issuance)}, verification ${red(verification)})`,
    }
  }

  return {
    allow: false,
    fixtureId: id,
    handleFamily: `${family}:UNKNOWN`,
    reason: `unhandled near-miss failure_mode: ${vector.failure_mode ?? vector.name}`,
  }
}

// ── Function-invocation filter seam ──────────────────────────────────
// Models SK IFunctionInvocationFilter.OnFunctionInvocationAsync(context, next).
// The filter calls next() only when the verdict allows. The kernel function
// body runs strictly inside next(), so a denial means it never executes.

export interface InvocationContext {
  events: string[]
  invoked: boolean
  denial: { fixtureId: string; handleFamily: string; reason: string } | null
}

export type Next = () => void

export function functionInvocationFilter(verdict: Verdict, ctx: InvocationContext, next: Next): void {
  ctx.events.push('verify')
  if (!verdict.allow) {
    ctx.events.push('deny')
    ctx.denial = { fixtureId: verdict.fixtureId, handleFamily: verdict.handleFamily, reason: verdict.reason }
    return // short-circuit: next() is never called
  }
  ctx.events.push('allow')
  next()
}

/** Run one vector through the seam with a fresh context. The kernel function
 *  body sets invoked=true; it can only run from inside next(). */
export function runThroughFilter(verdict: Verdict): InvocationContext {
  const ctx: InvocationContext = { events: [], invoked: false, denial: null }
  functionInvocationFilter(verdict, ctx, () => {
    ctx.events.push('invoke')
    ctx.invoked = true
  })
  return ctx
}

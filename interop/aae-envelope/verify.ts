// Conformance runner for the AAE chain-envelope interop vectors. Run as:
//   npm run verify:aae-envelope
//   (or: npx tsx interop/aae-envelope/verify.ts)
//
// Loads the four V*.json vectors (MoltyCel AAE chain-envelope shape:
// {"chain":[parent, child]}), maps each AAE credential to a REAL APS
// delegation via a small adapter, then decides each chain with the SHIPPED
// APS verifier primitives - verifyDelegation (signature / expiry / notBefore /
// revocation / depth) and scopeCovers (monotonic narrowing). The decision is
// real SDK output; this runner only adapts inputs and asserts the expected
// result + reason code per vector.
//
// The repo's existing fixtures use tsx runner scripts (see
// fixtures/composition/*/verify.ts), not vitest; this runner follows that
// convention. Same contract: walk vectors, assert expected, exit non-zero on
// any mismatch.
//
// V4 note: revocation is consulted WHEN THE CHAIN IS VERIFIED (check-time
// cascade). A revoked parent invalidates the child subtree in the same
// verification pass - not on a later lookup. Matches NEG-STALE-REVOCATION.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── Load the SHIPPED APS SDK verifier (built dist; no source modified) ──
// SDK path resolves from APS_SDK_PATH when set, else the default local build location.
const SDK = process.env.APS_SDK_PATH || `${process.env.HOME}/agent-passport-system/dist/src/index.js`
const { generateKeyPair, canonicalize, sign, verifyDelegation, scopeCovers } =
  await import(SDK)

// ── AAE envelope types (the bits we read) ──
interface AaeValidity {
  not_before: string
  not_after: string
  single_use: boolean
  revocation_check: { mechanism?: string; status?: string; revoked_at?: string }
}
interface AaeCredential {
  vc_id: string
  issuer: string
  subject: string
  delegator_did?: string
  depth?: number
  max_depth?: number
  mandate: { actions: string[] }
  constraints?: Record<string, unknown>
  validity: AaeValidity
}
interface AaeEnvelope {
  vector_id: string
  expected_result: 'ACCEPT' | 'REJECT'
  expected_reason_code: string | null
  chain: AaeCredential[]
}

interface Decision {
  result: 'ACCEPT' | 'REJECT'
  reason: string | null
  reason_code: string | null
}

// ── Adapter: one AAE credential -> one signed APS delegation ──
// Keys are generated per DID so that a child's delegatedBy (issuer key) equals
// its parent's delegatedTo (subject key) - the cryptographic chain link. The
// AAE validity window maps directly onto the APS delegation's notBefore /
// expiresAt, and mandate.actions onto APS scope tokens. Signing uses the SDK's
// own canonicalize + sign, so verifyDelegation's signature check is real.
type KeyCache = Record<string, { publicKey: string; privateKey: string }>
function keyFor(did: string, cache: KeyCache) {
  if (!cache[did]) cache[did] = generateKeyPair()
  return cache[did]
}

function aaeToApsDelegation(
  cred: AaeCredential,
  cache: KeyCache,
  currentDepth: number,
  maxDepth: number,
) {
  const issuer = keyFor(cred.issuer, cache)
  const subject = keyFor(cred.subject, cache)
  const unsigned = {
    delegationId: cred.vc_id,
    delegatedTo: subject.publicKey,
    delegatedBy: issuer.publicKey,
    scope: cred.mandate.actions,
    scopeInterpretation: 'exact' as const,
    expiresAt: cred.validity.not_after,
    spentAmount: 0,
    maxDepth,
    currentDepth,
    createdAt: cred.validity.not_before,
    notBefore: cred.validity.not_before,
  }
  const signature = sign(canonicalize(unsigned), issuer.privateKey)
  return { ...unsigned, signature }
}

// ── Chain verifier: runs APS's existing checks, cascades parent -> child ──
function verifyChain(env: AaeEnvelope): Decision {
  const cache: KeyCache = {}
  const creds = env.chain
  const nowISO = new Date().toISOString()

  const dels = creds.map((c, i) =>
    aaeToApsDelegation(c, cache, i === 0 ? 0 : (c.depth ?? i), c.max_depth ?? 2),
  )

  // Per-node APS verification. Revocation state is supplied at verification
  // time from the AAE revocation_check (check-time, stateless cache input).
  const statuses = creds.map((c, i) => {
    const revoked = c.validity?.revocation_check?.status === 'revoked'
    return verifyDelegation(dels[i], {
      revocationCheckPolicy: 'fail_closed',
      cachedRevocationState: revoked ? { revoked: true, checkedAt: nowISO } : undefined,
    })
  })

  // 1. Chain-link continuity: child.delegator_did/issuer == parent.subject,
  //    and the keys actually chain (child.delegatedBy == parent.delegatedTo).
  for (let i = 1; i < creds.length; i++) {
    const parent = creds[i - 1], child = creds[i]
    if (
      child.issuer !== parent.subject ||
      (child.delegator_did && child.delegator_did !== parent.subject) ||
      dels[i].delegatedBy !== dels[i - 1].delegatedTo
    ) {
      return { result: 'REJECT', reason: `chain broken at hop ${i}: delegator_did/issuer != parent.subject`, reason_code: 'CHAIN_BROKEN' }
    }
  }

  // 2. Signature validity per node.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].errors.includes('Invalid delegation signature')) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) signature invalid`, reason_code: 'SIGNATURE_INVALID' }
    }
  }

  // 3. Monotonic narrowing (APS scopeCovers): every child action must be
  //    covered by some parent action. child_scope ⊄ parent_scope -> widening.
  for (let i = 1; i < creds.length; i++) {
    const parentScope = creds[i - 1].mandate.actions
    const childScope = creds[i].mandate.actions
    const notCovered = childScope.filter((a) => !parentScope.some((p: string) => scopeCovers(p, a)))
    if (notCovered.length) {
      return { result: 'REJECT', reason: `scope-widening: [${notCovered.join(', ')}] not covered by parent [${parentScope.join(', ')}]`, reason_code: 'SCOPE_WIDENING' }
    }
  }

  // 4. Expiry cascade: an expired ancestor invalidates the subtree.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].expired) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) expired (cascades to subtree)`, reason_code: 'DELEGATION_EXPIRED' }
    }
  }

  // 5. Revocation cascade (CHECK-TIME): a revoked ancestor invalidates the
  //    subtree in this verification pass, not on a later lookup.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].revoked) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) revoked (check-time cascade)`, reason_code: 'DELEGATION_REVOKED' }
    }
  }

  // 6. notBefore / depth.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].notYetValid) return { result: 'REJECT', reason: `node ${i} not yet valid`, reason_code: 'DELEGATION_NOT_YET_VALID' }
    if (statuses[i].depthExceeded) return { result: 'REJECT', reason: `node ${i} depth exceeded`, reason_code: 'DEPTH_EXCEEDED' }
  }

  return { result: 'ACCEPT', reason: null, reason_code: null }
}

// ── Run all four vectors ──
const VECTORS = [
  'V1-narrowing-valid.json',
  'V2-widened-scope-reject.json',
  'V3-expired-parent-reject.json',
  'V4-revoked-parent-cascade-reject.json',
]

console.log(`aae-envelope: running ${VECTORS.length} chain-envelope vector(s) against the shipped APS verifier\n`)

let failures = 0
const summary: Array<Record<string, unknown>> = []

for (const file of VECTORS) {
  const env = JSON.parse(readFileSync(join(__dirname, file), 'utf8')) as AaeEnvelope
  const decision = verifyChain(env)

  const resultOk = decision.result === env.expected_result
  const codeOk = (decision.reason_code ?? null) === (env.expected_reason_code ?? null)
  const pass = resultOk && codeOk
  if (!pass) failures++

  const tag = pass ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m'
  console.log(`${tag} ${env.vector_id}`)
  console.log(`        expected: ${env.expected_result}${env.expected_reason_code ? ` / ${env.expected_reason_code}` : ''}`)
  console.log(`        actual:   ${decision.result}${decision.reason_code ? ` / ${decision.reason_code}` : ''}`)
  if (decision.reason) console.log(`        reason:   ${decision.reason}`)
  if (!pass) {
    if (!resultOk) console.log(`        >>> RESULT MISMATCH`)
    if (!codeOk) console.log(`        >>> REASON-CODE MISMATCH`)
  }
  console.log()

  summary.push({
    vector: env.vector_id,
    expected: `${env.expected_result}${env.expected_reason_code ? '/' + env.expected_reason_code : ''}`,
    actual: `${decision.result}${decision.reason_code ? '/' + decision.reason_code : ''}`,
    pass,
  })
}

console.log('summary:', JSON.stringify(summary, null, 2))
if (failures > 0) {
  console.error(`\naae-envelope: ${failures}/${VECTORS.length} vector(s) FAILED`)
  process.exit(1)
}
console.log(`\naae-envelope: all ${VECTORS.length} vector(s) decided as expected by the APS verifier`)

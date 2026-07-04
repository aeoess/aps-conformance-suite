// Cold-clone verifier for the Presidio x402 accountability-record fixture (PART 1).
//
// Run as (from aps-conformance-suite/ after npm install):
//   npx tsx fixtures/presidio-x402/verify.ts
//
// For every vector: re-derives signing input and canonical bytes, byte-parity
// check against stored fields, full Ed25519 verification plus action_digest
// binding and action_ref recomputation. Asserts outcome matches
// expected_verification. Exits 0 only if all vectors match.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS, sha256Hex, utf8Hex, signingInput, verifyRecord } from '../accountability-record/lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE = join(__dirname, 'presidio-x402-accountability-record-fixture-v1.json')

const fx = JSON.parse(readFileSync(FIXTURE, 'utf8'))
let failures = 0

console.log(`Presidio x402 accountability-record verifier (PART 1) — ${fx.vectors.length} vectors from ${FIXTURE}\n`)

for (const v of fx.vectors) {
  const problems: string[] = []

  // 1. byte-parity
  const si = signingInput(v.record)
  if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
  if (utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
  const canonical = canonicalizeJCS(v.record)
  if (canonical !== v.canonical) problems.push('canonical mismatch')
  if (utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
  if (sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')

  // 2. record.sig equals the published signature
  if (v.record.sig !== v.ed25519_signature_over_signing_input_hex) problems.push('record.sig != published signature')

  // 3-4. crypto/digest outcome
  const res = verifyRecord(v.record, v.ed25519_pubkey_hex)
  if (v.rejection_kind !== 'schema') {
    if (res.ok !== v.expected_verification) {
      problems.push(`verification ${res.ok} != expected ${v.expected_verification}`)
    }
    if (v.expected_verification === false) {
      if (v.rejection_kind === 'digest_mismatch' && res.checks.action_digest_binds !== false) {
        problems.push('declared digest_mismatch but digest bound')
      }
      if (v.rejection_kind === 'signature' && res.checks.signature !== false) {
        problems.push('declared signature rejection but signature verified')
      }
    }
  }

  const ok = problems.length === 0
  if (!ok) failures++
  const tag = v.rejection_kind === 'schema' ? ' [schema: enforced by validate.py]'
    : v.rejection_kind ? ` [${v.rejection_kind}]` : ''
  console.log(
    `  ${ok ? 'PASS' : 'FAIL'} ${v.name.padEnd(40)} verify=${res.ok} expected=${v.expected_verification}` + tag +
    (problems.length ? `\n         ${problems.join('; ')}` : ''),
  )
}

console.log(`\n${failures === 0 ? 'ALL VECTORS PASS' : failures + ' VECTOR(S) FAILED'}`)
process.exit(failures === 0 ? 0 : 1)

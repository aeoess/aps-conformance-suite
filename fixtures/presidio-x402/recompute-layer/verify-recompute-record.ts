// Native-APS verification of the PART 2 recompute-layer record.
//
// The whole point of PART 2: this record is APS-NATIVE-VALID. It passes byte-parity,
// Ed25519 signature (signed by the key signer_did resolves to), and action_digest
// binding. The failure it demonstrates is NOT an APS failure — it lives in the
// proposed recompute layer (see ../../../recompute-layer/recompute_check.py).
//
// Run as (from aps-conformance-suite/):
//   npx tsx fixtures/presidio-x402/verify-recompute-record.ts

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS, sha256Hex, utf8Hex, signingInput, verifyRecord } from '../../accountability-record/lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const RECORD_PATH = join(__dirname, 'presidio-x402-verdict-not-recomputable.record.json')

const doc = JSON.parse(readFileSync(RECORD_PATH, 'utf8'))
const v = doc
let problems: string[] = []

console.log(`Native-APS verification of recompute-layer record from ${RECORD_PATH}\n`)

// byte-parity
const si = signingInput(v.record)
if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
if (utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
const canonical = canonicalizeJCS(v.record)
if (canonical !== v.canonical) problems.push('canonical mismatch')
if (utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
if (sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')
if (v.record.sig !== v.ed25519_signature_over_signing_input_hex) problems.push('record.sig != published signature')

// native verification MUST be TRUE
const res = verifyRecord(v.record, v.ed25519_pubkey_hex)
if (res.ok !== v.expected_verification) problems.push(`verification ${res.ok} != expected ${v.expected_verification}`)
if (res.ok !== true) problems.push('recompute-layer record MUST verify TRUE (native-valid) — that is the point')

console.log(`  signature:            ${res.checks.signature}`)
console.log(`  action_digest_binds:  ${res.checks.action_digest_binds}`)
console.log(`  action_ref_recomputes:${res.checks.action_ref_recomputes}`)
console.log(`  verifyRecord.ok:      ${res.ok}  (expected ${v.expected_verification})`)
console.log(`  recorded decision:    ${v.record.decision}`)
console.log(`  presidio_recompute_expected: ${v.presidio_recompute_expected}`)

const ok = problems.length === 0
console.log(`\n  ${ok ? 'PASS' : 'FAIL'} native-APS: record is ${res.ok ? 'VALID' : 'INVALID'}` +
  (problems.length ? `\n         ${problems.join('; ')}` : ''))
console.log(`\n${ok ? 'RECOMPUTE-LAYER RECORD IS APS-NATIVE-VALID (as intended)' : 'FAILED'}`)
process.exit(ok ? 0 : 1)

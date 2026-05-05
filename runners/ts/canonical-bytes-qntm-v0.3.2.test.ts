// APS conformance suite — canonical-bytes regression for qntm v0.3.2.
//
// Mirrors corpollc/qntm#15. Verifies the string-concatenation preimage
// failure class is captured against APS-side canonicalization:
//
//   1. Pre-fix path (legacy string-concat preimage) reproduces the
//      fixture's pre-fix sha256 (`53cce2bf...`).
//   2. Post-fix path (canonical JSON) reproduces the fixture's post-fix
//      sha256 (`040cfc8c...`).
//   3. Pre-fix and post-fix hashes diverge.
//   4. Preimage ambiguity collision: two semantically different inputs
//      produce identical concatenation bytes (and therefore the same
//      legacy chain hash).
//   5. Canonical JSON is immune to that collision: the same two inputs
//      under canonical JSON produce different hashes.
//
// The post-fix branch uses the suite's vendored JCS canonicalizer
// (runners/ts/canonicalize.ts). Plain string-typed objects under JCS
// produce byte-identical output to Python's
// `json.dumps(sort_keys=True, separators=(",", ":"))` — the form the
// upstream qntm verifier uses. Canonicalizer source: agent-passport-system
// `src/core/canonical-jcs.ts` at the time of suite extraction.
//
// Run:
//   npx tsx runners/ts/canonical-bytes-qntm-v0.3.2.test.ts
//
// Exit 0 on full pass, 1 on any failure.

import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from './canonicalize.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(
  __dirname, '..', '..',
  'fixtures', 'canonical-bytes', 'canonical-bytes-diff-v032.json',
)

interface Fixture {
  components: {
    request_hash: string
    response_hash: string
    transaction_id: string
    timestamp: string
    buyer_fingerprint: string
    seller: string
  }
  pre_fix: {
    canonical_bytes_hex: string
    chain_hash: string
  }
  post_fix: {
    canonical_bytes_utf8: string
    canonical_bytes_hex: string
    chain_hash: string
  }
  preimage_ambiguity_proof: {
    original: {
      seller: string
      upstream_timestamp: string
      chain_hash: string
    }
    collision: {
      seller: string
      upstream_timestamp: string
      chain_hash: string
    }
  }
}

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex')
}

function stripPrefix(h: string): string {
  return h.startsWith('sha256:') ? h.slice('sha256:'.length) : h
}

interface Check {
  name: string
  ok: boolean
  detail?: string
}

const checks: Check[] = []

function expect(name: string, ok: boolean, detail?: string): void {
  checks.push({ name, ok, detail })
}

const fx: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))
const c = fx.components

// Check 1: pre-fix legacy string-concatenation hash.
const legacyInput = c.request_hash + c.response_hash + c.transaction_id +
  c.timestamp + c.buyer_fingerprint + c.seller
const legacyHash = sha256Hex(legacyInput)
expect(
  'pre-fix sha256 (legacy concat) matches fixture',
  legacyHash === stripPrefix(fx.pre_fix.chain_hash),
  `expected ${stripPrefix(fx.pre_fix.chain_hash)}, got ${legacyHash}`,
)
expect(
  'pre-fix canonical_bytes_hex matches concat hex',
  Buffer.from(legacyInput, 'utf8').toString('hex') === fx.pre_fix.canonical_bytes_hex,
)

// Check 2: post-fix canonical JSON via vendored JCS.
const canonicalData = {
  request_hash: c.request_hash,
  response_hash: c.response_hash,
  transaction_id: c.transaction_id,
  timestamp: c.timestamp,
  buyer_fingerprint: c.buyer_fingerprint,
  seller: c.seller,
}
const canonical = canonicalizeJCS(canonicalData)
const canonicalHash = sha256Hex(canonical)
expect(
  'post-fix sha256 (canonical JSON via vendored JCS) matches fixture',
  canonicalHash === stripPrefix(fx.post_fix.chain_hash),
  `expected ${stripPrefix(fx.post_fix.chain_hash)}, got ${canonicalHash}`,
)
expect(
  'post-fix canonical bytes utf-8 match fixture (vendored JCS == python json.dumps sort_keys)',
  canonical === fx.post_fix.canonical_bytes_utf8,
)
expect(
  'post-fix canonical bytes hex matches fixture',
  Buffer.from(canonical, 'utf8').toString('hex') === fx.post_fix.canonical_bytes_hex,
)

// Check 3: pre-fix and post-fix diverge (the whole point of the fix).
expect(
  'pre-fix and post-fix hashes diverge',
  legacyHash !== canonicalHash,
)

// Check 4: preimage ambiguity collision under string concat.
const amb = fx.preimage_ambiguity_proof
const extInput = legacyInput + amb.original.upstream_timestamp
const extHash = sha256Hex(extInput)
expect(
  'extended legacy input reproduces ambiguity-original chain_hash',
  extHash === stripPrefix(amb.original.chain_hash),
)

const collisionInput = c.request_hash + c.response_hash + c.transaction_id +
  c.timestamp + c.buyer_fingerprint + amb.collision.seller +
  amb.collision.upstream_timestamp
const collisionHash = sha256Hex(collisionInput)
expect(
  'collision concat input reproduces ambiguity-collision chain_hash',
  collisionHash === stripPrefix(amb.collision.chain_hash),
)
expect(
  'collision: two semantically different inputs produce same legacy hash',
  collisionHash === extHash,
)

// Check 5: canonical JSON is immune to the collision.
const canonicalOriginal = canonicalizeJCS({
  ...canonicalData,
  upstream_timestamp: amb.original.upstream_timestamp,
})
const canonicalCollision = canonicalizeJCS({
  request_hash: c.request_hash,
  response_hash: c.response_hash,
  transaction_id: c.transaction_id,
  timestamp: c.timestamp,
  buyer_fingerprint: c.buyer_fingerprint,
  seller: amb.collision.seller,
  upstream_timestamp: amb.collision.upstream_timestamp,
})
expect(
  'canonical JSON path produces different hashes for the two inputs (collision class eliminated)',
  sha256Hex(canonicalOriginal) !== sha256Hex(canonicalCollision),
)

// Report.
let failed = 0
for (const ch of checks) {
  if (ch.ok) {
    console.log(`  PASS  ${ch.name}`)
  } else {
    failed += 1
    console.log(`  FAIL  ${ch.name}${ch.detail ? ` (${ch.detail})` : ''}`)
  }
}
console.log()
console.log(`canonical-bytes-qntm-v0.3.2: ${checks.length - failed}/${checks.length} pass`)
console.log(`  Pre-fix hash:  sha256:${legacyHash}`)
console.log(`  Post-fix hash: sha256:${canonicalHash}`)
process.exit(failed > 0 ? 1 : 0)

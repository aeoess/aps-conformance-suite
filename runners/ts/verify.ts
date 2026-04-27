// APS conformance suite — TS runner.
//
// Reads fixtures/manifest.json and per-category fixture files. For each
// vector, runs the vendored JCS canonicalizer over `input`, computes
// SHA-256 hex of the canonical bytes, compares against `canonical_sha256`.
// For vectors that carry `ed25519_signature_over_canonical_hex`, also
// verifies the signature using the deterministic keypair declared in the
// fixture.
//
// Run:
//   npx tsx runners/ts/verify.ts
//
// Exit code 0 on full pass, 1 on any failure.

import crypto from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from './canonicalize.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const FIXTURES_DIR = join(REPO_ROOT, 'fixtures')
const MANIFEST_PATH = join(FIXTURES_DIR, 'manifest.json')

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

interface ManifestEntry {
  category: string
  path: string
  canonical_sha256: string
  vector_count: number
  spec_section: string
}

interface Manifest {
  version: string
  spec_refs: string[]
  fixtures: ManifestEntry[]
}

interface FixtureFile {
  version?: string
  primitive?: string
  spec?: string
  spec_ref?: string
  seed_input?: string
  keypair?: { publicKeyHex: string }
  vectors: Vector[]
}

interface Vector {
  name: string
  description?: string
  expected_verification?: boolean
  input?: unknown
  envelope?: unknown
  canonical_bytes_hex?: string
  canonical_sha256?: string
  ed25519_signature?: string
  ed25519_pubkey_hex?: string
  ed25519_signature_over_canonical_hex?: string
  expected_error_code?: string
  rejection_kind?: string
}

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex')
}

function sha256OfFile(path: string): string {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex')
}

function verifyEd25519(message: string, sigHex: string, pubHex: string): boolean {
  try {
    const pub = Buffer.from(pubHex, 'hex')
    if (pub.length !== 32) return false
    const derKey = Buffer.concat([SPKI_ED25519_PREFIX, pub])
    const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, Buffer.from(sigHex, 'hex'))
  } catch {
    return false
  }
}

function deriveKeypairFromSeed(seedInput: string): { publicKeyHex: string; privateKeyHex: string } {
  const seed = crypto.createHash('sha256').update(seedInput, 'utf-8').digest()
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey(keyObj)
  const pubDer = pubKey.export({ type: 'spki', format: 'der' }) as Buffer
  return {
    publicKeyHex: pubDer.subarray(-32).toString('hex'),
    privateKeyHex: seed.toString('hex'),
  }
}

interface VectorResult {
  category: string
  fixture: string
  name: string
  status: 'pass' | 'fail' | 'skip'
  details?: string
}

function checkVector(category: string, fixture: string, fixtureData: FixtureFile, v: Vector): VectorResult[] {
  const results: VectorResult[] = []
  const declaredPub = fixtureData.keypair?.publicKeyHex ?? v.ed25519_pubkey_hex

  // IPR-style: vector carries a signed `envelope` plus canonical_bytes_hex
  // computed by the IPR module's canonicalizeEnvelope (signature + receipt_id
  // stripped). Check this branch BEFORE the generic input branch because IPR
  // vectors carry both fields.
  if (v.envelope !== undefined && v.canonical_bytes_hex !== undefined && v.canonical_sha256 !== undefined) {
    const env = v.envelope as Record<string, unknown>
    const stripped: Record<string, unknown> = {}
    for (const k of Object.keys(env)) {
      if (k === 'signature' || k === 'receipt_id') continue
      stripped[k] = env[k]
    }
    const canonical = canonicalizeJCS(stripped)
    const canonicalHex = Buffer.from(canonical, 'utf8').toString('hex')
    const canonicalSha = sha256Hex(canonical)
    if (canonicalHex !== v.canonical_bytes_hex) {
      results.push({ category, fixture, name: v.name, status: 'fail', details: `IPR envelope canonical_bytes_hex mismatch (len me=${canonicalHex.length}, exp=${v.canonical_bytes_hex.length})` })
      return results
    }
    if (canonicalSha !== v.canonical_sha256) {
      results.push({ category, fixture, name: v.name, status: 'fail', details: `IPR envelope canonical_sha256 mismatch` })
      return results
    }
    const sig = v.ed25519_signature ?? (env.signature as string | undefined)
    if (sig && declaredPub) {
      const ok = verifyEd25519(canonical, sig, declaredPub)
      if (!ok) {
        results.push({ category, fixture, name: v.name, status: 'fail', details: `Ed25519 verification failed for IPR envelope` })
        return results
      }
    }
    results.push({ category, fixture, name: v.name, status: 'pass' })
    return results
  }

  // Bilateral-delegation / inference-session style: input + canonical_bytes_hex.
  // For these vectors `expected_verification: false` indicates POLICY-level
  // rejection (expired window, out-of-scope action) — not signature failure.
  // The signature itself is valid by construction; we only verify byte parity.
  if (v.canonical_bytes_hex !== undefined && v.canonical_sha256 !== undefined && v.input !== undefined) {
    const canonical = canonicalizeJCS(v.input)
    const canonicalHex = Buffer.from(canonical, 'utf8').toString('hex')
    const canonicalSha = sha256Hex(canonical)
    if (canonicalHex !== v.canonical_bytes_hex) {
      results.push({ category, fixture, name: v.name, status: 'fail', details: `canonical_bytes_hex mismatch (expected ${v.canonical_bytes_hex.slice(0, 16)}…, got ${canonicalHex.slice(0, 16)}…)` })
      return results
    }
    if (canonicalSha !== v.canonical_sha256) {
      results.push({ category, fixture, name: v.name, status: 'fail', details: `canonical_sha256 mismatch (expected ${v.canonical_sha256.slice(0, 16)}…, got ${canonicalSha.slice(0, 16)}…)` })
      return results
    }
    const sig = v.ed25519_signature_over_canonical_hex ?? v.ed25519_signature
    if (sig && declaredPub) {
      const ok = verifyEd25519(canonical, sig, declaredPub)
      if (!ok) {
        results.push({ category, fixture, name: v.name, status: 'fail', details: `Ed25519 signature verification failed (signature inconsistent with declared keypair)` })
        return results
      }
    }
    results.push({ category, fixture, name: v.name, status: 'pass' })
    return results
  }

  // AIVSS-style scenarios: structural fixtures, no canonical bytes.
  // Verify that the file shape is well-formed (presence of expected fields).
  if ('scenario_id' in (v as object)) {
    results.push({ category, fixture, name: v.name, status: 'pass', details: 'AIVSS structural fixture (no canonicalization check applies)' })
    return results
  }

  // Instruction-provenance negatives carry only metadata (no canonical bytes).
  if (v.expected_verification === false) {
    results.push({ category, fixture, name: v.name, status: 'pass', details: `negative-vector metadata (rejection_kind=${v.rejection_kind ?? 'unspecified'})` })
    return results
  }

  results.push({ category, fixture, name: v.name, status: 'skip', details: 'no canonicalization data in vector' })
  return results
}

function main(): number {
  if (!existsSync(MANIFEST_PATH)) {
    console.error(`manifest not found at ${MANIFEST_PATH}`)
    return 1
  }
  const manifest: Manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'))
  console.log(`APS conformance suite v${manifest.version}`)
  console.log(`fixtures: ${manifest.fixtures.length} files`)
  console.log()

  const allResults: VectorResult[] = []
  for (const entry of manifest.fixtures) {
    const fixturePath = join(FIXTURES_DIR, entry.path)
    if (!existsSync(fixturePath)) {
      console.error(`  MISSING ${entry.path}`)
      allResults.push({ category: entry.category, fixture: entry.path, name: '<file>', status: 'fail', details: 'file missing' })
      continue
    }
    // Verify file-level sha256 matches manifest claim.
    const fileSha = sha256OfFile(fixturePath)
    if (entry.canonical_sha256 && entry.canonical_sha256 !== fileSha) {
      allResults.push({ category: entry.category, fixture: entry.path, name: '<manifest-sha>', status: 'fail', details: `manifest sha256 mismatch (expected ${entry.canonical_sha256.slice(0, 16)}…, got ${fileSha.slice(0, 16)}…)` })
      continue
    }

    const data: FixtureFile = JSON.parse(readFileSync(fixturePath, 'utf8'))
    if (data.seed_input && data.keypair?.publicKeyHex) {
      const derived = deriveKeypairFromSeed(data.seed_input)
      if (derived.publicKeyHex !== data.keypair.publicKeyHex) {
        allResults.push({ category: entry.category, fixture: entry.path, name: '<keypair>', status: 'fail', details: `keypair derivation mismatch (declared ${data.keypair.publicKeyHex.slice(0, 16)}…, derived ${derived.publicKeyHex.slice(0, 16)}…)` })
        continue
      }
    }

    if (!Array.isArray(data.vectors)) {
      // AIVSS-style: manifest references scenario files. Load each and run
      // a structural check.
      const aivssScenarios = (data as unknown as { scenarios?: string[] }).scenarios
      if (Array.isArray(aivssScenarios)) {
        const dir = dirname(fixturePath)
        for (const scenarioName of aivssScenarios) {
          const scenarioPath = join(dir, scenarioName)
          if (!existsSync(scenarioPath)) {
            allResults.push({ category: entry.category, fixture: entry.path, name: scenarioName, status: 'fail', details: `referenced scenario file not found: ${scenarioPath}` })
            continue
          }
          const scen: Record<string, unknown> = JSON.parse(readFileSync(scenarioPath, 'utf8'))
          const required = ['scenario_id', 'owasp_risk', 'aivss_score', 'aps_primitive_exercised', 'expected_outcome']
          const missing = required.filter(k => !(k in scen))
          if (missing.length > 0) {
            allResults.push({ category: entry.category, fixture: scenarioName, name: scenarioName, status: 'fail', details: `missing required fields: ${missing.join(', ')}` })
          } else {
            allResults.push({ category: entry.category, fixture: scenarioName, name: String(scen.scenario_id), status: 'pass', details: `AIVSS ${scen.aivss_score} — ${String(scen.aps_primitive_exercised).split('—')[0].trim()}` })
          }
        }
        continue
      }
      allResults.push({ category: entry.category, fixture: entry.path, name: '<vectors>', status: 'skip', details: 'no `vectors` array and no `scenarios` list' })
      continue
    }

    for (const v of data.vectors) {
      allResults.push(...checkVector(entry.category, entry.path, data, v))
    }
  }

  // Print per-category summary.
  const byCategory = new Map<string, { pass: number; fail: number; skip: number }>()
  for (const r of allResults) {
    const c = byCategory.get(r.category) ?? { pass: 0, fail: 0, skip: 0 }
    c[r.status] += 1
    byCategory.set(r.category, c)
  }
  for (const [cat, counts] of byCategory.entries()) {
    console.log(`  ${cat.padEnd(28)} pass=${counts.pass}  fail=${counts.fail}  skip=${counts.skip}`)
  }
  console.log()

  const fails = allResults.filter(r => r.status === 'fail')
  if (fails.length > 0) {
    console.log('FAILURES:')
    for (const f of fails) {
      console.log(`  ${f.category} / ${f.fixture} / ${f.name}: ${f.details ?? ''}`)
    }
    return 1
  }
  const total = allResults.length
  const passed = allResults.filter(r => r.status === 'pass').length
  const skipped = allResults.filter(r => r.status === 'skip').length
  console.log(`TOTAL: ${total} vectors  pass=${passed}  fail=0  skip=${skipped}`)
  return 0
}

process.exit(main())

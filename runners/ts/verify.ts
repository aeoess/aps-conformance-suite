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
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from './canonicalize.js'
// Real per-category verifiers (the same primitives the dedicated
// fixtures/<cat>/verify.ts scripts use). Namespaced to avoid symbol collisions
// (both libs export canonicalizeJCS / sha256Hex / utf8Hex / verifyUtf8).
import * as acctLib from '../../fixtures/accountability-record/lib.js'
import * as rfrLib from '../../fixtures/read-fidelity-receipt/lib.js'
import * as rfrWordlist from '../../fixtures/read-fidelity-receipt/wordlist.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
// The fixtures directory defaults to the in-repo fixtures. APS_FIXTURES_DIR
// overrides it so a test harness can point the runner at a copied-and-mutated
// fixture tree (used to prove the fail-loud behaviour without touching any
// published fixture file). Not used in normal operation.
const FIXTURES_DIR = process.env.APS_FIXTURES_DIR
  ? resolve(process.env.APS_FIXTURES_DIR)
  : join(REPO_ROOT, 'fixtures')
const MANIFEST_PATH = join(FIXTURES_DIR, 'manifest.json')

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

interface ManifestEntry {
  category: string
  path: string
  canonical_sha256: string
  vector_count: number
  spec_section: string
  // When set, the file carries no `vectors`/`scenarios` this runner can assert
  // over because it is deep-verified by a dedicated test. The runner records an
  // explicit skip with this reason instead of failing loud. Anything else with
  // no assertable shape is a FAILURE, not a silent skip.
  skip_in_runner?: string
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
  // An explicit, runner-recognized skip marker for a vector that is genuinely
  // not applicable to this runner. Its presence (with a reason) is the ONLY way
  // a vector may skip; an unrecognized/unhandled shape is a failure.
  skip_reason?: string
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

  // Negative vectors (expected_verification === false) reaching this point carry
  // only rejection metadata (e.g. instruction-provenance TIER_RESERVED / OMISSION
  // / PATH_SMUGGLING). A negative may only PASS when the reference genuinely
  // cannot verify it as a positive: it must declare rejection metadata AND, if it
  // also carries positive crypto material (input + canonical bytes + signature)
  // that verifies cleanly, the negative label is contradicted -> FAIL. The
  // absence (or failure) of positive verification IS the rejection we assert.
  if (v.expected_verification === false) {
    const hasRejectionMeta = v.rejection_kind !== undefined || v.expected_error_code !== undefined
    if (!hasRejectionMeta) {
      results.push({ category, fixture, name: v.name, status: 'fail', details: 'negative vector declares no rejection metadata (rejection_kind/expected_error_code) and carries no recomputable data; rejection cannot be confirmed' })
      return results
    }
    const negSig = v.ed25519_signature_over_canonical_hex ?? v.ed25519_signature
    if (v.input !== undefined && v.canonical_bytes_hex !== undefined && negSig && declaredPub) {
      const canonical = canonicalizeJCS(v.input)
      const canonicalHex = Buffer.from(canonical, 'utf8').toString('hex')
      if (canonicalHex === v.canonical_bytes_hex && verifyEd25519(canonical, negSig, declaredPub)) {
        results.push({ category, fixture, name: v.name, status: 'fail', details: 'declared negative but canonical bytes and Ed25519 signature verify cleanly' })
        return results
      }
    }
    results.push({ category, fixture, name: v.name, status: 'pass', details: `negative confirmed non-verifiable (rejection=${v.rejection_kind ?? v.expected_error_code})` })
    return results
  }

  // A vector that reaches this point matched no known shape. Only an explicit,
  // runner-recognized skip marker may downgrade it to skip; otherwise it is a
  // FAILURE. Silently skipping an unrecognized shape is exactly the defect this
  // runner used to have -- it let vectors assert nothing while the suite stayed
  // green.
  if (typeof v.skip_reason === 'string' && v.skip_reason.length > 0) {
    results.push({ category, fixture, name: v.name, status: 'skip', details: `explicit skip: ${v.skip_reason}` })
    return results
  }
  results.push({ category, fixture, name: v.name, status: 'fail', details: 'unrecognized vector shape: no verifiable data and no explicit skip_reason (fail-loud; a not-applicable vector must declare skip_reason)' })
  return results
}

// Real verification for the accountability-record family. Mirrors
// fixtures/accountability-record/verify.ts: byte-parity of signing input and
// canonical bytes re-derived from the record, published-signature match, then
// full crypto verification (Ed25519 over the signing input plus action_digest
// binding / action_ref recompute when the payload is inline). Schema negatives
// are rejected by validate.py, not the crypto layer, so their outcome is not
// asserted here (their bytes are self-consistent) -- byte-parity still runs.
function verifyAccountabilityFile(category: string, fixture: string, data: FixtureFile): VectorResult[] {
  const out: VectorResult[] = []
  for (const v of (data.vectors as unknown as Array<Record<string, any>>)) {
    const problems: string[] = []
    const si = acctLib.signingInput(v.record)
    if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
    if (acctLib.utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
    const canonical = acctLib.canonicalizeJCS(v.record)
    if (canonical !== v.canonical) problems.push('canonical mismatch')
    if (acctLib.utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
    if (acctLib.sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')
    if (v.record.sig !== v.ed25519_signature_over_signing_input_hex) problems.push('record.sig != published signature')

    const res = acctLib.verifyRecord(v.record, v.ed25519_pubkey_hex)
    if (v.rejection_kind !== 'schema') {
      if (res.ok !== v.expected_verification) {
        problems.push(`verification ${res.ok} != expected ${v.expected_verification}`)
      }
      if (v.expected_verification === false) {
        if (v.rejection_kind === 'digest_mismatch' && res.checks.action_digest_binds !== false) {
          problems.push('declared digest_mismatch but action_digest bound')
        }
        if (v.rejection_kind === 'signature' && res.checks.signature !== false) {
          problems.push('declared signature rejection but signature verified')
        }
      }
    }

    const status: VectorResult['status'] = problems.length ? 'fail' : 'pass'
    const detail = problems.length
      ? problems.join('; ')
      : v.rejection_kind === 'schema'
        ? 'byte-parity checked; schema rejection enforced by validate.py'
        : v.rejection_kind
          ? `negative confirmed (${v.rejection_kind})`
          : undefined
    out.push({ category, fixture, name: v.name, status, details: detail })
  }
  return out
}

// Real verification for the read-fidelity-receipt family. Mirrors
// fixtures/read-fidelity-receipt/verify.ts: wordlist integrity, then per vector
// either record verification (byte-parity, Ed25519 over the sig-excluded JCS
// bytes against the embedded attester, seed derivation, span commitments and k
// recompute for positives) or word-handle codec verification. Every negative
// must fail for its STATED reason.
function verifyReadFidelityFile(category: string, fixture: string, data: FixtureFile): VectorResult[] {
  const out: VectorResult[] = []
  const fx = data as unknown as Record<string, any>

  // Wordlist integrity: the vendored wordlist must hash to the pinned lexicon id.
  {
    const recomputed = `sha256:${rfrLib.sha256Hex(rfrWordlist.canonicalWordlistText())}`
    const ok = rfrWordlist.WORDS.length === 2048 && recomputed === rfrWordlist.LEXICON_ID && fx.lexicon_id === rfrWordlist.LEXICON_ID
    out.push({ category, fixture, name: 'wordlist-integrity', status: ok ? 'pass' : 'fail', details: ok ? undefined : 'wordlist integrity failed (word count / lexicon id mismatch)' })
  }

  for (const v of (fx.vectors as Array<Record<string, any>>)) {
    const problems: string[] = []

    if (v.kind === 'record') {
      const si = rfrLib.canonicalNoSig(v.record)
      if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
      if (rfrLib.utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
      const canonical = rfrLib.canonicalizeJCS(v.record)
      if (canonical !== v.canonical) problems.push('canonical mismatch')
      if (rfrLib.utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
      if (rfrLib.sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')
      if (v.record.attester !== v.ed25519_pubkey_hex) problems.push('attester != published pubkey')

      const res = rfrLib.verifyReadFidelityReceipt(v.record)
      if (res.valid !== v.expected_verification) {
        problems.push(`verification ${res.valid} != expected ${v.expected_verification}`)
      }
      if (v.expected_verification === false) {
        if (res.reason !== v.expected_reason) {
          problems.push(`failed for ${res.reason}, stated reason is ${v.expected_reason}`)
        }
        if (v.rejection_kind === 'seed') {
          if (!rfrLib.verifyUtf8(rfrLib.canonicalNoSig(v.record), v.record.sig, v.record.attester)) {
            problems.push('declared seed rejection but the re-signed signature does not verify')
          }
        }
        if (v.rejection_kind === 'signature') {
          if (rfrLib.verifyUtf8(rfrLib.canonicalNoSig(v.record), v.record.sig, v.record.attester)) {
            problems.push('declared signature rejection but the signature verifies')
          }
        }
      } else {
        const against = rfrLib.verifyAgainstSource(v.record, v.source_text)
        if (!against.valid) problems.push(`against-source failed: ${against.reason}`)
        if (v.responses) {
          const spans = rfrLib.sampleSpans(v.source_text, v.record.challenge.seed, v.record.n, v.record.challenge.span_len)
          const { k } = rfrLib.scoreResponses(spans.map((s) => s.text), v.responses)
          if (k !== v.record.k) problems.push(`k recompute ${k} != recorded ${v.record.k}`)
          const rd = `sha256:${rfrLib.sha256Hex(rfrLib.canonicalizeJCS(v.responses))}`
          if (rd !== v.record.response_digest) problems.push('response_digest recompute mismatch')
        }
      }
    } else if (v.kind === 'word_handle') {
      const reEncoded = rfrLib.encodeProfile(v.digest, v.profile)
      if (JSON.stringify(reEncoded) !== JSON.stringify(v.original_words)) {
        problems.push('original_words do not re-encode from digest')
      }
      const orig = rfrLib.decodeProfile(v.original_words, v.profile)
      if (orig.checksumOk !== true) problems.push('unmutated base fails its own checksum')

      const res = rfrLib.decodeProfile(v.words, v.profile)
      const actualReason = res.outOfLexicon.length > 0 ? 'OUT_OF_LEXICON' : res.checksumOk ? 'NONE' : 'CHECKSUM_MISMATCH'
      if (res.checksumOk !== v.expected.checksum_ok) {
        problems.push(`checksum_ok ${res.checksumOk} != expected ${v.expected.checksum_ok}`)
      }
      if (JSON.stringify(res.outOfLexicon) !== JSON.stringify(v.expected.out_of_lexicon)) {
        problems.push(`out_of_lexicon ${JSON.stringify(res.outOfLexicon)} != expected ${JSON.stringify(v.expected.out_of_lexicon)}`)
      }
      if ((res.prefixHex === null) !== v.expected.prefix_hex_null) {
        problems.push('prefix_hex null-ness mismatch')
      }
      if (actualReason !== v.expected_reason) {
        problems.push(`failed for ${actualReason}, stated reason is ${v.expected_reason}`)
      }
    } else {
      problems.push(`unknown vector kind ${v.kind}`)
    }

    out.push({ category, fixture, name: v.name, status: problems.length ? 'fail' : 'pass', details: problems.length ? problems.join('; ') : undefined })
  }
  return out
}

// Compare two strings by Unicode code point. JavaScript's default string
// comparison and Array#sort order by UTF-16 code unit, which differs from code
// point order for astral-plane characters (a high BMP scope must sort before an
// astral scope). Array.from iterates by code point, so surrogate pairs collapse
// to a single element before comparison.
function compareCodePoints(a: string, b: string): number {
  const aa = Array.from(a)
  const bb = Array.from(b)
  const n = Math.min(aa.length, bb.length)
  for (let i = 0; i < n; i++) {
    const ca = aa[i].codePointAt(0) as number
    const cb = bb[i].codePointAt(0) as number
    if (ca !== cb) return ca - cb
  }
  return aa.length - bb.length
}

// Native APS action_ref (draft-pidlisnyi-aps-03 section 4.1): NFC-normalize each
// scope string, sort scopeRequired by Unicode code point, then SHA-256 over the
// RFC 8785 (JCS) canonicalization of {agentId, actionType, scopeRequired,
// timestamp}. Reuses the vendored JCS canonicalizer and the accountability lib's
// SHA-256 helper; no crypto is reimplemented here.
function computeNativeActionRef(input: {
  agentId: string
  actionType: string
  scopeRequired: string[]
  timestamp: string
}): { actionRef: string; scopeOrder: string[] } {
  const scopeOrder = input.scopeRequired.map((s) => s.normalize('NFC')).sort(compareCodePoints)
  const tuple = {
    agentId: input.agentId,
    actionType: input.actionType,
    scopeRequired: scopeOrder,
    timestamp: input.timestamp,
  }
  return { actionRef: acctLib.sha256Hex(canonicalizeJCS(tuple)), scopeOrder }
}

// actionref-canonical family: recompute action_ref for each input and assert it
// equals the vector's recorded action_ref (and, when present, the canonical
// scope order). These vectors carry expected action_ref values, so this is a
// real assertion, not a byte-parity echo.
function verifyActionRefFile(category: string, fixture: string, data: FixtureFile): VectorResult[] {
  const out: VectorResult[] = []
  for (const v of (data.vectors as unknown as Array<Record<string, any>>)) {
    const problems: string[] = []
    if (!v.input || !Array.isArray(v.input.scopeRequired)) {
      problems.push('missing input.scopeRequired')
    } else {
      const { actionRef, scopeOrder } = computeNativeActionRef(v.input)
      if (typeof v.action_ref !== 'string') {
        problems.push('vector declares no expected action_ref')
      } else if (actionRef !== v.action_ref) {
        problems.push(`action_ref mismatch (recomputed ${actionRef.slice(0, 16)}…, expected ${v.action_ref.slice(0, 16)}…)`)
      }
      if (Array.isArray(v.canonical_scope_order) && JSON.stringify(scopeOrder) !== JSON.stringify(v.canonical_scope_order)) {
        problems.push(`canonical scope order mismatch (recomputed ${JSON.stringify(scopeOrder)}, expected ${JSON.stringify(v.canonical_scope_order)})`)
      }
    }
    out.push({ category, fixture, name: v.name, status: problems.length ? 'fail' : 'pass', details: problems.length ? problems.join('; ') : undefined })
  }
  return out
}

// Structural reconciliation of a bilateral receipt pair. Per the fixture README
// the per-copy Ed25519 signatures are presumed already verified; reconciliation
// compares the relying party's copy against the counterparty copy (or its
// absence) and emits reason-coded mismatch classes. Field identity that differs
// per copy by construction (receiptId, agreedAt, signatures) is not compared;
// only the semantic binding fields are.
function reconcileBilateralPair(
  local: Record<string, any>,
  counterparty: Record<string, any> | null | undefined,
  policy: Record<string, any>,
): { status: string; mismatches: string[] } {
  const mismatches: string[] = []
  if (counterparty === null || counterparty === undefined) {
    if (local.outcome?.status === 'success') mismatches.push('unilateral_success')
    return { status: 'unilateral', mismatches }
  }
  if (policy?.requireAudience) {
    const recipients: string[] = counterparty.aud?.recipients ?? []
    if (!recipients.includes(policy.selfRecipientId)) mismatches.push('wrong_audience')
  }
  if (local.requestingAgentId !== counterparty.requestingAgentId || local.servingAgentId !== counterparty.servingAgentId) {
    mismatches.push('recipient_changed')
  }
  if (canonicalizeJCS(local.outcome) !== canonicalizeJCS(counterparty.outcome)) {
    mismatches.push('payload_changed')
  }
  if (local.action_ref !== counterparty.action_ref) {
    mismatches.push('action_ref_mismatch')
  }
  return { status: mismatches.length ? 'mismatch' : 'reconciled', mismatches }
}

// bilateral-pair family: run reconciliation over each pair and assert the
// resulting status plus mismatch set match the vector's expected verdict. The
// mismatch lists are compared order-independently.
function verifyBilateralPairFile(category: string, fixture: string, data: FixtureFile): VectorResult[] {
  const out: VectorResult[] = []
  const sorted = (a: string[]): string => JSON.stringify([...a].sort())
  for (const v of (data.vectors as unknown as Array<Record<string, any>>)) {
    const problems: string[] = []
    if (!v.local || !v.expected) {
      problems.push('missing local receipt or expected verdict')
    } else {
      const r = reconcileBilateralPair(v.local, v.counterparty, v.policy ?? {})
      if (r.status !== v.expected.status) {
        problems.push(`status ${r.status} != expected ${v.expected.status}`)
      }
      const expectedMismatches: string[] = Array.isArray(v.expected.mismatches) ? v.expected.mismatches : []
      if (sorted(r.mismatches) !== sorted(expectedMismatches)) {
        problems.push(`mismatches ${JSON.stringify(r.mismatches)} != expected ${JSON.stringify(expectedMismatches)}`)
      }
    }
    out.push({ category, fixture, name: v.name, status: problems.length ? 'fail' : 'pass', details: problems.length ? problems.join('; ') : undefined })
  }
  return out
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

    // Categories with a dedicated per-category verifier are dispatched to it so
    // their positive vectors are actually checked and their negatives are only
    // marked PASS when the reference genuinely rejects them (no vacuous passes).
    if (entry.category === 'accountability-record') {
      allResults.push(...verifyAccountabilityFile(entry.category, entry.path, data))
      continue
    }
    if (entry.category === 'read-fidelity-receipt') {
      allResults.push(...verifyReadFidelityFile(entry.category, entry.path, data))
      continue
    }
    if (entry.category === 'actionref-canonical') {
      allResults.push(...verifyActionRefFile(entry.category, entry.path, data))
      continue
    }
    if (entry.category === 'bilateral-pair') {
      allResults.push(...verifyBilateralPairFile(entry.category, entry.path, data))
      continue
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
      // No `vectors` and no `scenarios` this runner can assert over. Only an
      // explicit, manifest-declared skip (deep-verified elsewhere) may downgrade
      // to skip; otherwise this is a FAILURE, not a silent skip.
      if (typeof entry.skip_in_runner === 'string' && entry.skip_in_runner.length > 0) {
        allResults.push({ category: entry.category, fixture: entry.path, name: '<file>', status: 'skip', details: `explicit skip: ${entry.skip_in_runner}` })
      } else {
        allResults.push({ category: entry.category, fixture: entry.path, name: '<vectors>', status: 'fail', details: 'no `vectors` array and no `scenarios` list, and manifest declares no skip_in_runner (fail-loud)' })
      }
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

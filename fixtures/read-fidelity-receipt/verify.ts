// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Cold-clone verifier for the read-fidelity-receipt fixture family.
//
// Run as:  npx tsx fixtures/read-fidelity-receipt/verify.ts
//
// Record vectors: re-derives the signing input and canonical bytes from each
// record and checks byte-parity against the stored fields, then runs full
// verification (shape, Ed25519 over the JCS bytes with sig excluded against
// the embedded attester, seed derivation recompute, span commitments against
// the source text) and asserts the outcome matches expected_verification.
// Word handle vectors: re-encodes the base digest, decodes the mutated words,
// and asserts the decode outcome.
//
// EVERY negative must fail for its STATED reason (expected_reason), and the
// stated and actual reasons are printed side by side. Exits 0 only if all
// vectors match.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { LEXICON_ID, WORDS, canonicalWordlistText } from './wordlist.js'
import {
  canonicalNoSig,
  canonicalizeJCS,
  decodeProfile,
  encodeProfile,
  sampleSpans,
  scoreResponses,
  sha256Hex,
  utf8Hex,
  verifyAgainstSource,
  verifyReadFidelityReceipt,
  verifyUtf8,
} from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE = join(__dirname, 'read-fidelity-receipt-fixture-v1.json')

const fx = JSON.parse(readFileSync(FIXTURE, 'utf8'))
let failures = 0

console.log(`read-fidelity-receipt verifier: ${fx.vectors.length} vectors from ${FIXTURE}\n`)

// Wordlist integrity: the vendored wordlist must hash to the pinned lexicon id.
{
  const recomputed = `sha256:${sha256Hex(canonicalWordlistText())}`
  const ok = WORDS.length === 2048 && recomputed === LEXICON_ID && fx.lexicon_id === LEXICON_ID
  if (!ok) failures++
  console.log(`  ${ok ? 'PASS' : 'FAIL'} wordlist integrity (2048 words, sha256 == ${LEXICON_ID.slice(0, 18)}...)`)
}

for (const v of fx.vectors) {
  const problems: string[] = []
  let outcome = ''

  if (v.kind === 'record') {
    // 1. byte-parity: signing input and canonical bytes re-derive from the record.
    const si = canonicalNoSig(v.record)
    if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
    if (utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
    const canonical = canonicalizeJCS(v.record)
    if (canonical !== v.canonical) problems.push('canonical mismatch')
    if (utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
    if (sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')

    // 2. attester is the published fixture key.
    if (v.record.attester !== v.ed25519_pubkey_hex) problems.push('attester != published pubkey')

    // 3. full verification; negatives must fail for the STATED reason.
    const res = verifyReadFidelityReceipt(v.record)
    outcome = res.valid ? 'valid' : `reason=${res.reason}`
    if (res.valid !== v.expected_verification) {
      problems.push(`verification ${res.valid} != expected ${v.expected_verification}`)
    }
    if (v.expected_verification === false) {
      if (res.reason !== v.expected_reason) {
        problems.push(`failed for ${res.reason}, stated reason is ${v.expected_reason}`)
      }
      if (v.rejection_kind === 'seed') {
        // Re-signed negatives: the signature itself MUST be valid over the
        // mutated bytes, so only the seed derivation rejects the record.
        if (!verifyUtf8(canonicalNoSig(v.record), v.record.sig, v.record.attester)) {
          problems.push('declared seed rejection but the re-signed signature does not verify')
        }
      }
      if (v.rejection_kind === 'signature') {
        if (verifyUtf8(canonicalNoSig(v.record), v.record.sig, v.record.attester)) {
          problems.push('declared signature rejection but the signature verifies')
        }
      }
    } else {
      // Positives: span commitments must verify against the source text,
      // and k must recompute from the stored responses.
      const against = verifyAgainstSource(v.record, v.source_text)
      if (!against.valid) problems.push(`against-source failed: ${against.reason}`)
      if (v.responses) {
        const spans = sampleSpans(v.source_text, v.record.challenge.seed, v.record.n, v.record.challenge.span_len)
        const { k } = scoreResponses(spans.map((s: { text: string }) => s.text), v.responses)
        if (k !== v.record.k) problems.push(`k recompute ${k} != recorded ${v.record.k}`)
        const rd = `sha256:${sha256Hex(canonicalizeJCS(v.responses))}`
        if (rd !== v.record.response_digest) problems.push('response_digest recompute mismatch')
      }
    }
  } else if (v.kind === 'word_handle') {
    // 1. the base digest re-encodes to the recorded original words.
    const reEncoded = encodeProfile(v.digest, v.profile)
    if (JSON.stringify(reEncoded) !== JSON.stringify(v.original_words)) {
      problems.push('original_words do not re-encode from digest')
    }
    const orig = decodeProfile(v.original_words, v.profile)
    if (orig.checksumOk !== true) problems.push('unmutated base fails its own checksum')

    // 2. the mutated words fail for the STATED reason.
    const res = decodeProfile(v.words, v.profile)
    const actualReason = res.outOfLexicon.length > 0 ? 'OUT_OF_LEXICON' : res.checksumOk ? 'NONE' : 'CHECKSUM_MISMATCH'
    outcome = `checksum_ok=${res.checksumOk} out_of_lexicon=${JSON.stringify(res.outOfLexicon)} reason=${actualReason}`
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

  const ok = problems.length === 0
  if (!ok) failures++
  const stated = v.expected_reason ? ` stated=${v.expected_reason}` : ''
  console.log(
    `  ${ok ? 'PASS' : 'FAIL'} ${v.name.padEnd(42)} ${outcome}${stated}` +
      (problems.length ? `\n         ${problems.join('; ')}` : ''),
  )
}

console.log(`\n${failures === 0 ? 'ALL VECTORS PASS' : failures + ' VECTOR(S) FAILED'}`)
process.exit(failures === 0 ? 0 : 1)

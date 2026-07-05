// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Deterministic fixture-vector generator for the APS read-fidelity-receipt family.
//
// Run as:  npx tsx fixtures/read-fidelity-receipt/generate-fixtures.ts
//
// Eight vectors:
//   v1 positive full readback: valid signed record, k == n           (positive)
//   v2 handle substitution: one data word replaced                   (NEGATIVE, checksum)
//   v3 handle out-of-lexicon: unknown words, indices reported        (NEGATIVE, out_of_lexicon)
//   v4 tampered content_digest after signing                         (NEGATIVE, signature)
//   v5 honest partial: recorded k < n, still a valid record          (positive)
//   v6 replayed nonce: nonce swapped, record RE-SIGNED (sig valid)   (NEGATIVE, seed)
//   v7 presentation swap: presentation_digest swapped, RE-SIGNED     (NEGATIVE, seed)
//   v8 handle transposition: adjacent differing data words swapped   (NEGATIVE, checksum)
//
// Fully deterministic: every input is a fixed string or derived from sha256
// over a fixed label. No wall clock, no randomness. The signing key is a
// FIXTURE-ONLY deterministic key derived from a published seed string; it is
// reproducible by anyone and must never be used outside this fixture.

import { writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { LEXICON_ID, LEXICON_NAME, WORDS } from './wordlist.js'
import {
  LEXICON_PROFILE,
  PROFILES,
  canonicalNoSig,
  canonicalizeJCS,
  commitSpans,
  decodeProfile,
  deriveKeypair,
  deriveSeed,
  encodeProfile,
  sampleSpans,
  scoreResponses,
  sha256Hex,
  shapeReason,
  signUtf8,
  utf8Hex,
  verifyAgainstSource,
  verifyReadFidelityReceipt,
  verifyUtf8,
  type ReadFidelityReceipt,
  type WordHandleProfileName,
} from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dirname, 'read-fidelity-receipt-fixture-v1.json')

// FIXTURE-ONLY deterministic key. Private key = sha256(SEED_INPUT); the seed
// string is published in the fixture so anyone can reproduce the keypair.
// Never a production key.
const SEED_INPUT = 'aps-read-fidelity-receipt-fixture-v1 FIXTURE-ONLY key'
const KP = deriveKeypair(SEED_INPUT)

/** First 4 bytes of sha256(label) as a big-endian uint32. */
function seedUint32(label: string): number {
  return createHash('sha256').update(label, 'utf8').digest().readUInt32BE(0)
}

const WORD_TO_INDEX: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  for (let i = 0; i < WORDS.length; i++) m.set(WORDS[i], i)
  return m
})()

// ── record building ────────────────────────────────────────────────

const T_CHALLENGE = '2026-07-05T00:00:00Z'
const T_RESPONSE = '2026-07-05T00:00:30Z'
const T_RECEIPT = '2026-07-05T00:01:00Z'

interface RecordSpec {
  sourceText: string
  presentationDigest: string | null
  nonce: string
  n: number
  spanLen: number
  /** Indices of responses replaced with a deliberate misread. */
  missIndices?: readonly number[]
  lexiconFields?: boolean
}

interface BuiltRecord {
  record: ReadFidelityReceipt
  sourceText: string
  responses: string[]
  spanTexts: string[]
}

function buildRecord(spec: RecordSpec): BuiltRecord {
  const contentDigest = `sha256:${sha256Hex(spec.sourceText)}`
  const seed = deriveSeed(contentDigest, spec.presentationDigest, spec.nonce, '1')
  const spans = sampleSpans(spec.sourceText, seed, spec.n, spec.spanLen)
  const spanTexts = spans.map((s) => s.text)
  const responses = spanTexts.map((t, i) =>
    spec.missIndices !== undefined && spec.missIndices.includes(i) ? `MISREAD:${t}` : t,
  )
  const { k } = scoreResponses(spanTexts, responses)
  const body: Omit<ReadFidelityReceipt, 'sig'> = {
    type: 'read_fidelity_receipt',
    content_digest: contentDigest,
    presentation_digest: spec.presentationDigest,
    challenge: {
      nonce: spec.nonce,
      seed,
      algorithm: 'span_sample_v1',
      version: '1',
      span_len: spec.spanLen,
      span_commitments: commitSpans(spanTexts),
    },
    response_digest: `sha256:${sha256Hex(canonicalizeJCS(responses))}`,
    k,
    n: spec.n,
    scoring_method: 'exact_match_v1',
    attester: KP.publicKeyHex,
    model_claim: 'example-model-v1',
    runtime_claim: 'example-runtime-v1',
    verification_method: 'asserted',
    challenge_issued_at: T_CHALLENGE,
    response_observed_at: T_RESPONSE,
    receipt_issued_at: T_RECEIPT,
    ...(spec.lexiconFields ? { lexicon_id: LEXICON_ID, lexicon_profile: LEXICON_PROFILE } : {}),
  }
  const sig = signUtf8(canonicalNoSig(body), KP.privateKeyHex)
  return { record: { ...body, sig }, sourceText: spec.sourceText, responses, spanTexts }
}

/** Re-sign a mutated record body with the fixture key (deliberate re-sign cases). */
function reSign(record: ReadFidelityReceipt): ReadFidelityReceipt {
  const { sig: _sig, ...body } = record
  return { ...body, sig: signUtf8(canonicalNoSig(body), KP.privateKeyHex) } as ReadFidelityReceipt
}

// ── sources (fixed, ascii) ─────────────────────────────────────────

const SRC_A =
  'The verifier samples five spans from this fixture source text and the ' +
  'reader returns each span exactly as written, so the recorded k equals n.'
const SRC_B =
  'Honest partial readback: some spans come back exactly and others do not, ' +
  'and the record says so with k strictly less than n rather than rounding up.'
const SRC_C =
  'Presentation binding: the seed commits to the rendered presentation ' +
  'digest, so swapping the presentation after signing breaks the derivation.'

// ── word handle cases ──────────────────────────────────────────────

interface HandleCase {
  digest: string
  profile: WordHandleProfileName
  originalWords: string[]
  originalIndices: number[]
  words: string[]
  wordIndices: (number | null)[]
}

function handleBase(label: string, profile: WordHandleProfileName): HandleCase {
  const digest = sha256Hex(label)
  const originalWords = encodeProfile(digest, profile)
  const originalIndices = originalWords.map((w) => WORD_TO_INDEX.get(w) as number)
  return {
    digest,
    profile,
    originalWords,
    originalIndices,
    words: originalWords.slice(),
    wordIndices: originalIndices.slice(),
  }
}

// v2: substitution. One data word replaced, position and replacement both
// derived from fixed labels.
const sub = handleBase('rfr-handle:0', 'default')
const subPos = seedUint32('rfr-handle-substitute-pos') % PROFILES.default.dataWords
const subDelta = 1 + (seedUint32('rfr-handle-substitute-delta') % (WORDS.length - 1))
const subNewIdx = ((sub.originalIndices[subPos] as number) + subDelta) % WORDS.length
sub.words[subPos] = WORDS[subNewIdx]
sub.wordIndices[subPos] = subNewIdx

// v3: out-of-lexicon. Two words replaced with strings outside the lexicon.
const ool = handleBase('rfr-handle:1', 'default')
const OOL_INDICES = [1, 3]
ool.words[1] = 'notaword'
ool.words[3] = 'zzxxqq'
ool.wordIndices[1] = null
ool.wordIndices[3] = null

// v8: transposition. First adjacent differing data word pair swapped.
const tr = handleBase('rfr-handle:2', 'default')
let trPair = -1
for (let i = 0; i < PROFILES.default.dataWords - 1; i++) {
  if (tr.originalWords[i] !== tr.originalWords[i + 1]) {
    trPair = i
    break
  }
}
if (trPair < 0) throw new Error('no adjacent differing data words in transposition base')
tr.words[trPair] = tr.originalWords[trPair + 1]
tr.words[trPair + 1] = tr.originalWords[trPair]
tr.wordIndices[trPair] = tr.originalIndices[trPair + 1]
tr.wordIndices[trPair + 1] = tr.originalIndices[trPair]

// ── records ────────────────────────────────────────────────────────

// v1 base (also the base for v4 and v6).
const v1Built = buildRecord({
  sourceText: SRC_A,
  presentationDigest: null,
  nonce: 'rfr-fixture-nonce-1',
  n: 5,
  spanLen: 12,
  lexiconFields: true,
})

// v4: tamper content_digest AFTER signing; keep the original signature.
const v4Record: ReadFidelityReceipt = {
  ...v1Built.record,
  content_digest: `sha256:${sha256Hex('rfr-tampered-content-v1')}`,
}

// v5: honest partial, k < n, valid and expected to verify TRUE.
const v5Built = buildRecord({
  sourceText: SRC_B,
  presentationDigest: null,
  nonce: 'rfr-fixture-nonce-5',
  n: 6,
  spanLen: 10,
  missIndices: [1, 4],
})

// v6: replayed nonce. Identical span_commitments and responses, DIFFERENT
// nonce, seed left as derived from the ORIGINAL nonce, then re-signed.
const v6Record = reSign({
  ...v1Built.record,
  challenge: { ...v1Built.record.challenge, nonce: 'rfr-fixture-nonce-2' },
})

// v7 base: presentation_digest present, then swapped and re-signed.
const V7_PRESENTATION = `sha256:${sha256Hex('rfr-presentation-v1')}`
const V7_PRESENTATION_SWAPPED = `sha256:${sha256Hex('rfr-presentation-v2')}`
const v7Built = buildRecord({
  sourceText: SRC_C,
  presentationDigest: V7_PRESENTATION,
  nonce: 'rfr-fixture-nonce-7',
  n: 4,
  spanLen: 9,
})
const v7Record = reSign({ ...v7Built.record, presentation_digest: V7_PRESENTATION_SWAPPED })

// ── vector assembly ────────────────────────────────────────────────

interface RecordVector {
  name: string
  kind: 'record'
  description: string
  record: ReadFidelityReceipt
  source_text: string
  responses?: string[]
  signing_input_canonical: string
  signing_input_bytes_hex: string
  canonical: string
  canonical_bytes_hex: string
  canonical_sha256: string
  ed25519_pubkey_hex: string
  expected_verification: boolean
  rejection_kind?: string
  expected_reason?: string
}

interface HandleVector {
  name: string
  kind: 'word_handle'
  description: string
  digest: string
  profile: WordHandleProfileName
  original_words: string[]
  original_indices: number[]
  words: string[]
  word_indices: (number | null)[]
  mutation: { type: string; indices: number[] }
  expected: { checksum_ok: boolean; out_of_lexicon: number[]; prefix_hex_null: boolean }
  expected_verification: false
  rejection_kind: string
  expected_reason: string
}

function makeRecordVector(o: {
  name: string
  description: string
  built: { record: ReadFidelityReceipt; sourceText: string; responses?: string[] }
  expected: boolean
  rejection_kind?: string
  expected_reason?: string
  includeResponses?: boolean
}): RecordVector {
  const si = canonicalNoSig(o.built.record)
  const canonical = canonicalizeJCS(o.built.record)
  const v: RecordVector = {
    name: o.name,
    kind: 'record',
    description: o.description,
    record: o.built.record,
    source_text: o.built.sourceText,
    signing_input_canonical: si,
    signing_input_bytes_hex: utf8Hex(si),
    canonical,
    canonical_bytes_hex: utf8Hex(canonical),
    canonical_sha256: sha256Hex(canonical),
    ed25519_pubkey_hex: KP.publicKeyHex,
    expected_verification: o.expected,
  }
  if (o.includeResponses && o.built.responses) v.responses = o.built.responses
  if (o.rejection_kind) v.rejection_kind = o.rejection_kind
  if (o.expected_reason) v.expected_reason = o.expected_reason
  return v
}

function makeHandleVector(o: {
  name: string
  description: string
  c: HandleCase
  mutation: { type: string; indices: number[] }
  outOfLexicon: number[]
  expected_reason: string
  rejection_kind: string
}): HandleVector {
  return {
    name: o.name,
    kind: 'word_handle',
    description: o.description,
    digest: o.c.digest,
    profile: o.c.profile,
    original_words: o.c.originalWords,
    original_indices: o.c.originalIndices,
    words: o.c.words,
    word_indices: o.c.wordIndices,
    mutation: o.mutation,
    expected: {
      checksum_ok: false,
      out_of_lexicon: o.outOfLexicon,
      prefix_hex_null: o.outOfLexicon.length > 0,
    },
    expected_verification: false,
    rejection_kind: o.rejection_kind,
    expected_reason: o.expected_reason,
  }
}

const vectors: (RecordVector | HandleVector)[] = [
  makeRecordVector({
    name: 'v1-positive-full-readback',
    description:
      'POSITIVE. Valid signed record with k == n: every sampled span was read back ' +
      'exactly. Carries the optional lexicon_id and lexicon_profile fields. ' +
      'Signature, seed derivation, and span commitments all verify against the source text.',
    built: v1Built,
    expected: true,
    includeResponses: true,
  }),
  makeHandleVector({
    name: 'v2-negative-handle-substitution',
    description:
      'NEGATIVE (checksum). One data word of a default-profile handle replaced with a ' +
      'different lexicon word. decode MUST report checksum_ok false (detected). The ' +
      'checksum is position-dependent: sha256 over BE16(prefixBits) plus the packed prefix bits.',
    c: sub,
    mutation: { type: 'substitution', indices: [subPos] },
    outOfLexicon: [],
    expected_reason: 'CHECKSUM_MISMATCH',
    rejection_kind: 'checksum',
  }),
  makeHandleVector({
    name: 'v3-negative-handle-out-of-lexicon',
    description:
      'NEGATIVE (out_of_lexicon). Two words are not in the lexicon (exact code-unit ' +
      'equality, no trim, no unicode normalization). decode MUST report their indices, ' +
      'with prefixHex and prefixBits null and checksum_ok false.',
    c: ool,
    mutation: { type: 'out_of_lexicon', indices: OOL_INDICES },
    outOfLexicon: OOL_INDICES,
    expected_reason: 'OUT_OF_LEXICON',
    rejection_kind: 'out_of_lexicon',
  }),
  makeRecordVector({
    name: 'v4-negative-tampered-content-digest',
    description:
      'NEGATIVE (signature). content_digest was swapped AFTER signing while the original ' +
      'signature was kept, so the Ed25519 signature over the JCS bytes with sig excluded ' +
      'MUST fail. Tampering after signing fails on the signature before the seed check runs.',
    built: { record: v4Record, sourceText: SRC_A },
    expected: false,
    rejection_kind: 'signature',
    expected_reason: 'SIGNATURE_INVALID',
  }),
  makeRecordVector({
    name: 'v5-positive-honest-partial',
    description:
      'POSITIVE. Honest partial readback: two of six responses are deliberate misreads, so ' +
      'the record carries k=4 of n=6. The record verifies TRUE with the recorded k; the ' +
      'record format has no pass threshold and the consumer judges k of n.',
    built: v5Built,
    expected: true,
    includeResponses: true,
  }),
  makeRecordVector({
    name: 'v6-negative-replayed-nonce',
    description:
      'NEGATIVE (seed). Identical span_commitments and responses as v1 but a DIFFERENT ' +
      'nonce, and the record was RE-SIGNED so the signature is valid over its own bytes. ' +
      'Verification MUST fail because challenge.seed no longer matches the derivation ' +
      'over content_digest, presentation_digest, nonce, and version: the replay binding.',
    built: { record: v6Record, sourceText: SRC_A, responses: v1Built.responses },
    expected: false,
    rejection_kind: 'seed',
    expected_reason: 'SEED_MISMATCH',
    includeResponses: true,
  }),
  makeRecordVector({
    name: 'v7-negative-presentation-digest-mismatch',
    description:
      'NEGATIVE (seed). presentation_digest was swapped for a different digest and the ' +
      'record RE-SIGNED (signature valid over its own bytes). The seed derivation binds ' +
      'the presentation digest, so verification MUST fail on the seed recompute.',
    built: { record: v7Record, sourceText: SRC_C },
    expected: false,
    rejection_kind: 'seed',
    expected_reason: 'SEED_MISMATCH',
  }),
  makeHandleVector({
    name: 'v8-negative-handle-transposition',
    description:
      'NEGATIVE (checksum). Two adjacent differing data words of a default-profile handle ' +
      'swapped. The checksum construction is position-dependent (the hash runs over the ' +
      'ordered packed bits), so the transposition MUST be detected: checksum_ok false.',
    c: tr,
    mutation: { type: 'transposition', indices: [trPair, trPair + 1] },
    outOfLexicon: [],
    expected_reason: 'CHECKSUM_MISMATCH',
    rejection_kind: 'checksum',
  }),
]

// ── self-verification (generator; nothing is written on failure) ───

let failures = 0
console.log('== self-verification (generator) ==')

function check(name: string, ok: boolean, detail: string): void {
  if (!ok) failures++
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${name.padEnd(42)} ${detail}`)
}

for (const v of vectors) {
  if (v.kind === 'record') {
    const shape = shapeReason(v.record)
    check(v.name, shape === null, `shape=${shape ?? 'ok'}`)
    const res = verifyReadFidelityReceipt(v.record)
    check(v.name, res.valid === v.expected_verification, `verify=${res.valid} expected=${v.expected_verification}`)
    if (!v.expected_verification) {
      check(v.name, res.reason === v.expected_reason, `reason=${res.reason} stated=${v.expected_reason}`)
    } else {
      const against = verifyAgainstSource(v.record, v.source_text)
      check(v.name, against.valid, `against-source valid=${against.valid}`)
      if (v.responses) {
        const spans = sampleSpans(v.source_text, v.record.challenge.seed, v.record.n, v.record.challenge.span_len)
        const { k } = scoreResponses(spans.map((s) => s.text), v.responses)
        check(v.name, k === v.record.k, `k recompute=${k} recorded=${v.record.k}`)
        const rd = `sha256:${sha256Hex(canonicalizeJCS(v.responses))}`
        check(v.name, rd === v.record.response_digest, 'response_digest recompute')
      }
    }
    if (v.rejection_kind === 'seed') {
      const sigValid = verifyUtf8(canonicalNoSig(v.record), v.record.sig, v.record.attester)
      check(v.name, sigValid, `re-signed: signature valid over own bytes=${sigValid}`)
    }
    if (v.rejection_kind === 'signature') {
      const sigValid = verifyUtf8(canonicalNoSig(v.record), v.record.sig, v.record.attester)
      check(v.name, !sigValid, `tampered: signature valid=${sigValid} (must be false)`)
    }
  } else {
    const res = decodeProfile(v.words, v.profile)
    check(v.name, res.checksumOk === v.expected.checksum_ok, `checksum_ok=${res.checksumOk}`)
    check(
      v.name,
      JSON.stringify(res.outOfLexicon) === JSON.stringify(v.expected.out_of_lexicon),
      `out_of_lexicon=${JSON.stringify(res.outOfLexicon)}`,
    )
    check(v.name, (res.prefixHex === null) === v.expected.prefix_hex_null, `prefix_hex_null=${res.prefixHex === null}`)
    const roundTrip = encodeProfile(v.digest, v.profile)
    check(v.name, JSON.stringify(roundTrip) === JSON.stringify(v.original_words), 'original words re-encode')
    const orig = decodeProfile(v.original_words, v.profile)
    check(v.name, orig.checksumOk === true, `unmutated base decodes checksum_ok=${orig.checksumOk}`)
  }
}

// Explicit cross-checks on the paired vectors.
const v1 = vectors[0] as RecordVector
const v6 = vectors[5] as RecordVector
check(
  'v6 commitments identical to v1',
  JSON.stringify(v1.record.challenge.span_commitments) === JSON.stringify(v6.record.challenge.span_commitments),
  'span_commitments equal',
)
check(
  'v6 responses identical to v1',
  JSON.stringify(v1.responses) === JSON.stringify(v6.responses),
  'responses equal',
)
check('v6 nonce differs from v1', v1.record.challenge.nonce !== v6.record.challenge.nonce, 'nonce differs')
check('v5 recorded k < n', (vectors[4] as RecordVector).record.k < (vectors[4] as RecordVector).record.n, 'honest partial')

if (failures > 0) {
  console.error(`\n${failures} check(s) failed. NOT writing fixture.`)
  process.exit(1)
}

const fixture = {
  version: 'v1',
  spec:
    'APS read-fidelity-receipt v0.1. A read fidelity receipt proves sampled readback ' +
    'fidelity at the stated n under the declared sampling assumptions. It does not prove ' +
    'every byte was read correctly, does not prove perception or comprehension, does not ' +
    'prove which channel was used, and carries no normative pass threshold: the consumer ' +
    'judges k of n. Canonicalization: JCS RFC 8785. Signature: Ed25519 over the JCS of the ' +
    'record with the sig field excluded entirely. Seed derivation: sha256hex(utf8(' +
    'content_digest + (presentation_digest or empty string when null) + nonce + version)), ' +
    'no separators. Word handle vectors exercise the word_digest_handle codec: 11-bit words ' +
    'over the pinned lexicon with a position-dependent checksum.',
  schema: './read-fidelity-receipt.schema.json',
  lexicon_name: LEXICON_NAME,
  lexicon_id: LEXICON_ID,
  lexicon_profile: LEXICON_PROFILE,
  seed_input: SEED_INPUT,
  seed_sha256_hex: KP.seedHex,
  keypair: {
    publicKeyHex: KP.publicKeyHex,
    note: 'FIXTURE-ONLY deterministic key: private key = sha256(seed_input), reproducible by anyone. Never a production key.',
  },
  generated_at: '2026-07-05',
  signing:
    'record.sig = Ed25519(privateKey, UTF-8 bytes of JCS(record without the sig field)). ' +
    'signing_input_canonical/_bytes_hex are those bytes; canonical/_bytes_hex are the JCS of ' +
    'the full record including sig. The attester field inside each record is the ' +
    'verification key. Negatives fail for the STATED reason in expected_reason: v4 on the ' +
    'signature (tampered after signing), v6 and v7 on the seed derivation (re-signed, so ' +
    'the signature itself is valid over the mutated bytes), v2 and v8 on the handle ' +
    'checksum, v3 on out-of-lexicon words.',
  vectors,
}

writeFileSync(OUT, JSON.stringify(fixture, null, 2) + '\n')
console.log(`\n== wrote ==\n  ${OUT}`)
console.log(`  ${vectors.length} vectors; fixture pub ${KP.publicKeyHex.slice(0, 16)}...`)

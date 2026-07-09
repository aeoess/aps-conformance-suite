// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Shared primitives for the read-fidelity-receipt fixture family.
//
// Vendored from agent-passport-system so this family verifies from a cold
// clone with no runtime dependency on the SDK:
//   - canonicalizeJCS        : RFC 8785, byte-identical to src/core/canonical-jcs.ts.
//   - Ed25519 sign/verify    : same Node-crypto pattern and DER prefixes as
//                              src/crypto/keys.ts (strict 64-hex pubkey / 128-hex sig).
//   - word handle codec      : matches src/v2/word_handles/codec.ts exactly
//                              (bit order, packed prefix, position-dependent checksum,
//                              best-effort localization).
//   - sampler + receipt      : matches src/v2/read_fidelity_receipt/{sampler,receipt}.ts
//                              (seed derivation, span_sample_v1, exact_match_v1,
//                              shape checks, verification order).
//
// Deterministic, pure functions: no I/O, no clock, no randomness.

import crypto from 'node:crypto'

import { WORDS } from './wordlist.js'

// ── JCS (RFC 8785) ─────────────────────────────────────────────────

/** RFC 8785 JSON Canonicalization Scheme. */
export function canonicalizeJCS(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!isFinite(value)) throw new Error('JCS does not support Infinity or NaN')
      return JSON.stringify(value)
    }
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((item) => canonicalizeJCS(item)).join(',') + ']'
      }
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const pairs: string[] = []
      for (const key of keys) {
        pairs.push(`${JSON.stringify(key)}:${canonicalizeJCS(obj[key])}`)
      }
      return '{' + pairs.join(',') + '}'
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`)
  }
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex')
}

export const utf8Hex = (s: string): string => Buffer.from(s, 'utf8').toString('hex')

// ── Ed25519 (Node crypto, raw 32-byte keys as hex) ─────────────────

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export interface Keypair {
  seedHex: string
  privateKeyHex: string
  publicKeyHex: string
}

/** Deterministic Ed25519 keypair from SHA-256(seedInput). Private key IS the seed. */
export function deriveKeypair(seedInput: string): Keypair {
  const seed = crypto.createHash('sha256').update(seedInput, 'utf-8').digest()
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubDer = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' }) as Buffer
  return {
    seedHex: seed.toString('hex'),
    privateKeyHex: seed.toString('hex'),
    publicKeyHex: Buffer.from(pubDer.subarray(-32)).toString('hex'),
  }
}

/** Ed25519 sign the UTF-8 bytes of `message`. Returns lowercase hex (128 chars). */
export function signUtf8(message: string, privateKeyHex: string): string {
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(privateKeyHex, 'hex')])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const sig = crypto.sign(null, Buffer.from(message, 'utf8'), keyObj)
  return Buffer.from(sig).toString('hex')
}

/** Ed25519 verify. Mirrors src/crypto/keys.ts: strict 64-hex pubkey / 128-hex sig. */
export function verifyUtf8(message: string, signatureHex: string, publicKeyHex: string): boolean {
  if (typeof publicKeyHex !== 'string' || publicKeyHex.length !== 64) return false
  if (typeof signatureHex !== 'string' || signatureHex.length !== 128) return false
  try {
    const derKey = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyHex, 'hex')])
    const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, Buffer.from(signatureHex, 'hex'))
  } catch {
    return false
  }
}

// ── word handle codec (word_digest_handle) ─────────────────────────
// Encoding rules (v2):
//   - prefixBits is a positive multiple of 11; checksumWords is 1 or 2.
//     Word count = prefixBits/11 + checksumWords.
//   - Bit order is MSB-first from byte 0. Data word i covers bits
//     [11*i, 11*i + 11) as an integer index into WORDS.
//   - packedPrefix = the first prefixBits bits packed into ceil(prefixBits/8)
//     bytes, MSB-first, unused low-order bits of the final byte set to 0.
//   - checksumDigest = sha256( BE16(prefixBits) || packedPrefix ). Checksum
//     word j = bits [11*j, 11*j + 11) of checksumDigest, appended after the
//     data words in order.
//   - The construction is position-dependent: the hash runs over the ordered
//     packed bits, so transposing any two differing data words changes
//     packedPrefix and fails the checksum with probability 1 - 2^-11 per
//     event for one checksum word (1 - 2^-22 for two).

const WORD_BITS = 11
const HEX_RE = /^[0-9a-fA-F]*$/

/** Identifier of the lexicon layout profile used by this codec. */
export const LEXICON_PROFILE = 'single-list-v1'

export type WordHandleProfileName = 'compact' | 'default' | 'high_assurance'

export interface WordHandleProfile {
  name: WordHandleProfileName
  dataWords: number
  checksumWords: number
  prefixBits: number
}

export const PROFILES: Readonly<Record<WordHandleProfileName, WordHandleProfile>> = {
  compact: { name: 'compact', dataWords: 4, checksumWords: 1, prefixBits: 44 },
  default: { name: 'default', dataWords: 6, checksumWords: 1, prefixBits: 66 },
  high_assurance: { name: 'high_assurance', dataWords: 8, checksumWords: 2, prefixBits: 88 },
}

export interface DecodeResult {
  prefixHex: string | null
  prefixBits: number | null
  checksumOk: boolean
  failedWordIndex: number | null
  outOfLexicon: number[]
}

/** Lexicon word to index, built once. Exact code-unit key equality. */
const WORD_INDEX: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  for (let i = 0; i < WORDS.length; i++) m.set(WORDS[i], i)
  return m
})()

function validatePrefixBits(prefixBits: number): void {
  if (!Number.isInteger(prefixBits) || prefixBits <= 0 || prefixBits % WORD_BITS !== 0) {
    throw new Error(`prefixBits must be a positive multiple of ${WORD_BITS}, got ${prefixBits}`)
  }
  if (prefixBits > 0xffff) {
    throw new Error(`prefixBits must fit in 16 bits (BE16 header), got ${prefixBits}`)
  }
}

function validateChecksumWords(checksumWords: number): void {
  if (checksumWords !== 1 && checksumWords !== 2) {
    throw new Error(`checksumWords must be 1 or 2, got ${checksumWords}`)
  }
}

function stripSha256Prefix(hex: string): string {
  return hex.startsWith('sha256:') ? hex.slice('sha256:'.length) : hex
}

function toBytes(input: Uint8Array | string): { bytes: Uint8Array; bitLength: number } {
  if (typeof input === 'string') {
    const hex = stripSha256Prefix(input)
    if (!HEX_RE.test(hex)) {
      throw new Error('input hex string contains non-hex characters')
    }
    const bitLength = hex.length * 4
    const padded = hex.length % 2 === 0 ? hex : hex + '0'
    const bytes = new Uint8Array(padded.length / 2)
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(padded.slice(2 * i, 2 * i + 2), 16)
    }
    return { bytes, bitLength }
  }
  return { bytes: input, bitLength: input.length * 8 }
}

/** Bit i of a byte array, MSB-first from byte 0. */
function getBit(bytes: Uint8Array, i: number): number {
  return (bytes[i >> 3] >> (7 - (i & 7))) & 1
}

function packPrefix(bytes: Uint8Array, prefixBits: number): Uint8Array {
  const byteLen = Math.ceil(prefixBits / 8)
  const packed = new Uint8Array(byteLen)
  packed.set(bytes.subarray(0, byteLen))
  const rem = prefixBits % 8
  if (rem !== 0) {
    packed[byteLen - 1] &= (0xff << (8 - rem)) & 0xff
  }
  return packed
}

function checksumIndicesFor(
  prefixBits: number,
  packedPrefix: Uint8Array,
  checksumWords: number,
): number[] {
  const msg = new Uint8Array(2 + packedPrefix.length)
  msg[0] = (prefixBits >> 8) & 0xff
  msg[1] = prefixBits & 0xff
  msg.set(packedPrefix, 2)
  const digest = crypto.createHash('sha256').update(msg).digest()
  const out: number[] = []
  for (let j = 0; j < checksumWords; j++) {
    let idx = 0
    for (let b = 0; b < WORD_BITS; b++) {
      idx = (idx << 1) | getBit(digest, WORD_BITS * j + b)
    }
    out.push(idx)
  }
  return out
}

/** Encode the first prefixBits bits of input as data words plus checksum words. */
export function encode(
  input: Uint8Array | string,
  prefixBits = 66,
  checksumWords = 1,
): string[] {
  validatePrefixBits(prefixBits)
  validateChecksumWords(checksumWords)
  const { bytes, bitLength } = toBytes(input)
  if (bitLength < prefixBits) {
    throw new Error(`input supplies ${bitLength} bits, need at least ${prefixBits}`)
  }
  const dataWordCount = prefixBits / WORD_BITS
  const words: string[] = []
  for (let i = 0; i < dataWordCount; i++) {
    let idx = 0
    for (let b = 0; b < WORD_BITS; b++) {
      idx = (idx << 1) | getBit(bytes, WORD_BITS * i + b)
    }
    words.push(WORDS[idx])
  }
  const packed = packPrefix(bytes, prefixBits)
  for (const idx of checksumIndicesFor(prefixBits, packed, checksumWords)) {
    words.push(WORDS[idx])
  }
  return words
}

/** Encode with a named profile (prefixBits and checksumWords from the table). */
export function encodeProfile(input: Uint8Array | string, profile: WordHandleProfileName): string[] {
  const p = PROFILES[profile]
  if (p === undefined) throw new Error(`unknown word handle profile: ${profile}`)
  return encode(input, p.prefixBits, p.checksumWords)
}

/** Rebuild the packed prefix bytes from data word indices. */
function packFromIndices(indices: readonly number[], prefixBits: number): Uint8Array {
  const packed = new Uint8Array(Math.ceil(prefixBits / 8))
  let bitPos = 0
  for (const idx of indices) {
    for (let b = WORD_BITS - 1; b >= 0; b--) {
      if ((idx >> b) & 1) {
        packed[bitPos >> 3] |= 0x80 >> (bitPos & 7)
      }
      bitPos++
    }
  }
  return packed
}

function toHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Decode a word handle. Never throws on unknown words (reported via
 * outOfLexicon; exact code-unit equality, no trim, no unicode
 * normalization). When outOfLexicon is non-empty, prefixHex and prefixBits
 * are null, checksumOk is false, failedWordIndex is null. Localization
 * (failedWordIndex) is best effort and only attempted when the checksum
 * fails and every word is in the lexicon; with 44-bit prefixes it is
 * frequently ambiguous (a wrong position is coincidentally fixable with
 * probability about 0.63) while detection misses only with probability
 * 2^-11 (or 2^-22 for two checksum words).
 */
export function decode(words: readonly string[], checksumWords = 1): DecodeResult {
  validateChecksumWords(checksumWords)

  const outOfLexicon: number[] = []
  for (let i = 0; i < words.length; i++) {
    if (!WORD_INDEX.has(words[i])) outOfLexicon.push(i)
  }
  if (outOfLexicon.length > 0) {
    return { prefixHex: null, prefixBits: null, checksumOk: false, failedWordIndex: null, outOfLexicon }
  }

  const dataWordCount = words.length - checksumWords
  if (dataWordCount <= 0) {
    throw new Error(`word count ${words.length} with ${checksumWords} checksum word(s) leaves no data words`)
  }
  const prefixBits = WORD_BITS * dataWordCount
  validatePrefixBits(prefixBits)

  const indices = words.slice(0, dataWordCount).map((w) => WORD_INDEX.get(w) as number)
  const givenChecksums = words.slice(dataWordCount).map((w) => WORD_INDEX.get(w) as number)
  const packed = packFromIndices(indices, prefixBits)
  const prefixHex = toHex(packed)

  const expectedChecksums = checksumIndicesFor(prefixBits, packed, checksumWords)
  const checksumOk = expectedChecksums.every((e, j) => e === givenChecksums[j])

  let failedWordIndex: number | null = null
  if (!checksumOk) {
    const fixable: number[] = []
    const trial = indices.slice()
    for (let i = 0; i < dataWordCount; i++) {
      const original = trial[i]
      for (let cand = 0; cand < WORDS.length; cand++) {
        if (cand === original) continue
        trial[i] = cand
        const candPacked = packFromIndices(trial, prefixBits)
        const candChecksums = checksumIndicesFor(prefixBits, candPacked, checksumWords)
        if (candChecksums.every((e, j) => e === givenChecksums[j])) {
          fixable.push(i)
          break
        }
      }
      trial[i] = original
    }
    if (fixable.length === 1) {
      failedWordIndex = fixable[0]
    } else if (fixable.length === 0) {
      const differing: number[] = []
      for (let j = 0; j < checksumWords; j++) {
        if (givenChecksums[j] !== expectedChecksums[j]) {
          differing.push(dataWordCount + j)
        }
      }
      failedWordIndex = differing.length === 1 ? differing[0] : null
    } else {
      failedWordIndex = null
    }
  }

  return { prefixHex, prefixBits, checksumOk, failedWordIndex, outOfLexicon }
}

/** Decode with a named profile. Throws when the word count does not match. */
export function decodeProfile(words: readonly string[], profile: WordHandleProfileName): DecodeResult {
  const p = PROFILES[profile]
  if (p === undefined) throw new Error(`unknown word handle profile: ${profile}`)
  const expected = p.dataWords + p.checksumWords
  if (words.length !== expected) {
    throw new Error(`profile ${p.name} expects ${expected} words, got ${words.length}`)
  }
  return decode(words, p.checksumWords)
}

// ── sampler (span_sample_v1) and scoring (exact_match_v1) ──────────

export interface SampledSpan {
  pos: number
  len: number
  text: string
}

/**
 * Derive the challenge seed. The preimage is the RFC 8785 JCS
 * canonicalization of an object carrying the four bound fields, so the
 * component boundaries are unambiguous: presentation_digest is a distinct
 * JSON member (null when absent), never foldable into the nonce.
 */
export function deriveSeed(
  contentDigest: string,
  presentationDigestOrNull: string | null,
  nonce: string,
  version: string,
): string {
  return sha256Hex(
    canonicalizeJCS({
      content_digest: contentDigest,
      presentation_digest: presentationDigestOrNull,
      nonce,
      version,
    }),
  )
}

/**
 * Sample n spans of spanLen code points from sourceText at distinct
 * positions determined by seed. Position i (attempt j, starting at 0):
 * h = sha256(utf8(seed + ":" + i + ":" + j)); pos = BE-uint64(first 8
 * bytes) mod range; bump j on repeat. Code points via Array.from, so
 * astral characters count as one position each.
 */
export function sampleSpans(sourceText: string, seed: string, n: number, spanLen: number): SampledSpan[] {
  if (!Number.isInteger(spanLen) || spanLen < 1) {
    throw new Error(`spanLen must be a positive integer, got ${spanLen}`)
  }
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`n must be a positive integer, got ${n}`)
  }
  const cps = Array.from(sourceText)
  const L = cps.length
  if (L < spanLen) {
    throw new Error(`source has ${L} code points, need at least spanLen ${spanLen}`)
  }
  const range = L - spanLen + 1
  if (n > range) {
    throw new Error(`n ${n} exceeds the position range ${range}`)
  }
  const used = new Set<number>()
  const spans: SampledSpan[] = []
  for (let i = 0; i < n; i++) {
    for (let j = 0; ; j++) {
      const h = crypto.createHash('sha256').update(`${seed}:${i}:${j}`, 'utf8').digest()
      const pos = Number(h.readBigUInt64BE(0) % BigInt(range))
      if (used.has(pos)) continue
      used.add(pos)
      spans.push({ pos, len: spanLen, text: cps.slice(pos, pos + spanLen).join('') })
      break
    }
  }
  return spans
}

/** Commit to span texts: "sha256:" + sha256hex(UTF-8 of each span text), in order. */
export function commitSpans(spanTexts: readonly string[]): string[] {
  return spanTexts.map((t) => `sha256:${sha256Hex(t)}`)
}

export interface ScoreResponsesResult {
  k: number
  results: boolean[]
}

/** Score responses under exact_match_v1: exact string equality per index. */
export function scoreResponses(
  spanTexts: readonly string[],
  responses: readonly string[],
): ScoreResponsesResult {
  if (spanTexts.length !== responses.length) {
    throw new Error(`responses length ${responses.length} does not match span count ${spanTexts.length}`)
  }
  const results = spanTexts.map((t, i) => responses[i] === t)
  let k = 0
  for (const r of results) {
    if (r) k++
  }
  return { k, results }
}

// ── read_fidelity_receipt record ───────────────────────────────────

/**
 * A read fidelity receipt proves sampled readback fidelity at the stated n
 * under the declared sampling assumptions. It does not prove every byte was
 * read correctly, does not prove perception or comprehension, does not
 * prove which channel was used, and carries no normative pass threshold:
 * the consumer judges k of n.
 */
export interface ReadFidelityReceipt {
  type: 'read_fidelity_receipt'
  content_digest: string
  presentation_digest: string | null
  challenge: {
    nonce: string
    seed: string
    algorithm: 'span_sample_v1'
    version: '1'
    span_len: number
    span_commitments: string[]
  }
  response_digest: string
  k: number
  n: number
  scoring_method: 'exact_match_v1'
  attester: string
  model_claim: string
  runtime_claim: string
  verification_method: 'asserted' | 'provider_attestation'
  challenge_issued_at: string
  response_observed_at: string
  receipt_issued_at: string
  lexicon_id?: string
  lexicon_profile?: string
  sig: string
}

export type ReadFidelityVerifyReason =
  | 'INVALID_TYPE'
  | 'INVALID_CONTENT_DIGEST'
  | 'INVALID_PRESENTATION_DIGEST'
  | 'INVALID_CHALLENGE'
  | 'INVALID_N'
  | 'N_MISMATCH'
  | 'INVALID_K'
  | 'INVALID_RESPONSE_DIGEST'
  | 'INVALID_SCORING_METHOD'
  | 'INVALID_ATTESTER'
  | 'INVALID_CLAIMS'
  | 'INVALID_VERIFICATION_METHOD'
  | 'INVALID_TIMESTAMP'
  | 'INVALID_LEXICON_FIELDS'
  | 'INVALID_SIG_FORMAT'
  | 'SIGNATURE_INVALID'
  | 'SEED_MISMATCH'
  | 'SPAN_RECOMPUTE_FAILED'
  | 'COMMITMENT_MISMATCH'

export interface ReadFidelityVerifyResult {
  valid: boolean
  reason?: ReadFidelityVerifyReason
}

export interface VerifyAgainstSourceResult extends ReadFidelityVerifyResult {
  commitment_matches: boolean[]
  signature_valid: boolean
  seed_valid: boolean
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const HEX64_RE = /^[0-9a-f]{64}$/
const HEX128_RE = /^[0-9a-f]{128}$/
const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/

/**
 * Canonical signing preimage: RFC 8785 JCS of the record with the sig key
 * removed entirely (not a record with an emptied sig field).
 */
export function canonicalNoSig(record: object): string {
  const { sig: _sig, ...rest } = record as Record<string, unknown>
  return canonicalizeJCS(rest)
}

function challengeShapeReason(value: unknown): ReadFidelityVerifyReason | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'INVALID_CHALLENGE'
  }
  const c = value as Record<string, unknown>
  if (typeof c.nonce !== 'string' || c.nonce.length === 0) return 'INVALID_CHALLENGE'
  if (typeof c.seed !== 'string' || !HEX64_RE.test(c.seed)) return 'INVALID_CHALLENGE'
  if (c.algorithm !== 'span_sample_v1') return 'INVALID_CHALLENGE'
  if (c.version !== '1') return 'INVALID_CHALLENGE'
  if (typeof c.span_len !== 'number' || !Number.isInteger(c.span_len) || c.span_len < 1) {
    return 'INVALID_CHALLENGE'
  }
  if (!Array.isArray(c.span_commitments) || c.span_commitments.length === 0) {
    return 'INVALID_CHALLENGE'
  }
  for (const s of c.span_commitments) {
    if (typeof s !== 'string' || !DIGEST_RE.test(s)) return 'INVALID_CHALLENGE'
  }
  return null
}

/** Structural checks. First failing reason, or null. No signature or seed check. */
export function shapeReason(value: unknown): ReadFidelityVerifyReason | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'INVALID_TYPE'
  }
  const r = value as Record<string, unknown>
  if (r.type !== 'read_fidelity_receipt') return 'INVALID_TYPE'
  if (typeof r.content_digest !== 'string' || !DIGEST_RE.test(r.content_digest)) {
    return 'INVALID_CONTENT_DIGEST'
  }
  if (
    r.presentation_digest !== null &&
    (typeof r.presentation_digest !== 'string' || !DIGEST_RE.test(r.presentation_digest))
  ) {
    return 'INVALID_PRESENTATION_DIGEST'
  }
  const challengeReason = challengeShapeReason(r.challenge)
  if (challengeReason !== null) return challengeReason
  const c = r.challenge as Record<string, unknown>
  const commitments = c.span_commitments as readonly string[]
  if (typeof r.n !== 'number' || !Number.isInteger(r.n) || r.n < 1) return 'INVALID_N'
  if (r.n !== commitments.length) return 'N_MISMATCH'
  if (typeof r.k !== 'number' || !Number.isInteger(r.k) || r.k < 0 || r.k > r.n) {
    return 'INVALID_K'
  }
  if (typeof r.response_digest !== 'string' || !DIGEST_RE.test(r.response_digest)) {
    return 'INVALID_RESPONSE_DIGEST'
  }
  if (r.scoring_method !== 'exact_match_v1') return 'INVALID_SCORING_METHOD'
  if (typeof r.attester !== 'string' || !HEX64_RE.test(r.attester)) return 'INVALID_ATTESTER'
  if (typeof r.model_claim !== 'string' || typeof r.runtime_claim !== 'string') {
    return 'INVALID_CLAIMS'
  }
  if (r.verification_method !== 'asserted' && r.verification_method !== 'provider_attestation') {
    return 'INVALID_VERIFICATION_METHOD'
  }
  for (const field of ['challenge_issued_at', 'response_observed_at', 'receipt_issued_at'] as const) {
    const t = r[field]
    if (typeof t !== 'string' || !ISO_8601_RE.test(t)) return 'INVALID_TIMESTAMP'
  }
  if ('lexicon_id' in r || 'lexicon_profile' in r) {
    if (typeof r.lexicon_id !== 'string' || !DIGEST_RE.test(r.lexicon_id)) {
      return 'INVALID_LEXICON_FIELDS'
    }
    if (
      'lexicon_profile' in r &&
      (typeof r.lexicon_profile !== 'string' || r.lexicon_profile.length === 0)
    ) {
      return 'INVALID_LEXICON_FIELDS'
    }
  }
  if (typeof r.sig !== 'string' || !HEX128_RE.test(r.sig)) return 'INVALID_SIG_FORMAT'
  return null
}

function seedMatches(record: ReadFidelityReceipt): boolean {
  return (
    record.challenge.seed ===
    deriveSeed(
      record.content_digest,
      record.presentation_digest,
      record.challenge.nonce,
      record.challenge.version,
    )
  )
}

/**
 * Verify a read fidelity receipt: shape checks, n consistency against
 * challenge.span_commitments, Ed25519 signature against the embedded
 * attester, then the seed derivation recompute. A record tampered after
 * signing fails on the signature; a record re-signed after a nonce or
 * presentation swap carries a valid signature and fails on the seed
 * derivation, which is the replay binding doing its job.
 */
export function verifyReadFidelityReceipt(record: unknown): ReadFidelityVerifyResult {
  const reason = shapeReason(record)
  if (reason !== null) return { valid: false, reason }
  const r = record as ReadFidelityReceipt
  if (!verifyUtf8(canonicalNoSig(r), r.sig, r.attester)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  if (!seedMatches(r)) {
    return { valid: false, reason: 'SEED_MISMATCH' }
  }
  return { valid: true }
}

/**
 * Verify a receipt against the source text it claims to sample: everything
 * verifyReadFidelityReceipt checks, plus a recompute of the spans from
 * challenge.seed / n / span_len over sourceText, a sha256 commitment of
 * each recomputed span, and a positionwise comparison against
 * challenge.span_commitments. ALL commitments must match.
 */
export function verifyAgainstSource(record: unknown, sourceText: string): VerifyAgainstSourceResult {
  const reason = shapeReason(record)
  if (reason !== null) {
    return { valid: false, reason, commitment_matches: [], signature_valid: false, seed_valid: false }
  }
  const r = record as ReadFidelityReceipt
  const signature_valid = verifyUtf8(canonicalNoSig(r), r.sig, r.attester)
  const seed_valid = seedMatches(r)

  let commitment_matches: boolean[] = []
  let spanReason: ReadFidelityVerifyReason | null = null
  try {
    const spans = sampleSpans(sourceText, r.challenge.seed, r.n, r.challenge.span_len)
    const recomputed = commitSpans(spans.map((s) => s.text))
    commitment_matches = recomputed.map((c, i) => c === r.challenge.span_commitments[i])
  } catch {
    spanReason = 'SPAN_RECOMPUTE_FAILED'
  }

  const allMatch = spanReason === null && commitment_matches.every((m) => m === true)
  const valid = signature_valid && seed_valid && allMatch
  let failure: ReadFidelityVerifyReason | undefined
  if (!signature_valid) failure = 'SIGNATURE_INVALID'
  else if (!seed_valid) failure = 'SEED_MISMATCH'
  else if (spanReason !== null) failure = spanReason
  else if (!allMatch) failure = 'COMMITMENT_MISMATCH'
  return valid
    ? { valid, commitment_matches, signature_valid, seed_valid }
    : { valid, reason: failure, commitment_matches, signature_valid, seed_valid }
}

// Deterministic fixture-vector generator for the APS accountability-record family.
//
// Run as:  npx tsx fixtures/accountability-record/generate-fixtures.ts
//
// Twelve vectors (five original cases + five new cases, the same-second case being
// a pair):
//    1 allow+executed with settlement_ref            (positive)
//    2 deny, no settlement                            (positive)
//    3 halt                                           (positive)
//    4 detached payload (digest only)                 (positive)
//    5 tampered payload (digest mismatch)             (NEGATIVE, digest)
//    6 wrong-key signature                            (NEGATIVE, signature)
//    7 out-of-enum decision                           (NEGATIVE, schema)
//    8 type relabel (record_type swapped, stale sig)  (NEGATIVE, signature)
//    9 deny + executed:true                           (positive)
//   10 same-second collision A (shared action_ref)    (positive)
//   11 same-second collision B (shared action_ref)    (positive)
//   12 sig_alg "ed25519" lowercase                    (NEGATIVE, schema)
//
// The inline payload field is named `action`, matching the inline `action` object
// on the SDK ActionReceipt/CommerceActionReceipt (a different, smaller shape here:
// type/scope/timestamp). The name also collides with the ActivityStreams `action`
// verb-object, which is not used. action_digest is over the `action` object.
//
// Synthetic test DIDs and deterministic test keys only; never real agent IDs.
// Each vector carries canonical bytes AND signing-input bytes. The generator
// self-checks every vector and exits non-zero on any mismatch. rejection_kind
// 'schema' negatives are enforced by validate.py (the generator does no schema
// check), so they are reported here but not asserted on the crypto layer.

import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  deriveKeypair,
  computeActionRef,
  actionDigestSha256,
  signUtf8,
  canonicalizeJCS,
  sha256Hex,
  utf8Hex,
  verifyRecord,
  type RecordedAction,
  type AccountabilityRecord,
  type Keypair,
} from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dirname, 'accountability-record-fixture-v1.json')

const SPEC_VERSION = '0.1.0'
const SEED_INPUT = 'aps-accountability-record-fixture-v1'
const WRONG_SEED_INPUT = 'aps-accountability-record-fixture-v1-wrongkey'

const KP = deriveKeypair(SEED_INPUT)
const WRONG_KP = deriveKeypair(WRONG_SEED_INPUT)

// Synthetic test identities (never real agent IDs).
const SIGNER_DID = 'did:key:zAcctRecorderTestV1'      // recorder that signs
const AGENT_DID = 'did:key:zAcctAgentTestV1'          // recorded agent (distinct)
const PRINCIPAL_REF = 'did:key:zAcctPrincipalTestV1'  // beneficiary attribution
const DELEGATION_REF = 'sha256:' + sha256Hex('aps-acct-test-delegation-chain-v1')

type RecordNoSig = Omit<AccountabilityRecord, 'sig'>

function buildRecordNoSig(o: {
  inlineAction?: RecordedAction
  refAction: RecordedAction
  digestAction: RecordedAction
  decision: 'allow' | 'deny' | 'halt'
  executed: boolean
  issued_at: string
  settlement_ref?: string
  settlement_rail?: string
}): RecordNoSig {
  const rec: RecordNoSig = {
    spec_version: SPEC_VERSION,
    record_type: 'accountability_record',
    action_ref: computeActionRef(AGENT_DID, o.refAction),
    action_digest: { sha256: actionDigestSha256(o.digestAction) },
    signer_did: SIGNER_DID,
    agent_did: AGENT_DID,
    delegation_ref: DELEGATION_REF,
    principal_ref: PRINCIPAL_REF,
    decision: o.decision,
    executed: o.executed,
    issued_at: o.issued_at,
    sig_alg: 'Ed25519',
  }
  if (o.inlineAction) rec.action = o.inlineAction
  if (o.settlement_ref) rec.settlement_ref = o.settlement_ref
  if (o.settlement_rail) rec.settlement_rail = o.settlement_rail
  return rec
}

interface Vector {
  name: string
  description: string
  record: AccountabilityRecord
  signing_input_canonical: string
  signing_input_bytes_hex: string
  canonical: string
  canonical_bytes_hex: string
  canonical_sha256: string
  ed25519_pubkey_hex: string
  ed25519_signature_over_signing_input_hex: string
  expected_verification: boolean
  rejection_kind?: string
  expected_error_code?: string
}

function makeVector(o: {
  name: string
  description: string
  recordNoSig: RecordNoSig
  signWith: Keypair
  verifyWith: string
  expected: boolean
  rejection_kind?: string
  expected_error_code?: string
  overrideSig?: string // use this as record.sig instead of signing recordNoSig (stale-sig / relabel)
}): Vector {
  const si = canonicalizeJCS(o.recordNoSig) // signing input: JCS of record without `sig`
  const sig = o.overrideSig ?? signUtf8(si, o.signWith.privateKeyHex)
  const record = { ...o.recordNoSig, sig } as AccountabilityRecord
  const canonical = canonicalizeJCS(record)
  const v: Vector = {
    name: o.name,
    description: o.description,
    record,
    signing_input_canonical: si,
    signing_input_bytes_hex: utf8Hex(si),
    canonical,
    canonical_bytes_hex: utf8Hex(canonical),
    canonical_sha256: sha256Hex(canonical),
    ed25519_pubkey_hex: o.verifyWith,
    ed25519_signature_over_signing_input_hex: sig,
    expected_verification: o.expected,
  }
  if (o.rejection_kind) v.rejection_kind = o.rejection_kind
  if (o.expected_error_code) v.expected_error_code = o.expected_error_code
  return v
}

// ── action payloads (synthetic) ──
const A1: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:00:00Z' }
const A2: RecordedAction = { type: 'commerce.refund', scope: ['commerce:refund'], timestamp: '2026-07-04T12:05:00Z' }
const A3: RecordedAction = { type: 'data.export', scope: ['data:export'], timestamp: '2026-07-04T12:10:00Z' }
const A4: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:15:00Z' }
const A5_INLINE: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge:elevated'], timestamp: '2026-07-04T12:20:00Z' }
const A5_COMMITTED: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:20:00Z' }
const A6: RecordedAction = { type: 'identity.rotate', scope: ['identity:rotate'], timestamp: '2026-07-04T12:25:00Z' }
const A7: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:30:00Z' }
const A8: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:35:00Z' }
const A9: RecordedAction = { type: 'data.delete', scope: ['data:delete'], timestamp: '2026-07-04T12:40:00Z' }
// same-second collision: identical tuple, timestamps differ only in sub-second ms.
const A10A: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:45:00.100Z' }
const A10B: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:45:00.900Z' }
const A11: RecordedAction = { type: 'commerce.charge', scope: ['commerce:charge'], timestamp: '2026-07-04T12:50:00Z' }

// vector 7: out-of-enum decision (schema negative) — build valid then relabel decision.
const v7NoSig = buildRecordNoSig({
  inlineAction: A7, refAction: A7, digestAction: A7,
  decision: 'allow', executed: false, issued_at: '2026-07-04T12:30:01Z',
})
;(v7NoSig as { decision: string }).decision = 'permit' // decisionReceipt vocabulary, out of allow|deny|halt

// vector 8: type relabel — sign the valid record_type, then present with record_type swapped.
const v8OrigNoSig = buildRecordNoSig({
  inlineAction: A8, refAction: A8, digestAction: A8,
  decision: 'allow', executed: true, issued_at: '2026-07-04T12:35:01Z',
})
const v8OrigSig = signUtf8(canonicalizeJCS(v8OrigNoSig), KP.privateKeyHex)
const v8RelabeledNoSig = { ...v8OrigNoSig, record_type: 'audit_receipt' } as unknown as RecordNoSig

// vector 12: sig_alg lowercase (schema negative) — build valid then downcase sig_alg.
const v12NoSig = buildRecordNoSig({
  inlineAction: A11, refAction: A11, digestAction: A11,
  decision: 'allow', executed: true, issued_at: '2026-07-04T12:50:01Z',
})
;(v12NoSig as { sig_alg: string }).sig_alg = 'ed25519'

const vectors: Vector[] = [
  makeVector({
    name: 'allow-executed-settled',
    description: 'Boundary decision allow, action executed, with an opaque settlement_ref and rail-neutral settlement_rail label. Inline action present.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A1, refAction: A1, digestAction: A1,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:00:01Z',
      settlement_ref: 'stl_test_0a1b2c3d4e5f6070', settlement_rail: 'test-rail',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'deny-no-settlement',
    description: 'Boundary decision deny, action not executed, no settlement fields. Inline action present.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A2, refAction: A2, digestAction: A2,
      decision: 'deny', executed: false, issued_at: '2026-07-04T12:05:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'halt',
    description: 'Boundary decision halt, action not executed, no settlement. Inline action present.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A3, refAction: A3, digestAction: A3,
      decision: 'halt', executed: false, issued_at: '2026-07-04T12:10:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'detached-payload',
    description: 'Detached-payload pattern: action_digest and action_ref commit to a payload that is NOT inlined. A verifier without the payload checks the signature and structure and reports payload-unverified; digest binding is deferred to whoever holds the payload.',
    recordNoSig: buildRecordNoSig({
      inlineAction: undefined, refAction: A4, digestAction: A4,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:15:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'negative-tampered-payload',
    description: 'NEGATIVE (digest). Signature is valid over the record bytes, but the inline action was swapped after commitment: action_digest commits to the original payload while the inline payload is a scope-elevated variant, so sha256(JCS(action)) != action_digest.sha256. MUST fail verification on digest binding.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A5_INLINE, refAction: A5_INLINE, digestAction: A5_COMMITTED,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:20:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: false,
    rejection_kind: 'digest_mismatch', expected_error_code: 'ACTION_DIGEST_MISMATCH',
  }),
  makeVector({
    name: 'negative-wrong-key',
    description: 'NEGATIVE (signature). A structurally valid, digest-consistent record signed by a DIFFERENT key than the one signer_did resolves to (the primary keypair). MUST fail signature verification against ed25519_pubkey_hex.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A6, refAction: A6, digestAction: A6,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:25:01Z',
    }),
    signWith: WRONG_KP, verifyWith: KP.publicKeyHex, expected: false,
    rejection_kind: 'signature', expected_error_code: 'SIGNATURE_INVALID',
  }),
  makeVector({
    name: 'negative-schema-decision',
    description: 'NEGATIVE (schema). decision is "permit" (decisionReceipt policy-evaluation vocabulary), which is out of the accountability boundary enum allow|deny|halt. Signature is valid over its own bytes; the record MUST be rejected by schema validation (validate.py), not by the crypto layer.',
    recordNoSig: v7NoSig,
    signWith: KP, verifyWith: KP.publicKeyHex, expected: false,
    rejection_kind: 'schema', expected_error_code: 'DECISION_NOT_IN_ENUM',
  }),
  makeVector({
    name: 'negative-type-relabel',
    description: 'NEGATIVE (signature). record_type is bound by the signature. This record was signed with record_type="accountability_record", then relabeled to "audit_receipt" while keeping the original signature. Because record_type is inside the signing preimage, the signature MUST fail (domain separation). It also violates the record_type const, but the decisive, demonstrated failure is the signature.',
    recordNoSig: v8RelabeledNoSig,
    signWith: KP, verifyWith: KP.publicKeyHex, expected: false, overrideSig: v8OrigSig,
    rejection_kind: 'signature', expected_error_code: 'SIGNATURE_INVALID',
  }),
  makeVector({
    name: 'positive-deny-executed',
    description: 'POSITIVE. decision=deny but executed=true: the action executed despite a deny verdict (a recorded boundary violation). Valid and verifiable. Demonstrates that decision and executed are recorded independently and are not derived from each other.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A9, refAction: A9, digestAction: A9,
      decision: 'deny', executed: true, issued_at: '2026-07-04T12:40:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'positive-collision-same-second-a',
    description: 'POSITIVE. Same-second collision A. Same agent, action type, and scope; timestamp 12:45:00.100Z. Shares its action_ref with vector B (second-precision normalization) but has a distinct action_digest (the full payload timestamp differs). Demonstrates action_ref is a correlation key, not a unique event id.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A10A, refAction: A10A, digestAction: A10A,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:45:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'positive-collision-same-second-b',
    description: 'POSITIVE. Same-second collision B. Same tuple as A; timestamp 12:45:00.900Z. Same action_ref as A, different action_digest. The pair proves distinct actions can share an action_ref within one second.',
    recordNoSig: buildRecordNoSig({
      inlineAction: A10B, refAction: A10B, digestAction: A10B,
      decision: 'allow', executed: true, issued_at: '2026-07-04T12:45:01Z',
    }),
    signWith: KP, verifyWith: KP.publicKeyHex, expected: true,
  }),
  makeVector({
    name: 'negative-sig-alg-lowercase',
    description: 'NEGATIVE (schema). sig_alg is "ed25519" (lowercase), which violates the const "Ed25519". Signature is valid over its own bytes; the record MUST be rejected by schema validation (validate.py). Guards against algorithm-label non-canonicalization.',
    recordNoSig: v12NoSig,
    signWith: KP, verifyWith: KP.publicKeyHex, expected: false,
    rejection_kind: 'schema', expected_error_code: 'SIG_ALG_NOT_CANONICAL',
  }),
]

// ── self-verify: crypto/digest layer must match expected, EXCEPT schema negatives ──
// (schema negatives are enforced by validate.py; the generator does no schema check).
let failures = 0
console.log('== self-verification (generator; crypto/digest layer) ==')
for (const v of vectors) {
  const res = verifyRecord(v.record, v.ed25519_pubkey_hex)
  if (v.rejection_kind === 'schema') {
    console.log(`  NOTE ${v.name.padEnd(32)} schema-negative (enforced by validate.py); crypto layer ok=${res.ok}`)
    continue
  }
  const pass = res.ok === v.expected_verification
  if (!pass) failures++
  console.log(
    `  ${pass ? 'OK  ' : 'FAIL'} ${v.name.padEnd(32)} expected=${v.expected_verification} actual=${res.ok}  ` +
    `checks=${JSON.stringify(res.checks)}`,
  )
}

// cross-check the same-second collision invariant explicitly.
const va = vectors.find((v) => v.name === 'positive-collision-same-second-a')!
const vb = vectors.find((v) => v.name === 'positive-collision-same-second-b')!
const sameRef = va.record.action_ref === vb.record.action_ref
const diffDigest = va.record.action_digest.sha256 !== vb.record.action_digest.sha256
console.log(`  ${sameRef && diffDigest ? 'OK  ' : 'FAIL'} collision invariant: shared action_ref=${sameRef}, distinct action_digest=${diffDigest}`)
if (!(sameRef && diffDigest)) failures++

if (failures > 0) {
  console.error(`\n${failures} vector(s) did not match expected. NOT writing fixture.`)
  process.exit(1)
}

const fixture = {
  version: 'v1',
  spec: 'APS accountability-record v0.1. Record shape derived from agent-passport-system (decisionReceipt predicate + execution-envelope field convention + computeActionRef, draft-pidlisnyi-aps-00 §4.1). Canonicalization: JCS RFC 8785. Signature: Ed25519 over the signing input. Inline payload field is `action`; action_digest is over the `action` object.',
  spec_ref: 'https://datatracker.ietf.org/doc/draft-pidlisnyi-aps-00/',
  schema: './accountability-record.schema.json',
  seed_input: SEED_INPUT,
  seed_sha256_hex: KP.seedHex,
  keypair: { publicKeyHex: KP.publicKeyHex },
  wrong_keypair: {
    seed_input: WRONG_SEED_INPUT,
    publicKeyHex: WRONG_KP.publicKeyHex,
    note: 'Used only to produce the negative-wrong-key vector; signer_did resolves to keypair.publicKeyHex, not this one.',
  },
  generated_at: '2026-07-04',
  signing: 'record.sig = Ed25519(privateKey, UTF-8 bytes of JCS(record without the sig field)). signing_input_canonical/_bytes_hex are those bytes; canonical/_bytes_hex are the JCS of the full record including sig. Verification key is keypair.publicKeyHex (the key signer_did resolves to). rejection_kind: schema negatives are enforced by validate.py; signature/digest_mismatch negatives by verify.ts.',
  vectors,
}

writeFileSync(OUT, JSON.stringify(fixture, null, 2) + '\n')
console.log(`\n== wrote ==\n  ${OUT}`)
console.log(`  ${vectors.length} vectors; primary pub ${KP.publicKeyHex.slice(0, 16)}...  wrong pub ${WRONG_KP.publicKeyHex.slice(0, 16)}...`)

// Verifier for the two-wrapper attribution fixture pair (vocab #36, Path B
// recording wrapper). Standalone, matches the suite's per-fixture verify style.
//   npx tsx fixtures/attribution/two-wrapper-v0/verify.ts
//
// Asserts:
//   - wrapper-a and wrapper-b each verify under their OWN emitter key,
//   - both bind the SAME wrapped_receipt_digest, equal to the embedded receipt's
//     own receipt.integrity.digest and to its receipt_id (the shared base),
//   - the two wrappers are genuinely independent (distinct kid / recorded_by /
//     recording_event_id / signature bytes),
//   - all three negatives fail closed.
// Exits non-zero on any surprise.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyWrapper, type RecordingWrapper } from './lib.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const read = (rel: string) => JSON.parse(readFileSync(join(HERE, rel), 'utf-8'))

const BASE_DIGEST = 'sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9'
const registry: Record<string, string> = read('keys/registry.json')

const wrapperA: RecordingWrapper = read('wrapper-a.json')
const wrapperB: RecordingWrapper = read('wrapper-b.json')
const negatives: Array<{ name: string; reason: string; expected_verification: boolean; wrapper: RecordingWrapper }> = [
  read('negatives/neg-01-substituted-base.json'),
  read('negatives/neg-02-kid-cross-key.json'),
  read('negatives/neg-03-tampered-event-id.json'),
]

let failures = 0
const check = (label: string, ok: boolean) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`)
  if (!ok) failures++
}

// The embedded receipt is the full served SAR-402 document R; its integrity
// block sits at R.receipt.integrity.digest (nutstrut, vocab #36).
const embeddedDigest = (w: RecordingWrapper): string =>
  ((w.receipt.receipt as Record<string, unknown>).integrity as Record<string, string>).digest
const embeddedReceiptId = (w: RecordingWrapper): string => (w.receipt as Record<string, string>).receipt_id

// Positives: each wrapper verifies under its own key.
check('wrapper-a verifies under emitter-a', verifyWrapper(wrapperA, registry) === true)
check('wrapper-b verifies under emitter-b', verifyWrapper(wrapperB, registry) === true)

// Shared base digest, identical across both, matching the embedded receipt.
check('wrapper-a wrapped_receipt_digest == base digest', wrapperA.wrapped_receipt_digest === BASE_DIGEST)
check('wrapper-b wrapped_receipt_digest == base digest', wrapperB.wrapped_receipt_digest === BASE_DIGEST)
check('both wrappers share the same wrapped_receipt_digest', wrapperA.wrapped_receipt_digest === wrapperB.wrapped_receipt_digest)
check('wrapper-a digest == embedded receipt.integrity.digest', wrapperA.wrapped_receipt_digest === embeddedDigest(wrapperA))
check('wrapper-b digest == embedded receipt.integrity.digest', wrapperB.wrapped_receipt_digest === embeddedDigest(wrapperB))
check('wrapper-a embedded receipt_id == base digest', embeddedReceiptId(wrapperA) === BASE_DIGEST)
check('wrapper-b embedded receipt_id == base digest', embeddedReceiptId(wrapperB) === BASE_DIGEST)

// Independence: same base, different recording identities and signatures.
check('distinct recording_key_id', wrapperA.recording_key_id !== wrapperB.recording_key_id)
check('distinct recorded_by', wrapperA.recorded_by !== wrapperB.recorded_by)
check('distinct recording_event_id', wrapperA.recording_event_id !== wrapperB.recording_event_id)
check('distinct signature bytes', wrapperA.recording_signature.sig !== wrapperB.recording_signature.sig)

// Cross-key isolation: wrapper-a must NOT verify under emitter-b, and vice versa.
check('wrapper-a does NOT verify under emitter-b key', verifyWrapper({ ...wrapperA, recording_signature: { ...wrapperA.recording_signature, kid: 'emitter-b-key-01' } }, registry) === false)
check('wrapper-b does NOT verify under emitter-a key', verifyWrapper({ ...wrapperB, recording_signature: { ...wrapperB.recording_signature, kid: 'emitter-a-key-01' } }, registry) === false)

// Negatives: every one must fail closed.
for (const n of negatives) {
  const result = verifyWrapper(n.wrapper, registry)
  check(`negative "${n.name}" fails closed`, result === false && n.expected_verification === false)
}

console.log(`\ntwo-wrapper-attribution: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`)
process.exit(failures === 0 ? 0 : 1)

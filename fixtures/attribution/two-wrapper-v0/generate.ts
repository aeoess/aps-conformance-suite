// Deterministic generator for the two-wrapper attribution fixture pair.
// Run once to (re)produce the committed JSON; verify.ts re-checks the outputs.
//   npx tsx fixtures/attribution/two-wrapper-v0/generate.ts
//
// Two independent emitters each record an attribution wrapper over the SAME
// public base receipt (wrapped_receipt_digest sha256:91e2ae85...). Both wrappers
// verify under their own key; they differ in recording_event_id, recorded_by,
// recording_key_id, recording_service, and recording_signature. Three negatives
// demonstrate fail-closed behaviour. Keys derive from fixed FIXTURE-ONLY seeds so
// the whole corpus is reproducible.

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { pubKeyHexFromSeedHex, signObjectHex, wrapperSignedBody, type RecordingWrapper } from './lib.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const write = (rel: string, obj: unknown) => writeFileSync(join(HERE, rel), JSON.stringify(obj, null, 2) + '\n')

const BASE_DIGEST = 'sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9'
const baseReceipt = JSON.parse(readFileSync(join(HERE, 'base-receipt.json'), 'utf-8')) as Record<string, unknown>

// FIXTURE-ONLY Ed25519 seeds. Synthetic, never production keys, never reused.
const EMITTER_A_SEED = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
const EMITTER_B_SEED = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'
const A_KID = 'emitter-a-key-01'
const B_KID = 'emitter-b-key-01'
const A_PUB = pubKeyHexFromSeedHex(EMITTER_A_SEED)
const B_PUB = pubKeyHexFromSeedHex(EMITTER_B_SEED)

write('keys/emitter-a.json', { kid: A_KID, note: 'FIXTURE-ONLY synthetic Ed25519 key, not a production emitter', alg: 'ed25519', seed_hex: EMITTER_A_SEED, public_key_hex: A_PUB })
write('keys/emitter-b.json', { kid: B_KID, note: 'FIXTURE-ONLY synthetic Ed25519 key, not a production emitter', alg: 'ed25519', seed_hex: EMITTER_B_SEED, public_key_hex: B_PUB })
write('keys/registry.json', { [A_KID]: A_PUB, [B_KID]: B_PUB })

function buildWrapper(opts: { kid: string; seed: string; recordedBy: string; service: string; eventId: string }): RecordingWrapper {
  const w: RecordingWrapper = {
    wrapper_version: 'path-b-recording-v0',
    wrapped_receipt_digest: BASE_DIGEST,
    recorded_by: opts.recordedBy,
    recording_service: opts.service,
    recording_key_id: opts.kid,
    recording_event_id: opts.eventId,
    recording_context: 'ingestion',
    source_evidence_created_by: 'resource_server',
    receipt: baseReceipt,
    recording_signature: { kid: opts.kid, alg: 'ed25519', sig: '' },
  }
  w.recording_signature.sig = signObjectHex(wrapperSignedBody(w), opts.seed)
  return w
}

const wrapperA = buildWrapper({ kid: A_KID, seed: EMITTER_A_SEED, recordedBy: 'did:web:emitter-a.fixture.aeoess.dev', service: 'aps-conformance-fixture-emitter-a', eventId: 'rec-2wrap-a-0001' })
const wrapperB = buildWrapper({ kid: B_KID, seed: EMITTER_B_SEED, recordedBy: 'did:web:emitter-b.fixture.aeoess.dev', service: 'aps-conformance-fixture-emitter-b', eventId: 'rec-2wrap-b-0001' })
write('wrapper-a.json', wrapperA)
write('wrapper-b.json', wrapperB)

const clone = (w: RecordingWrapper): RecordingWrapper => JSON.parse(JSON.stringify(w))

// N1: substituted base receipt. Swap the bound digest (wrapper field + the
// embedded receipt's own receipt.integrity.digest) AFTER signing. The embedded
// receipt is the full served SAR-402 document R, so its integrity block is at
// R.receipt.integrity.digest. The original signature no longer covers it.
const n1 = clone(wrapperA)
const OTHER_DIGEST = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
n1.wrapped_receipt_digest = OTHER_DIGEST
const n1inner = (n1.receipt.receipt as Record<string, unknown>).integrity as Record<string, unknown>
n1inner.digest = OTHER_DIGEST
write('negatives/neg-01-substituted-base.json', { name: 'substituted-base', reason: 'wrapped_receipt_digest and embedded receipt.integrity.digest swapped after signing; signature was over the original base', expected_verification: false, wrapper: n1 })

// N2: cross-key / kid mismatch. wrapper-a body and signature unchanged, but the
// signature claims emitter-b as its kid. Verifier looks up emitter-b's key and fails.
const n2 = clone(wrapperA)
n2.recording_signature.kid = B_KID
write('negatives/neg-02-kid-cross-key.json', { name: 'kid-cross-key', reason: 'recording_signature.kid points at emitter-b while the signature bytes are emitter-a; verifies against the wrong key and fails', expected_verification: false, wrapper: n2 })

// N3: tampered recording_event_id after signing. Signed body changed, original sig kept.
const n3 = clone(wrapperA)
n3.recording_event_id = 'rec-2wrap-a-0001-TAMPERED'
write('negatives/neg-03-tampered-event-id.json', { name: 'tampered-event-id', reason: 'recording_event_id altered after signing; the signature no longer matches the wrapper body', expected_verification: false, wrapper: n3 })

console.log('generated: keys/{emitter-a,emitter-b,registry}.json, wrapper-a.json, wrapper-b.json, negatives/neg-01..03')
console.log('emitter-a pub:', A_PUB)
console.log('emitter-b pub:', B_PUB)

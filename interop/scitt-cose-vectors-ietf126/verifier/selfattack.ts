// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Phase 6 self-attack: take three positive vectors, mutate exactly one byte in
// each of three different artifacts (payload, statement signature, receipt
// audit-path digest), run the verifier over an in-memory copy of the vector
// directory, and confirm each fails closed at the stage that byte belongs to.
// Nothing on disk under the pinned clone is modified: mutants are written to a
// scratch copy directory per case.

import { createHash } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runVector } from './verify.js'
import { parseCoseSign1 } from './cose.js'

const VECTORS = process.env.VECTORS_DIR ?? join(process.env.HOME!, 'capsule-verify/upstream-scitt-cose/test-vectors')

function copyVector(id: string): string {
  const src = join(VECTORS, 'v1', id)
  const dst = mkdtempSync(join(tmpdir(), `capsule-attack-${id}-`))
  cpSync(src, dst, { recursive: true })
  return dst
}

function flipByteInFile(path: string, at: number): { before: number; after: number } {
  const buf = readFileSync(path)
  const before = buf[at]
  buf[at] = before ^ 0x01
  writeFileSync(path, buf)
  return { before, after: buf[at] }
}

interface AttackOutcome {
  name: string
  vector: string
  target: string
  byteOffset: number
  expectedStage: string
  observedStage: string | null
  observedResult: string
  passed: boolean
}

const outcomes: AttackOutcome[] = []

// Attack 1: payload byte. Flipping payload.bin breaks the payload digest stage
// (and, because the statement signs the payload, the statement signature too;
// payload-digest is the earlier stage, so it is the one that must catch it).
{
  const dir = copyVector('valid-eddsa')
  const { before, after } = flipByteInFile(join(dir, 'payload.bin'), 0)
  const run = runVector(dir, 'valid-eddsa')
  outcomes.push({
    name: 'payload byte flip', vector: 'valid-eddsa', target: 'payload.bin[0]',
    byteOffset: 0, expectedStage: 'payload-digest',
    observedStage: run.failingStage, observedResult: run.observedResult,
    passed: run.observedResult === 'INVALID' && run.failingStage === 'payload-digest',
  })
  console.log(`attack1 payload.bin[0] ${before}->${after}: result ${run.observedResult}, stage ${run.failingStage}`)
}

// Attack 2: signature byte. Flip one byte inside the statement's COSE_Sign1
// signature (element index 3). Must fail at statement-sig.
{
  const dir = copyVector('valid-es256')
  const raw = new Uint8Array(readFileSync(join(dir, 'statement.cose')))
  const cose = parseCoseSign1(raw)
  // Locate the signature bytes within the file by exact-match search.
  const sig = cose.signature
  let sigStart = -1
  outer: for (let i = 0; i + sig.length <= raw.length; i++) {
    for (let j = 0; j < sig.length; j++) if (raw[i + j] !== sig[j]) continue outer
    sigStart = i; break
  }
  if (sigStart < 0) throw new Error('could not locate signature bytes in statement.cose')
  const at = sigStart + Math.floor(sig.length / 2)
  const { before, after } = flipByteInFile(join(dir, 'statement.cose'), at)
  // Mirror the vector set's own fail-bad-statement-sig construction: the log
  // registered the tampered bytes, so the leaf entry is the digest of what it
  // was given. Recompute expected leaf_entry over the mutated statement so the
  // leaf-entry stage passes and the mutation is isolated to statement-sig.
  const expected2 = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'))
  expected2.leaf_entry = createHash('sha256').update(readFileSync(join(dir, 'statement.cose'))).digest('hex')
  writeFileSync(join(dir, 'expected.json'), JSON.stringify(expected2))
  const run = runVector(dir, 'valid-es256')
  outcomes.push({
    name: 'statement signature byte flip', vector: 'valid-es256', target: `statement.cose[${at}] (signature)`,
    byteOffset: at, expectedStage: 'statement-sig',
    observedStage: run.failingStage, observedResult: run.observedResult,
    passed: run.observedResult === 'INVALID' && run.failingStage === 'statement-sig',
  })
  console.log(`attack2 statement.cose sig byte @${at} ${before}->${after}: result ${run.observedResult}, stage ${run.failingStage}`)
}

// Attack 3: digest byte. Flip one byte inside the receipt's first audit-path
// node. That breaks the reconstructed root, so the receipt signature over that
// root must fail. Locate the node bytes from expected.json's inclusion_path[0].
{
  const dir = copyVector('valid-eddsa')
  const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'))
  const node0 = Buffer.from(expected.inclusion_path[0], 'hex')
  const raw = new Uint8Array(readFileSync(join(dir, 'receipt.cose')))
  let nodeStart = -1
  outer2: for (let i = 0; i + node0.length <= raw.length; i++) {
    for (let j = 0; j < node0.length; j++) if (raw[i + j] !== node0[j]) continue outer2
    nodeStart = i; break
  }
  if (nodeStart < 0) throw new Error('could not locate audit-path node in receipt.cose')
  const at = nodeStart + 3
  const { before, after } = flipByteInFile(join(dir, 'receipt.cose'), at)
  const run = runVector(dir, 'valid-eddsa')
  // The embedded audit path now differs from expected.json, so the earliest
  // stage that catches the mutation is inclusion-proof (path-bytes cross-check).
  outcomes.push({
    name: 'receipt digest byte flip', vector: 'valid-eddsa', target: `receipt.cose[${at}] (audit-path node 0)`,
    byteOffset: at, expectedStage: 'inclusion-proof',
    observedStage: run.failingStage, observedResult: run.observedResult,
    passed: run.observedResult === 'INVALID' && run.failingStage === 'inclusion-proof',
  })
  console.log(`attack3 receipt.cose digest byte @${at} ${before}->${after}: result ${run.observedResult}, stage ${run.failingStage}`)
}

const allPassed = outcomes.every(o => o.passed)
writeFileSync(join(process.env.OUT_DIR ?? join(process.env.HOME!, 'capsule-verify'), 'selfattack-results.json'), JSON.stringify(outcomes, null, 1) + '\n')
console.log(`\nself-attack: ${outcomes.filter(o => o.passed).length}/${outcomes.length} failed closed at the expected stage`)
process.exit(allPassed ? 0 : 1)

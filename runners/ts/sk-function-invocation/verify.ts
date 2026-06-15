// SK function-invocation filter conformance runner.
//
// Imports two portable fixture classes and asserts one property: a negative
// vector never reaches the kernel function. The function body runs only inside
// next(); on any negative the filter denies before next(), so invoked stays
// false and a denial is emitted with the fixture id, handle family, and a
// redacted reason.
//
// Fixture classes:
//   byte-level handle-correctness (recompute-drift): giskard09/argentum-core
//     (external) and aeoess/aps-conformance-suite action-ref-v1-negatives
//     (ours, a second implementation of the same class).
//   issuer-binding and scope-replay (near-miss): giskard09/argentum-core
//     (external).
//
// Run: npx tsx runners/ts/sk-function-invocation/verify.ts
// Exit 0 on full pass, 1 on any failure.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  verifyHandleCorrectness,
  verifyNearMiss,
  runThroughFilter,
  type Verdict,
} from './runner.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..', '..')
const VEND = join(__dirname, 'test-fixtures', 'argentum-core')
const OURS = join(REPO_ROOT, 'fixtures', 'cross-stack', 'action-ref-v1-negatives', 'vectors.json')

const read = (p: string) => JSON.parse(readFileSync(p, 'utf8'))

const AEOESS = 'aeoess/aps-conformance-suite (ours)'
const ARGENTUM = 'giskard09/argentum-core (external)'

interface Case {
  source: string
  klass: 'handle-correctness' | 'near-miss'
  expectInvoke: boolean
  verdict: () => Verdict
  id: string
}

const cases: Case[] = []

// OURS: byte-level handle-correctness, positives and negatives.
const ours = read(OURS)
for (const v of ours.positive_fixture.vectors) {
  cases.push({ source: AEOESS, klass: 'handle-correctness', expectInvoke: true, id: v.id,
    verdict: () => verifyHandleCorrectness(v, { positive: true, family: ours.positive_fixture.fixture_id }) })
}
for (const v of ours.negative_fixture.vectors) {
  cases.push({ source: AEOESS, klass: 'handle-correctness', expectInvoke: false, id: v.id,
    verdict: () => verifyHandleCorrectness(v, { positive: false, family: ours.negative_fixture.fixture_id }) })
}

// EXTERNAL: argentum-core recompute-drift, positives and negatives.
const drvPos = read(join(VEND, 'recompute-drift-v1-positive.fixture.json'))
for (const v of drvPos.vectors) {
  cases.push({ source: ARGENTUM, klass: 'handle-correctness', expectInvoke: true, id: v.id,
    verdict: () => verifyHandleCorrectness(v, { positive: true, family: drvPos.fixture_id }) })
}
const drvNeg = read(join(VEND, 'recompute-drift-v1-negative.fixture.json'))
for (const v of drvNeg.vectors) {
  cases.push({ source: ARGENTUM, klass: 'handle-correctness', expectInvoke: false, id: v.id,
    verdict: () => verifyHandleCorrectness(v, { positive: false, family: drvNeg.fixture_id }) })
}

// EXTERNAL: argentum-core near-miss, all negatives.
const nm = read(join(VEND, 'near-miss-v1.fixture.json'))
for (const v of nm.vectors) {
  cases.push({ source: ARGENTUM, klass: 'near-miss', expectInvoke: false, id: v.name ?? v.id,
    verdict: () => verifyNearMiss(v) })
}

// ── Run + assert ─────────────────────────────────────────────────────
let pass = 0
const failures: string[] = []

for (const c of cases) {
  const verdict = c.verdict()
  const ctx = runThroughFilter(verdict)
  const errs: string[] = []

  if (c.expectInvoke) {
    if (!ctx.invoked) errs.push('expected invoke, function did not run')
    if (ctx.denial) errs.push('positive vector produced a denial')
    if (ctx.events.join(',') !== 'verify,allow,invoke') errs.push(`unexpected event order ${ctx.events.join(',')}`)
  } else {
    if (ctx.invoked) errs.push('NEGATIVE BYPASS: function ran on a negative vector')
    if (!ctx.denial) errs.push('no denial emitted on a negative vector')
    if (ctx.events.includes('invoke')) errs.push('invoke event present on a negative vector')
    if (ctx.events.join(',') !== 'verify,deny') errs.push(`denial not before next(): events ${ctx.events.join(',')}`)
    if (ctx.denial) {
      if (!ctx.denial.fixtureId) errs.push('denial missing fixtureId')
      if (!ctx.denial.handleFamily) errs.push('denial missing handleFamily')
      if (!ctx.denial.reason) errs.push('denial missing reason')
    }
  }

  if (errs.length === 0) {
    pass++
    const tag = c.expectInvoke ? 'INVOKE ' : 'DENY   '
    const extra = c.expectInvoke ? '' : `  [${ctx.denial!.handleFamily}] ${ctx.denial!.reason}`
    console.log(`  PASS ${tag} ${c.klass.padEnd(18)} ${c.id.padEnd(34)} ${c.source}${extra}`)
  } else {
    failures.push(`${c.id} (${c.source}): ${errs.join('; ')}`)
    console.log(`  FAIL ${c.id} (${c.source}): ${errs.join('; ')}`)
  }
}

const pos = cases.filter((c) => c.expectInvoke).length
const neg = cases.length - pos
console.log('')
console.log(`SK function-invocation filter conformance`)
console.log(`  positives (must invoke): ${pos}`)
console.log(`  negatives (must deny before next): ${neg}`)
console.log(`  passed: ${pass}/${cases.length}`)
console.log(`  property: the invocation path cannot bypass the verifier`)

if (failures.length > 0) {
  console.error(`\nFAILED: ${failures.length} vector(s) did not hold the fail-closed property`)
  process.exit(1)
}
console.log('\nOK: every negative denied before invocation; every positive invoked.')

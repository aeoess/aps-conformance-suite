// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Runner: iterate the pinned manifest, run every vector through the staged
// verifier, compare observed vs expected, and emit results.json plus
// RESULTS.md. Deterministic and offline: inputs are the local clone only.

import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { runVector } from './verify.js'

const VECTORS = resolve(process.env.VECTORS_DIR ?? join(process.env.HOME!, 'capsule-verify/upstream-scitt-cose/test-vectors'))
const OUT = resolve(process.env.OUT_DIR ?? join(process.env.HOME!, 'capsule-verify'))

// Stage-to-failure-code mapping, declared once so the comparison is explicit.
const STAGE_TO_CODE: Record<string, string> = {
  'statement-sig': 'BAD_STATEMENT_SIGNATURE',
  'vds-gate': 'UNSUPPORTED_VDS',
  'inclusion-proof': 'TAMPERED_INCLUSION_PATH',
  'receipt-sig': 'TAMPERED_INCLUSION_PATH',
}

interface ResultRow {
  id: string
  polarity: 'positive' | 'negative'
  expected: string
  observed: string
  stage: string | null
  expected_failure_code: string | null
  mapped_failure_code: string | null
  verdict: 'match' | 'divergence'
  unsupported: string[]
  stages: { stage: string; ok: boolean; detail: string }[]
}

const manifest = JSON.parse(readFileSync(join(VECTORS, 'manifest.json'), 'utf8'))
const rows: ResultRow[] = []

for (const entry of manifest.vectors) {
  const dir = join(VECTORS, entry.dir)
  const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'))
  const run = runVector(dir, entry.id)
  const expectedResult: string = expected.result
  const expectedCode: string | null = expected.failure_code ?? null
  const mappedCode = run.failingStage ? (STAGE_TO_CODE[run.failingStage] ?? `UNMAPPED(${run.failingStage})`) : null
  const resultMatches = run.observedResult === expectedResult
  const codeMatches = expectedResult === 'VALID' || mappedCode === expectedCode
  rows.push({
    id: entry.id,
    polarity: expectedResult === 'VALID' ? 'positive' : 'negative',
    expected: expectedResult + (expectedCode ? `/${expectedCode}` : ''),
    observed: run.observedResult + (mappedCode ? `/${mappedCode}` : ''),
    stage: run.failingStage,
    expected_failure_code: expectedCode,
    mapped_failure_code: mappedCode,
    verdict: resultMatches && codeMatches ? 'match' : 'divergence',
    unsupported: run.unsupported,
    stages: run.stages,
  })
}

const totals = {
  vectors: rows.length,
  match: rows.filter(r => r.verdict === 'match').length,
  divergence: rows.filter(r => r.verdict === 'divergence').length,
  with_unsupported_subchecks: rows.filter(r => r.unsupported.length > 0).length,
}

writeFileSync(join(OUT, 'results.json'), JSON.stringify({ manifest_version: manifest.version, rows, totals }, null, 1) + '\n')

const md: string[] = []
md.push('# Capsule vector run: stage-by-stage results')
md.push('')
md.push('Input: scitt-cose test-vectors at tag vectors-ietf126 (529515ba). Verifier:')
md.push('from-scratch TypeScript in verifier/ (CBOR codec, RFC 9052')
md.push('COSE_Sign1, RFC 9162 inclusion proofs written fresh; node:crypto primitives).')
md.push('')
for (const r of rows) {
  md.push(`## ${r.id} (${r.polarity})`)
  md.push('')
  md.push(`expected ${r.expected}; observed ${r.observed}; verdict **${r.verdict}**`)
  md.push('')
  for (const s of r.stages) md.push(`- ${s.ok ? 'PASS' : 'FAIL'} ${s.stage}: ${s.detail}`)
  for (const u of r.unsupported) md.push(`- UNSUPPORTED ${u}`)
  md.push('')
}
md.push('## Totals')
md.push('')
md.push(`vectors ${totals.vectors}; match ${totals.match}; divergence ${totals.divergence}; vectors carrying an unsupported sub-check ${totals.with_unsupported_subchecks}`)
md.push('')
writeFileSync(join(OUT, 'RESULTS.md'), md.join('\n'))

console.log(JSON.stringify(totals))
for (const r of rows) console.log(`${r.verdict === 'match' ? 'MATCH  ' : 'DIVERGE'} ${r.id}: expected ${r.expected}, observed ${r.observed}${r.stage ? ` (stage ${r.stage})` : ''}`)
process.exit(rows.some(r => r.verdict === 'divergence') ? 1 : 0)

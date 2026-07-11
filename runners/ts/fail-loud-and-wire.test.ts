// Fail-before / pass-after test for the fail-loud + wired-vector fix.
//
// Verifies two properties the runner used to violate:
//   1. WIRED ASSERTIONS: the actionref-canonical (4) and bilateral-pair (6)
//      vectors are actually asserted (real pass counts), so the whole suite has
//      exactly one legitimate, explicitly-declared skip.
//   2. FAIL LOUD: a vector that carries a corrupted expected value, and a vector
//      of an unrecognized shape, each make the runner EXIT NON-ZERO instead of
//      being silently downgraded to skip.
//
// On the pre-fix runner these vectors silently skip and the runner exits 0, so
// every assertion below fails: this test fails-before and passes-after.
//
// Run: npx tsx runners/ts/fail-loud-and-wire.test.ts

import { spawnSync } from 'node:child_process'
import { mkdtempSync, cpSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const VERIFY = join(REPO_ROOT, 'runners', 'ts', 'verify.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

let failures = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`)
  }
}

interface Run {
  code: number
  stdout: string
  stderr: string
}

function runVerify(fixturesDir?: string): Run {
  const env = { ...process.env }
  if (fixturesDir) env.APS_FIXTURES_DIR = fixturesDir
  const r = spawnSync(TSX, [VERIFY], { encoding: 'utf8', env })
  return { code: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

function categoryCounts(stdout: string, category: string): { pass: number; fail: number; skip: number } | null {
  const re = new RegExp(`^\\s*${category}\\s+pass=(\\d+)\\s+fail=(\\d+)\\s+skip=(\\d+)`, 'm')
  const m = stdout.match(re)
  if (!m) return null
  return { pass: Number(m[1]), fail: Number(m[2]), skip: Number(m[3]) }
}

function totalSkip(stdout: string): number | null {
  const m = stdout.match(/TOTAL:.*skip=(\d+)/)
  return m ? Number(m[1]) : null
}

function sha256OfFile(path: string): string {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex')
}

// Copy the whole fixtures tree into a temp dir and return its path. Callers
// mutate the copy and repair the copied manifest's file-level sha so the runner
// reaches the per-vector layer instead of failing at the manifest-sha gate.
function copyFixtures(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aps-faillod-'))
  const dest = join(dir, 'fixtures')
  cpSync(join(REPO_ROOT, 'fixtures'), dest, { recursive: true })
  return dest
}

function repairManifestSha(fixturesDir: string, fixturePath: string): void {
  const manifestPath = join(fixturesDir, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const entry = manifest.fixtures.find((e: { path: string }) => e.path === fixturePath)
  if (!entry) throw new Error(`manifest entry not found for ${fixturePath}`)
  entry.canonical_sha256 = sha256OfFile(join(fixturesDir, fixturePath))
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2))
}

console.log('fail-loud + wired-vector test')
if (!existsSync(TSX)) {
  console.error(`tsx binary not found at ${TSX}`)
  process.exit(2)
}

// 1. Real fixtures: wired vectors are asserted; exactly one explicit skip.
{
  const r = runVerify()
  check('real fixtures exit 0', r.code === 0, `exit ${r.code}`)
  const ar = categoryCounts(r.stdout, 'actionref-canonical')
  check('actionref-canonical asserted (pass=4 fail=0 skip=0)', !!ar && ar.pass === 4 && ar.fail === 0 && ar.skip === 0, JSON.stringify(ar))
  const bp = categoryCounts(r.stdout, 'bilateral-pair')
  check('bilateral-pair asserted (pass=6 fail=0 skip=0)', !!bp && bp.pass === 6 && bp.fail === 0 && bp.skip === 0, JSON.stringify(bp))
  const skip = totalSkip(r.stdout)
  check('total skip == 1 (only the explicitly-declared skip remains)', skip === 1, `skip=${skip}`)
}

// 2. Fail loud on a corrupted expected value (wired assertion must reject it).
{
  const fixturesDir = copyFixtures()
  const rel = 'actionref-canonical/actionref-canonical-fixture-v1.json'
  const p = join(fixturesDir, rel)
  const fx = JSON.parse(readFileSync(p, 'utf8'))
  // Flip the last hex nibble of the first vector's expected action_ref.
  const ref: string = fx.vectors[0].action_ref
  const last = ref.slice(-1)
  fx.vectors[0].action_ref = ref.slice(0, -1) + (last === '0' ? '1' : '0')
  writeFileSync(p, JSON.stringify(fx, null, 2))
  repairManifestSha(fixturesDir, rel)
  const r = runVerify(fixturesDir)
  check('corrupted action_ref makes runner exit non-zero', r.code !== 0, `exit ${r.code}`)
  check('corruption is reported as a failure, not a skip', /actionref-canonical/.test(r.stdout) && /fail=/.test(r.stdout) && r.code !== 0)
}

// 3. Fail loud on an unrecognized vector shape (no verifiable data, no skip_reason).
{
  const fixturesDir = copyFixtures()
  const rel = 'bilateral-delegation/canonicalize-fixture-v1.json'
  const p = join(fixturesDir, rel)
  const fx = JSON.parse(readFileSync(p, 'utf8'))
  fx.vectors.push({ name: 'junk-unrecognized-shape', description: 'no verifiable data and no skip_reason' })
  writeFileSync(p, JSON.stringify(fx, null, 2))
  repairManifestSha(fixturesDir, rel)
  const r = runVerify(fixturesDir)
  check('unrecognized vector shape makes runner exit non-zero', r.code !== 0, `exit ${r.code}`)
  check('unrecognized shape names the offending vector', /junk-unrecognized-shape/.test(r.stdout), 'expected vector name in FAILURES')
}

console.log()
if (failures > 0) {
  console.log(`FAILED: ${failures} check(s) failed`)
  process.exit(1)
}
console.log('PASSED: fail-loud enforced and actionref-canonical + bilateral-pair wired')
process.exit(0)

// Verifier for the a2a-1496-negative-paths composition fixture. Run as:
//   npm run verify:a2a-1496-negative-paths
//
// Walks every *.fixture.json file in this directory, hands each fixture's
// `input` to validateNegativePathInput() from ./lib.js, and asserts the
// thrown NegativePathError's `code` equals the fixture's
// `expected_error_code`. A non-throw is a failure.
//
// Empty-directory case: prints "no fixtures present, nothing to verify"
// and exits 0. This keeps the scaffold valid in CI before any fixture
// PR lands.
//
// Fixture shape (see ./README.md for the full contract):
//   { name, description, input, expected_error_code }

import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { NegativePathError, validateNegativePathInput } from './lib.js'

interface NegativePathFixture {
  name: string
  description: string
  input: unknown
  expected_error_code: string
}

const __dirname = dirname(fileURLToPath(import.meta.url))

const fixtures = readdirSync(__dirname)
  .filter((f) => f.endsWith('.fixture.json'))
  .sort()

if (fixtures.length === 0) {
  console.log('a2a-1496-negative-paths: no fixtures present, nothing to verify')
  process.exit(0)
}

let failures = 0
console.log(`a2a-1496-negative-paths: running ${fixtures.length} fixture(s)`)

for (const file of fixtures) {
  let fx: NegativePathFixture
  try {
    fx = JSON.parse(readFileSync(join(__dirname, file), 'utf-8')) as NegativePathFixture
  } catch (e) {
    failures++
    console.log(`  FAIL  ${file}`)
    console.log(`    fixture parse error: ${(e as Error).message}`)
    continue
  }
  const label = `${file} [${fx.name}]`

  try {
    validateNegativePathInput(fx.input)
    failures++
    console.log(`  FAIL  ${label}`)
    console.log(`    expected throw with code=${fx.expected_error_code}; got no throw`)
  } catch (e) {
    const code = e instanceof NegativePathError ? e.code : 'NON_NEGATIVE_PATH_ERROR'
    if (code === fx.expected_error_code) {
      console.log(`  PASS  ${label} (code=${code})`)
    } else {
      failures++
      console.log(`  FAIL  ${label}`)
      console.log(`    expected code: ${fx.expected_error_code}`)
      console.log(`    actual code:   ${code}`)
      if (!(e instanceof NegativePathError)) {
        console.log(`    detail:        ${(e as Error).message}`)
      }
    }
  }
}

console.log('')
if (failures === 0) {
  console.log(`a2a-1496-negative-paths: ALL PASS (${fixtures.length} fixture(s))`)
  process.exit(0)
} else {
  console.log(`a2a-1496-negative-paths: ${failures} FAIL of ${fixtures.length}`)
  process.exit(1)
}

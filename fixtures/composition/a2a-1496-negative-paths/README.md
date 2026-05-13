# a2a-1496-negative-paths composition fixture

Negative-path conformance vectors for the APS delegation validator. Each
fixture asserts that running the validator over a structurally invalid input
yields a specific, named error code from the closed taxonomy. Where
envoys-rfc9421 proves byte-match positive composition across L1/L2/L3, this
directory proves the validator's refusal surface: violations of monotonic
narrowing, depth bounds, signature integrity, and validity windows MUST
surface as the same error code across every conformant implementation.

## Cross-refs

- A2A#1496, review track on the CTEF v0.3.x conformance scope.
- A2A#1786, composition thread where the scaffold was agreed.
- CTEF v0.3.2 §A, Conformance Verification Appendix, defines the error-code
  vocabulary the fixtures pin against.
- `~/agent-passport-system/src/v2/delegation-v2.ts` carries the reference
  `validateV2Delegation()` whose refusal surface these fixtures exercise.

## Verifier-runner contract

Each fixture is a JSON document with the shape:

```json
{
  "name": "short-stable-id-for-the-case",
  "description": "human-readable sentence on what this exercises",
  "input": { /* the structurally invalid input handed to the validator */ },
  "expected_error_code": "INVALID_CLAIM_SCOPE"
}
```

The runner at `./verify.ts` walks every `*.fixture.json` file in this
directory and, for each one:

1. Loads the fixture.
2. Invokes `validateNegativePathInput(input)` from `./lib.ts`.
3. Asserts that the call throws a `NegativePathError` whose `code` field
   equals `expected_error_code`.
4. Reports PASS or FAIL per fixture and exits 0 only if every fixture
   passes. If a fixture's validator call does NOT throw, that fixture
   fails.

Empty directory: the runner prints `no fixtures present, nothing to verify`
and exits 0. This keeps the scaffold valid in CI before any fixture lands.

## Planned cases

| Case                  | `expected_error_code`        |
| --------------------- | ---------------------------- |
| scope expansion       | `INVALID_CLAIM_SCOPE`        |
| depth violation       | `DELEGATION_DEPTH_EXCEEDED`  |
| signature substitution| `INVALID_SIGNATURE`          |
| expired chain         | `VALIDITY_EXPIRED`           |

The four codes are drawn from the CTEF v0.3.2 §A error vocabulary.

## Validator wire-up status

`./lib.ts` ships a scaffold stub of `validateNegativePathInput()` that
throws `SCAFFOLD_VALIDATOR_NOT_WIRED`. The production wire-up lands
alongside the first fixture PR (or in a preceding follow-up commit) and
ports the refusal-path logic from
`~/agent-passport-system/src/v2/delegation-v2.ts`'s `validateV2Delegation()`
into this directory's `lib.ts`, following the self-contained convention
established by `fixtures/composition/envoys-rfc9421/lib.ts`. Until that
wire-up lands, only the empty-directory case exercises the runner end-to-end.

## Run

```sh
npm run verify:a2a-1496-negative-paths
```

The aggregate `npm test` also exercises this directory.

## Attribution

Fixture cases proposed by @kenneives; scaffold maintained by APS.

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
and exits 0, so the runner stays green in CI when no fixtures are present.

## Cases

| Case                  | `expected_error_code`        |
| --------------------- | ---------------------------- |
| scope expansion       | `INVALID_CLAIM_SCOPE`        |
| depth violation       | `DELEGATION_DEPTH_EXCEEDED`  |
| signature substitution| `INVALID_SIGNATURE`          |
| expired chain         | `VALIDITY_EXPIRED`           |

The four codes are drawn from the CTEF v0.3.2 §A error vocabulary.

## Validator status

`./lib.ts` implements `validateNegativePathInput`, which checks delegation
depth, validity windows, signatures, and scope expansion against the closed
CTEF v0.3.2 §A error-code taxonomy. It is self-contained, following the
convention established by `fixtures/composition/envoys-rfc9421/lib.ts`. All
four fixtures pass: scope-expansion resolves to `INVALID_CLAIM_SCOPE`,
depth-violation to `DELEGATION_DEPTH_EXCEEDED`, signature-substitution to
`INVALID_SIGNATURE`, and validity-expired to `VALIDITY_EXPIRED`.

## Run

```sh
npm run verify:a2a-1496-negative-paths
```

The aggregate `npm test` also exercises this directory.

## Attribution

Fixture cases proposed by @kenneives; scaffold maintained by APS.

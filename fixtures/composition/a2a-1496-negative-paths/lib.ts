// Shared validator + helpers for the a2a-1496-negative-paths fixture.
// Negative-path conformance asserts that running the APS delegation
// validator over a structurally invalid input throws a `NegativePathError`
// whose `code` field equals the fixture's `expected_error_code`.
//
// Convention follows fixtures/composition/envoys-rfc9421/lib.ts: no runtime
// dependency on agent-passport-system. The validator logic is ported into
// this file with reference comments pointing back to its source location in
// the SDK so cross-impl reviewers can audit the equivalence.
//
// Scaffold status: validateNegativePathInput() is a sentinel-throwing stub
// until the production wire-up lands alongside the first fixture PR. The
// stub throws SCAFFOLD_VALIDATOR_NOT_WIRED, distinct from any of the four
// CTEF v0.3.2 §A error codes the fixtures pin against, so a real fixture
// arriving before wire-up surfaces a clear "not implemented" failure rather
// than a misleading code match.

/** Closed taxonomy of error codes the fixtures pin against. Drawn from
 *  CTEF v0.3.2 §A Conformance Verification Appendix. */
export type NegativePathErrorCode =
  | 'INVALID_CLAIM_SCOPE'
  | 'DELEGATION_DEPTH_EXCEEDED'
  | 'INVALID_SIGNATURE'
  | 'VALIDITY_EXPIRED'

/** Error thrown by validateNegativePathInput() on a refused input. The
 *  `code` field carries the closed-taxonomy reason; verify.ts checks it
 *  against the fixture's expected_error_code. */
export class NegativePathError extends Error {
  readonly code: string
  constructor(code: string, message?: string) {
    super(message ?? code)
    this.name = 'NegativePathError'
    this.code = code
  }
}

/**
 * Validate a delegation-shaped input and throw on refusal.
 *
 * SCAFFOLD: this is a sentinel-throwing stub. The production wire-up
 * ports the refusal-path checks from
 * `~/agent-passport-system/src/v2/delegation-v2.ts`'s
 * `validateV2Delegation()` into this file so the conformance suite stays
 * self-contained (same convention as envoys-rfc9421/lib.ts which ports
 * canonicalize() from src/core/canonical.ts).
 *
 * The eventual implementation MUST throw a NegativePathError whose `code`
 * is one of: INVALID_CLAIM_SCOPE, DELEGATION_DEPTH_EXCEEDED,
 * INVALID_SIGNATURE, VALIDITY_EXPIRED.
 */
export function validateNegativePathInput(_input: unknown): void {
  throw new NegativePathError(
    'SCAFFOLD_VALIDATOR_NOT_WIRED',
    'Negative-path validator pending implementation. See ./README.md ' +
      '"Validator wire-up status" section.',
  )
}

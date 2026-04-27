"""APS conformance suite — Python runner (stub).

TODO: Port the TS runner at runners/ts/verify.ts. The Python port should:

1. Read fixtures/manifest.json
2. For each fixture file, run a vendored RFC 8785 JCS canonicalizer over
   each vector's `input`, compute SHA-256 hex, compare to canonical_sha256.
3. For vectors with `ed25519_signature_over_canonical_hex` or
   `ed25519_signature`, verify the signature against the deterministic
   keypair declared in the fixture.
4. Print pass/fail per vector + summary; exit 0 on full pass, 1 otherwise.

Cross-language byte-parity is the success criterion: the TS runner and the
Python runner MUST produce identical canonical bytes and identical SHA-256
hex for every fixture vector. If they diverge, the canonicalizer
implementation has drifted from RFC 8785.

Reference implementation: agent-passport-python/src/agent_passport/canonical/jcs.py
(Python SDK ships its own JCS canonicalizer that this stub will eventually
import, or the conformance suite will vendor a copy here for runtime
independence — same pattern as runners/ts/canonicalize.ts).

Status: stub, not yet implemented. Do not run.
"""

import sys

if __name__ == "__main__":
    print("APS conformance suite Python runner: not yet implemented.")
    print("See runners/ts/verify.ts for the reference implementation.")
    sys.exit(2)

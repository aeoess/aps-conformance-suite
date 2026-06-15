# Vendored fixtures: provenance

These fixtures are external. They are giskard09's, not ours. They are vendored
here unmodified so the SK function-invocation runner can import them without a
network fetch at test time.

Source repository: https://github.com/giskard09/argentum-core
Pinned commit: `b4e03c2ff902069d95ca4901bf74008e3e78fb77`
Fetched: 2026-06-15

Files, with upstream path at the pinned commit:

| Local file | Upstream path |
|---|---|
| `recompute-drift-v1-positive.fixture.json` | `examples/conformance/recompute-drift-v1/recompute-drift-v1-positive.fixture.json` |
| `recompute-drift-v1-negative.fixture.json` | `examples/conformance/recompute-drift-v1/recompute-drift-v1-negative.fixture.json` |
| `near-miss-v1.fixture.json` | `examples/conformance/near-miss-v1/near-miss-v1.fixture.json` |

Classes:
- `recompute-drift-v1-*` is the byte-level handle-correctness class.
- `near-miss-v1` is the issuer-binding and scope-replay class.

To refresh, refetch each path at the pinned commit and replace the file
in place. If the pin changes, update the commit SHA above in the same change.

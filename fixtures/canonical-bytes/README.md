# Canonical-bytes fixtures

Test vectors for the **string-concatenation preimage failure class**: where two semantically different inputs produce identical preimage bytes under naive `field1 + field2 + ...` concatenation, and the same hash, when the canonical-JSON path would distinguish them.

## Layout rationale

This directory is taxonomic-by-failure-class, not source-organization-specific. Future canonical-bytes fixtures from any implementation that hits the same class — APS, AgentGraph CTE, MoltyCel, others — land here under the same `canonical-bytes/` prefix. Filename carries source + version (`canonical-bytes-diff-v032.json`); category does not.

The class itself is documented under "INVALID_COMPOSITION" in the cross-impl conformance taxonomy (A2A#1786 §A): a chain hash fails to bind field boundaries, allowing two different field assignments to share a preimage.

## Fixtures

### `canonical-bytes-diff-v032.json`

**Source:** [corpollc/qntm#15](https://github.com/corpollc/qntm/pull/15) — qntm v0.3.2 canonical-bytes diff fixture for the string-concatenation preimage failure class. Mirrored under the cross-impl reciprocal-reference policy (A2A#1786 §A conformance appendix).

**Upstream verifier:** `specs/test-vectors/verify_canonical_bytes_diff.py` in the qntm repo. Five-check verifier (pre-fix hash, post-fix hash, divergence, collision, canonical immunity).

**Pre-fix sha256 (legacy concat path):** `sha256:53cce2bf015723f6ffe2eb31cccae5de9237c69c4ae49e3900a9295be7d6a332`
**Post-fix sha256 (canonical JSON path):** `sha256:040cfc8c93e252c8f9f524d9f947987a7a1e9bff7fc2952e0aa9ffe553811c69`
**File-level sha256 (byte-parity with qntm source):** `sha256:84df9e0a634eba40f5388872bed4f028a240e0c2f2d646755ecbdfb6b8ee0e42`

**APS-side regression test:** [`runners/ts/canonical-bytes-qntm-v0.3.2.test.ts`](../../runners/ts/canonical-bytes-qntm-v0.3.2.test.ts)

The APS-side test verifies all five checks of the upstream verifier plus a byte-equality assertion that the suite's vendored JCS canonicalizer (`runners/ts/canonicalize.ts`) produces output byte-identical to Python's `json.dumps(sort_keys=True, separators=(",", ":"))` for plain-string field objects. APS bilateral receipt construction (`agent-passport-system` `src/v2/accountability/bilateral.ts`) already uses canonical JSON, not string concatenation, and is therefore on the post-fix side of this diff. The fixture pins that property against regression.

## Cross-validation triangle

This fixture is one node in the three-impl / one-fixture / four-verifier-path conformance pattern documented at A2A#1786 §A:

| Impl | Verifier path |
|---|---|
| qntm (source) | Python `verify_canonical_bytes_diff.py` (`json.dumps`, `sort_keys=True`) |
| APS (this repo) | TypeScript `canonical-bytes-qntm-v0.3.2.test.ts` (vendored JCS canonicalizer) |
| AgentGraph (CTE) | CTE byte-parity vectors at `cross-impl-receipts/ctef-vectors.json` test the same canonical-JSON property at the bilateral-receipt layer |
| Future third-party impl | Imports either the upstream Python verifier or this TS test through the suite |

A change to either the canonical-JSON output or the legacy-concat preimage shape on any one impl would surface as a divergence here.

## Running

```bash
npm run test:canonical-bytes
```

Or via the full suite:

```bash
npm test
```

## Reciprocal pointer

This fixture closes the mirror commitment posted at [corpollc/qntm#15 (issuecomment-4376765242)](https://github.com/corpollc/qntm/pull/15#issuecomment-4376765242). The reciprocal pointer in qntm's repo references this directory.

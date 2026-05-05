# aps-conformance-suite

Cross-implementation test corpus for the **Agent Passport System (APS)** protocol. Byte-identical JCS canonicalization fixtures, deterministic Ed25519 signatures, OWASP AIVSS §3.6 scenario fixtures, and InstructionProvenanceReceipt vectors. Apache-2.0.

> **Status:** v0.1.0 (internal preview, pending external partner integration).

## What this suite is

A packaged corpus of test vectors that any APS-compatible implementation can run to verify it agrees, byte-for-byte, with the canonical APS reference. Four fixture categories cover the major spec surfaces:

- **bilateral-delegation** — JCS canonicalization (RFC 8785) vectors used in bilateral delegation receipts. 10 vectors, deterministic seed `aps-canonicalize-fixture-v1`.
- **inference-session** — CTEF v0.3.1 cryptographic agent identity vectors (validity windows, sequence bounds). 7 vectors, deterministic seed `ctef-synthetic-fixture-v1`.
- **instruction-provenance** — InstructionProvenanceReceipt v0.2 envelope, path canonicalization, exhaustiveness, action-time recompute. 10 vectors (6 positive + 4 negative), deterministic seed `aps-instruction-provenance-fixture-v1`.
- **aivss-scenarios** — AIVSS §3.6 worked scenarios (OWASP AAI001–AAI010) with CVSS+AIVSS scoring and APS-primitive mappings. 10 scenarios, structural fixtures.

A `.well-known/aps-test-vectors.json` mirrors the agentgraph.co `.well-known` shape for the canonical reference subset.

## What this suite isn't

- **Not a normative spec.** The spec lives in the seven APS papers (Zenodo) and the IETF Internet-Draft `draft-pidlisnyi-aps-00`. This suite is the conformance corpus that says "does your implementation match the canonical reference at the byte level."
- **Not the live test suite.** For full APS adversarial testing, run `agent-passport-system` `npm test` upstream. This suite extracts the byte-canonical reference set; it does not replace dynamic test execution.
- **Not a validator.** The runner verifies your canonicalizer against the corpus. It does not validate that your implementation's API surface matches APS — that's an integration question, not a canonicalization one.

## Running the TS runner

```bash
cd runners/ts
npm install
npm run verify
```

Or from the repo root:

```bash
npm install
npx tsx runners/ts/verify.ts
```

The runner ships a vendored RFC 8785 JCS canonicalizer in `runners/ts/canonicalize.ts` so external implementations can run it standalone — **no dependency on `agent-passport-system` at runtime**. Implementations under test bring their own canonicalizer; this runner verifies the corpus against the reference.

Output: pass/fail per vector + per-category summary. Exit code 0 on full pass, 1 on any failure.

A Python runner stub lives at `runners/python/verify.py`. Full Python port is a follow-up task.

## Repository layout

```
aps-conformance-suite/
├── README.md                          (this file)
├── LICENSE                            (Apache-2.0)
├── package.json
├── tsconfig.json
├── fixtures/
│   ├── manifest.json                  (top-level index of all fixtures with sha256)
│   ├── bilateral-delegation/          (10 vectors)
│   ├── inference-session/             (7 vectors)
│   ├── instruction-provenance/        (10 vectors)
│   └── aivss-scenarios/               (10 scenario files + manifest)
├── runners/
│   ├── ts/                            (TypeScript reference runner)
│   └── python/                        (Python runner stub)
├── docs/
│   ├── fixture-format.md
│   ├── canonicalization.md
│   └── adding-vectors.md
└── well-known/
    └── aps-test-vectors.json          (canonical reference subset)
```

## Cross-validation triangle (CTEF v0.3.2 §A-aligned)

Three independent implementations (ArkForge / APS / AgentGraph) verify the same canonical-bytes fixture set through four verifier code paths. Any third party resolving any one of the three repos arrives at byte-identical canonical envelopes — the conformance bar is reproducibility-without-maintainer-rerun, not the count of byte-matches.

| Implementation | Repo | Fixture path / harness URL | Verifier |
|---|---|---|---|
| **APS** | [`aeoess/aps-conformance-suite`](https://github.com/aeoess/aps-conformance-suite) | `cross-impl-receipts/` (this repo) + `fixtures/bilateral-delegation/canonicalize-fixture-v1.json` (upstream) | `runners/ts/verify.ts` (this repo) + Nobulex `scripts/verify-aps-byte-match.mjs` mirrored byte-exact at [`cross-impl-receipts/`](./cross-impl-receipts/) |
| **ArkForge** | [`corpollc/qntm`](https://github.com/corpollc/qntm) | `specs/test-vectors/` + production-derived `canonical-bytes-diff-v032.json` (qntm#15) | TODO — finalize when CTEF v0.3.2 §A draft names ArkForge's verifier code path |
| **AgentGraph** | [`agentgraph-co/agentgraph`](https://github.com/agentgraph-co/agentgraph) (frozen at `69ad94d`) | [`https://agentgraph.co/.well-known/interop-harness.json`](https://agentgraph.co/.well-known/interop-harness.json) `cross_validation_receipts` block | Nobulex `scripts/verify-ctef-byte-match.mjs` against CTEF v0.3.1 inline vectors (4/4 incl. negative-path `INVALID_CLAIM_SCOPE` + `INVALID_COMPOSITION`) — named normatively in CTEF v0.3.2 §A draft as one of the two reader-runnable verifier scripts |

### Three SHA-256 commitments

The byte-faithful mirrored receipts in [`cross-impl-receipts/`](./cross-impl-receipts/) carry the following SHA-256 hashes (frozen at `arian-gogani/nobulex@d68fcee`, fetched 2026-05-02T00:18:49Z):

| File | SHA-256 |
|---|---|
| `cross-impl-receipts/aps-byte-match-receipt.json`  | `a4d63359574a7408cac8dd3c132586cff611535c4c8f074ed3556a61cf165443` |
| `cross-impl-receipts/ctef-byte-match-receipt.json` | `2e8afc85080ed64fe539c913410f2343d10cba8c5b17f61cc8a7d19e4fa11216` |
| `cross-impl-receipts/ctef-vectors.json`            | `b655d1b3e7aeccb8b75517c1efc46d2dbf6759dea07581a1b39d4ab59baa7046` |

### Reciprocal pointer — AgentGraph harness aggregator

The same three SHA-256s are surfaced by AgentGraph at [`https://agentgraph.co/.well-known/interop-harness.json`](https://agentgraph.co/.well-known/interop-harness.json) under the `cross_validation_receipts.receipt_sources.mirror.files_pinned_2026_05_02` block, with `source_commit` pinned to `arian-gogani/nobulex@d68fcee`. Reviewers can pull receipt artifacts from either [`arian-gogani/nobulex`](https://github.com/arian-gogani/nobulex) (originating) or this mirror and reproduce the byte-match independently — the maintainer-rerun-dependency gap is closed.

### Forward pointer

CTEF v0.3.2 §A "Conformance Appendix" was drafted by [@kenneives](https://github.com/kenneives) on 2026-05-04 in [A2A#1786 comment](https://github.com/a2aproject/A2A/issues/1786#issuecomment-4373904351). The §A normative text adopts:

> Implementations claiming CTEF v0.3.2 conformance MUST demonstrate byte-match reproduction against the inline-vector set. Two reader-runnable verifier scripts are published under stable URLs as the canonical reproduction reference: `scripts/verify-aps-byte-match.mjs` (10/10 against the APS bilateral-delegation fixture) and `scripts/verify-ctef-byte-match.mjs` (4/4 against the CTEF inline vectors INCLUDING both negative-path vectors). The two scripts are maintained at `arian-gogani/nobulex` (originating verifier) and mirrored byte-exact at `aeoess/aps-conformance-suite/cross-impl-receipts/` with daily-poll synchronization. The harness aggregator at `https://agentgraph.co/.well-known/interop-harness.json` `cross_validation_receipts` block surfaces both source URLs with SHA-256 pins of the receipt artifacts. Reviewers verifying conformance MUST be able to reproduce byte-match without contacting the implementation maintainer.

Target publish for the v0.3.2 spec (which will normative-cite this section): mid-May 2026, post-launch. The ArkForge row TODO will firm up if the v0.3.2 spec text or a follow-up §A revision normatively enumerates an ArkForge-specific verifier code path; until then ArkForge's role is captured in the May 4 18:41 components plan ("cross-validated against APS depth-walker code path") rather than in the §A normative draft itself.

---

## Adoption

This suite is the **reference test corpus for the Agent Passport System protocol**. External implementations of APS-compatible delegation chains, decision receipts, instruction-provenance receipts, and adversarial scenarios are encouraged to validate against these fixtures.

Cross-implementation byte-parity is the contract: an implementation passes when every fixture vector's recomputed `canonical_bytes_hex` and `canonical_sha256` match the published values, and every Ed25519 signature verifies against the deterministic keypair.

## Adding new vectors

See `docs/adding-vectors.md`. Vectors are added upstream first, then copied here.

## Citation

This suite is the conformance reference for the protocol described in:

- *The Agent Social Contract* — https://doi.org/10.5281/zenodo.18749779
- *Monotonic Narrowing* — https://doi.org/10.5281/zenodo.18932404
- *Faceted Authority Attenuation* — https://doi.org/10.5281/zenodo.19260073
- *Behavioral Derivation Rights* — https://doi.org/10.5281/zenodo.19476002
- *Physics-Enforced Delegation* — https://doi.org/10.5281/zenodo.19478584
- *Governance in the Medium* — https://doi.org/10.5281/zenodo.19582550
- *Cognitive Attestation* — https://doi.org/10.5281/zenodo.19646276
- IETF Internet-Draft: `draft-pidlisnyi-aps-00`

AIVSS scenario fixtures cite: *AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8* (OWASP, accessed 2026-04-26).

## Related

- **Agent Passport System SDK** — https://github.com/aeoess/agent-passport-system
- **Agent Governance Vocabulary** — https://github.com/aeoess/agent-governance-vocabulary
- **AEOESS** — https://aeoess.com
- **InstructionProvenanceReceipt v0.2 spec** — `agent-passport-system/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md`

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.

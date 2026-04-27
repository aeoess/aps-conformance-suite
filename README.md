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

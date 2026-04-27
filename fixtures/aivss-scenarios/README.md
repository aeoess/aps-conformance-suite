# AIVSS §3.6 Scenario Fixtures

OWASP-canonical adversarial scenarios from the AIVSS scoring system, mapped
to APS protocol primitives. Each scenario carries:

- `scenario_id` — AIVSS section number (`AIVSS-3.6.N`)
- `owasp_risk` — OWASP Agentic AI Core risk identifier
- `cvss_base` — CVSS 4.0 base score
- `aars_uplift` — AARS factor uplift on top of CVSS
- `aivss_score` — combined AIVSS score
- `aps_primitive_exercised` — the APS function name that catches this scenario
- `expected_outcome` — what the primitive must do (block, refuse, throw)

## Source

OWASP/agent-security/AIVSS *Scoring System For OWASP Agentic AI Core
Security Risks v0.8* (PDF), §3.6 worked scenarios. Public review draft of
v1 ongoing as of 2026-04. Accessed 2026-04-26.

The scenario implementations and AARS factors are also encoded as live tests
in `agent-passport-system/tests/adversarial.ts` (commit `883f1b65`).

## Files

| File | Risk | AIVSS | Primitive |
|---|---|---|---|
| `3.6.1-tool-misuse.json` | AAI001 Agentic AI Tool Misuse | 9.9 | `createReceipt` scope check |
| `3.6.2-access-control-violation.json` | AAI002 Agent Access Control Violation | 9.7 | `verifyDelegation` TTL |
| `3.6.3-cascading-failures.json` | AAI003 Agent Cascading Failures | 9.4 | `verifyDelegation` cached revocation |
| `3.6.4-multi-agent-exploitation.json` | AAI004 Multi-Agent Exploitation | 10.0 | `subDelegate` monotonic narrowing |
| `3.6.5-identity-impersonation.json` | AAI005 Agent Identity Impersonation | 9.3 | `verifyDelegation` Ed25519 signature |
| `3.6.6-memory-manipulation.json` | AAI006 Agent Memory and Context Manipulation | 8.9 | `verifyReceipt` payload integrity |
| `3.6.7-critical-systems-interaction.json` | AAI007 Insecure Critical Systems Interaction | 9.2 | `createReceipt` scope check |
| `3.6.8-supply-chain.json` | AAI008 Agent Supply Chain and Dependency Risk | 9.7 | `computeDelegationChainRoot` |
| `3.6.9-untraceability.json` | AAI009 Agent Untraceability | 8.3 | `buildMerkleRoot` + `generateMerkleProof` |
| `3.6.10-goal-manipulation.json` | AAI010 Agent Goal and Instruction Manipulation | 7.1 | `createReceipt` scope check (drift bound at boundary; semantic-drift detection out of scope, see InstructionProvenanceReceipt v0.2) |

## Limitations

These fixtures encode the structural-test inputs — they are NOT a substitute
for running the live adversarial test suite at
`agent-passport-system/tests/adversarial.ts`. The tests embed Ed25519
keypair generation and dynamic delegation construction, which means each
test run produces fresh cryptographic material. The fixtures here serve as
the citable canonical scenario list with their AIVSS scoring, expected
outcome semantics, and APS primitive mapping.

For byte-identical cross-implementation conformance, see the
`bilateral-delegation/` and `inference-session/` fixture sets which use
deterministic seeds.

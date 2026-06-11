# Field mapping: nobulex bilateral-receipt v0 vectors

Provenance for `vectors.json` is in `SOURCE.md`. Recomputation is in
`run.mjs`, with machine-readable output in `results.json`.

## The three forms in play

1. **External correlation form** (`action-ref-v1-jcs-sha256`):
   snake_case preimage `{action_type, agent_id, scope, timestamp}`.
   `timestamp` is an RFC 3339 UTC string with exactly three fractional
   digits, matching `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`.
   Digest: RFC 8785 JCS canonicalization, then SHA-256, lowercase hex.
   Implemented by `computeExternalActionRefV1` in the agent-passport-system
   SDK (`dist/src/core/external-action-ref.js`).

2. **APS-native `action_ref`** (draft-pidlisnyi-aps §4.1): camelCase preimage
   keys `{agentId, actionType, scopeRequired, timestamp}`. `scopeRequired`
   is a multi-scope array, `timestamp` is second-precision ISO 8601. This is
   a distinct primitive with an intentionally different preimage. None of
   the nobulex vectors are in this form, so no APS-native digests appear
   below; the column exists in the per-field tables only to mark where each
   field would land.

3. **nobulex integer-epoch profile**: snake_case preimage
   `{action_type, agent_id, scope, timestamp_ms}` where `timestamp_ms` is an
   integer millisecond Unix epoch. Same JCS-then-SHA-256 discipline, but the
   timestamp field name and type differ from the external correlation form.

All four vectors in this fixture use profile 3. The digests therefore do not
byte-match the external string-timestamp form, and they are not supposed to.
That is the two-profile split: the same instant, two different canonical
preimages, two different digests. Each vector below shows both digests side
by side. Our stdlib recompute of each vector's own preimage reproduced the
vector's `expected_action_ref` in all four cases, so the divergence is
attributable to the profile difference alone, not to a canonicalization or
hashing disagreement.

## Per-vector mapping

### 0001-baseline-allow

| Preimage field | Value | Form it belongs to | External-form counterpart | APS-native counterpart |
| --- | --- | --- | --- | --- |
| `action_type` | `"send_email"` | shared snake_case (external form and nobulex profile) | `action_type` (same) | `actionType` |
| `agent_id` | `"nobulex-test-agent"` | shared snake_case (external form and nobulex profile) | `agent_id` (same) | `agentId` |
| `scope` | `"user@example.com"` | single string (external form and nobulex profile) | `scope` (same) | `scopeRequired` (would become a one-element array) |
| `timestamp_ms` | `1748000000000` | nobulex integer-epoch profile only | `timestamp: "2025-05-23T11:33:20.000Z"` | `timestamp` (second-precision ISO 8601) |

Two-profile split (integer-epoch preimage, no byte-match expected):

| Profile | Digest |
| --- | --- |
| Their integer-epoch digest (`expected_action_ref`, reproduced by stdlib recompute) | `86bdb19ed2ee90065ca9fbeaf597075ea03abab6ff01027d457239b9c7c5809b` |
| String-timestamp profile for the equivalent instant (SDK `computeExternalActionRefV1`) | `a5f9e95b08bdad7304bf68e13372089a74497fab6d4c67617a2887699a2538e1` |

The vector also carries `expected_canonical_preimage`; our minimal JCS
canonicalization reproduced it byte for byte.

### 0002-deny-receipt

| Preimage field | Value | Form it belongs to | External-form counterpart | APS-native counterpart |
| --- | --- | --- | --- | --- |
| `action_type` | `"delete_database"` | shared snake_case | `action_type` (same) | `actionType` |
| `agent_id` | `"nobulex-test-agent"` | shared snake_case | `agent_id` (same) | `agentId` |
| `scope` | `"production"` | single string | `scope` (same) | `scopeRequired` (one-element array) |
| `timestamp_ms` | `1748000001000` | nobulex integer-epoch profile only | `timestamp: "2025-05-23T11:33:21.000Z"` | `timestamp` (second-precision ISO 8601) |

Two-profile split:

| Profile | Digest |
| --- | --- |
| Their integer-epoch digest (reproduced by stdlib recompute) | `ae036c69337e09fcaab63d3ebc77e9a1d80a1f019a830815890c43bf1bd79d4f` |
| String-timestamp profile, equivalent instant (SDK) | `7c3198c983ee49225a37eb149761a9bdd4f0e901288b1e836adcbdc378d3de6e` |

The `verdict: "DENY"` field sits outside the digest preimage in their shape
and has no counterpart in either action_ref form.

### 0003-with-policy-version

| Preimage field | Value | Form it belongs to | External-form counterpart | APS-native counterpart |
| --- | --- | --- | --- | --- |
| `action_type` | `"transfer_funds"` | shared snake_case | `action_type` (same) | `actionType` |
| `agent_id` | `"nobulex-test-agent"` | shared snake_case | `agent_id` (same) | `agentId` |
| `scope` | `"100_USDC"` | single string | `scope` (same) | `scopeRequired` (one-element array) |
| `timestamp_ms` | `1748000002000` | nobulex integer-epoch profile only | `timestamp: "2025-05-23T11:33:22.000Z"` | `timestamp` (second-precision ISO 8601) |

Two-profile split:

| Profile | Digest |
| --- | --- |
| Their integer-epoch digest (reproduced by stdlib recompute) | `dd0a1ec0afdcdfd4be7eb45404449ecdb7f697b01d707a06a32305fc05fadf75` |
| String-timestamp profile, equivalent instant (SDK) | `85e5fd4b6960626f7e08463432999790cc8828b7349d80b793e15461bcfc6d80` |

`policy_version` (`"risk-policy-v2.1"`) is envelope metadata in their shape,
outside the digest preimage, with no counterpart in either action_ref form.

### 0004-issued-valid-executed-revoked

| Preimage field | Value | Form it belongs to | External-form counterpart | APS-native counterpart |
| --- | --- | --- | --- | --- |
| `action_type` | `"transfer_funds"` | shared snake_case | `action_type` (same) | `actionType` |
| `agent_id` | `"nobulex-test-agent"` | shared snake_case | `agent_id` (same) | `agentId` |
| `scope` | `"500_USDC_to_vendor"` | single string | `scope` (same) | `scopeRequired` (one-element array) |
| `timestamp_ms` | `1748000003000` | nobulex integer-epoch profile only | `timestamp: "2025-05-23T11:33:23.000Z"` | `timestamp` (second-precision ISO 8601) |

Two-profile split:

| Profile | Digest |
| --- | --- |
| Their integer-epoch digest (reproduced by stdlib recompute) | `57c4990825b8be98f326acf8065a43280f51e2c6727ffd9bdb14c62eff6985da` |
| String-timestamp profile, equivalent instant (SDK) | `cf92f7264d00fd8f368f87509a66b947054a7d5c8f6d238d41c7e35cbae152c8` |

`verdict`, `policy_version`, `authority_verified_at_ms`,
`revocation_check_at_ms`, and `revocation_status` are envelope metadata in
their dual-timestamp scenario, outside the digest preimage, with no
counterpart in either action_ref form.

## Recomputation results

Produced by `node run.mjs` (Node v24, SDK build of 2026-06-10). Exit code 0.
Full machine-readable output is in `results.json`.

| vector id | profile | their digest | stdlib recompute (their profile) | SDK string-profile digest | status |
| --- | --- | --- | --- | --- | --- |
| 0001-baseline-allow | integer-epoch (timestamp_ms) | `86bdb19ed2ee90065ca9fbeaf597075ea03abab6ff01027d457239b9c7c5809b` | `86bdb19ed2ee90065ca9fbeaf597075ea03abab6ff01027d457239b9c7c5809b` | `a5f9e95b08bdad7304bf68e13372089a74497fab6d4c67617a2887699a2538e1` | DIVERGE(two-profile) |
| 0002-deny-receipt | integer-epoch (timestamp_ms) | `ae036c69337e09fcaab63d3ebc77e9a1d80a1f019a830815890c43bf1bd79d4f` | `ae036c69337e09fcaab63d3ebc77e9a1d80a1f019a830815890c43bf1bd79d4f` | `7c3198c983ee49225a37eb149761a9bdd4f0e901288b1e836adcbdc378d3de6e` | DIVERGE(two-profile) |
| 0003-with-policy-version | integer-epoch (timestamp_ms) | `dd0a1ec0afdcdfd4be7eb45404449ecdb7f697b01d707a06a32305fc05fadf75` | `dd0a1ec0afdcdfd4be7eb45404449ecdb7f697b01d707a06a32305fc05fadf75` | `85e5fd4b6960626f7e08463432999790cc8828b7349d80b793e15461bcfc6d80` | DIVERGE(two-profile) |
| 0004-issued-valid-executed-revoked | integer-epoch (timestamp_ms) | `57c4990825b8be98f326acf8065a43280f51e2c6727ffd9bdb14c62eff6985da` | `57c4990825b8be98f326acf8065a43280f51e2c6727ffd9bdb14c62eff6985da` | `cf92f7264d00fd8f368f87509a66b947054a7d5c8f6d238d41c7e35cbae152c8` | DIVERGE(two-profile) |

Summary: 0 MATCH, 4 DIVERGE(two-profile), 0 MISMATCH. All four expected
digests were reproduced from the vectors' own preimages by the stdlib-only
recompute, so the canonicalization and hashing discipline is shared and the
only divergence is the timestamp profile (integer `timestamp_ms` versus the
RFC 3339 string `timestamp`). Behavior described here is specified, tested,
and validated against these four vectors only.

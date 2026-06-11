// Recomputation runner for the action-ref-v1 recompute-negative vectors.
// See SOURCE.md for provenance and README.md for the drift-family map.
//
// Property under test: a verifier recomputes action_ref from the invocation
// payload's tuple and MUST fail closed, before invocation, when the claimed
// action_ref does not match. It never retries alternative preimages, never
// coerces, never normalizes to force a match.
//
// Two independent recomputation paths:
//   1. stdlib-only: node:crypto SHA-256 over a minimal RFC 8785 (JCS)
//      canonicalization for a flat four-string object.
//   2. SDK: the shipping computeExternalActionRefV1 from the
//      agent-passport-system build. Its grammar gate rejects non-canonical
//      timestamp forms by throwing.
//
// Positives must recompute byte-identical on both paths. Negatives must be
// grammar-rejected or digest-mismatched on both paths; the verifier verdict
// comes from a single canonical recomputation with NO fallback recompute
// over any drifted serialization. The fixture-integrity block recomputes
// the drifted digests only to check the fixture data itself; its results
// never feed the verifier verdict.
//
// Usage: node run.mjs
//   Optional: APS_SDK_EXTERNAL_ACTION_REF=/abs/path/to/external-action-ref.js
// Exits 0 when every positive is MATCH and every negative is FAIL-CLOSED
// with the expected failure stage. Exits 1 otherwise.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const here = new URL('.', import.meta.url);
const sdkModuleUrl =
  process.env.APS_SDK_EXTERNAL_ACTION_REF
    ? new URL(`file://${process.env.APS_SDK_EXTERNAL_ACTION_REF}`)
    : new URL(
        '../../../../agent-passport-system/dist/src/core/external-action-ref.js',
        import.meta.url,
      );
const { computeExternalActionRefV1 } = await import(sdkModuleUrl.href);

// Minimal RFC 8785 (JCS) canonicalization for flat objects whose values are
// strings or safe integers. Key order is lexicographic by UTF-16 code unit,
// which for these ASCII keys matches the RFC 8785 sort. Strings serialize
// via JSON.stringify per the ECMA-262 rules RFC 8785 references.
function jcsFlat(obj) {
  const parts = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${jcsValue(obj[k])}`);
  return `{${parts.join(',')}}`;
}

function jcsValue(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' && Number.isSafeInteger(v)) return String(v);
  throw new Error(`jcsFlat: unsupported value type for ${JSON.stringify(v)}`);
}

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

// Canonical external timestamp grammar: RFC 3339 UTC, exactly three
// fractional digits, mandatory Z.
const CANONICAL_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// The verifier under test. Single path: grammar gate, one canonical
// recomputation, one comparison. No retries, no coercion, no normalization.
function verifyClaim(payload, claimedActionRef) {
  for (const field of ['action_type', 'agent_id', 'scope', 'timestamp']) {
    if (!Object.hasOwn(payload, field)) {
      return { ok: false, stage: 'grammar', reason: `missing required field: ${field}` };
    }
  }
  const ts = payload.timestamp;
  if (typeof ts !== 'string' || !CANONICAL_TS.test(ts)) {
    return { ok: false, stage: 'grammar', reason: 'timestamp grammar rejected' };
  }
  const recomputed = sha256hex(jcsFlat(payload));
  if (recomputed !== claimedActionRef) {
    return { ok: false, stage: 'recompute', reason: 'recomputed action_ref does not match claim', recomputed };
  }
  return { ok: true, stage: 'recompute', reason: 'match', recomputed };
}

// SDK path for the same payload: throws on grammar violation.
function sdkDigest(payload) {
  try {
    return {
      digest: computeExternalActionRefV1({
        agentId: payload.agent_id,
        actionType: payload.action_type,
        scope: payload.scope,
        timestamp: payload.timestamp,
      }),
      threw: false,
    };
  } catch {
    return { digest: null, threw: true };
  }
}

const fixture = JSON.parse(readFileSync(new URL('vectors.json', here), 'utf8'));

const rows = [];
let failures = 0;

// ---- positives: both paths must reproduce the expected digest ----
for (const v of fixture.positive_fixture.vectors) {
  const verdict = verifyClaim(v.preimage, v.action_ref);
  const sdk = sdkDigest(v.preimage);
  const ok = verdict.ok && !sdk.threw && sdk.digest === v.action_ref;
  if (!ok) failures += 1;
  rows.push({
    id: v.id,
    kind: 'positive',
    expected: v.action_ref,
    stdlibDigest: verdict.recomputed ?? null,
    sdkDigest: sdk.digest,
    status: ok ? 'MATCH' : 'MISMATCH',
  });
}

// ---- negatives: verdict must be failure at the expected stage, both paths ----
const stageMap = { grammar_reject: 'grammar', recompute_mismatch: 'recompute' };
for (const v of fixture.negative_fixture.vectors) {
  const verdict = verifyClaim(v.invocation_payload, v.claimed_action_ref);
  const sdk = sdkDigest(v.invocation_payload);
  const sdkRejects = sdk.threw || sdk.digest !== v.claimed_action_ref;
  const expectedStage = stageMap[v.expected_failure_stage];
  const ok = !verdict.ok && verdict.stage === expectedStage && sdkRejects;
  if (!ok) failures += 1;
  rows.push({
    id: v.id,
    kind: `negative(${v.failure_mode})`,
    claimed: v.claimed_action_ref,
    stdlibDigest: verdict.recomputed ?? null,
    sdkDigest: sdk.threw ? 'grammar-throw' : sdk.digest,
    failureStage: verdict.stage,
    status: ok ? 'FAIL-CLOSED' : verdict.ok ? 'ACCEPTED(bug)' : 'WRONG-STAGE',
  });
}

// ---- fixture integrity: drifted digests are byte-derived, not invented ----
// Separate from the verifier; never rescues a claim.
for (const v of fixture.negative_fixture.vectors) {
  const drifted = v.drifted_serialization ?? v.drifted_jcs_payload;
  if (!drifted || sha256hex(drifted) !== v.claimed_action_ref) {
    failures += 1;
    rows.push({ id: v.id, kind: 'integrity', status: 'CLAIM-NOT-BYTE-DERIVED' });
  }
  if (v.claimed_action_ref === v.correct_action_ref) {
    failures += 1;
    rows.push({ id: v.id, kind: 'integrity', status: 'DIGEST-COLLISION' });
  }
  const canonicalPayload = v.canonical_form_payload ?? v.invocation_payload;
  if (sha256hex(jcsFlat(canonicalPayload)) !== v.correct_action_ref) {
    failures += 1;
    rows.push({ id: v.id, kind: 'integrity', status: 'CORRECT-REF-STALE' });
  }
}

// Print the per-vector table.
const header = ['vector id', 'kind', 'stdlib digest', 'SDK digest', 'status'];
const tableRows = rows.map((r) => [
  r.id,
  r.kind,
  (r.stdlibDigest ?? '-').slice(0, 16),
  (r.sdkDigest ?? '-').slice(0, 16),
  r.status,
]);
const widths = header.map((h, i) =>
  Math.max(h.length, ...tableRows.map((row) => String(row[i]).length)),
);
const fmt = (row) => row.map((c, i) => String(c).padEnd(widths[i])).join('  ');
console.log(fmt(header));
console.log(widths.map((w) => '-'.repeat(w)).join('  '));
for (const row of tableRows) console.log(fmt(row));

const results = {
  fixture: 'fixtures/cross-stack/action-ref-v1-negatives/vectors.json',
  source: 'authored for argentum-core examples/conformance conventions; mirrors local branch fixtures/action-ref-v1-recompute @ 43223a658b6805c68a679f258a1dfb1a16964338 (local clone only, not pushed; see SOURCE.md)',
  sdk_module: 'agent-passport-system dist/src/core/external-action-ref.js (computeExternalActionRefV1)',
  ran_at: new Date().toISOString(),
  failures,
  vectors: rows,
};
writeFileSync(new URL('results.json', here), JSON.stringify(results, null, 2) + '\n');

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log(
  `\nAll vectors accounted for: ${fixture.positive_fixture.vectors.length} positives recomputed byte-identical on both paths, ` +
  `${fixture.negative_fixture.vectors.length} negatives failed closed at the expected stage.`,
);

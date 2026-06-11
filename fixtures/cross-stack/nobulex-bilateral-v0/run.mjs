// Recomputation runner for the nobulex bilateral-receipt v0 vectors.
// See SOURCE.md for provenance and MAPPING.md for the field mapping.
//
// Two independent recomputations per vector:
//   1. stdlib-only: node:crypto SHA-256 over a minimal RFC 8785 (JCS)
//      canonicalization for flat objects, applied to the vector's own
//      preimage fields verbatim (nobulex integer-epoch profile).
//   2. SDK: the shipping computeExternalActionRefV1 from the
//      agent-passport-system build, applied to the equivalent instant
//      rendered as the external string-timestamp form
//      (RFC 3339 UTC, exactly three fractional digits, Z suffix).
//
// Where a vector uses the integer-epoch preimage, the two digests are not
// expected to byte-match. That divergence is recorded as DIVERGE(two-profile)
// and is the documented two-profile split, not a failure. A failure is when
// the stdlib recompute of a vector's own preimage does not reproduce the
// vector's expected_action_ref.
//
// Usage: node run.mjs
//   Optional: APS_SDK_EXTERNAL_ACTION_REF=/abs/path/to/external-action-ref.js
// Exits 0 when every vector is either MATCH or DIVERGE(two-profile) with a
// reproducible expected digest. Exits 1 on any MISMATCH.

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
// strings or safe integers. That is the full value space of these preimages.
// Key order is lexicographic by UTF-16 code unit, which for these ASCII keys
// matches the RFC 8785 sort. Strings serialize via JSON.stringify, which
// follows the ECMA-262 rules RFC 8785 references. Safe integers serialize
// with no fraction and no exponent, matching RFC 8785 number serialization.
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

// Date.prototype.toISOString emits YYYY-MM-DDTHH:MM:SS.mmmZ, which is exactly
// the external profile shape: RFC 3339 UTC, three fractional digits, Z.
const EXTERNAL_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
function msToExternalTimestamp(ms) {
  const iso = new Date(ms).toISOString();
  if (!EXTERNAL_TS.test(iso)) {
    throw new Error(`unexpected ISO shape for ${ms}: ${iso}`);
  }
  return iso;
}

const fixture = JSON.parse(
  readFileSync(new URL('vectors.json', here), 'utf8'),
);

const rows = [];
let failures = 0;

for (const v of fixture.vectors) {
  const p = v.preimage_fields;
  const isIntegerEpoch = Object.hasOwn(p, 'timestamp_ms');
  const profile = isIntegerEpoch
    ? 'integer-epoch (timestamp_ms)'
    : 'string-timestamp';

  // Recompute their digest from their own preimage, stdlib only.
  const canonical = jcsFlat(p);
  const stdlibDigest = sha256hex(canonical);

  if (v.expected_canonical_preimage && v.expected_canonical_preimage !== canonical) {
    failures += 1;
    rows.push({
      id: v.id,
      profile,
      theirDigest: v.expected_action_ref,
      stdlibDigest,
      sdkStringProfileDigest: null,
      status: 'MISMATCH(canonical-preimage)',
    });
    continue;
  }

  // Equivalent instant under the external string-timestamp profile, via the
  // shipping SDK implementation.
  const externalTimestamp = isIntegerEpoch
    ? msToExternalTimestamp(p.timestamp_ms)
    : p.timestamp;
  const sdkStringProfileDigest = computeExternalActionRefV1({
    agentId: p.agent_id,
    actionType: p.action_type,
    scope: p.scope,
    timestamp: externalTimestamp,
  });

  let status;
  if (stdlibDigest !== v.expected_action_ref) {
    status = 'MISMATCH(recompute)';
    failures += 1;
  } else if (isIntegerEpoch) {
    // Expected, documented split: same instant, different preimage profile.
    status = 'DIVERGE(two-profile)';
  } else {
    status =
      sdkStringProfileDigest === v.expected_action_ref
        ? 'MATCH'
        : 'MISMATCH(string-profile)';
    if (status !== 'MATCH') failures += 1;
  }

  rows.push({
    id: v.id,
    profile,
    externalTimestamp,
    theirDigest: v.expected_action_ref,
    stdlibDigest,
    sdkStringProfileDigest,
    status,
  });
}

// Print the per-vector table.
const header = ['vector id', 'profile', 'their digest', 'stdlib recompute (their profile)', 'SDK string-profile digest', 'status'];
const tableRows = rows.map((r) => [
  r.id,
  r.profile,
  r.theirDigest ?? '-',
  r.stdlibDigest ?? '-',
  r.sdkStringProfileDigest ?? '-',
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
  fixture: 'fixtures/cross-stack/nobulex-bilateral-v0/vectors.json',
  source:
    'https://github.com/arian-gogani/nobulex/blob/89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546/fixtures/bilateral-receipt/v0/vectors.json',
  source_commit_sha: '89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546',
  sdk_module: 'agent-passport-system dist/src/core/external-action-ref.js (computeExternalActionRefV1)',
  ran_at: new Date().toISOString(),
  failures,
  vectors: rows,
};
writeFileSync(
  new URL('results.json', here),
  JSON.stringify(results, null, 2) + '\n',
);

if (failures > 0) {
  console.error(`\n${failures} vector(s) failed recomputation.`);
  process.exit(1);
}
console.log('\nAll vectors accounted for: expected digests reproduced; two-profile divergences recorded.');

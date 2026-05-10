// One-shot fixture generator for the envoys-rfc9421 composition. Run as:
//   npx tsx fixtures/composition/envoys-rfc9421/generate.ts
//
// Writes three deterministic fixtures to disk: L1 (per-message RFC 9421
// signature alone), L2 (L1 anchored under an APS bilateral_receipt), and
// L3 (3-link APS delegation chain whose leaf delegatee is the wire-signing
// agent that produced L1). All three derive from seeds and fixed inputs in
// lib.ts. Re-running this script produces byte-identical files; the verifier
// at verify.ts re-derives the same bytes and exits 1 on any mismatch.
//
// L1 pins to jschoemaker's @envoys/sdk v1.4.0 §13 Vector 2 (POST /api/task).
// L2 uses the BilateralReceipt schema at ~/agent-passport-system/src/types/
// bilateral-receipt.ts (no schema fields invented). L3 uses the V2Delegation
// schema at ~/agent-passport-system/src/v2/types.ts with monotonic narrowing
// across the three action_categories sets.

import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  FIXED_AGREED_AT,
  FIXED_COMPLETED_AT,
  FIXED_REQUESTED_AT,
  L1_BODY,
  L1_CREATED,
  L1_KEYID,
  L1_METHOD,
  L1_NONCE,
  L1_PATH,
  L2_RECEIPT_ID,
  L3_LEAF_DELEGATION_ID,
  L3_MIDDLE_DELEGATION_ID,
  L3_ROOT_DELEGATION_ID,
  POLICY_CTX_CREATED_AT,
  POLICY_CTX_VALID_FROM,
  POLICY_CTX_VALID_UNTIL,
  SEED_CHAIN_LEAF_HEX,
  SEED_CHAIN_MIDDLE_HEX,
  SEED_CHAIN_ROOT_HEX,
  SEED_SERVING_HEX,
  SEED_WIRE_AGENT_HEX,
  canonicalize,
  l1ContentDigest,
  l1SignatureBase,
  l1SignatureHeader,
  l1SignatureInputHeader,
  l1SignatureValueBase64,
  pubKeyHexFromSeedHex,
  sha256Hex,
  signCanonicalStringHex,
  signObjectHex,
} from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

function writeJSON(name: string, obj: unknown): string {
  const path = join(__dirname, name)
  // Pretty-print with 2-space indent so the committed file is reviewable;
  // verifier re-derives signatures from inputs, not from the file's formatting.
  const text = JSON.stringify(obj, null, 2) + '\n'
  writeFileSync(path, text)
  return path
}

// ─────────────────────────────────────────────────────────────────────────────
// L1 — per-message RFC 9421 signature (jschoemaker v1.4.0 §13 Vector 2)
// ─────────────────────────────────────────────────────────────────────────────

const wireAgentPubHex = pubKeyHexFromSeedHex(SEED_WIRE_AGENT_HEX)
const l1Inputs = {
  method: L1_METHOD,
  path: L1_PATH,
  body: L1_BODY,
  keyid: L1_KEYID,
  created: L1_CREATED,
  nonce: L1_NONCE,
}
const l1SigBase = l1SignatureBase(l1Inputs)
const l1SigB64 = l1SignatureValueBase64(l1SigBase, SEED_WIRE_AGENT_HEX)
const l1SigInputHeader = l1SignatureInputHeader(l1Inputs)
const l1SigHeader = l1SignatureHeader(l1SigB64)
const l1ContentDigestHeader = l1ContentDigest(L1_BODY)

const L1_FIXTURE = {
  layer: 'L1',
  description:
    "Per-message RFC 9421 HTTP Message Signature over jschoemaker's @envoys/sdk v1.4.0 §13 Vector 2 (POST /api/task). Signed with RFC 8032 §7.1 Test 1 Ed25519 keypair. Reproduces the spec's expected Signature header byte-identical.",
  spec_refs: {
    envoys_signature_v140: 'https://github.com/jschoemaker/Envoys-public/blob/main/specs/signature/v1.md',
    envoys_sdk_npm: 'https://www.npmjs.com/package/@envoys/sdk',
    envoys_sdk_version: '0.7.0',
    rfc_9421: 'https://www.rfc-editor.org/rfc/rfc9421',
    rfc_9530_content_digest: 'https://www.rfc-editor.org/rfc/rfc9530',
    rfc_8032_test_vectors: 'https://www.rfc-editor.org/rfc/rfc8032#section-7.1',
    a2a_issue: 'https://github.com/a2aproject/A2A/issues/1829',
  },
  keypair: {
    seed_hex: SEED_WIRE_AGENT_HEX,
    seed_source: 'RFC 8032 §7.1 Test 1',
    public_key_hex: wireAgentPubHex,
  },
  request: {
    method: L1_METHOD,
    path: L1_PATH,
    body: L1_BODY,
    headers: {
      'Content-Digest': l1ContentDigestHeader,
      'Signature-Input': l1SigInputHeader,
      Signature: l1SigHeader,
    },
  },
  covered_components: ['@method', '@path', 'content-digest'],
  signature_params: {
    keyid: L1_KEYID,
    created: L1_CREATED,
    nonce: L1_NONCE,
  },
  signature_base: l1SigBase,
  signature_value_base64: l1SigB64,
  expected_verifier_output: {
    verified: true,
    method: 'POST',
    path: '/api/task',
    covered_components: ['@method', '@path', 'content-digest'],
    keyid_resolution_required: true,
  },
}

writeJSON('L1.fixture.json', L1_FIXTURE)

// ─────────────────────────────────────────────────────────────────────────────
// L2 — L1 wrapped in APS bilateral_receipt envelope
// ─────────────────────────────────────────────────────────────────────────────

const servingAgentPubHex = pubKeyHexFromSeedHex(SEED_SERVING_HEX)
const l1RequestBodyHashHex = sha256Hex(L1_BODY)
const l1ResponseBody = '{"task_id":"t-envoys-rfc9421-l2","status":"accepted"}'
const l1ResponseHashHex = sha256Hex(l1ResponseBody)
const l1SignatureValueHashHex = sha256Hex(l1SigB64)

// BilateralReceipt body. Matches the exact field set on the BilateralReceipt
// interface at ~/agent-passport-system/src/types/bilateral-receipt.ts. No
// fields invented; gatewaySignature and delegationId left absent on purpose
// (this fixture has no gateway witness and the delegation chain is the L3
// concern, not L2's).
const l2Body = {
  receiptId: L2_RECEIPT_ID,
  version: '1.0' as const,
  requestingAgentId: `did:key:z${wireAgentPubHex}`,
  servingAgentId: `did:key:z${servingAgentPubHex}`,
  outcome: {
    toolName: 'envoys.rfc9421.post_task',
    requestHash: l1RequestBodyHashHex,
    responseHash: l1ResponseHashHex,
    status: 'success' as const,
    summary:
      'Wire-signed POST /api/task accepted by serving agent; outcome counter-signed under bilateral receipt envelope.',
  },
  requestedAt: FIXED_REQUESTED_AT,
  completedAt: FIXED_COMPLETED_AT,
  agreedAt: FIXED_AGREED_AT,
  evidenceCommitments: [
    {
      // type follows the open-string convention in EvidenceCommitment; this
      // value names the L1 wire-signature anchor as evidence the bilateral
      // receipt depends on.
      type: 'rfc9421_message_signature',
      credentialHash: l1SignatureValueHashHex,
      committedAt: FIXED_AGREED_AT,
    },
  ],
}

const l2RequestingSig = signCanonicalStringHex(l2Body, SEED_WIRE_AGENT_HEX)
const l2ServingSig = signCanonicalStringHex(l2Body, SEED_SERVING_HEX)

const l2Receipt = {
  ...l2Body,
  requestingAgentSignature: l2RequestingSig,
  servingAgentSignature: l2ServingSig,
}

const L2_FIXTURE = {
  layer: 'L2',
  description:
    'APS bilateral_receipt envelope wrapping the L1 wire signature. Both requesting and serving agents counter-sign the same outcome body. The L1 signature value (base64) is bound into evidenceCommitments[0].credentialHash via SHA-256.',
  binds_to_l1: {
    l1_request_body_sha256_hex: l1RequestBodyHashHex,
    l1_signature_value_sha256_hex: l1SignatureValueHashHex,
  },
  schema_ref:
    '~/agent-passport-system/src/types/bilateral-receipt.ts BilateralReceipt + EvidenceCommitment',
  signing_convention:
    'Both signatures cover the canonical-JSON form of the receipt body (null-stripped, sorted keys) per ~/agent-passport-system/src/core/bilateral-receipt.ts. Signature bytes are returned as hex; canonical form is signed directly (no extra sha256 wrap).',
  keypair_requesting: {
    seed_hex: SEED_WIRE_AGENT_HEX,
    seed_source: 'RFC 8032 §7.1 Test 1 (same as L1)',
    public_key_hex: wireAgentPubHex,
  },
  keypair_serving: {
    seed_hex: SEED_SERVING_HEX,
    seed_source: '32 bytes of 0x01',
    public_key_hex: servingAgentPubHex,
  },
  receipt: l2Receipt,
  canonical_receipt_body: canonicalize(l2Body),
  canonical_receipt_body_sha256_hex: sha256Hex(canonicalize(l2Body)),
  expected_verifier_output: {
    valid: true,
    requestingAgentSignatureValid: true,
    servingAgentSignatureValid: true,
    gatewaySignatureValid: null,
    outcomeConsistent: true,
    timingValid: true,
    errors: [] as string[],
  },
}

writeJSON('L2.fixture.json', L2_FIXTURE)

// ─────────────────────────────────────────────────────────────────────────────
// L3 — 3-link APS delegation chain whose leaf delegatee is the wire-signing
// agent that produced L1. Three signers (root/middle/leaf seeds 0x02/0x03/0x04)
// across three V2Delegation records. Monotonic scope narrowing demonstrated by
// shrinking action_categories at each link.
// ─────────────────────────────────────────────────────────────────────────────

const rootPubHex = pubKeyHexFromSeedHex(SEED_CHAIN_ROOT_HEX)
const middlePubHex = pubKeyHexFromSeedHex(SEED_CHAIN_MIDDLE_HEX)
const leafPubHex = pubKeyHexFromSeedHex(SEED_CHAIN_LEAF_HEX)

const policyContext = {
  policy_version: 'v2',
  values_floor_version: 'v1',
  trust_epoch: 0,
  issuer_id: 'did:aps:envoys-rfc9421-fixture',
  created_at: POLICY_CTX_CREATED_AT,
  valid_from: POLICY_CTX_VALID_FROM,
  valid_until: POLICY_CTX_VALID_UNTIL,
}

function buildDelegation(input: {
  id: string
  delegator: string
  delegatee: string
  scope: {
    action_categories: string[]
    domain?: string
    constraints?: Record<string, string>
  }
  delegatorSeedHex: string
}): Record<string, unknown> {
  // Match the unsigned-data shape that createV2Delegation builds before
  // signObject() runs (see ~/agent-passport-system/src/v2/delegation-v2.ts).
  // Null fields are present here for schema completeness; canonicalize()
  // strips them so they do not contribute to the signed bytes.
  const data: Record<string, unknown> = {
    id: input.id,
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: input.delegator,
    delegatee: input.delegatee,
    scope: input.scope,
    policy_context: policyContext,
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
  const signature = signObjectHex(data, input.delegatorSeedHex)
  return { ...data, signature }
}

// Monotonic narrowing demonstration: each link drops one action category.
// Root grants three; middle two; leaf one. The leaf delegation's scope is the
// scope under which the wire-signing agent acted in L1 (commerce.checkout
// covers the POST /api/task summarize-and-charge flow).
const SCOPE_ROOT = ['commerce.checkout', 'commerce.refund', 'commerce.dispute']
const SCOPE_MIDDLE = ['commerce.checkout', 'commerce.refund']
const SCOPE_LEAF = ['commerce.checkout']

const dRoot = buildDelegation({
  id: L3_ROOT_DELEGATION_ID,
  delegator: `did:key:z${rootPubHex}`,
  delegatee: `did:key:z${middlePubHex}`,
  scope: { action_categories: SCOPE_ROOT, domain: 'commerce' },
  delegatorSeedHex: SEED_CHAIN_ROOT_HEX,
})

const dMiddle = buildDelegation({
  id: L3_MIDDLE_DELEGATION_ID,
  delegator: `did:key:z${middlePubHex}`,
  delegatee: `did:key:z${leafPubHex}`,
  scope: { action_categories: SCOPE_MIDDLE, domain: 'commerce' },
  delegatorSeedHex: SEED_CHAIN_MIDDLE_HEX,
})

const dLeaf = buildDelegation({
  id: L3_LEAF_DELEGATION_ID,
  delegator: `did:key:z${leafPubHex}`,
  delegatee: `did:key:z${wireAgentPubHex}`,
  scope: {
    action_categories: SCOPE_LEAF,
    domain: 'commerce',
    // Binds this leaf delegation to the L2 receipt the wire-signing agent
    // is operating under. constraints values are strings per the schema.
    constraints: { bilateral_receipt_ref: L2_RECEIPT_ID },
  },
  delegatorSeedHex: SEED_CHAIN_LEAF_HEX,
})

const L3_FIXTURE = {
  layer: 'L3',
  description:
    '3-link APS delegation chain whose final delegatee is the wire-signing agent that produced L1 and counter-signed L2. Monotonic narrowing is demonstrated by dropping one action category at each link.',
  binds_to_l2: {
    bilateral_receipt_ref: L2_RECEIPT_ID,
    leaf_delegation_constraint: 'scope.constraints.bilateral_receipt_ref',
  },
  schema_ref: '~/agent-passport-system/src/v2/types.ts V2Delegation + V2ScopeDefinition + PolicyContext',
  signing_convention:
    'Each link signed via signObject() at ~/agent-passport-system/src/v2/bridge.ts: signature = ed25519_sign(seed, utf8(sha256_hex(canonicalize(delegation_minus_signature))))',
  keypair_root: { seed_hex: SEED_CHAIN_ROOT_HEX, seed_source: '32 bytes of 0x02', public_key_hex: rootPubHex },
  keypair_middle: { seed_hex: SEED_CHAIN_MIDDLE_HEX, seed_source: '32 bytes of 0x03', public_key_hex: middlePubHex },
  keypair_leaf: { seed_hex: SEED_CHAIN_LEAF_HEX, seed_source: '32 bytes of 0x04', public_key_hex: leafPubHex },
  final_delegatee_public_key_hex: wireAgentPubHex,
  scopes: {
    root: SCOPE_ROOT,
    middle: SCOPE_MIDDLE,
    leaf: SCOPE_LEAF,
    monotonic_narrowing: 'root ⊇ middle ⊇ leaf (each child is a subset of its parent)',
  },
  policy_context: policyContext,
  chain: [dRoot, dMiddle, dLeaf],
  expected_verifier_output: {
    chain_valid: true,
    links_verified: 3,
    narrowing_holds: true,
    final_delegatee_matches_wire_agent: true,
    leaf_bilateral_receipt_ref: L2_RECEIPT_ID,
  },
}

writeJSON('L3.fixture.json', L3_FIXTURE)

// eslint-disable-next-line no-console
console.log('wrote L1.fixture.json, L2.fixture.json, L3.fixture.json')

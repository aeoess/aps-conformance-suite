// Verifier for the envoys-rfc9421 composition fixture. Run as:
//   npm run verify:envoys-rfc9421
//
// Re-derives every signature in L1.fixture.json / L2.fixture.json /
// L3.fixture.json from the documented seeds and fixed inputs in lib.ts, and
// compares against the committed fixture bytes. Exits 0 on byte-match across
// all three layers, 1 on any mismatch with diff.
//
// Verification covers:
//   L1: RFC 9421 Signature header byte-match against jschoemaker's v1.4.0 §13
//       Vector 2; content-digest match; signature-base reconstruction; live
//       Ed25519 verify against the public key (RFC 8032 §7.1 Test 1).
//   L2: BilateralReceipt body canonical-bytes match; requestingAgentSignature
//       and servingAgentSignature byte-match the seeded re-signs; live verify
//       of both signatures over the canonical-form body.
//   L3: Each of three V2Delegation records signs cleanly under signObject()
//       semantics; per-link signature byte-match; monotonic narrowing across
//       scopes; final delegatee equals the L1 wire-signing agent's pubkey;
//       leaf delegation's scope.constraints.bilateral_receipt_ref equals
//       L2.receiptId.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
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
  SEED_CHAIN_LEAF_HEX,
  SEED_CHAIN_MIDDLE_HEX,
  SEED_CHAIN_ROOT_HEX,
  SEED_SERVING_HEX,
  SEED_WIRE_AGENT_HEX,
  canonicalize,
  ed25519VerifyHexUtf8,
  l1ContentDigest,
  l1SignatureBase,
  l1SignatureHeader,
  l1SignatureInputHeader,
  l1SignatureValueBase64,
  pubKeyHexFromSeedHex,
  sha256Hex,
  signCanonicalStringHex,
  signObjectHex,
  verifyObjectHex,
} from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const HERE = (name: string) => join(__dirname, name)

let failures = 0

function check(label: string, expected: unknown, actual: unknown): void {
  const e = typeof expected === 'string' ? expected : JSON.stringify(expected)
  const a = typeof actual === 'string' ? actual : JSON.stringify(actual)
  if (e === a) {
    console.log(`  PASS  ${label}`)
  } else {
    failures++
    console.log(`  FAIL  ${label}`)
    console.log(`    expected: ${e}`)
    console.log(`    actual:   ${a}`)
  }
}

function checkTrue(label: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  PASS  ${label}`)
  } else {
    failures++
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// L1 — RFC 9421 wire signature
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n== L1: RFC 9421 wire signature ==')
const L1 = JSON.parse(readFileSync(HERE('L1.fixture.json'), 'utf-8'))
const wireAgentPubHex = pubKeyHexFromSeedHex(SEED_WIRE_AGENT_HEX)

const l1Inputs = {
  method: L1_METHOD,
  path: L1_PATH,
  body: L1_BODY,
  keyid: L1_KEYID,
  created: L1_CREATED,
  nonce: L1_NONCE,
}
const reSigBase = l1SignatureBase(l1Inputs)
const reSigB64 = l1SignatureValueBase64(reSigBase, SEED_WIRE_AGENT_HEX)
const reSigInputHeader = l1SignatureInputHeader(l1Inputs)
const reSigHeader = l1SignatureHeader(reSigB64)
const reContentDigest = l1ContentDigest(L1_BODY)

check('public_key_hex matches re-derived', L1.keypair.public_key_hex, wireAgentPubHex)
check('content-digest header byte-match', L1.request.headers['Content-Digest'], reContentDigest)
check('signature-input header byte-match', L1.request.headers['Signature-Input'], reSigInputHeader)
check('signature header byte-match', L1.request.headers['Signature'], reSigHeader)
check('signature-base byte-match', L1.signature_base, reSigBase)
check('signature_value_base64 byte-match', L1.signature_value_base64, reSigB64)
check('signature_value_base64 matches §13 V2 spec', reSigB64,
  'i5tKcOHKhRTCztR2cazuzNAg9rPiRf47MKTOGve92Rs43gNmltuN5LVScedR6C08MGsQykMc7txJ21KCG8SEBQ==')

// Live Ed25519 verify of the wire signature.
const sigHex = Buffer.from(reSigB64, 'base64').toString('hex')
const liveVerify = ed25519VerifyHexUtf8(reSigBase, sigHex, wireAgentPubHex)
checkTrue('ed25519 verify(signature, signature-base, public_key) returns true', liveVerify)

// ─────────────────────────────────────────────────────────────────────────────
// L2 — bilateral_receipt wrap
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n== L2: bilateral_receipt envelope ==')
const L2 = JSON.parse(readFileSync(HERE('L2.fixture.json'), 'utf-8'))
const servingPubHex = pubKeyHexFromSeedHex(SEED_SERVING_HEX)

check('L2.requestingAgentId pubkey matches wire-agent pubkey',
  L2.keypair_requesting.public_key_hex, wireAgentPubHex)
check('L2.servingAgent pubkey matches seed-0x01 derivation',
  L2.keypair_serving.public_key_hex, servingPubHex)
check('L2.receipt.receiptId pinned', L2.receipt.receiptId, L2_RECEIPT_ID)

// Reconstruct receipt body (minus signature fields) and re-sign with each seed.
const { requestingAgentSignature: _r, servingAgentSignature: _s, ...l2Body } = L2.receipt
const reqSigHex = signCanonicalStringHex(l2Body, SEED_WIRE_AGENT_HEX)
const servSigHex = signCanonicalStringHex(l2Body, SEED_SERVING_HEX)
check('requestingAgentSignature byte-match', L2.receipt.requestingAgentSignature, reqSigHex)
check('servingAgentSignature byte-match', L2.receipt.servingAgentSignature, servSigHex)

const reCanonical = canonicalize(l2Body)
check('canonical_receipt_body byte-match', L2.canonical_receipt_body, reCanonical)
check('canonical_receipt_body sha256 byte-match',
  L2.canonical_receipt_body_sha256_hex, sha256Hex(reCanonical))

// Live verify both signatures against the canonical-form body.
const reqVerify = ed25519VerifyHexUtf8(reCanonical, L2.receipt.requestingAgentSignature, wireAgentPubHex)
const servVerify = ed25519VerifyHexUtf8(reCanonical, L2.receipt.servingAgentSignature, servingPubHex)
checkTrue('ed25519 verify of requestingAgentSignature returns true', reqVerify)
checkTrue('ed25519 verify of servingAgentSignature returns true', servVerify)

// L1→L2 binding: the request body hash and the L1 signature value hash
// recorded in L2 must match what L1 actually carries.
check('L2 binds L1 request body hash', L2.binds_to_l1.l1_request_body_sha256_hex, sha256Hex(L1_BODY))
check('L2 binds L1 signature value hash', L2.binds_to_l1.l1_signature_value_sha256_hex,
  sha256Hex(L1.signature_value_base64))
check('L2 evidenceCommitments[0].credentialHash matches L1 sig hash',
  L2.receipt.evidenceCommitments[0].credentialHash, sha256Hex(L1.signature_value_base64))

// ─────────────────────────────────────────────────────────────────────────────
// L3 — 3-link delegation chain
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n== L3: 3-link APS delegation chain ==')
const L3 = JSON.parse(readFileSync(HERE('L3.fixture.json'), 'utf-8'))
const rootPubHex = pubKeyHexFromSeedHex(SEED_CHAIN_ROOT_HEX)
const middlePubHex = pubKeyHexFromSeedHex(SEED_CHAIN_MIDDLE_HEX)
const leafPubHex = pubKeyHexFromSeedHex(SEED_CHAIN_LEAF_HEX)

check('chain root pubkey', L3.keypair_root.public_key_hex, rootPubHex)
check('chain middle pubkey', L3.keypair_middle.public_key_hex, middlePubHex)
check('chain leaf pubkey', L3.keypair_leaf.public_key_hex, leafPubHex)
check('final_delegatee_public_key_hex matches wire-agent pubkey',
  L3.final_delegatee_public_key_hex, wireAgentPubHex)
checkTrue('chain has exactly 3 links', Array.isArray(L3.chain) && L3.chain.length === 3,
  `got ${Array.isArray(L3.chain) ? L3.chain.length : 'not-array'}`)

const [dRoot, dMiddle, dLeaf] = L3.chain as Array<Record<string, unknown>>

// IDs pinned.
check('root delegation id', dRoot.id, L3_ROOT_DELEGATION_ID)
check('middle delegation id', dMiddle.id, L3_MIDDLE_DELEGATION_ID)
check('leaf delegation id', dLeaf.id, L3_LEAF_DELEGATION_ID)

// Re-derive each signature.
function unsignedCopy(d: Record<string, unknown>): Record<string, unknown> {
  const { signature: _sig, ...rest } = d
  return rest
}

const reRootSig = signObjectHex(unsignedCopy(dRoot), SEED_CHAIN_ROOT_HEX)
const reMiddleSig = signObjectHex(unsignedCopy(dMiddle), SEED_CHAIN_MIDDLE_HEX)
const reLeafSig = signObjectHex(unsignedCopy(dLeaf), SEED_CHAIN_LEAF_HEX)

check('root signature byte-match', dRoot.signature, reRootSig)
check('middle signature byte-match', dMiddle.signature, reMiddleSig)
check('leaf signature byte-match', dLeaf.signature, reLeafSig)

// Live verify each signature against its delegator's pubkey, matching
// validateV2Delegation() in ~/agent-passport-system/src/v2/delegation-v2.ts.
checkTrue('verifyObject(root) returns true',
  verifyObjectHex(unsignedCopy(dRoot), dRoot.signature as string, rootPubHex))
checkTrue('verifyObject(middle) returns true',
  verifyObjectHex(unsignedCopy(dMiddle), dMiddle.signature as string, middlePubHex))
checkTrue('verifyObject(leaf) returns true',
  verifyObjectHex(unsignedCopy(dLeaf), dLeaf.signature as string, leafPubHex))

// Monotonic narrowing: each child's action_categories must be a subset of
// its parent's. This is what isScopeNarrowing() at v2/delegation-v2.ts checks.
function isSubset(child: string[], parent: string[]): boolean {
  const ps = new Set(parent)
  for (const c of child) if (!ps.has(c)) return false
  return true
}

const rootCats = (dRoot.scope as { action_categories: string[] }).action_categories
const middleCats = (dMiddle.scope as { action_categories: string[] }).action_categories
const leafCats = (dLeaf.scope as { action_categories: string[] }).action_categories

checkTrue('scope narrows root → middle', isSubset(middleCats, rootCats),
  `middle=${JSON.stringify(middleCats)} root=${JSON.stringify(rootCats)}`)
checkTrue('scope narrows middle → leaf', isSubset(leafCats, middleCats),
  `leaf=${JSON.stringify(leafCats)} middle=${JSON.stringify(middleCats)}`)

// Delegator/delegatee chain integrity: each link's delegatee must equal the
// next link's delegator. Root delegator → ... → leaf delegatee == wire-agent.
check('middle.delegator equals root.delegatee', dMiddle.delegator, dRoot.delegatee)
check('leaf.delegator equals middle.delegatee', dLeaf.delegator, dMiddle.delegatee)
check('leaf.delegatee equals wire-agent did:key',
  dLeaf.delegatee, `did:key:z${wireAgentPubHex}`)

// L2 binding via leaf scope constraints.
const leafScope = dLeaf.scope as { constraints?: Record<string, string> }
check('leaf.scope.constraints.bilateral_receipt_ref equals L2.receiptId',
  leafScope.constraints?.bilateral_receipt_ref, L2_RECEIPT_ID)
check('leaf scope constraint binds the L2 fixture',
  L3.binds_to_l2.bilateral_receipt_ref, L2.receipt.receiptId)

// ─────────────────────────────────────────────────────────────────────────────

console.log('')
if (failures === 0) {
  console.log('envoys-rfc9421 composition: ALL PASS (L1 + L2 + L3 byte-match)')
  process.exit(0)
} else {
  console.log(`envoys-rfc9421 composition: ${failures} FAIL`)
  process.exit(1)
}

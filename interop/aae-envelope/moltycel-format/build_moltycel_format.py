#!/usr/bin/env python3
"""ONE-TIME cross-encoding: APS's four canonical AAE-envelope vectors (V1-V4)
re-expressed in MoltyCel's published signed-JWS conformance-vector format
(draft-kroehl-agentic-trust-aae-00).

APS's canonical vectors at interop/aae-envelope/V*.json remain the source of
truth. The files this script emits are a one-time alignment artifact to show the
two implementations agree on the four overlapping scenarios; they are NOT a
maintained parallel set.

Signing reuses MoltyCel's committed PUBLIC test keys (testkeys/) and their
sign_jws construction, so the JWS verify under examples/python-verify.py with
their offline DID documents. Re-run is deterministic given the same keys.

Requires the MoltyCel repo clone (default /tmp/aae-moltycel, override with
AAE_MOLTYCEL_REPO). Run: python3 build_moltycel_format.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MOLTYCEL = os.environ.get("AAE_MOLTYCEL_REPO", "/tmp/aae-moltycel")
TESTKEYS = os.path.join(MOLTYCEL, "testkeys")
OUT = os.path.dirname(os.path.abspath(__file__))

REGISTRY = "did:web:example.com:registry"
AGENT_A = "did:web:example.com:agent-a"
AGENT_B = "did:web:example.com:agent-b"
PRINCIPAL = "did:web:example.com:enterprise-corp"

CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://moltrust.ch/contexts/aae/v1",
]
VC_TYPE = ["VerifiableCredential", "AgentAuthorizationEnvelope"]

NB = "2026-05-20T08:00:00Z"
NA = "2026-05-20T16:00:00Z"
NOON = "2026-05-20T12:00:00Z"
NA_PAST = "2026-05-20T10:00:00Z"  # parent already expired at NOON (V3)

SECTION = "draft-kroehl-agentic-trust-aae-00"


# --- JWS signing (identical construction to MoltyCel tools/build_vectors.py) --

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_key(filename: str) -> dict:
    with open(os.path.join(TESTKEYS, filename)) as fh:
        return json.load(fh)


def signer(key: dict) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64url_decode(key["jwk"]["d"]))


def sign_jws(payload: dict, key: dict, kid: str | None = None) -> str:
    header = {"alg": "EdDSA", "cty": "aae+json", "kid": kid or key["kid"]}
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = signer(key).sign(f"{h_b64}.{p_b64}".encode("ascii"))
    return f"{h_b64}.{p_b64}.{b64url(sig)}"


def jws_hash(jws: str) -> str:
    return "sha-256:" + b64url(hashlib.sha256(jws.encode("ascii")).digest())


def vc(vc_id: str, issuer: str, subject: str, aae: dict, valid_from: str = NB) -> dict:
    return {
        "@context": CONTEXT,
        "type": VC_TYPE,
        "id": vc_id,
        "issuer": issuer,
        "validFrom": valid_from,
        "credentialSubject": {"id": subject, "aae": aae},
    }


def root_mandate(actions, max_depth=2):
    return {
        "actions": actions,
        "purpose": "APS cross-encoding scenario",
        "scope": "aps-interop",
        "principal_did": PRINCIPAL,
        "delegation_policy": {"max_depth": max_depth},
    }


def child_delegation(parent_id, parent_jws, depth=1, max_depth=2):
    return {
        "delegator_did": AGENT_A,
        "delegator_aae_id": parent_id,
        "delegator_aae_uri": "https://aae.example/p/" + parent_id,
        "delegator_aae_hash": jws_hash(parent_jws),
        "depth": depth,
        "max_depth": max_depth,
    }


REGISTRY_KEY = load_key("issuer-test-key-1.json")
AGENT_A_KEY = load_key("agent-a-key.json")


def write(filename: str, vector: dict) -> None:
    with open(os.path.join(OUT, filename), "w") as fh:
        json.dump(vector, fh, indent=2)
        fh.write("\n")
    print(f"wrote {filename}  ({vector['id']}: {vector['expected']['result']})")


# --- the four re-encodings (mirror interop/aae-envelope/V1-V4) ----------------

def build():
    # V1 - narrowing valid: parent [read,write] -> child [read] (subset). ACCEPT.
    p1_id = "urn:uuid:00000091-0000-4000-8000-0000000000a0"
    p1 = vc(p1_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "write"]),
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    p1_jws = sign_jws(p1, REGISTRY_KEY)
    c1 = vc("urn:uuid:00000091-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read"], "delegation": child_delegation(p1_id, p1_jws)},
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("V1-narrowing-valid.json", {
        "id": "aae-vector-91",
        "name": "APS V1 cross-encoding: narrowing valid (child actions subset of parent)",
        "description": "ONE-TIME APS->AAE cross-encoding of interop/aae-envelope/V1-narrowing-valid. Depth-1 delegated AAE (agent-a->agent-b) whose actions [read] are a subset of the parent [read, write]; both windows current; no revocation.",
        "section_ref": f"{SECTION} §3, §5 step 9",
        "input": {"secured_aae": sign_jws(c1, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [p1_jws],
        }},
        "expected": {"result": "ACCEPT", "verification_step": 9, "rejection_reason": None},
        "rationale": "Mirrors APS V1: child actions [read] subset parent [read, write], parent->child link valid, both windows current, no revocation. APS verifyDelegation+scopeCovers ACCEPT; AAE §5 step 9 ACCEPT.",
    })

    # V2 - widened scope: parent [read] -> child [read,write,delete] (superset). REJECT.
    p2_id = "urn:uuid:00000092-0000-4000-8000-0000000000a0"
    p2 = vc(p2_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read"]),
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    p2_jws = sign_jws(p2, REGISTRY_KEY)
    c2 = vc("urn:uuid:00000092-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read", "write", "delete"], "delegation": child_delegation(p2_id, p2_jws)},
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("V2-widened-scope-reject.json", {
        "id": "aae-vector-92",
        "name": "APS V2 cross-encoding: widened scope (child actions superset of parent)",
        "description": "ONE-TIME APS->AAE cross-encoding of interop/aae-envelope/V2-widened-scope-reject. Delegated AAE lists [read, write, delete]; the parent grants only [read]; write/delete are not held by the delegator.",
        "section_ref": f"{SECTION} §3 (Actions subset), §5 step 9",
        "input": {"secured_aae": sign_jws(c2, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [p2_jws],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegated_actions_not_subset"},
        "rationale": "Mirrors APS V2 (SCOPE_WIDENING): child_scope [read, write, delete] is not a subset of parent [read]. AAE §3 rejects at step 9 delegated_actions_not_subset; APS rejects via scopeCovers (child_scope not subset of parent_scope).",
    })

    # V3 - expired parent: parent not_after in the past, child current. REJECT (cascade).
    p3_id = "urn:uuid:00000093-0000-4000-8000-0000000000a0"
    p3 = vc(p3_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "write"]),
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA_PAST, "single_use": False},
    })
    p3_jws = sign_jws(p3, REGISTRY_KEY)
    c3 = vc("urn:uuid:00000093-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read"], "delegation": child_delegation(p3_id, p3_jws)},
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("V3-expired-parent-reject.json", {
        "id": "aae-vector-93",
        "name": "APS V3 cross-encoding: expired parent invalidates chain",
        "description": "ONE-TIME APS->AAE cross-encoding of interop/aae-envelope/V3-expired-parent-reject. The child window is current but the parent's not_after is in the past; an expired ancestor invalidates the subtree.",
        "section_ref": f"{SECTION} §2.4 (not_after), §5 step 9 (ancestor temporal)",
        "input": {"secured_aae": sign_jws(c3, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [p3_jws],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "expired_not_after"},
        "rationale": "Mirrors APS V3 (DELEGATION_EXPIRED): the presented child is temporally valid, but step 9 re-checks each ancestor's temporal validity; the parent's not_after (10:00Z) precedes current_time (12:00Z), so the chain is rejected at step 9 expired_not_after. APS reaches the same outcome by cascading parent expiry to the subtree.",
    })

    # V4 - revoked parent (check-time cascade): child fully valid, parent revoked. REJECT.
    p4_id = "urn:uuid:00000094-0000-4000-8000-0000000000a0"
    p4 = vc(p4_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "write"]),
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False,
                     "revocation_check": "https://api.example.com/aae/revocation/{id}"},
    })
    p4_jws = sign_jws(p4, REGISTRY_KEY)
    c4 = vc("urn:uuid:00000094-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read"], "delegation": child_delegation(p4_id, p4_jws)},
        "constraints": {},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("V4-revoked-parent-cascade-reject.json", {
        "id": "aae-vector-94",
        "name": "APS V4 cross-encoding: revoked parent cascades to child at check time",
        "description": "ONE-TIME APS->AAE cross-encoding of interop/aae-envelope/V4-revoked-parent-cascade-reject. The child is fully valid on its own; the parent's revocation endpoint reports revoked at verification time, invalidating the subtree. CHECK-TIME cascade, not next-lookup.",
        "section_ref": f"{SECTION} §6.5 (Delegation Revocation), §5 step 9 (+ step 8 per ancestor)",
        "input": {"secured_aae": sign_jws(c4, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [p4_jws],
            "revocation_responses": {p4_id: {"revoked": True}},
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "ancestor_revoked"},
        "rationale": "Mirrors APS V4 (DELEGATION_REVOKED, check-time cascade): the child credential is independently valid, but step 9 applies the revocation check to each ancestor at verification time; the parent reports revoked:true so the descendant is rejected at step 9 ancestor_revoked. APS reaches the same outcome: a revoked parent invalidates the subtree when the chain is verified.",
    })


if __name__ == "__main__":
    build()
    print("\ndone: 4 one-time cross-encoded vectors written to", OUT)

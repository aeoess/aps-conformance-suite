#!/usr/bin/env python3
"""ONE-TIME cross-encoding: two APS constraint-monotonicity scenarios re-expressed
in MoltyCel's signed-JWS conformance-vector format (draft-kroehl-agentic-trust-aae-00).

Parallels MoltyCel's vectors 08 (numeric cap relaxation) and 15 (currency change):

  A (cap-relaxing)  -> aae-vector-95 -> REJECT delegated_constraint_relaxed
  B (currency-change) -> aae-vector-96 -> REJECT delegation_currency_mismatch

Grounding in APS primitives (see aps_grounding.py and README.md):
  A is enforced natively by APS core subDelegate (a child spendLimit above the
    parent remaining throws). Strong, sub-delegation-time alignment with 08.
  B is NOT rejected by APS core subDelegate (its spendLimitUnit is a unit tag,
    currency|invocations, and a unit change is accepted). APS enforces currency at
    the v2 payment-rails layer (preAuthorize: delegation.currency != request
    currency is denied), at enforcement time and under a different reason code.
    This divergence is documented, not papered over.

Signing reuses MoltyCel's committed PUBLIC test keys (testkeys/) and the same
sign_jws construction as build_moltycel_format.py, so the JWS verify under
examples/python-verify.py with their offline DID documents. Deterministic given
the same keys.

Requires the MoltyCel repo clone (default /tmp/aae-moltycel, override with
AAE_MOLTYCEL_REPO). Run: python3 build_constraint_vectors.py
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
SECTION = "draft-kroehl-agentic-trust-aae-00"


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
        "purpose": "APS constraint-monotonicity scenario",
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


def max_tx(value, currency="USD", required=True):
    return {"value": value, "currency": currency, "required": required}


REGISTRY_KEY = load_key("issuer-test-key-1.json")
AGENT_A_KEY = load_key("agent-a-key.json")


def write(filename: str, vector: dict) -> None:
    with open(os.path.join(OUT, filename), "w") as fh:
        json.dump(vector, fh, indent=2)
        fh.write("\n")
    print(f"wrote {filename}  ({vector['id']}: {vector['expected']['result']} {vector['expected']['rejection_reason']})")


def build():
    # A: cap-relaxing. Child max_transaction_value 1000 USD exceeds parent 500 USD.
    a_root_id = "urn:uuid:00000095-0000-4000-8000-0000000000a0"
    a_root = vc(a_root_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    a_root_jws = sign_jws(a_root, REGISTRY_KEY)
    a_child = vc("urn:uuid:00000095-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read"], "delegation": child_delegation(a_root_id, a_root_jws)},
        "constraints": {"max_transaction_value": max_tx(1000, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("A-cap-relaxing-reject.json", {
        "id": "aae-vector-95",
        "name": "APS constraint-monotonicity cross-encoding: child relaxes numeric cap (reject)",
        "description": "ONE-TIME APS->AAE cross-encoding parallel to MoltyCel vector 08. Depth-1 delegated AAE (agent-a->agent-b) whose max_transaction_value (1000 USD) exceeds the parent cap (500 USD). Same currency, so the numeric upper-bound rule fires.",
        "section_ref": f"{SECTION} §3 (numeric upper-bound), §5 step 9",
        "input": {"secured_aae": sign_jws(a_child, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "USD"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [a_root_jws],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegated_constraint_relaxed"},
        "rationale": "Monotonic narrowing allows a child to tighten a numeric cap, never raise it. 1000 USD exceeds the parent 500 USD, so the link is rejected at step 9. APS core subDelegate enforces the same rule natively: a child spendLimit above the parent remaining throws 'Spend limit ... exceeds parent remaining ...'.",
    })

    # B: currency-change. Child denominates the cap in EUR against a USD parent.
    b_root_id = "urn:uuid:00000096-0000-4000-8000-0000000000a0"
    b_root = vc(b_root_id, REGISTRY, AGENT_A, {
        "mandate": root_mandate(["read", "book"]),
        "constraints": {"max_transaction_value": max_tx(500, "USD")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    b_root_jws = sign_jws(b_root, REGISTRY_KEY)
    b_child = vc("urn:uuid:00000096-0000-4000-8000-0000000000b1", AGENT_A, AGENT_B, {
        "mandate": {"actions": ["read"], "delegation": child_delegation(b_root_id, b_root_jws)},
        "constraints": {"max_transaction_value": max_tx(300, "EUR")},
        "validity": {"not_before": NB, "not_after": NA, "single_use": False},
    })
    write("B-currency-change-reject.json", {
        "id": "aae-vector-96",
        "name": "APS constraint-monotonicity cross-encoding: child changes constraint currency (reject)",
        "description": "ONE-TIME APS->AAE cross-encoding parallel to MoltyCel vector 15. Depth-1 delegated AAE whose max_transaction_value is denominated in EUR while the parent is USD, with no conversion policy. Changing the constraint dimension escapes the parent bound.",
        "section_ref": f"{SECTION} §3 (currency-valued constraints), §5 step 9",
        "input": {"secured_aae": sign_jws(b_child, AGENT_A_KEY), "context": {
            "current_time": NOON,
            "requested_action": "read",
            "action_context": {"amount": 50, "currency": "EUR"},
            "subject_binding": {"challenge_response_valid": True},
            "delegation_chain": [b_root_jws],
        }},
        "expected": {"result": "REJECT", "verification_step": 9, "rejection_reason": "delegation_currency_mismatch"},
        "rationale": "A currency-valued delegated constraint must keep the parent currency unless an explicit conversion policy exists. EUR against a USD parent escapes the bound, so the link is rejected at step 9. APS enforces currency at the v2 payment-rails layer (preAuthorize denies a request whose currency differs from the delegation), at enforcement time and under a different reason code (spend_limit_exceeded); APS core subDelegate does NOT reject a unit change. See README.md.",
    })


if __name__ == "__main__":
    build()
    print("\ndone: 2 constraint-monotonicity cross-encoded vectors written to", OUT)

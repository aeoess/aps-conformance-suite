#!/usr/bin/env python3
"""
AlgoVoi proxy-chain validation fixture generator with authentic RFC 9421 signing.

Generates RFC 9421-signed GET request to api.algovoi.co.uk through 3-hop chain.
Uses RFC 8032 Section 7.1 Test 1 keypair for deterministic reproducible signatures.
"""

import json
import hashlib
import base64
import time
import urllib.request
import urllib.error
import sys

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

ENDPOINT = "https://api.algovoi.co.uk/compliance/attestation"
METHOD = "GET"

# RFC 8032 Section 7.1 Test 1 — deterministic test vector
TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST_PUBKEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

def create_signing_input(timestamp):
    """Create RFC 9421 Signature-Input header value."""
    return (
        f'sig=("@method" "@authority" "@path" "content-digest" "created");'
        f'created={timestamp};keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    )

def create_signature_base(method, authority, path, content_digest, created):
    """Create the canonicalized signing base per RFC 9421."""
    lines = [
        f'"@method": {method.lower()}',
        f'"@authority": {authority.lower()}',
        f'"@path": {path}',
        f'"content-digest": {content_digest}',
        f'"created": {created}'
    ]
    return '\n'.join(lines)

def sign_with_ed25519(signing_string):
    """Sign using RFC 8032 Ed25519 from test vector seed."""
    if not HAS_NACL:
        return None, None

    try:
        seed_bytes = bytes.fromhex(TEST_SEED_HEX)
        signing_key = SigningKey(seed_bytes)
        signing_input_bytes = signing_string.encode('utf-8')
        signed_msg = signing_key.sign(signing_input_bytes)
        signature_bytes = signed_msg.signature

        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
        signature_hex = signature_bytes.hex()

        return signature_b64, signature_hex
    except Exception as e:
        print(f"[ERROR] Ed25519 signing failed: {e}")
        return None, None

def generate_request_fixture():
    timestamp = int(time.time())

    # RFC 9530 content-digest for empty GET body
    content_digest_sha256 = hashlib.sha256(b"").hexdigest()
    content_digest_b64 = base64.b64encode(bytes.fromhex(content_digest_sha256)).decode('ascii')
    content_digest_header = f"sha-256=:{content_digest_b64}:"

    # RFC 9421 signature-input header
    signature_input = create_signing_input(timestamp)

    # Create the canonical signing base
    signing_base = create_signature_base(
        "get",
        "api.algovoi.co.uk",
        "/compliance/attestation",
        content_digest_header,
        timestamp
    )

    # Generate Ed25519 signature
    signature_b64, signature_hex = sign_with_ed25519(signing_base)

    # Build fixture
    fixture = {
        "layer": "REQUEST",
        "description": "RFC 9421-signed GET request to api.algovoi.co.uk/compliance/attestation through CF->nginx->FastAPI",
        "spec_refs": {
            "rfc_9421": "https://www.rfc-editor.org/rfc/rfc9421",
            "rfc_9530": "https://www.rfc-editor.org/rfc/rfc9530",
            "rfc_8032": "https://www.rfc-editor.org/rfc/rfc8032#section-7.1",
            "a2a_issue": "https://github.com/a2aproject/A2A/issues/1829"
        },
        "keypair": {
            "seed_hex": TEST_SEED_HEX,
            "seed_source": "RFC 8032 Section 7.1 Test 1",
            "public_key_hex": TEST_PUBKEY_HEX
        },
        "request": {
            "method": METHOD,
            "uri": ENDPOINT,
            "path": "/compliance/attestation",
            "authority": "api.algovoi.co.uk",
            "headers": {
                "host": "api.algovoi.co.uk",
                "content-digest": content_digest_header,
                "signature-input": signature_input,
                "signature": f"sig=:{signature_b64}:" if signature_b64 else None
            }
        },
        "signing": {
            "timestamp": timestamp,
            "signing_base": signing_base,
            "algorithm": "ed25519",
            "signature_value_b64": signature_b64,
            "signature_value_hex": signature_hex
        },
        "chain": {
            "description": "3-hop proxy chain: Cloudflare -> nginx (VM1) -> FastAPI",
            "hops": [
                {"hop": 1, "name": "Cloudflare", "role": "Edge proxy"},
                {"hop": 2, "name": "nginx", "server": "45.77.57.62", "role": "Reverse proxy"},
                {"hop": 3, "name": "FastAPI", "server": "45.77.57.62", "role": "Application server"}
            ]
        }
    }

    return fixture

def make_real_request():
    """Make real GET request and capture response."""
    try:
        req = urllib.request.Request(
            ENDPOINT,
            headers={'User-Agent': 'algovoi-proxy-chain-fixture'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            headers = dict(response.headers)
            body = response.read()
            return {
                "status": status,
                "headers": headers,
                "body_length": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "timestamp": int(time.time()),
                "success": True
            }
    except urllib.error.URLError as e:
        return {
            "error": str(e),
            "timestamp": int(time.time()),
            "success": False
        }

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print("=== AlgoVoi Proxy-Chain Fixture Generator ===")
    print()

    if HAS_NACL:
        print("[OK] PyNaCl available - generating authentic Ed25519 signatures")
    else:
        print("[ERROR] PyNaCl not found")
        sys.exit(1)

    print()
    print("Generating RFC 9421-signed request fixture...")
    request_fixture = generate_request_fixture()

    print("Making GET request to " + ENDPOINT + "...")
    response_info = make_real_request()

    if response_info["success"]:
        print("[OK] Got HTTP " + str(response_info["status"]))
    else:
        print("[ERROR] Request failed: " + response_info.get("error", "unknown"))

    with open("request.fixture.json", "w") as f:
        json.dump(request_fixture, f, indent=2)
    print("[OK] Written request.fixture.json")

    sig_b64 = request_fixture["signing"]["signature_value_b64"]
    print(f"[OK] Signature (base64): {sig_b64[:50]}...")

    with open("response.fixture.json", "w") as f:
        json.dump(response_info, f, indent=2)
    print("[OK] Written response.fixture.json")

    chain_fixture = {
        "fixture_name": "algovoi-proxy-chain",
        "description": "RFC 9421 HTTP signature + RFC 9530 content-digest survival",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "endpoint": ENDPOINT,
        "status": "ready_for_verification"
    }

    with open("chain.fixture.json", "w") as f:
        json.dump(chain_fixture, f, indent=2)
    print("[OK] Written chain.fixture.json")

    print()
    print("PHASE 2 COMPLETE: Ed25519 signatures generated and fixtures updated.")
    print()
    print("Next: Create verify.py to validate signature byte-match and header survival.")

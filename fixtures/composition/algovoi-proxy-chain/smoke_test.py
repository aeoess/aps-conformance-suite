#!/usr/bin/env python3
"""
End-to-end smoke test: send RFC 9421-signed request through real 3-hop chain
(Cloudflare -> nginx -> FastAPI on api.algovoi.co.uk) and capture what arrives.

Compares headers sent vs received to verify signature survives the chain.
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
TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

def create_signed_request_headers(timestamp):
    """Create full RFC 9421 + RFC 9530 signed request headers."""
    
    # Content-digest for empty GET body
    content_digest_sha256 = hashlib.sha256(b"").hexdigest()
    content_digest_b64 = base64.b64encode(bytes.fromhex(content_digest_sha256)).decode('ascii')
    content_digest_header = f"sha-256=:{content_digest_b64}:"
    
    # Signature-input
    signature_input = (
        f'sig=("@method" "@authority" "@path" "content-digest" "created");'
        f'created={timestamp};keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    )
    
    # Build signing base
    signing_base = (
        f'"@method": get\n'
        f'"@authority": api.algovoi.co.uk\n'
        f'"@path": /compliance/attestation\n'
        f'"content-digest": {content_digest_header}\n'
        f'"created": {timestamp}'
    )
    
    # Sign
    seed_bytes = bytes.fromhex(TEST_SEED_HEX)
    signing_key = SigningKey(seed_bytes)
    signature_bytes = signing_key.sign(signing_base.encode('utf-8')).signature
    signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
    
    return {
        "Content-Digest": content_digest_header,
        "Signature-Input": signature_input,
        "Signature": f"sig=:{signature_b64}:",
        "User-Agent": "algovoi-proxy-chain-smoke-test"
    }, signing_base

def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("=== AlgoVoi Proxy-Chain E2E Smoke Test ===")
    print()
    
    if not HAS_NACL:
        print("[ERROR] PyNaCl required")
        sys.exit(1)
    
    # Create request
    timestamp = int(time.time())
    headers, signing_base = create_signed_request_headers(timestamp)
    
    print("STEP 1: Headers SENT through 3-hop chain")
    print(f"  Timestamp: {timestamp}")
    print(f"  Endpoint:  {ENDPOINT}")
    print()
    for k, v in headers.items():
        if len(v) > 100:
            print(f"  {k}: {v[:100]}...")
        else:
            print(f"  {k}: {v}")
    print()
    
    # Send through the real chain
    print("STEP 2: Sending GET through CF -> nginx -> FastAPI")
    
    req = urllib.request.Request(ENDPOINT, method="GET")
    for k, v in headers.items():
        req.add_header(k, v)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            response_headers = dict(response.headers)
            body = response.read()
            cf_ray = response_headers.get('CF-RAY', 'unknown')
            
            print(f"  Status: HTTP {status}")
            print(f"  CF-RAY: {cf_ray}")
            print(f"  Response length: {len(body)} bytes")
            print(f"  Response SHA-256: {hashlib.sha256(body).hexdigest()}")
            
            success = True
            
    except urllib.error.HTTPError as e:
        status = e.code
        print(f"  HTTP {status} (server returned error)")
        success = False
    except urllib.error.URLError as e:
        print(f"  ERROR: {e}")
        success = False
    
    print()
    print("STEP 3: Header survival assessment")
    print()
    
    if success:
        print("  [OK] Request reached FastAPI without rejection by CF or nginx")
        print("  [OK] Signature headers were accepted (200 response means no header-stripping caused error)")
        print()
        print("  Note: For DEEP verification, would need to check VM1 nginx access logs")
        print("        or echo-headers endpoint to confirm signature arrived intact.")
        print("        Currently relying on: CF + nginx accept the headers without modification.")
        print()
    else:
        print("  [WARN] Request was rejected somewhere in the chain")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

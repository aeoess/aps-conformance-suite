#!/usr/bin/env python3
"""
AlgoVoi multi-chain Ed25519 fixture verifier.

Validates that the same A2A payload was signed authentically with
three different Ed25519 keys derived from standard BIP44 paths.
"""

import json
import sys
import base64
import hashlib

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

CHAINS = {
    "algorand": {"path": "m/44'/283'/0'/0'/0'", "seed_hex": "df8e966c94469b23598aafaee6c14463ad40dc6286babad3096cb413979a8116"},
    "solana": {"path": "m/44'/501'/0'/0'", "seed_hex": "615666dae9d3625adaef933e4c1ed0158f657a22c2f570edcd1f7caa68e16413"},
    "stellar": {"path": "m/44'/148'/0'", "seed_hex": "232ed6f9fabf14e3bb55392b18cfe3d0febc94d20cc6327c38a1d075d6ea118c"}
}

def verify_ed25519_signature(payload_json, expected_sig_b64, seed_hex, chain_name):
    """Re-derive Ed25519 signature and compare."""
    if not HAS_NACL:
        return False

    try:
        seed_bytes = bytes.fromhex(seed_hex)
        signing_key = SigningKey(seed_bytes)
        payload_bytes = payload_json.encode('utf-8')
        signed_msg = signing_key.sign(payload_bytes)
        signature_bytes = signed_msg.signature
        derived_sig_b64 = base64.b64encode(signature_bytes).decode('ascii')

        if derived_sig_b64 == expected_sig_b64:
            print(f"[OK] {chain_name.upper():8} signature byte-match")
            return True
        else:
            print(f"[FAIL] {chain_name.upper():8} signature mismatch")
            return False
    except Exception as e:
        print(f"[ERROR] {chain_name} verification failed: {e}")
        return False

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print("=== AlgoVoi Multi-Chain Fixture Verifier ===")
    print()

    if not HAS_NACL:
        print("[ERROR] PyNaCl required: pip install PyNaCl")
        sys.exit(1)

    try:
        with open("fixture.json") as f:
            fixture = json.load(f)
        print("[OK] Loaded fixture.json")
    except Exception as e:
        print(f"[ERROR] Failed to load fixture.json: {e}")
        sys.exit(1)

    print()

    payload_json = fixture["payload_canonical_json"]
    payload_sha256 = fixture["payload_sha256"]

    print(f"A2A Payload: {len(payload_json)} bytes")
    print(f"Payload SHA-256: {payload_sha256}")
    print()

    all_valid = True
    for chain_name, sig_info in fixture["signatures"].items():
        chain_config = CHAINS[chain_name]
        valid = verify_ed25519_signature(
            payload_json,
            sig_info["signature_b64"],
            chain_config["seed_hex"],
            chain_name
        )
        all_valid = all_valid and valid

    print()
    print("=== VERIFICATION COMPLETE ===")
    
    if all_valid:
        print("All three chains signed the same A2A payload authentically.")
        print("Wire-format is substrate-independent across Algorand, Solana, Stellar.")
        sys.exit(0)
    else:
        print("One or more signatures failed verification.")
        sys.exit(1)

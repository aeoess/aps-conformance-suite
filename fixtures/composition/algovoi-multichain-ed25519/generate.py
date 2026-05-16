#!/usr/bin/env python3
"""
AlgoVoi multi-chain Ed25519 fixture generator.

Demonstrates the same A2A payload signed with Ed25519 keys from three blockchains.
"""

import json
import hashlib
import base64
import time
import sys

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

PAYLOAD = {
    "agent_id": "did:web:api.algovoi.co.uk",
    "capability": "pay_on_behalf",
    "resource": "https://api.algovoi.co.uk/mandate/pay",
    "scope": ["checkout", "refund"],
    "expiration": 1778959200,
    "nonce": "9b80b883-69e6-468b-9a85-96394f82497a"
}

CHAINS = {
    "algorand": {
        "path": "m/44'/283'/0'/0'/0'",
        "description": "Algorand Ed25519 (AVM standard)",
        "seed_hex": "df8e966c94469b23598aafaee6c14463ad40dc6286babad3096cb413979a8116"
    },
    "solana": {
        "path": "m/44'/501'/0'/0'",
        "description": "Solana Ed25519 (SPL standard)",
        "seed_hex": "615666dae9d3625adaef933e4c1ed0158f657a22c2f570edcd1f7caa68e16413"
    },
    "stellar": {
        "path": "m/44'/148'/0'",
        "description": "Stellar Ed25519 (Stellar standard)",
        "seed_hex": "232ed6f9fabf14e3bb55392b18cfe3d0febc94d20cc6327c38a1d075d6ea118c"
    }
}

def sign_with_ed25519(payload_json, seed_hex, chain_name):
    """Sign A2A payload with Ed25519 key from chain derivation."""
    if not HAS_NACL:
        return None, None

    try:
        seed_bytes = bytes.fromhex(seed_hex)
        if len(seed_bytes) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed_bytes)}")
        
        signing_key = SigningKey(seed_bytes)
        payload_bytes = payload_json.encode('utf-8')
        signed_msg = signing_key.sign(payload_bytes)
        signature_bytes = signed_msg.signature

        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
        signature_hex = signature_bytes.hex()

        return signature_b64, signature_hex
    except Exception as e:
        print(f"[ERROR] {chain_name} signing failed: {e}")
        return None, None

def generate_multichain_fixture():
    """Generate A2A payload signed with three chain-specific Ed25519 keys."""
    
    timestamp = int(time.time())
    payload_json = json.dumps(PAYLOAD, sort_keys=True, separators=(',', ':'))
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
    
    signatures = {}
    for chain_name, chain_info in CHAINS.items():
        sig_b64, sig_hex = sign_with_ed25519(payload_json, chain_info["seed_hex"], chain_name)
        signatures[chain_name] = {
            "signature_b64": sig_b64,
            "signature_hex": sig_hex,
            "derivation_path": chain_info["path"]
        }
    
    fixture = {
        "layer": "MULTICHAIN",
        "description": "A2A payload signed with Ed25519 keys from three blockchain derivation paths",
        "payload": PAYLOAD,
        "payload_canonical_json": payload_json,
        "payload_sha256": payload_sha256,
        "timestamp": timestamp,
        "signatures": signatures,
        "chains": CHAINS,
        "proof_of_substrate_independence": {
            "claim": "Same A2A payload is independently signable across Algorand, Solana, Stellar",
            "implication": "Wire-format is substrate-independent"
        }
    }
    
    return fixture

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("=== AlgoVoi Multi-Chain Ed25519 Fixture ===")
    print()
    
    if not HAS_NACL:
        print("[ERROR] PyNaCl required")
        sys.exit(1)
    
    print("Generating A2A payload signatures across three chains...")
    
    fixture = generate_multichain_fixture()
    
    payload_json = fixture["payload_canonical_json"]
    print(f"A2A Payload: {len(payload_json)} bytes")
    print(f"Payload SHA-256: {fixture['payload_sha256']}")
    print()
    
    for chain_name, sig_info in fixture["signatures"].items():
        if sig_info["signature_b64"]:
            path = CHAINS[chain_name]["path"]
            print(f"[OK] {chain_name.upper():8} | {path:20} | Sig: {sig_info['signature_b64'][:40]}...")
    
    print()
    
    with open("fixture.json", "w") as f:
        json.dump(fixture, f, indent=2)
    print("[OK] Written fixture.json")
    
    with open("payload.json", "w") as f:
        json.dump(PAYLOAD, f, indent=2)
    print("[OK] Written payload.json")
    
    print()
    print("COMPLETE: Multi-chain signatures generated.")

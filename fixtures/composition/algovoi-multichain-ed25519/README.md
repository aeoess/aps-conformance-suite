# AlgoVoi Multi-Chain Ed25519 Fixture

Demonstrates wire-format substrate independence by signing the same A2A payload with Ed25519 keys derived from three different blockchain standards.

## Overview

**Key Finding**: The same A2A protocol payload can be independently signed across three blockchain networks using standard BIP44 derivation paths, proving that wire-format is not coupled to any single chain.

## Blockchains

1. **Algorand** — `m/44'/283'/0'/0'/0'` (AVM standard derivation)
2. **Solana** — `m/44'/501'/0'/0'` (SPL standard derivation)
3. **Stellar** — `m/44'/148'/0'` (Stellar standard derivation)

## A2A Payload

```json
{
  "agent_id": "did:web:api.algovoi.co.uk",
  "capability": "pay_on_behalf",
  "resource": "https://api.algovoi.co.uk/mandate/pay",
  "scope": ["checkout", "refund"],
  "expiration": 1778959200,
  "nonce": "9b80b883-69e6-468b-9a85-96394f82497a"
}
```

**Canonical JSON (221 bytes)**:
```
{"agent_id":"did:web:api.algovoi.co.uk","capability":"pay_on_behalf","expiration":1778959200,"nonce":"9b80b883-69e6-468b-9a85-96394f82497a","resource":"https://api.algovoi.co.uk/mandate/pay","scope":["checkout","refund"]}
```

**SHA-256**: `4f867161a905274c1d94aaa0bd0b093c4dcbcc10db5196aa7be11b120b56267c`

## Signatures

Each chain has an authentic Ed25519 signature over the canonical JSON payload:

| Chain | Derivation Path | Signature (first 40 chars) |
|-------|-----------------|---------------------------|
| Algorand | `m/44'/283'/0'/0'/0'` | `fj0plkJ/UCBYSj4e9VAzVJYd+VOoTcP41r...` |
| Solana | `m/44'/501'/0'/0'` | `ytE+NFOiKWC+hMUO/i7x0hLHzI648kPfOC...` |
| Stellar | `m/44'/148'/0'` | `6brTXQAQiyCMSlPOTetxsLxLFs9N65Hcu3I...` |

## Verification

```bash
python3 verify.py
```

Output on success:
```
[OK] ALGORAND signature byte-match
[OK] SOLANA   signature byte-match
[OK] STELLAR  signature byte-match

All three chains signed the same A2A payload authentically.
Wire-format is substrate-independent across Algorand, Solana, Stellar.
```

Exit code 0 = all signatures verified.

## Reproducibility

Re-running `generate.py` produces byte-identical signatures from the deterministic seeds. All signatures are independently verifiable by anyone with the seed and chainlib.

## Cross-Reference

A2A #1829 second remaining commitment (v0.3.3, mid-June):
https://github.com/a2aproject/A2A/issues/1829

## Files

- `generate.py` — Multi-chain signature generator
- `verify.py` — Verification script
- `fixture.json` — Signed payloads for all three chains
- `payload.json` — A2A payload reference
- `README.md` — This file

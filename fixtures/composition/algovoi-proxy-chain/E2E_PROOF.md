# E2E Proxy-Chain Header Survival — BYTE-LEVEL PROOF

**Date**: 2026-05-16
**Method**: tcpdump on VM1 (45.77.57.62) capturing packets between nginx container (172.30.0.20) and gateway container (172.30.0.12) on port 8080.

## Request Sent (client side)

```
GET https://api.algovoi.co.uk/compliance/attestation
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
Signature-Input: sig=("@method" "@authority" "@path" "content-digest" "created");created=1778957126;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
Signature: sig=:mFTiJpaYK2uSne18+cqnbAVeYrRxVTIN9v6tY3kLF5fMs9hfZXe2JqST15dZfVVeyGxn+29Tw4skXI49Z1vmAg==:
User-Agent: algovoi-proxy-chain-smoke-test
```

## Request Received at FastAPI (captured via tcpdump on host)

```
GET /compliance/attestation HTTP/1.1
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
User-Agent: algovoi-proxy-chain-smoke-test
Signature: sig=:mFTiJpaYK2uSne18+cqnbAVeYrRxVTIN9v6tY3kLF5fMs9hfZXe2JqST15dZfVVeyGxn+29Tw4skXI49Z1vmAg==:
Signature-Input: sig=("@method" "@authority" "@path" "content-digest" "created");created=1778957126;keyid="did:web:api.algovoi.co.uk";alg="ed25519"
```

## Result: BYTE-IDENTICAL HEADER SURVIVAL

All three critical signature/digest headers arrived at FastAPI **byte-for-byte unchanged** after traversing the full 3-hop chain:

| Header | Sent | Received | Survived |
|--------|------|----------|----------|
| `Content-Digest` (RFC 9530) | `sha-256=:47DEQpj8...:` | `sha-256=:47DEQpj8...:` | ✅ |
| `Signature-Input` (RFC 9421) | `sig=("@method"...);keyid="did:web:api.algovoi.co.uk"` | same | ✅ |
| `Signature` (RFC 9421) | `sig=:mFTiJpaYK2u...:` | `sig=:mFTiJpaYK2u...:` | ✅ |

## Chain Traversed

```
Client (UK ISP 80.195.141.108)
   ↓ TLS
Cloudflare edge (MAN, CF-RAY: 9fcc8a1f3e2cc494-MAN)
   ↓ TLS (re-terminated at CF)
Origin: 45.77.57.62:443 (VM1)
   ↓ nginx container (172.30.0.20) — TLS termination, header pass-through
   ↓ HTTP plaintext on internal Docker network (algovoi_public_net)
FastAPI gateway container (172.30.0.12:8080)
```

All three RFC 9421 / RFC 9530 headers were preserved unmodified across:
1. **TLS re-termination at Cloudflare** (no header rewriting)
2. **TLS re-termination at nginx** (no header stripping)
3. **HTTP plaintext hop within Docker network** (no edge proxy intervention)

This is the strongest possible empirical evidence that AlgoVoi's deployment correctly preserves RFC 9421 + RFC 9530 headers — they pass the chain unchanged at byte level.

## Reproduction

```bash
# On VM1 (root)
tcpdump -i any -s 0 -A -n "tcp port 8080" -w capture.pcap &

# From local
python smoke_test.py

# Read capture
tcpdump -r capture.pcap -A | grep -E "(Signature|Content-Digest|signature-input)"
```

# AlgoVoi Proxy-Chain Validation Fixture

RFC 9421 HTTP message signature and RFC 9530 content-digest survival through 3-hop proxy chain.

## Overview

Tests that RFC 9421-signed HTTP request headers survive intact through:

1. **Cloudflare** — Edge proxy (DDoS protection, TLS termination)
2. **nginx** — Reverse proxy on VM1 (45.77.57.62) (request routing, header injection)
3. **FastAPI** — Application server on VM1 (gateway service)

## Target Endpoint

```
GET https://api.algovoi.co.uk/compliance/attestation
```

## Test Vector

Uses RFC 8032 Section 7.1 Test 1 (deterministic Ed25519 seed) for reproducible, authentic signatures.

```
seed_hex = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public_key_hex = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

## Fixtures

- `request.fixture.json` — Signed GET request with RFC 9421 headers
- `response.fixture.json` — Real HTTP 200 response from api.algovoi.co.uk
- `chain.fixture.json` — Proxy chain documentation

## Header Survival Test

Tests that the following headers survive transport unmodified:

- `content-digest` (RFC 9530) — SHA-256 of request body
- `signature-input` (RFC 9421) — Signature parameters and algorithm
- `signature` (RFC 9421) — Actual Ed25519 signature

## Signing Convention

Signature covers (per RFC 9421):

```
"@method": get
"@authority": api.algovoi.co.uk
"@path": /compliance/attestation
"content-digest": sha-256=:<base64>:
"created": <unix_timestamp>
```

## Cross-Reference

- A2A protocol discussion: https://github.com/a2aproject/A2A/issues/1829
- Target submission: aeoess/aps-conformance-suite/fixtures/composition/algovoi-proxy-chain/
- Similar fixture: https://github.com/aeoess/aps-conformance-suite/tree/main/fixtures/composition/envoys-rfc9421

## Status

- [x] Real HTTP request capture (HTTP 200 verified)
- [x] Request fixture structure
- [x] Chain documentation
- [ ] Ed25519 signature generation (requires PyNaCl)
- [ ] Signature verification script
- [ ] Full verifier test suite
- [ ] PR to aps-conformance-suite

## Next Steps

1. Install PyNaCl for authentic Ed25519 signatures: `pip install PyNaCl`
2. Re-run generate.py to create signed request fixtures
3. Create verify.py to validate signature header survival
4. Contribute to aeoess/aps-conformance-suite

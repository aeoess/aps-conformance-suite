#!/usr/bin/env python3
"""Schema + cross-language validation for the Presidio x402 accountability-record fixture (PART 1).

Run as (from aps-conformance-suite/):
  python3 fixtures/presidio-x402/validate.py
Requires: jsonschema  cryptography

Checks:
  1. Meta-validate the schema (Draft 2020-12) from the parent accountability-record/ dir.
  2. Schema-validate each vector record. Positive MUST be schema-valid; the signature
     negative is schema-valid too (only its signature fails).
  3. Cross-language JCS byte-parity (Python re-derives signing_input/canonical/sha256).
  4. action_digest binding: both records bind (no tampered payloads in PART 1).
  5. Ed25519: positive verifies; signature negative (wrong key) fails against ed25519_pubkey_hex.
Exit 0 only if every required check passes.
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "..", "accountability-record", "accountability-record.schema.json")
FIXTURE_PATH = os.path.join(HERE, "presidio-x402-accountability-record-fixture-v1.json")

from jsonschema import Draft202012Validator


def jcs(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    if not os.path.exists(SCHEMA_PATH):
        print(f"Schema not found at {SCHEMA_PATH}. Run from aps-conformance-suite/ root.")
        return 1

    schema = json.load(open(SCHEMA_PATH))
    fx = json.load(open(FIXTURE_PATH))
    vectors = fx["vectors"]
    failures = 0

    print(f"Presidio x402 accountability-record (PART 1) — {len(vectors)} vectors\n")

    print("== 1. meta-validate schema (Draft 2020-12) ==")
    try:
        Draft202012Validator.check_schema(schema)
        print("  schema is a valid Draft 2020-12 schema: OK")
    except Exception as e:
        print(f"  schema INVALID: {e}")
        return 1
    validator = Draft202012Validator(schema)

    print("\n== 2. schema-validate each vector record ==")
    for v in vectors:
        errs = sorted(validator.iter_errors(v["record"]), key=lambda e: list(e.path))
        rk = v.get("rejection_kind")
        if rk == "schema":
            if errs:
                print(f"  OK   {v['name']:40} schema-INVALID as required ({errs[0].message[:56]})")
            else:
                failures += 1
                print(f"  FAIL {v['name']:40} expected schema rejection but record is schema-valid")
        elif rk in ("signature", "digest_mismatch"):
            state = "schema-valid" if not errs else f"schema-invalid ({errs[0].message[:36]})"
            print(f"  --   {v['name']:40} {state} (crypto negative; schema not decisive)")
        else:
            if errs:
                failures += 1
                print(f"  FAIL {v['name']:40} schema errors: {errs[0].message}")
            else:
                print(f"  OK   {v['name']:40} schema-valid (positive)")

    print("\n== 3. cross-language JCS byte-parity (Python vs stored bytes) ==")
    for v in vectors:
        rec = v["record"]
        rec_no_sig = {k: val for k, val in rec.items() if k != "sig"}
        si = jcs(rec_no_sig)
        canon = jcs(rec)
        ok = (si == v["signing_input_canonical"]
              and canon == v["canonical"]
              and sha256_hex(canon) == v["canonical_sha256"])
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:40} signing_input+canonical+sha256 parity")

    print("\n== 4. action_digest binding ==")
    for v in vectors:
        rec = v["record"]
        if "action" in rec:
            recomputed = sha256_hex(jcs(rec["action"]))
            matches = recomputed == rec["action_digest"]["sha256"]
            ok = matches
            print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:40} digest binds (bound={matches})")
            if not ok:
                failures += 1
        else:
            print(f"  --   {v['name']:40} detached (no inline action)")

    print("\n== 5. Ed25519 signature verification ==")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        have_crypto = True
    except ImportError:
        have_crypto = False
        print("  `cryptography` not installed. Run: pip install cryptography")

    if have_crypto:
        for v in vectors:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["ed25519_pubkey_hex"]))
            msg = v["signing_input_canonical"].encode("utf-8")
            sig = bytes.fromhex(v["record"]["sig"])
            try:
                pub.verify(sig, msg)
                verified = True
            except InvalidSignature:
                verified = False
            rk = v.get("rejection_kind")
            if rk == "signature":
                ok = not verified
                note = "signature correctly rejected (wrong key)"
            else:
                ok = verified
                note = "signature verifies" if v["expected_verification"] else "signature valid over bytes (fails elsewhere)"
            if not ok:
                failures += 1
            print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:40} {note} (verified={verified})")

    if failures:
        print(f"\n{failures} CHECK(S) FAILED")
        return 1
    if not have_crypto:
        print("\nINCOMPLETE: schema, byte-parity, and digest checks passed, but Ed25519")
        print("signatures were NOT verified (cryptography missing). Not a full pass.")
        return 2
    print("\nALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

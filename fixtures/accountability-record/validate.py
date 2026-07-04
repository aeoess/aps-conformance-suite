#!/usr/bin/env python3
"""Schema + cross-language validation for the accountability-record family.

Run as:  python3 fixtures/accountability-record/validate.py
Requires: jsonschema  (pip install jsonschema); Ed25519 signature checks also use
`cryptography` if present, otherwise they are deferred to verify.ts.

Checks, printed verbatim:
  1. Meta-validate the schema (Draft 2020-12).
  2. Validate every vector record against the schema. All four positives MUST
     pass. The two negatives are well-formed records (they fail at verification,
     not schema), so they are expected to pass schema validation too.
  3. Cross-language JCS byte-parity: a Python canonicalizer reproduces
     signing_input_canonical and canonical byte-for-byte (proves the TS
     generator and an independent Python impl agree on RFC 8785 bytes).
  4. Detached-payload digest binding: for inline-action vectors, recompute
     sha256(JCS(action)) and compare to action_digest.sha256. The tampered
     negative MUST mismatch; positives MUST match.
  5. Ed25519 (if `cryptography` present): positives verify, wrong-key negative
     fails, against ed25519_pubkey_hex.
Exit 0 only if every required check passes.
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "accountability-record.schema.json")
FIXTURE_PATH = os.path.join(HERE, "accountability-record-fixture-v1.json")

from jsonschema import Draft202012Validator


def jcs(value) -> str:
    """RFC 8785 JCS for the ASCII/string/bool/null/array/object data used here.
    Byte-identical to agent-passport-system canonicalizeJCS for this domain:
    keys sorted, null preserved, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    schema = json.load(open(SCHEMA_PATH))
    fx = json.load(open(FIXTURE_PATH))
    vectors = fx["vectors"]
    failures = 0

    print("== 1. meta-validate schema (Draft 2020-12) ==")
    try:
        Draft202012Validator.check_schema(schema)
        print("  schema is a valid Draft 2020-12 schema: OK")
    except Exception as e:  # noqa
        print(f"  schema INVALID: {e}")
        return 1
    validator = Draft202012Validator(schema)

    print("\n== 2. schema-validate each vector record ==")
    for v in vectors:
        errs = sorted(validator.iter_errors(v["record"]), key=lambda e: list(e.path))
        rk = v.get("rejection_kind")
        if rk == "schema":
            # schema negative MUST be rejected by the schema.
            if errs:
                print(f"  OK   {v['name']:34} schema-INVALID as required ({errs[0].message[:56]})")
            else:
                failures += 1
                print(f"  FAIL {v['name']:34} expected schema rejection but record is schema-valid")
        elif rk in ("signature", "digest_mismatch"):
            # crypto/digest negatives; schema validity is incidental, not asserted here.
            state = "schema-valid" if not errs else f"schema-invalid ({errs[0].message[:36]})"
            print(f"  --   {v['name']:34} {state} (crypto/digest negative; schema not decisive)")
        else:
            # positive: MUST be schema-valid.
            if errs:
                failures += 1
                print(f"  FAIL {v['name']:34} schema errors: {errs[0].message}")
            else:
                print(f"  OK   {v['name']:34} schema-valid (positive)")

    print("\n== 3. cross-language JCS byte-parity (Python vs stored TS bytes) ==")
    for v in vectors:
        rec = v["record"]
        rec_no_sig = {k: val for k, val in rec.items() if k != "sig"}
        si = jcs(rec_no_sig)
        canon = jcs(rec)
        ok = (si == v["signing_input_canonical"] and canon == v["canonical"]
              and sha256_hex(canon) == v["canonical_sha256"])
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:28} signing_input+canonical+sha256 parity")

    print("\n== 4. detached-payload digest binding ==")
    for v in vectors:
        rec = v["record"]
        if "action" in rec:
            recomputed = sha256_hex(jcs(rec["action"]))
            matches = recomputed == rec["action_digest"]["sha256"]
            if v["name"] == "negative-tampered-payload":
                ok = (matches is False)  # MUST mismatch
                print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} digest MISMATCH as required (bound={matches})")
            else:
                ok = (matches is True)  # everything else with an inline payload MUST bind
                print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} digest binds (bound={matches})")
            if not ok:
                failures += 1
        else:
            print(f"  --   {v['name']:34} detached (no inline action), digest binding deferred")

    print("\n== 5. Ed25519 signature verification ==")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        have_crypto = True
    except ImportError:
        have_crypto = False
        print("  `cryptography` not installed. Ed25519 verification was NOT performed here.")
        print("  Run `pip install cryptography`, or verify signatures with:")
        print("    npx tsx fixtures/accountability-record/verify.ts")

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
                ok = (verified is False)  # wrong-key and type-relabel: sig MUST NOT verify
                note = "signature correctly rejected"
            else:
                # positives + schema/digest negatives: the signature is valid over its own bytes
                ok = (verified is True)
                note = "signature verifies" if v["expected_verification"] is True else "signature valid over bytes (fails elsewhere)"
            if not ok:
                failures += 1
            print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} {note} (verified={verified})")

    # Honest exit: schema, byte-parity, and digest checks may pass, but if the
    # Ed25519 path was skipped this is NOT a full pass. Never print a green banner
    # or exit 0 when signatures went unverified.
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

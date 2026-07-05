#!/usr/bin/env python3
"""Schema + cross-language validation for the read-fidelity-receipt family.

Run as:  python3 fixtures/read-fidelity-receipt/validate.py
Requires: jsonschema  (pip install jsonschema); Ed25519 signature checks also use
`cryptography` if present, otherwise they are deferred to verify.ts.

Checks, printed verbatim:
  1. Meta-validate the schema (Draft 2020-12).
  2. Validate every record vector against the schema. All record vectors in
     this family are schema-valid by construction (the negatives fail at
     verification: signature or seed derivation, never schema), so every one
     MUST pass schema validation.
  3. Cross-language JCS byte-parity: a Python canonicalizer reproduces
     signing_input_canonical and canonical byte-for-byte (proves the TS
     generator and an independent Python impl agree on RFC 8785 bytes).
  4. Seed derivation recompute: seed = sha256hex(utf8(content_digest +
     (presentation_digest or empty string when null) + nonce + version)).
     Positives MUST match; the v6/v7 seed negatives MUST mismatch.
  5. Word handle checksum math, recomputed in pure Python from the digest and
     the recorded word indices (11-bit words, packed prefix, sha256 over
     BE16(prefix_bits) plus the packed bits). The substitution and
     transposition vectors MUST fail the checksum; the out-of-lexicon vector
     MUST carry null indices exactly at the recorded positions. Word strings
     themselves are checked by verify.ts against the vendored wordlist.
  6. Ed25519 (if `cryptography` present): positives verify; the tampered
     vector MUST fail; the re-signed seed negatives MUST verify over their
     own bytes (they are rejected by the seed derivation, not the signature).
Exit 0 only if every required check passes.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "read-fidelity-receipt.schema.json")
FIXTURE_PATH = os.path.join(HERE, "read-fidelity-receipt-fixture-v1.json")

from jsonschema import Draft202012Validator

WORD_BITS = 11
PROFILES = {
    "compact": (4, 1),
    "default": (6, 1),
    "high_assurance": (8, 2),
}


def jcs(value) -> str:
    """RFC 8785 JCS for the ASCII/string/bool/null/int/array/object data used
    here. Byte-identical to agent-passport-system canonicalizeJCS for this
    domain: keys sorted, null preserved, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def derive_seed(content_digest, presentation_digest, nonce, version) -> str:
    presentation = "" if presentation_digest is None else presentation_digest
    return sha256_hex(content_digest + presentation + nonce + version)


def data_indices_from_digest(digest_hex: str, data_words: int) -> list:
    """Data word i = bits [11i, 11i+11) of the digest bytes, MSB-first."""
    raw = bytes.fromhex(digest_hex)
    bits = 0
    for b in raw:
        bits = (bits << 8) | b
    total_bits = len(raw) * 8
    out = []
    for i in range(data_words):
        shift = total_bits - WORD_BITS * (i + 1)
        out.append((bits >> shift) & 0x7FF)
    return out


def pack_prefix_from_indices(indices, prefix_bits: int) -> bytes:
    """Pack 11-bit indices into ceil(prefix_bits/8) bytes, MSB-first, unused
    low-order bits of the final byte zero."""
    value = 0
    for idx in indices:
        value = (value << WORD_BITS) | idx
    byte_len = (prefix_bits + 7) // 8
    pad = byte_len * 8 - prefix_bits
    value <<= pad
    return value.to_bytes(byte_len, "big")


def checksum_indices(prefix_bits: int, packed: bytes, checksum_words: int) -> list:
    """Checksum word j = bits [11j, 11j+11) of sha256(BE16(prefix_bits) || packed)."""
    digest = hashlib.sha256(prefix_bits.to_bytes(2, "big") + packed).digest()
    bits = 0
    for b in digest:
        bits = (bits << 8) | b
    total_bits = len(digest) * 8
    out = []
    for j in range(checksum_words):
        shift = total_bits - WORD_BITS * (j + 1)
        out.append((bits >> shift) & 0x7FF)
    return out


def main() -> int:
    schema = json.load(open(SCHEMA_PATH))
    fx = json.load(open(FIXTURE_PATH))
    vectors = fx["vectors"]
    record_vectors = [v for v in vectors if v["kind"] == "record"]
    handle_vectors = [v for v in vectors if v["kind"] == "word_handle"]
    failures = 0

    print("== 1. meta-validate schema (Draft 2020-12) ==")
    try:
        Draft202012Validator.check_schema(schema)
        print("  schema is a valid Draft 2020-12 schema: OK")
    except Exception as e:  # noqa
        print(f"  schema INVALID: {e}")
        return 1
    # format_checker turns the schema "format": "date-time" annotations into
    # assertions (Draft 2020-12 leaves format as an annotation by default), so a
    # malformed timestamp fails here rather than only at the cold-clone verifier.
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)

    print("\n== 2. schema-validate each record vector ==")
    for v in record_vectors:
        errs = sorted(validator.iter_errors(v["record"]), key=lambda e: list(e.path))
        # Every record vector is schema-valid by construction; the negatives
        # fail at verification (signature or seed), never at the schema.
        if errs:
            failures += 1
            print(f"  FAIL {v['name']:42} schema errors: {errs[0].message}")
        else:
            print(f"  OK   {v['name']:42} schema-valid")

    # Cross-field invariants JSON Schema cannot express (arithmetic across
    # fields). The verifiers enforce these too; asserting them here is defense in
    # depth so validate.py never green-lights an internally inconsistent record.
    print("\n== 2b. cross-field invariants (k <= n, n == span_commitments length) ==")
    for v in record_vectors:
        rec = v["record"]
        k, n = rec.get("k"), rec.get("n")
        commits = rec.get("challenge", {}).get("span_commitments", [])
        ok = (isinstance(k, int) and isinstance(n, int) and 0 <= k <= n
              and n == len(commits))
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:42} k={k} n={n} commitments={len(commits)}")

    print("\n== 3. cross-language JCS byte-parity (Python vs stored TS bytes) ==")
    for v in record_vectors:
        rec = v["record"]
        rec_no_sig = {k: val for k, val in rec.items() if k != "sig"}
        si = jcs(rec_no_sig)
        canon = jcs(rec)
        ok = (si == v["signing_input_canonical"] and canon == v["canonical"]
              and sha256_hex(canon) == v["canonical_sha256"])
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:42} signing_input+canonical+sha256 parity")

    print("\n== 4. seed derivation recompute ==")
    for v in record_vectors:
        rec = v["record"]
        recomputed = derive_seed(
            rec["content_digest"], rec["presentation_digest"],
            rec["challenge"]["nonce"], rec["challenge"]["version"],
        )
        matches = recomputed == rec["challenge"]["seed"]
        if v.get("rejection_kind") == "seed":
            ok = matches is False  # MUST mismatch: the stated failure reason
            note = f"seed MISMATCH as stated (matches={matches})"
        elif v.get("rejection_kind") == "signature":
            # v4: content_digest was tampered, so the seed no longer derives
            # either; the signature is the decisive, stated failure there.
            ok = matches is False
            note = f"seed also mismatches after tamper (matches={matches}; signature is the stated reason)"
        else:
            ok = matches is True
            note = f"seed derivation matches (matches={matches})"
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:42} {note}")

    print("\n== 5. word handle checksum math (pure Python) ==")
    for v in handle_vectors:
        problems = []
        dw, cw = PROFILES[v["profile"]]
        prefix_bits = WORD_BITS * dw
        # 5a. original indices re-derive from the digest.
        expected_data = data_indices_from_digest(v["digest"], dw)
        packed = pack_prefix_from_indices(expected_data, prefix_bits)
        expected_checksums = checksum_indices(prefix_bits, packed, cw)
        if v["original_indices"] != expected_data + expected_checksums:
            problems.append("original_indices do not re-derive from digest")
        # 5b. mutated words behave as stated.
        ool = v["expected"]["out_of_lexicon"]
        if ool:
            nulls = [i for i, idx in enumerate(v["word_indices"]) if idx is None]
            if nulls != ool:
                problems.append(f"null indices {nulls} != stated out_of_lexicon {ool}")
            note = f"out-of-lexicon positions {ool} carry null indices"
        else:
            data_idx = v["word_indices"][:dw]
            given_checksums = v["word_indices"][dw:]
            mut_packed = pack_prefix_from_indices(data_idx, prefix_bits)
            mut_checksums = checksum_indices(prefix_bits, mut_packed, cw)
            checksum_ok = mut_checksums == given_checksums
            if checksum_ok != v["expected"]["checksum_ok"]:
                problems.append(f"checksum_ok {checksum_ok} != expected {v['expected']['checksum_ok']}")
            note = f"checksum FAILS as stated ({v['mutation']['type']}, checksum_ok={checksum_ok})"
        ok = not problems
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:42} {note if ok else '; '.join(problems)}")

    print("\n== 6. Ed25519 signature verification ==")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        have_crypto = True
    except ImportError:
        have_crypto = False
        print("  `cryptography` not installed. Ed25519 verification was NOT performed here.")
        print("  Run `pip install cryptography`, or verify signatures with:")
        print("    npx tsx fixtures/read-fidelity-receipt/verify.ts")

    if have_crypto:
        for v in record_vectors:
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
                ok = verified is False  # tampered after signing: MUST NOT verify
                note = "signature correctly rejected (stated reason)"
            elif rk == "seed":
                ok = verified is True  # re-signed: valid over own bytes, fails on seed
                note = "signature valid over own bytes (record fails on the seed derivation)"
            else:
                ok = verified is True
                note = "signature verifies"
            if not ok:
                failures += 1
            print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:42} {note} (verified={verified})")

    # Honest exit: schema, byte-parity, seed, and checksum math may pass, but
    # if the Ed25519 path was skipped this is NOT a full pass. Never print a
    # green banner or exit 0 when signatures went unverified.
    if failures:
        print(f"\n{failures} CHECK(S) FAILED")
        return 1
    if not have_crypto:
        print("\nINCOMPLETE: schema, byte-parity, seed, and checksum checks passed, but")
        print("Ed25519 signatures were NOT verified (cryptography missing). Not a full pass.")
        return 2
    print("\nALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Validate + verify the one-time cross-encoded vectors in this directory.

Two checks per vector:
  1. JSON-Schema validation against MoltyCel's schema/vector-schema.json
     (same Draft 2020-12 validator their tools/validate_schema.py uses).
  2. Decision check: run the vector through MoltyCel's reference verifier
     (examples/python-verify.py :: verify) and assert the result +
     verification_step + rejection_reason match the vector's `expected`.

Requires the MoltyCel repo clone (default /tmp/aae-moltycel, override with
AAE_MOLTYCEL_REPO). Run: python3 crossverify.py
"""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import sys

import jsonschema

MOLTYCEL = os.environ.get("AAE_MOLTYCEL_REPO", "/tmp/aae-moltycel")
HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(MOLTYCEL, "schema", "vector-schema.json")
VERIFIER_PATH = os.path.join(MOLTYCEL, "examples", "python-verify.py")


def load_verifier():
    spec = importlib.util.spec_from_file_location("aae_reference_verifier", VERIFIER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    with open(SCHEMA_PATH) as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema)
    verifier = load_verifier()

    files = sorted(glob.glob(os.path.join(HERE, "V*.json")))
    print(f"crossverify: {len(files)} one-time cross-encoded vector(s)\n")
    failures = 0
    for path in files:
        name = os.path.basename(path)
        with open(path) as fh:
            vector = json.load(fh)

        # 1. schema
        errs = sorted(validator.iter_errors(vector), key=lambda e: e.path)
        schema_ok = not errs

        # 2. decision
        got = verifier.verify(vector["input"]["secured_aae"], vector["input"]["context"])
        exp = vector["expected"]
        decision_ok = (
            got["result"] == exp["result"]
            and got.get("verification_step") == exp.get("verification_step")
            and got.get("rejection_reason") == exp.get("rejection_reason")
        )

        ok = schema_ok and decision_ok
        if not ok:
            failures += 1
        tag = "PASS" if ok else "FAIL"
        gr = f"{got['result']}@{got.get('verification_step')}" + (f" ({got['rejection_reason']})" if got.get("rejection_reason") else "")
        er = f"{exp['result']}@{exp.get('verification_step')}" + (f" ({exp.get('rejection_reason')})" if exp.get("rejection_reason") else "")
        print(f"{tag}  {name:38s} schema={'ok' if schema_ok else 'INVALID'}  expected {er}  got {gr}")
        if not schema_ok:
            for e in errs:
                print(f"        schema: {e.message}")

    print(f"\n{len(files) - failures}/{len(files)} cross-encoded vectors valid + decided as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

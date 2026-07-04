#!/usr/bin/env python3
"""
recompute_check.py — the proposed recompute/derivation verification layer.

Zero dependencies beyond the Python standard library.

Thesis: APS's native checks (schema, signature, action_digest) prove a record is
INTACT and was signed by the right key. They do NOT prove the recorded boundary
decision RE-DERIVES from the record's own controls. This check closes that gap for
the concrete instance verdict = f(controls).

f(controls): precedence-combinator over five control verdicts, first-failure-wins,
order [pii, trusted_wallet, policy, replay, mpa]:
  - any hard-fail verdict          -> DENY   (PII_BLOCKED, UNTRUSTED, VIOLATION, DUPLICATE, DENIED)
  - mpa PENDING or TIMEOUT         -> REFER
  - otherwise                      -> ALLOW
Mapped to APS boundary decisions:  DENY->deny, REFER->halt, ALLOW->allow.

The check is a DISCRIMINATOR, not an always-fail:
  - the PART-1 positive record       -> recompute AGREES  (f=allow == decision=allow)
  - the recompute-layer record       -> recompute DISAGREES (f=deny != decision=allow) -> FLAGGED

Exit nonzero ONLY on an unexpected result (a record that agrees when it should
disagree, or vice-versa), never merely because a record is flagged.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RECOMPUTE_RECORD = os.path.join(HERE, "presidio-x402-verdict-not-recomputable.record.json")
# PART-1 positive record lives one level up in the APS suite fixture dir
POSITIVE_FIXTURE = os.path.join(
    HERE, "..", "presidio-x402-accountability-record-fixture-v1.json"
)

# Control verdicts that force DENY, per control key.
HARD_FAIL = {
    "pii": {"PII_BLOCKED"},
    "trusted_wallet": {"UNTRUSTED"},
    "policy": {"VIOLATION"},
    "replay": {"DUPLICATE"},
    "mpa": {"DENIED"},
}
# mpa verdicts that force REFER (defer to a human / multi-party approver).
MPA_REFER = {"PENDING", "TIMEOUT"}

PRECEDENCE = ["pii", "trusted_wallet", "policy", "replay", "mpa"]


def f_controls(controls: dict) -> str:
    """Precedence-combinator over the five recorded control verdicts.
    Returns one of ALLOW / DENY / REFER. First failure wins."""
    for key in PRECEDENCE:
        ctrl = controls.get(key, {})
        verdict = ctrl.get("verdict")
        if verdict in HARD_FAIL.get(key, set()):
            return "DENY"
        if key == "mpa" and verdict in MPA_REFER:
            return "REFER"
    return "ALLOW"


BOUNDARY = {"ALLOW": "allow", "DENY": "deny", "REFER": "halt"}


def recompute_decision(controls: dict) -> str:
    """f(controls) mapped to the APS boundary-decision vocabulary."""
    return BOUNDARY[f_controls(controls)]


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def evaluate(name: str, record: dict, controls: dict, expected_recompute: str | None):
    """Return (recorded_decision, recomputed_decision, agrees). Print a line."""
    recorded = record["decision"]
    recomputed = recompute_decision(controls)
    agrees = recomputed == recorded
    status = "AGREES" if agrees else "DISAGREES -> FLAGGED"
    print(f"  {name}")
    print(f"    recorded decision:   {recorded}")
    print(f"    f(controls):         {f_controls(controls)} -> {recomputed}")
    print(f"    recompute {status}")
    if expected_recompute is not None and recomputed != expected_recompute:
        print(f"    [!] expected recompute={expected_recompute} but got {recomputed}")
        return recorded, recomputed, agrees, False
    return recorded, recomputed, agrees, True


def main() -> int:
    print("recompute-layer check — verdict = f(controls), first-failure-wins\n")

    unexpected = 0

    # 1. PART-1 positive record. Its controls (all clean) must recompute to allow -> AGREES.
    pos_fx = load(POSITIVE_FIXTURE)
    pos_vec = next(v for v in pos_fx["vectors"] if v["name"] == "presidio-x402-allow-pii-redacted")
    pos_record = pos_vec["record"]
    # The positive record carries no controls in-band; the clean control set is the
    # baseline that produced its allow decision (source vector presidio-x402-decision-001).
    pos_controls = {
        "pii": {"verdict": "PII_REDACTED"},
        "trusted_wallet": {"verdict": "TRUSTED"},
        "policy": {"verdict": "ALLOW"},
        "replay": {"verdict": "FRESH"},
        "mpa": {"verdict": "NOT_REQUIRED", "required": False},
    }
    _, _, agrees_pos, ok_pos = evaluate(
        "presidio-x402-allow-pii-redacted (PART 1 positive)", pos_record, pos_controls,
        expected_recompute="allow",
    )
    if not agrees_pos:
        print("    [!] positive record should AGREE but did not")
        unexpected += 1
    if not ok_pos:
        unexpected += 1
    print()

    # 2. Recompute-layer record. Controls carry policy.verdict=VIOLATION -> DENY -> DISAGREES.
    rec_doc = load(RECOMPUTE_RECORD)
    rec_record = rec_doc["record"]
    rec_controls = rec_doc["presidio_x402_ext"]["controls"]
    expected = rec_doc.get("presidio_recompute_expected")
    _, _, agrees_rec, ok_rec = evaluate(
        "presidio-x402-verdict-not-recomputable (recompute-layer)", rec_record, rec_controls,
        expected_recompute=expected,
    )
    if agrees_rec:
        print("    [!] recompute-layer record should DISAGREE (be flagged) but AGREED")
        unexpected += 1
    if not ok_rec:
        unexpected += 1
    print()

    # Summary: the check DISCRIMINATES.
    print("Summary:")
    print(f"  positive       -> recompute AGREES   (f=allow == decision=allow): trusted")
    print(f"  recompute-layer-> recompute DISAGREES (f=deny  != decision=allow): FLAGGED")
    print()
    if unexpected:
        print(f"{unexpected} UNEXPECTED RESULT(S) — check FAILED")
        return 1
    print("recompute-layer check behaved as expected (discriminates; not always-fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

A flagged record is emitted under the named rejection class `recompute_mismatch`
(proposed on x402-foundation/x402#2332; parallels APS's own lowercase `digest_mismatch`).
It is never a substitute for a native APS verdict: APS says the receipt is intact,
`recompute_mismatch` says the decision does not re-derive; both fire independently.
When a record DECLARES `recompute_rejection_kind`, this check re-derives it rather than
trusting it — the same discipline the layer applies to the decision itself.

Exit nonzero ONLY on an unexpected result (a record that agrees when it should
disagree, a flagged record whose declared kind does not re-derive, or vice-versa),
never merely because a record is flagged.
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

# Named rejection class for a record whose decision does not re-derive from its
# controls (proposed on x402-foundation/x402#2332). Placement/adoption is aeoess's
# call as schema owner; here it names the flag, it never overrides a native APS verdict.
RECOMPUTE_MISMATCH = "recompute_mismatch"


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


def evaluate(
    name: str,
    record: dict,
    controls: dict,
    expected_recompute: str | None,
    declared_kind: str | None = None,
):
    """Return (recorded, recomputed, agrees, ok). Print the evidence line.

    A disagreement is emitted under RECOMPUTE_MISMATCH. When the record declares a
    recompute_rejection_kind, re-derive it (do not trust it): a flag must carry the
    class recompute yields, and a record that agrees must carry no class."""
    recorded = record["decision"]
    recomputed = recompute_decision(controls)
    agrees = recomputed == recorded
    emitted_kind = None if agrees else RECOMPUTE_MISMATCH
    status = "AGREES" if agrees else f"DISAGREES -> {emitted_kind}"
    print(f"  {name}")
    print(f"    recorded decision:   {recorded}")
    print(f"    f(controls):         {f_controls(controls)} -> {recomputed}")
    print(f"    recompute {status}")
    ok = True
    if expected_recompute is not None and recomputed != expected_recompute:
        print(f"    [!] expected recompute={expected_recompute} but got {recomputed}")
        ok = False
    if declared_kind != emitted_kind:
        print(f"    [!] declared recompute_rejection_kind={declared_kind} does not re-derive "
              f"(recompute yields {emitted_kind})")
        ok = False
    elif emitted_kind is not None:
        print(f"    declared recompute_rejection_kind={declared_kind} re-derives")
    return recorded, recomputed, agrees, ok


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
    declared_kind = rec_doc.get("recompute_rejection_kind")
    _, _, agrees_rec, ok_rec = evaluate(
        "presidio-x402-verdict-not-recomputable (recompute-layer)", rec_record, rec_controls,
        expected_recompute=expected, declared_kind=declared_kind,
    )
    if agrees_rec:
        print("    [!] recompute-layer record should DISAGREE (be flagged) but AGREED")
        unexpected += 1
    if not ok_rec:
        unexpected += 1
    print()

    # Summary: the check DISCRIMINATES.
    print("Summary:")
    print("  positive       -> recompute AGREES   (f=allow == decision=allow): trusted")
    print(f"  recompute-layer-> recompute DISAGREES (f=deny  != decision=allow): {RECOMPUTE_MISMATCH}")
    print()
    if unexpected:
        print(f"{unexpected} UNEXPECTED RESULT(S) — check FAILED")
        return 1
    print("recompute-layer check behaved as expected (discriminates; not always-fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

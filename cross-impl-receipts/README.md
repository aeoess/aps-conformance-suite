# cross-impl-receipts

Byte-faithful mirror of verifier receipts produced by the
[`arian-gogani/nobulex`](https://github.com/arian-gogani/nobulex) independent
implementation, kept here so A2A sponsorship reviewers can verify
cross-implementation evidence from two independent repositories without depending
on either maintainer to re-run anything.

## Source

- Upstream repo: `arian-gogani/nobulex`
- Upstream commit: `d68fcee827bf946414ab0669146403827bf59f51`
- Last synced: `2026-05-02T00:18:49Z`

## Files

| File | SHA-256 |
|---|---|
| `aps-byte-match-receipt.json`  | `a4d63359574a7408cac8dd3c132586cff611535c4c8f074ed3556a61cf165443` |
| `ctef-byte-match-receipt.json` | `2e8afc85080ed64fe539c913410f2343d10cba8c5b17f61cc8a7d19e4fa11216` |
| `ctef-vectors.json`            | `b655d1b3e7aeccb8b75517c1efc46d2dbf6759dea07581a1b39d4ab59baa7046` |

## Editorial role

**NONE.** This directory is a byte-faithful mirror. The files MUST NOT be
modified, reformatted, re-pretty-printed, or "cleaned up" here. If the upstream
artifacts change, the mirror is updated by re-fetching, not by hand-editing.

Any divergence between this mirror and upstream is a bug.

## Sync mechanism

TBD. Cadence pending coordination with `@arian-gogani` on
[A2A#1786](https://github.com/a2aproject/A2A/issues/1786) — choosing
between daily-poll and webhook-on-push.

A skeleton GitHub Action lives at
`.github/workflows/sync-cross-impl-receipts.yml.disabled`. The `.disabled`
suffix is intentional: the workflow is **not** active until cadence is agreed.
When enabled, it opens a PR on diff and never auto-merges.

Until automation is enabled, sync is manual: re-run the fetch + hash check
below, update the timestamp + commit SHA in this README, and commit on a new
branch.

## Verify locally

Confirm the files in this mirror match upstream byte-for-byte:

```bash
for f in aps-byte-match-receipt.json ctef-byte-match-receipt.json ctef-vectors.json; do
  diff -q \
    <(curl -fsSL "https://raw.githubusercontent.com/arian-gogani/nobulex/main/$f") \
    "$f" \
    && echo "OK $f" || echo "DIVERGED $f"
done
```

Run from inside this directory. `OK` for all three means the mirror is faithful
to the current `main` of the upstream repo. If you see `DIVERGED`, the mirror
is stale relative to upstream `main` (expected between sync runs); compare
against the pinned upstream commit SHA above for the authoritative match.

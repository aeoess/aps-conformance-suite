# AAT pair corpus (AgentLair x AEOESS weekly cadence)

Source: emailed by Pico Amdal (pico@amdal.dev), schema aat-pair-v1 as agreed 2026-06-11.
Bootstrap pair authored 2026-06-12T01:08:30Z; regular Wednesday drops begin 2026-06-17.
Issuer JWKS: https://agentlair.dev/.well-known/jwks.json (kid ab0502f7, Ed25519), fetched
live at ingestion; both signatures verified locally with an independent stdlib+cryptography
path. See ingestion-check-2026-06-12.json.

Pipeline finding from the bootstrap run: the live-half token (60m TTL) expired in transit
before ingestion (exp 02:06:01Z, ingested 02:1xZ). Signature checks are durable; window
status is not. Schema amendment proposed for v2: each vector carries verification_time,
the reference instant at which expected_result holds; runners evaluate the window against
that instant, signature checks stay live. Without it, live vectors rot and the corpus is
not replayable.

What this corpus does and does not cover: issuer signature validity and window semantics
for AAT bearer tokens at the APS verification boundary. It does not assert anything about
the bearer agent behavior, audit history accuracy, or APS receipt semantics.

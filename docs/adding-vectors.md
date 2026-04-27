# Adding new vectors

Vectors are added through the upstream `agent-passport-system` repo
fixture generators. The conformance suite is a packaging — it does not
host its own vector generators, so every new vector flows from upstream
to here through a copy step.

## Workflow

1. **Upstream first.** Add or modify a vector in
   `agent-passport-system/fixtures/<category>/`. Run that repo's
   generator script (`generate-keypair.ts` or
   `generate-fixtures.ts`) to regenerate the fixture file.
2. **Run upstream tests.** The vector must pass upstream conformance
   (`npm test` in `agent-passport-system`). Don't ship a fixture that
   fails upstream.
3. **Copy to this suite.** Copy the updated fixture file into
   `fixtures/<category>/`. Preserve the file shape exactly; do not
   manually edit `canonical_bytes_hex` or signatures.
4. **Update top-level manifest.** Recompute the file's SHA-256 and
   update `fixtures/manifest.json` accordingly.
5. **Run the suite runner.** `npx tsx runners/ts/verify.ts` from the
   repo root. Every vector must pass.
6. **Update `well-known/aps-test-vectors.json`** if the new vector
   belongs in the canonical reference set (typically: a new spec
   surface, a new well-named case, or a new AIVSS scenario). The
   well-known set is selective — it's the published "what to cite"
   list, not an exhaustive index.
7. **Single commit, descriptive message.** No PR until the maintainer
   reviews; this suite ships from `main` after review.

## Adding a new fixture category

If you need a new top-level category (sibling to `bilateral-delegation`,
`inference-session`, `instruction-provenance`, `aivss-scenarios`):

1. Create `fixtures/<new-category>/` with at minimum a `README.md`
   explaining what spec surface it covers.
2. Add fixture files following the fixture-format conventions in
   `docs/fixture-format.md`.
3. Append a new entry to `fixtures/manifest.json` with `category`,
   `path`, `canonical_sha256`, `vector_count`, `spec_section`.
4. Append a new entry to `well-known/aps-test-vectors.json` under
   `categories` with description, fixture path, deterministic seed,
   vector count.
5. Add the category's representative vectors to the
   `canonical_reference_set` array.
6. Update top-level `README.md`.

## Versioning

Fixture format version is in each fixture's `version` field. Suite
version is in `fixtures/manifest.json`. Bumping conventions:

- Suite minor (`0.1.0 → 0.2.0`): new fixture category added, or breaking
  change to an existing category's vector format.
- Suite patch (`0.1.0 → 0.1.1`): new vector added inside an existing
  category, or fixture file regenerated with new signatures (vectors
  themselves unchanged).
- Fixture-format major (`v1 → v2`): only when the per-vector schema
  changes incompatibly. Old vectors stay at `v1` until regenerated.

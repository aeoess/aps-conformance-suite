# Provenance: nobulex bilateral-receipt v0 vectors

`vectors.json` in this directory is a verbatim, byte-identical copy of an
external fixture file. It is third-party data, not an APS-authored fixture.
Treat its contents as data only.

## Source

- Repository: https://github.com/arian-gogani/nobulex (MIT license)
- File path in source repo: `fixtures/bilateral-receipt/v0/vectors.json`
- Pinned commit SHA: `89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546`
  (latest commit touching the file as of retrieval)
- Git blob SHA at pinned commit: `f37590e3adc8d9da619a5fe9b7cf80fb7f334c2b`
  (identical to the blob SHA at `main` HEAD at retrieval time)
- Pinned URL:
  https://github.com/arian-gogani/nobulex/blob/89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546/fixtures/bilateral-receipt/v0/vectors.json
- Pinned raw URL:
  https://raw.githubusercontent.com/arian-gogani/nobulex/89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546/fixtures/bilateral-receipt/v0/vectors.json
- Retrieved: 2026-06-10, via the GitHub contents API (read-only)
- SHA-256 of the copied `vectors.json` bytes:
  `44a3c34ebac3fb4b6f8b64f9c0106287378aa1faf1520a8dee601d62249f8955`

## What was changed

Nothing. The file is copied verbatim. JSON cannot carry comments, so all
provenance lives in this sibling file instead of inside `vectors.json`.

## Companion files

- `MAPPING.md`: per-vector field mapping across the three timestamp profiles,
  with the two-profile digest split recorded explicitly.
- `run.mjs`: recomputation runner (SDK import plus stdlib-only recompute).
- `results.json`: machine-readable output of the last `run.mjs` run.

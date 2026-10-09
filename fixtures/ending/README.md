# KERI `Signature` header reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/end/ending.ts`, `test/end/ending.test.ts`
- Binary fields: none. Every value is header text, which is ASCII by construction; the signature
  material is qualified Base64.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/ending.mjs --write   # regenerate
node tools/reference-vectors/ending.mjs --check   # verify determinism
```

## Provenance of the signature material

`signers` records exactly what the pinned `test/end/ending.test.ts` uses: the raw 16-byte salt
`0123456789abcdef`, the three derivation paths `Hilga00`–`Hilga02`, the low tier, and the
temporary Argon2 profile (the reference's `temp` flag). The Rust test re-derives all three signers
from that salt, signs the same recorded text, and asserts it obtains the same verification keys and
the same indexed and unindexed signatures before it builds a single header — so the vectors are
proven end to end rather than copied. No secret is stored: the salt is the test's own public
constant.

## Contents

`cases` records seven headers with their inputs, exact bytes, and the reference's own re-parse of
those bytes:

- `indexed_default_tags` — each marker is tagged with its signature's index.
- `named_indexed` — explicit tags (`siger0`…) replace those defaults.
- `indexed_cesr_full` — every parameter present, in the order the reference writes them.
- `unindexed_default_tags` — each marker is tagged with the verification key that verifies it.
- `combined` — two signages in one header, which is how repeated headers merge.
- `authing_single_named_unindexed` — one named unindexed marker: the only shape
  `core/authing.ts` ever sends, and therefore the shape every request carries.
- `opaque_kind` — a non-CESR `kind`, whose marker values stay uninterpreted.

Each case's `reparsed` block is the reference reading those exact bytes back and recovering the
parameters and markers. Because the Rust test asserts its own rendering equals `header` first, that
records the reverse direction as well.

## Reference behavior recorded as safe Rust divergences

- **A tag forges header fields.** Tags are interpolated unescaped, so the tag `a";b="c` renders
  `…;a";b="c="AACs…"`, whose extra `b=` item a parser reads as a real field. Rust validates tags
  and values as `FieldText`, which excludes every delimiter.
- **A value forges header fields.** The same for values: the recorded header carries two `indexed`
  items, the second injected by a marker value.
- **Only the first space is removed.** `String.replace` with a string argument replaces one
  occurrence, so a second space survives — the fixture records it becoming part of the tag ` 1`,
  and records a header with a space before a later `indexed` failing to parse at all. keripy's
  `str.replace` removes them all. Rust skips whitespace around the `,` and `;` separators, which is
  what both implementations mean.
- **An item without a value crashes.** `designature('indexed="?1";garbage')` raises a `TypeError`
  by dereferencing the missing half, as does the empty string. Rust returns `MalformedItem`.
- **A value containing `=` is truncated**, and **quotes are stripped from anywhere** — the two
  cases where signify-ts and keripy disagree about the same header. Rust refuses both.
- **The `indexed` flag is true unless it matches `FALSY`.** `FALSY`'s `false` and `0` entries are a
  JavaScript boolean and number that a parsed string can never equal, so `indexed="0"` is read as
  **true**; so are `maybe` and the empty string. Rust accepts only the ten strings the reference's
  own tables can match. (keripy's `TRUTHY` has a related defect — `"yes" "true"` concatenates to
  `yestrue` — but it is unused, since only `FALSEY` is consulted.)
- **A repeated tag drops a signature.** Items are collected into a `Map`, so the second silently
  replaces the first.
- **A marker tagged as a parameter disappears.** Parameters are read out of the same map as the
  markers, so a marker tagged `signer` becomes the `signer` parameter and leaves no marker behind.
  Rust reserves the five parameter names.
- **An empty signage is accepted** in both directions, asserting nothing at all.
- **The flag can contradict the markers.** `indexed` is a separate argument, so an indexed
  signature with `indexed` false throws, as does an unindexed one with `indexed` true, and an
  unindexed marker with no verification key has nothing to build its default tag from. In Rust the
  flag is derived from the marker variant, so the first two states are unrepresentable and the
  third is a typed error at construction.

Rust tests consume the checked-in fixture and require neither Node nor network access.

# KERI request-authentication reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-19
- Sources: `src/keri/core/httping.ts`, `src/keri/core/authing.ts`, `test/core/httping.test.ts`,
  `test/core/authing.test.ts`
- Binary fields: none. Every value is header text or a signature base, which is UTF-8; the
  signature material is qualified Base64.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/http_authing.mjs --write   # regenerate
node tools/reference-vectors/http_authing.mjs --check   # verify determinism
```

## How the signature base is captured

`siginput` and `Authenticater.verify` never return the bytes they sign or check — the base is a
local variable in both. The generator therefore injects a **recording** signer and a **recording**
verifier: each is a thin object that captures the bytes it is handed and then delegates to the real
key. Every `signature_base` in this fixture is consequently the reference's own output, so the Rust
tests compare canonicalization directly rather than inferring it from a matching signature.

## Determinism

`siginput` reads the wall clock through `nowUTC()`, which is `new Date()`. The pinned unit tests
freeze it with `vitest.spyOn(utilApi, 'nowUTC')`; this generator freezes the global `Date` to the
same instant, `2021-01-01T00:00:00.000Z`, so `created` is the `1609459200` those tests assert. The
`clock` block records both.

## Provenance of the signature material

`signer` records what both pinned tests use: the raw 16-byte salt `0123456789abcdef` and
`salter.signer()`'s defaults — an Ed25519 seed, transferable, an empty derivation path, the low
tier, and the production Argon2 profile. The Rust test re-derives that signer from the salt and
asserts it obtains the same verification key before it builds a single header, so the vectors are
proven end to end rather than copied. No secret is stored: the salt is the tests' own public
constant.

## Contents

`siginput_cases` records seven `siginput` calls with their inputs, the exact base signed, the exact
`Signature-Input` emitted, the resulting signature, and the reference's own re-parse of those bytes:

- `httping_unit_test` — the pinned `test/core/httping.test.ts` case, whose asserted signature
  `0BAJWoDv…` the Rust test reproduces. Its covered list is mixed-case, which the base keeps
  verbatim.
- `derived_components_only` — only `@method` and `@path`.
- `header_components_only` — no derived component at all.
- `every_parameter` — all six parameters, pinning their order in both the header and the base.
- `no_parameters` — only the mandatory `created`.
- `percent_encoded_path` — a path carrying percent escapes, written verbatim.
- `latin1_header_value` — a covered value outside ASCII. An HTTP field value is a `ByteString`, so
  the reference's own collection refuses anything above Latin-1 outright; a Latin-1 value is
  accepted and then UTF-8 encoded into the signed bytes.

`authenticator_sign_cases` records two `Authenticater.sign` calls, including the pinned
`test/core/authing.test.ts` case whose asserted `Signature-Input` and `Signature`
(`0BChvN_BW…`) the Rust test reproduces byte for byte.

`authenticator_verify_cases` records three `Authenticater.verify` calls against the pinned
response: the one that verifies, and the same response checked against a different path and a
different method. Each records the base the reference reconstructed, which the Rust test rebuilds.

`desiginput_cases` records three parses, including the pinned unit test's, and
`two_entry_dictionary` pins the exact spelling the reference's serializer gives a two-member
dictionary — a comma and a space.

## Reference behavior recorded as safe Rust divergences

- **`created` comes from the system clock.** A message and its signature depend on when they were
  built. In Rust `created` is a required parameter, as the reply timestamp became in Roadmap 3.6.
- **An absent covered header is dropped.** On the signing side it disappears from the base *and*
  from the covered list, so a caller silently gets a weaker signature than it asked for; on the
  verifying side the field stays listed while only its item disappears, so the reconstructed base
  matches no signer. Rust returns `MissingCoveredHeader`.
- **An unknown derived component covers nothing.** Only `@method` and `@path` are implemented, so a
  covered list naming `@authority` advertises coverage the signature does not provide. Rust's
  `SignatureComponent` has exactly three variants.
- **A parameter is escaped in the header but not in the base.** `serializeDictionary` escapes `"`
  and `\`; the base interpolates the raw text. The fixture records `keyid=a"b\c` in the base
  against `keyid="a\"b\\c"` in the header — the two disagree about the key identifier.
- **A parameter containing a semicolon forges a parameter.** The base joins parameters with `;`, so
  the recorded `keyid="a;alg=forged"` produces a base carrying two `alg` parameters.
- **A path containing a newline forges a line.** The base joins items with `\n` and the path is
  interpolated unvalidated; the recorded base gains a whole forged `"@method": DELETE` line that
  the header does not show. `RequestTarget` validates both method and path.
- **An empty covered list is accepted**, binding neither method, path, nor any header.
- **Field names keep their case** in the covered list and the base while header lookup ignores it.
  keripy lower-cases the name instead, so a mixed-case covered list does not interoperate between
  the two implementations; Rust follows signify-ts and `default_components()` uses the lower-case
  spellings `Authenticater.DefaultFields` already uses.
- **Duplicate headers are joined** with `", "` by the browser collection, silently changing the
  base. `Headers` refuses a repeated name.
- **`desiginput` requires `created`** and **rejects a malformed dictionary** — the two
  reference-rejected vectors, recorded with the reference's own thrown error.
- **A duplicate label replaces the earlier input**, since a dictionary keeps only the last member
  with a given key. Rust returns `DuplicateLabel`.
- **`verify` hardcodes the `signify` label**, so a correctly signed message under any other label
  is reported unverified rather than checked. The label is a constructor parameter in Rust.
- **`verify` reads only the first signage**, so a signature carried in a later one is invisible.
  Rust searches every signage and requires exactly one match.
- **`verify` returns `false` for a missing header and throws for a bad signature**, so a caller has
  two failure shapes for one question. Rust returns a distinct error variant per failure.

Rust tests consume the checked-in fixture and require neither Node nor network access.

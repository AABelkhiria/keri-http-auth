# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the version and platform you were using, something we can run to
reproduce it, and what you think the impact is. If secret material was involved, say so, but please
generate throwaway keys for the report. Never send real seeds, salts, private keys or passcodes.

## Threat model

Everything parsed from outside is assumed hostile: header names and values, `Signature` and
`Signature-Input` header text, request methods and paths, covered-component lists, and signature
material carried in a header.

The sensitive material is the Ed25519 signer a `RequestSigner` holds. It is keri-cesr's `Signer`,
which redacts its `Debug` output, exposes no raw-byte accessor and zeroes its buffer on drop; this
crate never copies it out.

Given that, the implementation is built to hold up against a few specific things.

Malformed input shouldn't be able to panic or abort the process, so crate-owned code contains no
`unsafe`, `unwrap`, `expect`, panicking macro, or indexing that can fail, and every rejection is a
typed error. Every parser enforces an explicit ceiling (for example `MAX_HEADER_VALUE_BYTES`,
`MAX_HEADER_BYTES`, `MAX_SIGNATURE_INPUT_BYTES`, `MAX_SIGNATURE_BASE_BYTES` and `MAX_COMPONENTS`)
before it allocates from a size the input declares.

The grammar is strict, because the signature base is built from what the headers say. Tags and
values exclude every delimiter, so a header cannot be forged through a field; a repeated header
name, a repeated signature label, an item without a value, and a flag outside the reference's own
tables are all refused rather than normalized. A covered header that is absent is an error, never
silently dropped from the base.

Signature verification goes through keri-cesr's Ed25519 verification and reports one typed error
per failure. Only the `Signature-Input` that names the expected label is checked, and exactly one
must match.

## Randomness

This crate takes no entropy. Key material comes from the caller, and `created` is a parameter, so
nothing here reads a clock or a random source.

## Known limitations

Replay is not detected here. `created` is handed back to the caller and freshness is the
transport's policy; a correctly signed message is accepted whenever it was made.

Only the client half exists: signing a request and verifying a response. Verifying a request and
signing a response, which a KERIA agent needs, are not provided yet.

Interoperability is pinned to signify-ts. Where signify-ts and keripy disagree about the same
header, both spellings are refused rather than one of them being chosen.

## Dependencies

The one production dependency is `keri-cesr`, with its `crypto` feature, written and maintained by
this crate's author. `cargo deny` and the resolved graph get reviewed before each release.

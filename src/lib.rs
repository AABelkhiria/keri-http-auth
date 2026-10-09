//! KERI HTTP message signatures and request authentication.
//!
//! [`fields`] formats and parses the `Signature` header, which carries the signature material.
//! [`input`] formats and parses the `Signature-Input` header and derives the exact bytes a signature
//! covers. [`authentication`] composes both with a key, to sign a request and to verify a response.
//! [`timestamp`] formats the `Signify-Timestamp` header, and [`header`] holds the validated header
//! names and values the others read and write.

#![forbid(unsafe_code)]

pub mod authentication;
pub mod fields;
pub mod header;
pub mod input;
pub mod timestamp;

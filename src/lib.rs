//! Transport abstractions, HTTP signatures, request construction, and response handling.

#![forbid(unsafe_code)]

pub mod header;
pub mod request;
pub mod response;
pub mod signature;
pub mod transport;

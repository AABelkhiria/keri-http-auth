#![no_main]
#![forbid(unsafe_code)]

//! A server verifies whatever a peer sends: arbitrary bytes drive the four headers, method and path.

use std::time::SystemTime;

use keri_cesr::crypto::verifier::VerificationKey;
use keri_http_auth::header::{HeaderName, HeaderValue, Headers};
use keri_http_auth::input::{RequestTarget, SignatureInputHeader};
use keri_http_auth::server::{KeyLookup, RequestVerifier, canonical_path};
use libfuzzer_sys::fuzz_target;

const KEY: &str = "DAFFYufJkgED00EwDPDUfQ2jYT_kOkGKYRGYxySX_VjW";
const NAMES: [&str; 4] = ["Signature-Input", "Signature", "Signify-Resource", "Signify-Timestamp"];

struct AnyController;

impl KeyLookup for AnyController {
    fn first_current_key(&self, _controller: &str) -> Option<VerificationKey> {
        VerificationKey::from_qb64(KEY).ok()
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\n');
    let method = parts.next().unwrap_or_default();
    let path = canonical_path(parts.next().unwrap_or_default());

    let mut headers = Headers::new();
    for name in NAMES {
        let value = parts.next().unwrap_or_default();
        if let (Ok(name), Ok(value)) = (HeaderName::new(name), HeaderValue::new(value)) {
            let _ = headers.insert(name, value);
        }
    }
    if let Some(value) = headers.get("Signature-Input")
        && SignatureInputHeader::parse(value).is_ok()
    {
        assert!(SignatureInputHeader::parse_received(value).is_ok());
    }
    if let Ok(target) = RequestTarget::new(method, &path) {
        let verifier = RequestVerifier::new(AnyController);
        let _ = verifier.verify(&target, &headers, SystemTime::UNIX_EPOCH);
    }
});

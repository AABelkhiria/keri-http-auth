//! Microbenchmark for verifying one request, which a server does on every call.

use std::hint::black_box;
use std::time::SystemTime;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keri_http_auth::authentication::RequestSigner;
use keri_http_auth::header::{HeaderName, HeaderValue, Headers};
use keri_http_auth::input::{RequestTarget, default_components};
use keri_http_auth::server::{KeyLookup, RequestVerifier};

const CONTROLLER: &str = "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs";

struct OneKey(VerificationKey);

impl KeyLookup for OneKey {
    fn first_current_key(&self, _controller: &str) -> Option<VerificationKey> {
        Some(self.0.clone())
    }
}

fn setup() -> Option<(RequestVerifier<OneKey>, RequestTarget, Headers)> {
    let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?;
    let signer = salt
        .derive_signer_with_profile(
            "bench",
            KeyTransferability::Transferable,
            KeyDerivationProfile::Temporary,
        )
        .ok()?;
    let key = VerificationKey::from_qb64(&signer.verifier().qb64().ok()?).ok()?;
    let signer = RequestSigner::new(signer);

    let mut headers = Headers::new();
    for (name, value) in [
        ("Signify-Resource", CONTROLLER),
        ("Signify-Timestamp", "2022-09-24T00:05:48.196795+00:00"),
    ] {
        headers
            .insert(HeaderName::new(name).ok()?, HeaderValue::new(value).ok()?)
            .ok()?;
    }
    let target = RequestTarget::new("POST", "/identifiers").ok()?;
    let input = signer.signature_input(default_components().ok()?, 1_609_459_200).ok()?;
    signer.sign(&input, &target, &headers).ok()?.apply(&mut headers).ok()?;
    Some((RequestVerifier::new(OneKey(key)), target, headers))
}

fn benchmark_server(criterion: &mut Criterion) {
    let Some((verifier, target, headers)) = setup() else {
        return;
    };
    criterion.bench_function("verify_request", |bencher| {
        bencher.iter(|| verifier.verify(black_box(&target), black_box(&headers), SystemTime::UNIX_EPOCH));
    });
}

criterion_group!(benches, benchmark_server);
criterion_main!(benches);

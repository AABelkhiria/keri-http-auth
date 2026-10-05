//! Microbenchmarks for request authentication.
//!
//! Every request a Signify client sends is canonicalized, signed, and gets two headers rendered;
//! every response it receives is canonicalized again, parsed, and verified. Both sit on the hot
//! path of the whole SDK, and both run over attacker-influenced content. The measured shapes are
//! the ones KERIA traffic actually uses: the four components of `Authenticater.DefaultFields` over
//! a five-header message.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{RequestTarget, SignatureInputHeader, default_components};

/// The headers a KERIA request carries, two of which the signature covers.
const HEADERS: [(&str, &str); 5] = [
    ("Content-Type", "application/json"),
    ("Content-Length", "256"),
    ("Connection", "close"),
    ("Signify-Resource", "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"),
    ("Signify-Timestamp", "2022-09-24T00:05:48.196795+00:00"),
];

const CREATED: u64 = 1_609_459_200;

fn build_headers() -> Option<Headers> {
    let mut headers = Headers::new();
    for (name, value) in HEADERS {
        headers
            .insert(HeaderName::new(name).ok()?, HeaderValue::new(value).ok()?)
            .ok()?;
    }
    Some(headers)
}

fn benchmark_authing(criterion: &mut Criterion) {
    // Key derivation is setup, not the subject: the temporary Argon2 profile keeps it out of the
    // measurement entirely.
    let (Ok(salt), Some(headers), Ok(target)) = (
        Salt::from_raw(b"0123456789abcdef", SecurityTier::Low),
        build_headers(),
        RequestTarget::new("POST", "/boot"),
    ) else {
        return;
    };
    let Ok(signer) =
        salt.derive_signer_with_profile("", KeyTransferability::Transferable, KeyDerivationProfile::Temporary)
    else {
        return;
    };
    let signer = RequestSigner::new(signer);
    let (Ok(components), Ok(key)) = (default_components(), signer.key_identifier()) else {
        return;
    };
    let Ok(input) = signer.signature_input(components, CREATED) else {
        return;
    };
    let Ok(verification_key) = VerificationKey::from_qb64(key.as_str()) else {
        return;
    };

    // 289 bytes of signature base over four covered components.
    if let Ok(base) = input.signature_base(&target, &headers) {
        criterion.bench_function("authing_signature_base_four_components", |bencher| {
            bencher.iter(|| black_box(input.signature_base(black_box(&target), black_box(&headers))));
        });
        let _ = black_box(base);
    }

    criterion.bench_function("authing_sign_request", |bencher| {
        bencher.iter(|| black_box(signer.sign(black_box(&input), black_box(&target), black_box(&headers))));
    });

    let Ok(attached) = signer.sign(&input, &target, &headers) else {
        return;
    };
    let mut authenticated = headers.clone();
    if attached.apply(&mut authenticated).is_err() {
        return;
    }
    let verifier = ResponseVerifier::new(verification_key);
    criterion.bench_function("authing_verify_response", |bencher| {
        bencher.iter(|| black_box(verifier.verify(black_box(&target), black_box(&authenticated))));
    });

    let value = attached.signature_input().to_owned();
    criterion.bench_function("authing_parse_signature_input", |bencher| {
        bencher.iter(|| black_box(SignatureInputHeader::parse(black_box(&value))));
    });

    if let Ok(header) = SignatureInputHeader::parse(&value) {
        criterion.bench_function("authing_render_signature_input", |bencher| {
            bencher.iter(|| black_box(header.to_header_value()));
        });
    }
}

criterion_group!(benches, benchmark_authing);
criterion_main!(benches);

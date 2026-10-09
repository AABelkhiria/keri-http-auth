//! Microbenchmarks for the `Signature` header format.
//!
//! Every authenticated request renders one header, and every authenticated response parses one, so
//! both sit on the hot path of the whole SDK. The single-marker case is what `authing` actually
//! sends; the three-signature case is the multi-key shape the upstream tests use.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_http_auth::fields::{
    FieldText, IndexedMarker, SignageBuilder, SignageMarkers, SignatureHeader, UnindexedMarker,
};

const SIGERS: [&str; 3] = [
    "AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN",
    "ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA",
    "ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",
];
const CIGAR: &str = "0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";
const VERFER: &str = "DAi2TaRNVtGmV8eSUvqHIBzTzIgrQi57vKzw5Svmy7jw";

fn benchmark_ending(criterion: &mut Criterion) {
    let (Ok(cigar), Ok(key), Ok(tag)) = (
        UnindexedSignature::from_qb64(CIGAR),
        VerificationKey::from_qb64(VERFER),
        FieldText::new("signify"),
    ) else {
        return;
    };
    let Ok(signed) = cigar.with_verifier(key) else { return };

    // One named unindexed marker: exactly what a signed request carries.
    if let Ok(marker) = UnindexedMarker::named(tag, signed.clone())
        && let Ok(signage) = SignageBuilder::new(SignageMarkers::Unindexed(vec![marker])).build()
        && let Ok(header) = SignatureHeader::new(vec![signage])
        && let Ok(rendered) = header.to_header_value()
    {
        criterion.bench_function("ending_render_request_header", |bencher| {
            bencher.iter(|| black_box(&header).to_header_value());
        });
        criterion.bench_function("ending_parse_request_header", |bencher| {
            bencher.iter(|| SignatureHeader::parse(black_box(&rendered)));
        });
    }

    // Three indexed signatures with every parameter: the widest shape the upstream tests use.
    let markers: Option<Vec<IndexedMarker>> = SIGERS
        .iter()
        .map(|qb64| IndexedSignature::from_qb64(qb64).ok().map(IndexedMarker::new))
        .collect();
    if let (Some(markers), Ok(prefix)) = (markers, FieldText::new("EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-"))
        && let Ok(signage) = SignageBuilder::new(SignageMarkers::Indexed(markers))
            .signer(prefix.clone())
            .ordinal(prefix.clone())
            .digest(prefix)
            .build()
        && let Ok(header) = SignatureHeader::new(vec![signage])
        && let Ok(rendered) = header.to_header_value()
    {
        criterion.bench_function("ending_render_three_indexed", |bencher| {
            bencher.iter(|| black_box(&header).to_header_value());
        });
        criterion.bench_function("ending_parse_three_indexed", |bencher| {
            bencher.iter(|| SignatureHeader::parse(black_box(&rendered)));
        });
    }
}

criterion_group!(benches, benchmark_ending);
criterion_main!(benches);

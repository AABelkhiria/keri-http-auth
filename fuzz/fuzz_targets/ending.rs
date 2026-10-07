#![no_main]
#![forbid(unsafe_code)]

use keri_cesr::crypto::signature::IndexedSignature;
use libfuzzer_sys::fuzz_target;
use signify_http::signature::fields::{
    FieldText, IndexedMarker, MAX_FIELD_TEXT_BYTES, MAX_HEADER_BYTES, RESERVED_FIELDS, SignageBuilder, SignageMarkers,
    SignatureFieldError, SignatureHeader,
};

/// One signature pinned by `fixtures/http-ending/v1.json`, used to build headers around fuzzed tags.
const SIGER: &str = "AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    // 1. The parser runs on whatever a peer sends. Nothing may panic, every rejection must be a
    //    typed error, and anything accepted must already be canonical.
    match SignatureHeader::parse(text) {
        Ok(header) => {
            assert!(text.len() <= MAX_HEADER_BYTES, "an oversized header was accepted");
            match header.to_header_value() {
                Ok(rendered) => {
                    assert!(!rendered.contains(' '), "a rendered header carries whitespace");
                    match SignatureHeader::parse(&rendered) {
                        Ok(reparsed) => assert_eq!(reparsed, header, "a header did not survive reparsing"),
                        Err(error) => panic!("a rendered header failed to parse: {error}"),
                    }
                    // Every signage carries at least one marker and one `indexed` flag, so the
                    // rendered form always has at least one delimiter per signage.
                    for signage in header.signages() {
                        assert!(!signage.markers().is_empty(), "an empty signage was accepted");
                    }
                    assert_eq!(rendered.matches(',').count(), header.signages().len() - 1);
                }
                Err(SignatureFieldError::HeaderTooLong { .. }) => {}
                Err(error) => panic!("a parsed header failed to render: {error}"),
            }
        }
        Err(
            SignatureFieldError::HeaderTooLong { .. }
            | SignatureFieldError::MalformedItem { .. }
            | SignatureFieldError::MissingIndexedField
            | SignatureFieldError::InvalidIndexedFlag { .. }
            | SignatureFieldError::DuplicateField { .. }
            | SignatureFieldError::ReservedTag { .. }
            | SignatureFieldError::NoMarkers
            | SignatureFieldError::NoSignages
            | SignatureFieldError::KindMismatch { .. }
            | SignatureFieldError::EmptyFieldText
            | SignatureFieldError::FieldTextTooLong { .. }
            | SignatureFieldError::InvalidFieldText { .. }
            | SignatureFieldError::MissingVerificationKey
            | SignatureFieldError::Crypto { .. },
        ) => {}
        Err(error) => panic!("unexpected parse failure: {error}"),
    }

    // 2. Tags come from callers and are the reference's injection vector: whatever this module
    //    accepts must render a header with exactly one marker and no forged parameters.
    match FieldText::new(text) {
        Ok(tag) => {
            assert!(!text.is_empty() && text.len() <= MAX_FIELD_TEXT_BYTES);
            assert_eq!(tag.as_str(), text, "a tag was not stored verbatim");
            let Ok(signature) = IndexedSignature::from_qb64(SIGER) else {
                return;
            };
            match IndexedMarker::named(tag, signature) {
                Ok(marker) => {
                    let Ok(signage) = SignageBuilder::new(SignageMarkers::Indexed(vec![marker])).build() else {
                        return;
                    };
                    let Ok(header) = SignatureHeader::new(vec![signage]) else {
                        return;
                    };
                    let Ok(rendered) = header.to_header_value() else {
                        return;
                    };
                    // One `indexed` item and one marker item, whatever the tag contains.
                    assert_eq!(rendered.matches(';').count(), 1, "a tag forged a field: {rendered}");
                    assert_eq!(rendered.matches(',').count(), 0, "a tag forged a signage: {rendered}");
                    assert_eq!(rendered.matches('=').count(), 2, "a tag forged an item: {rendered}");
                    match SignatureHeader::parse(&rendered) {
                        Ok(reparsed) => {
                            assert_eq!(reparsed, header);
                            let recovered = reparsed.signages().first().map(|signage| signage.markers().len());
                            assert_eq!(recovered, Some(1), "a tag changed the marker count");
                        }
                        Err(error) => panic!("a tagged header failed to parse: {error}"),
                    }
                }
                Err(SignatureFieldError::ReservedTag { .. }) => {
                    assert!(RESERVED_FIELDS.contains(&text), "a usable tag was refused as reserved");
                }
                Err(error) => panic!("unexpected marker failure: {error}"),
            }
        }
        Err(
            SignatureFieldError::EmptyFieldText
            | SignatureFieldError::FieldTextTooLong { .. }
            | SignatureFieldError::InvalidFieldText { .. },
        ) => {}
        Err(error) => panic!("unexpected tag failure: {error}"),
    }
});

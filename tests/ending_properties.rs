//! Property and invalid-near-miss coverage for the `Signature` header format.

use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use proptest::{prelude::*, test_runner::TestCaseError};
use signify_http::signature::fields::{
    FieldText, IndexedMarker, MAX_FIELD_TEXT_BYTES, RESERVED_FIELDS, Signage, SignageBuilder, SignageMarkers,
    SignatureFieldError, SignatureHeader, UnindexedMarker,
};

/// Signature material pinned by `fixtures/http-ending/v1.json`.
const SIGERS: [&str; 3] = [
    "AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN",
    "ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA",
    "ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",
];
const CIGARS: [&str; 3] = [
    "0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN",
    "0BDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA",
    "0BDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",
];
const VERFERS: [&str; 3] = [
    "DAi2TaRNVtGmV8eSUvqHIBzTzIgrQi57vKzw5Svmy7jw",
    "DNK2KFnL0jUGlmvZHRse7HwNGVdtkM-ORvTZfFw7mDbt",
    "DDvIoIYqeuXJ4Zb8e2luWfjPTg4FeIzfHzIO8lC56WjD",
];
const PREFIX: &str = "EGqHykT1gVyuWxsVW6LUUsz_KtLJGYMi_SrohInwvjC-";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

/// Tags the grammar accepts, including near-misses of the reserved names.
fn tag_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z][a-z0-9_-]{0,10}",
        Just("signify".to_owned()),
        Just("indexed0".to_owned()),
        Just("Signer".to_owned()),
        "[A-Za-z0-9_-]{1,20}",
    ]
}

/// Text that is valid in the grammar, used for the optional parameters.
fn parameter_strategy() -> impl Strategy<Value = String> {
    prop_oneof![Just(PREFIX.to_owned()), Just("0".to_owned()), "[!-~&&[^\";,=]]{1,24}"]
}

/// Builds a signage from a selection of indexed markers with optional explicit tags.
fn indexed_signage(tags: &[Option<String>]) -> Result<Option<Signage>, TestCaseError> {
    let mut markers = Vec::new();
    for (position, tag) in tags.iter().enumerate() {
        let qb64 = SIGERS.get(position % SIGERS.len()).copied().unwrap_or(SIGERS[0]);
        let signature = fail(IndexedSignature::from_qb64(qb64))?;
        let marker = match tag {
            Some(tag) => match FieldText::new(tag.clone()).and_then(|tag| IndexedMarker::named(tag, signature)) {
                Ok(marker) => marker,
                // Reserved tags have their own property below.
                Err(_) => return Ok(None),
            },
            None => IndexedMarker::new(signature),
        };
        markers.push(marker);
    }
    match SignageBuilder::new(SignageMarkers::Indexed(markers)).build() {
        Ok(signage) => Ok(Some(signage)),
        // Duplicate tags have their own property below.
        Err(_) => Ok(None),
    }
}

proptest! {
    /// Whatever the builder produces survives a render/parse round trip unchanged, and rendering
    /// the parsed value reproduces the same bytes.
    #[test]
    fn every_built_header_round_trips(
        tags in proptest::collection::vec(proptest::option::of(tag_strategy()), 1..4),
        signer in proptest::option::of(parameter_strategy()),
        ordinal in proptest::option::of(parameter_strategy()),
        digest in proptest::option::of(parameter_strategy()),
        declare_kind in any::<bool>(),
    ) {
        let Some(signage) = indexed_signage(&tags)? else { return Ok(()) };
        let mut builder = SignageBuilder::new(signage.markers().clone());
        for (value, which) in [(signer, 0_u8), (ordinal, 1), (digest, 2)] {
            let Some(value) = value else { continue };
            let value = fail(FieldText::new(value))?;
            builder = match which {
                0 => builder.signer(value),
                1 => builder.ordinal(value),
                _ => builder.digest(value),
            };
        }
        if declare_kind {
            builder = builder.kind(fail(FieldText::new("CESR"))?);
        }
        let header = fail(SignatureHeader::new(vec![fail(builder.build())?]))?;

        let rendered = fail(header.to_header_value())?;
        let parsed = fail(SignatureHeader::parse(&rendered))?;
        prop_assert_eq!(&parsed, &header);
        prop_assert_eq!(fail(parsed.to_header_value())?, rendered);
    }

    /// Several signages concatenate with commas and split back apart the same way.
    #[test]
    fn signages_concatenate_and_split(count in 1_usize..4) {
        let mut signages = Vec::new();
        for position in 0..count {
            let qb64 = CIGARS.get(position % CIGARS.len()).copied().unwrap_or(CIGARS[0]);
            let key = VERFERS.get(position % VERFERS.len()).copied().unwrap_or(VERFERS[0]);
            let signature = fail(fail(UnindexedSignature::from_qb64(qb64))?
                .with_verifier(fail(VerificationKey::from_qb64(key))?))?;
            let marker = fail(UnindexedMarker::new(signature))?;
            signages.push(fail(SignageBuilder::new(SignageMarkers::Unindexed(vec![marker])).build())?);
        }
        let header = fail(SignatureHeader::new(signages))?;
        let rendered = fail(header.to_header_value())?;

        prop_assert_eq!(rendered.matches(',').count(), count - 1);
        let parsed = fail(SignatureHeader::parse(&rendered))?;
        prop_assert_eq!(parsed.signages().len(), count);
        prop_assert_eq!(parsed, header);
    }

    /// Whitespace around the separators is normalization, not corruption: it never changes the
    /// value parsed. Upstream every space after the first survives into a tag.
    #[test]
    fn whitespace_around_separators_never_changes_the_value(
        pad_comma in 0_usize..3,
        pad_semicolon in 0_usize..3,
    ) {
        let canonical = format!(
            r#"indexed="?1";0="{}";1="{}",indexed="?1";0="{}""#,
            SIGERS[0], SIGERS[1], SIGERS[0]
        );
        let spaced = canonical
            .replace(',', &format!(",{}", " ".repeat(pad_comma)))
            .replace(';', &format!(";{}", " ".repeat(pad_semicolon)));

        let plain = fail(SignatureHeader::parse(&canonical))?;
        let padded = fail(SignatureHeader::parse(&spaced))?;
        prop_assert_eq!(&padded, &plain);
        // Rendering always produces the canonical, space-free form.
        prop_assert_eq!(fail(padded.to_header_value())?, canonical);
    }

    /// No accepted tag can add, remove, or rename a field: the rendered header always has exactly
    /// one item per parameter plus one per marker. This is the property the reference violates.
    #[test]
    fn an_accepted_tag_cannot_forge_a_field(tag in "[ -~]{1,24}") {
        let signature = fail(IndexedSignature::from_qb64(SIGERS[0]))?;
        let Ok(text) = FieldText::new(tag.clone()) else { return Ok(()) };
        let Ok(marker) = IndexedMarker::named(text, signature) else {
            prop_assert!(RESERVED_FIELDS.contains(&tag.as_str()));
            return Ok(());
        };
        let signage = fail(SignageBuilder::new(SignageMarkers::Indexed(vec![marker])).build())?;
        let rendered = fail(fail(SignatureHeader::new(vec![signage]))?.to_header_value())?;

        // One `indexed` parameter and one marker, whatever the tag says.
        prop_assert_eq!(rendered.matches(';').count(), 1);
        prop_assert_eq!(rendered.matches(',').count(), 0);
        prop_assert_eq!(rendered.matches('=').count(), 2);
        let parsed = fail(SignatureHeader::parse(&rendered))?;
        let signage = parsed.signages().first().ok_or_else(|| TestCaseError::fail("no signage"))?;
        prop_assert_eq!(signage.markers().len(), 1);
        prop_assert_eq!(signage.signer(), None);
        prop_assert_eq!(signage.kind(), None);
    }

    /// The same holds for values: an opaque marker value cannot inject a parameter.
    #[test]
    fn an_accepted_value_cannot_forge_a_field(value in "[ -~]{1,24}") {
        let Ok(value) = FieldText::new(value) else { return Ok(()) };
        let Ok(marker) = signify_http::signature::fields::OpaqueMarker::new(fail(FieldText::new("x"))?, value.clone())
        else {
            return Ok(());
        };
        let signage = fail(
            SignageBuilder::new(SignageMarkers::Opaque { indexed: false, markers: vec![marker] })
                .kind(fail(FieldText::new("JSON"))?)
                .build(),
        )?;
        let rendered = fail(fail(SignatureHeader::new(vec![signage]))?.to_header_value())?;

        prop_assert_eq!(rendered.matches(';').count(), 2);
        let parsed = fail(SignatureHeader::parse(&rendered))?;
        let signage = parsed.signages().first().ok_or_else(|| TestCaseError::fail("no signage"))?;
        prop_assert_eq!(signage.markers().len(), 1);
        prop_assert!(!signage.is_indexed());
        prop_assert_eq!(signage.kind(), Some("JSON"));
    }

    /// `FieldText` accepts exactly the bytes the grammar can carry unambiguously.
    #[test]
    fn field_text_accepts_exactly_the_grammar(text in ".{0,40}") {
        let accepted = FieldText::new(text.clone()).is_ok();
        let usable = !text.is_empty()
            && text.len() <= MAX_FIELD_TEXT_BYTES
            && text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b';' | b',' | b'='));
        prop_assert_eq!(accepted, usable, "{:?}", text);
    }

    /// Hostile header text is refused with a typed error, never a panic, and anything accepted is
    /// already canonical.
    #[test]
    fn hostile_headers_are_typed_errors(value in "[ -~]{0,80}") {
        match SignatureHeader::parse(&value) {
            Ok(header) => {
                let rendered = fail(header.to_header_value())?;
                // Re-parsing the rendered form is stable, which is what a verifier depends on.
                prop_assert_eq!(fail(SignatureHeader::parse(&rendered))?, header);
                prop_assert!(!rendered.contains(' '));
            }
            Err(
                SignatureFieldError::Crypto { .. }
                | SignatureFieldError::MalformedItem { .. }
                | SignatureFieldError::MissingIndexedField
                | SignatureFieldError::InvalidIndexedFlag { .. }
                | SignatureFieldError::DuplicateField { .. }
                | SignatureFieldError::ReservedTag { .. }
                | SignatureFieldError::NoMarkers
                | SignatureFieldError::NoSignages
                | SignatureFieldError::KindMismatch { .. }
                | SignatureFieldError::EmptyFieldText
                | SignatureFieldError::InvalidFieldText { .. }
                | SignatureFieldError::FieldTextTooLong { .. }
                | SignatureFieldError::HeaderTooLong { .. }
                | SignatureFieldError::MissingVerificationKey,
            ) => {}
            Err(other) => return Err(TestCaseError::fail(other.to_string())),
        }
    }

    /// A repeated tag is always refused, wherever the repeat sits.
    #[test]
    fn repeated_tags_are_always_refused(position in 0_usize..3) {
        let tags: Vec<String> = (0..3)
            .map(|index| if index == position { "same".to_owned() } else { format!("tag{index}") })
            .collect();
        let mut markers = Vec::new();
        for tag in tags.iter().chain(core::iter::once(&"same".to_owned())) {
            let signature = fail(IndexedSignature::from_qb64(SIGERS[0]))?;
            markers.push(fail(IndexedMarker::named(fail(FieldText::new(tag.clone()))?, signature))?);
        }
        let refused = matches!(
            SignageBuilder::new(SignageMarkers::Indexed(markers)).build(),
            Err(SignatureFieldError::DuplicateField { .. })
        );
        prop_assert!(refused, "a repeated tag was accepted");
    }
}

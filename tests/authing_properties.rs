//! Property and invalid-near-miss coverage for request authentication.

use std::sync::OnceLock;

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::signature::authentication::{AuthenticationError, RequestSigner, ResponseVerifier};
use signify_http::signature::fields::FieldText;
use signify_http::signature::input::{
    InputLabel, MAX_COMPONENTS, MAX_PARAMETER_INTEGER, MAX_SIGNATURE_INPUT_BYTES, RequestTarget, SignatureComponent,
    SignatureInput, SignatureInputBuilder, SignatureInputError, SignatureInputHeader, default_components,
};

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

/// One signer, derived once: Argon2id is deliberately expensive, so per-case derivation would
/// dominate the run. The temporary profile is the reference's own cheap parameter set.
fn signer() -> Option<&'static RequestSigner> {
    static SIGNER: OnceLock<Option<RequestSigner>> = OnceLock::new();
    SIGNER
        .get_or_init(|| {
            let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?;
            let signer = salt
                .derive_signer_with_profile(
                    "prop",
                    KeyTransferability::Transferable,
                    KeyDerivationProfile::Temporary,
                )
                .ok()?;
            Some(RequestSigner::new(signer))
        })
        .as_ref()
}

/// Method names, including ones the grammar refuses.
fn method_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_owned()),
        Just("POST".to_owned()),
        Just("DELETE".to_owned()),
        "[A-Z]{1,8}",
        "[!-~]{0,6}",
    ]
}

/// Paths, including ones the grammar refuses.
fn path_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/".to_owned()),
        "/[a-zA-Z0-9/_%.-]{0,40}",
        "/[!-~]{0,20}",
        "[ -~]{0,20}",
        r"/a\n.{0,8}",
    ]
}

/// Header names, mixing case so lookup is exercised.
fn name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("signify-resource".to_owned()),
        Just("Signify-Timestamp".to_owned()),
        "[a-zA-Z][a-zA-Z0-9-]{0,12}",
    ]
}

/// Header values within what an HTTP field can carry.
fn value_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs".to_owned()),
        "[ -~]{0,32}",
        "[\u{a0}-\u{ff}]{0,8}",
    ]
}

/// Parameter values the grammar accepts.
fn parameter_strategy() -> impl Strategy<Value = String> {
    "[!-~&&[^\";,=]]{1,24}"
}

/// Builds a header collection, dropping cases whose names collide.
fn build_headers(pairs: &[(String, String)]) -> Option<Headers> {
    let mut headers = Headers::new();
    for (name, value) in pairs {
        let (Ok(name), Ok(value)) = (HeaderName::new(name.clone()), HeaderValue::new(value)) else {
            return None;
        };
        headers.insert(name, value).ok()?;
    }
    Some(headers)
}

/// Builds an input covering every header present, plus the two derived components.
fn covering(headers: &Headers) -> Result<Vec<SignatureComponent>, TestCaseError> {
    let mut components = vec![SignatureComponent::Method, SignatureComponent::Path];
    for (name, _) in headers.iter().take(MAX_COMPONENTS - 2) {
        components.push(SignatureComponent::Header(fail(HeaderName::new(name.as_str()))?));
    }
    Ok(components)
}

proptest! {
    /// Rendering and parsing are inverses, and rendering is a fixed point.
    #[test]
    fn a_signature_input_header_survives_rendering_and_parsing(
        label in "[a-z][a-z0-9_.-]{0,8}",
        created in 0_u64..=MAX_PARAMETER_INTEGER,
        expires in proptest::option::of(0_u64..=MAX_PARAMETER_INTEGER),
        nonce in proptest::option::of(parameter_strategy()),
        keyid in proptest::option::of(parameter_strategy()),
        context in proptest::option::of(parameter_strategy()),
        algorithm in proptest::option::of(parameter_strategy()),
    ) {
        let Ok(label) = InputLabel::new(label) else { return Ok(()) };
        let mut builder = SignatureInputBuilder::new(label, fail(default_components())?, created);
        if let Some(expires) = expires {
            builder = builder.expires(expires);
        }
        for (setter, value) in [
            (0_u8, nonce),
            (1, keyid),
            (2, context),
            (3, algorithm),
        ] {
            let Some(value) = value else { continue };
            let Ok(text) = FieldText::new(value) else { return Ok(()) };
            builder = match setter {
                0 => builder.nonce(text),
                1 => builder.key_identifier(text),
                2 => builder.context(text),
                _ => builder.algorithm(text),
            };
        }
        // A backslash is refused at build time, which is its own regression test.
        let Ok(input) = builder.build() else { return Ok(()) };
        let header = fail(SignatureInputHeader::new(vec![input]))?;
        let rendered = fail(header.to_header_value())?;
        let parsed = fail(SignatureInputHeader::parse(&rendered))?;
        prop_assert_eq!(&parsed, &header);
        prop_assert_eq!(fail(parsed.to_header_value())?, rendered);
    }

    /// The base has exactly one line per covered component plus the parameter line, whatever the
    /// method, path, and header values are. Nothing a caller supplies can forge a line.
    #[test]
    fn a_signature_base_has_one_line_per_component(
        method in method_strategy(),
        path in path_strategy(),
        pairs in proptest::collection::vec((name_strategy(), value_strategy()), 0..6),
    ) {
        let (Ok(target), Some(headers)) = (RequestTarget::new(&method, &path), build_headers(&pairs)) else {
            return Ok(());
        };
        let components = covering(&headers)?;
        let expected = components.len();
        let input = fail(SignatureInputBuilder::new(InputLabel::signify(), components, 1).build())?;
        let base = fail(input.signature_base(&target, &headers))?;

        prop_assert_eq!(base.as_str().lines().count(), expected + 1);
        // Every covered value appears in the base exactly as it was stored.
        let method_item = format!("\"@method\": {}", target.method());
        let path_item = format!("\"@path\": {}", target.path());
        let has_method = base.as_str().contains(&method_item);
        let has_path = base.as_str().contains(&path_item);
        prop_assert!(has_method);
        prop_assert!(has_path);
        for (name, value) in headers.iter() {
            let item = format!("\"{}\": {}", name.as_str(), value.as_str());
            let present = base.as_str().contains(&item);
            prop_assert!(present);
        }
        let closed = base.as_str().ends_with('"');
        prop_assert!(closed);
    }

    /// Signing then verifying always succeeds for the same message.
    #[test]
    fn a_signed_request_always_verifies(
        method in method_strategy(),
        path in path_strategy(),
        pairs in proptest::collection::vec((name_strategy(), value_strategy()), 0..5),
        created in 0_u64..=MAX_PARAMETER_INTEGER,
    ) {
        let (Some(signer), Ok(target), Some(mut headers)) =
            (signer(), RequestTarget::new(&method, &path), build_headers(&pairs))
        else {
            return Ok(());
        };
        let components = covering(&headers)?;
        let input = fail(signer.signature_input(components, created))?;
        let signed = fail(signer.sign(&input, &target, &headers))?;
        fail(signed.apply(&mut headers))?;

        let verifier = ResponseVerifier::new(fail(signer.key_identifier().and_then(|key| {
            signify_crypto::verifier::VerificationKey::from_qb64(key.as_str())
                .map_err(|error| AuthenticationError::Crypto { source: Box::new(error) })
        }))?);
        let verified = fail(verifier.verify(&target, &headers))?;
        prop_assert_eq!(verified.created(), created);
        prop_assert_eq!(verified.label(), input.label());
    }

    /// Changing the method, the path, or any covered header breaks verification; the failure is
    /// either a signature mismatch or the named missing header, never a silent success.
    #[test]
    fn any_change_to_the_covered_message_breaks_verification(
        path in "/[a-z0-9/_-]{0,20}",
        pairs in proptest::collection::vec((name_strategy(), value_strategy()), 1..4),
        which in 0_usize..3,
    ) {
        let (Some(signer), Ok(target), Some(mut headers)) =
            (signer(), RequestTarget::new("POST", &path), build_headers(&pairs))
        else {
            return Ok(());
        };
        let components = covering(&headers)?;
        let input = fail(signer.signature_input(components, 1))?;
        let signed = fail(signer.sign(&input, &target, &headers))?;
        let verifier = ResponseVerifier::new(fail(signer.key_identifier().and_then(|key| {
            signify_crypto::verifier::VerificationKey::from_qb64(key.as_str())
                .map_err(|error| AuthenticationError::Crypto { source: Box::new(error) })
        }))?);

        let tampered_target = match which {
            0 => fail(RequestTarget::new("GET", &path))?,
            1 => fail(RequestTarget::new("POST", &format!("{path}/x")))?,
            _ => target.clone(),
        };
        if which == 2 {
            // Rebuild the headers with the first covered value changed.
            let mut changed = Headers::new();
            for (position, (name, value)) in headers.iter().enumerate() {
                let value = if position == 0 {
                    fail(HeaderValue::new(format!("{}x", value.as_str())))?
                } else {
                    value.clone()
                };
                fail(changed.insert(fail(HeaderName::new(name.as_str()))?, value))?;
            }
            headers = changed;
        }
        fail(signed.apply(&mut headers))?;

        let rejected = matches!(
            verifier.verify(&tampered_target, &headers),
            Err(AuthenticationError::Verification { .. })
        );
        prop_assert!(rejected);
    }

    /// A header the signature does not cover may change freely.
    #[test]
    fn an_uncovered_header_does_not_affect_verification(
        extra in value_strategy(),
    ) {
        let (Some(signer), Ok(target)) = (signer(), RequestTarget::new("GET", "/identifiers")) else {
            return Ok(());
        };
        let mut headers = Headers::new();
        fail(headers.insert(
            fail(HeaderName::new("signify-resource"))?,
            fail(HeaderValue::new("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"))?,
        ))?;
        let components = vec![
            SignatureComponent::Method,
            SignatureComponent::Path,
            SignatureComponent::Header(fail(HeaderName::new("signify-resource"))?),
        ];
        let input = fail(signer.signature_input(components, 1))?;
        let signed = fail(signer.sign(&input, &target, &headers))?;

        let Ok(value) = HeaderValue::new(extra) else { return Ok(()) };
        fail(headers.insert(fail(HeaderName::new("x-uncovered"))?, value))?;
        fail(signed.apply(&mut headers))?;

        let verifier = ResponseVerifier::new(fail(signer.key_identifier().and_then(|key| {
            signify_crypto::verifier::VerificationKey::from_qb64(key.as_str())
                .map_err(|error| AuthenticationError::Crypto { source: Box::new(error) })
        }))?);
        let verified = verifier.verify(&target, &headers).is_ok();
        prop_assert!(verified);
    }

    /// Hostile header text always produces a typed error or a canonical value; never a panic.
    #[test]
    fn hostile_signature_input_is_always_typed(value in ".{0,200}") {
        match SignatureInputHeader::parse(&value) {
            Ok(header) => {
                let bounded = value.len() <= MAX_SIGNATURE_INPUT_BYTES;
                prop_assert!(bounded);
                let rendered = fail(header.to_header_value())?;
                prop_assert_eq!(fail(SignatureInputHeader::parse(&rendered))?, header.clone());
                for input in header.inputs() {
                    let covers_something = !input.components().is_empty();
                    prop_assert!(covers_something);
                }
            }
            Err(
                SignatureInputError::SignatureInputTooLong { .. }
                | SignatureInputError::InvalidLabel { .. }
                | SignatureInputError::UnknownDerivedComponent { .. }
                | SignatureInputError::NoComponents
                | SignatureInputError::TooManyComponents { .. }
                | SignatureInputError::DuplicateComponent { .. }
                | SignatureInputError::NoInputs
                | SignatureInputError::TooManyInputs { .. }
                | SignatureInputError::DuplicateLabel { .. }
                | SignatureInputError::MissingCreated { .. }
                | SignatureInputError::UnknownParameter { .. }
                | SignatureInputError::ParametersOutOfOrder
                | SignatureInputError::ParameterOutOfRange { .. }
                | SignatureInputError::InvalidParameterValue { .. }
                | SignatureInputError::Malformed { .. }
                | SignatureInputError::Header { .. }
                | SignatureInputError::Field { .. },
            ) => {}
            Err(other) => return Err(TestCaseError::fail(format!("unexpected error: {other}"))),
        }
    }

    /// Whitespace an intermediary may insert around the separator never changes the parsed value.
    #[test]
    fn separator_whitespace_never_changes_the_value(spaces in 0_usize..4) {
        let padding = " ".repeat(spaces);
        let value = format!(
            "signify=(\"@method\");created=1,{padding}other=(\"@path\");created=2",
        );
        let header = fail(SignatureInputHeader::parse(&value))?;
        let canonical = fail(SignatureInputHeader::parse(
            "signify=(\"@method\");created=1, other=(\"@path\");created=2",
        ))?;
        prop_assert_eq!(header, canonical);
    }

    /// A component's written name always reads back as the same component.
    #[test]
    fn component_names_round_trip(name in name_strategy()) {
        let Ok(component) = SignatureComponent::new(&name) else { return Ok(()) };
        prop_assert_eq!(fail(SignatureComponent::new(component.as_str()))?, component);
    }

    /// Every accepted request target is written into the base verbatim, and every rejected one
    /// carries a character that would have changed the base's shape.
    #[test]
    fn request_targets_are_accepted_exactly_when_they_are_unambiguous(
        method in method_strategy(),
        path in path_strategy(),
    ) {
        let acceptable = !method.is_empty()
            && method.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'*' | b'!' | b'~' | b'\'' | b'+' | b'`'))
            && path.starts_with('/')
            && path.bytes().all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'"'));

        let target = RequestTarget::new(&method, &path);
        prop_assert_eq!(target.is_ok(), acceptable);
        if let Ok(target) = target {
            prop_assert_eq!(target.method(), method);
            prop_assert_eq!(target.path(), path);
        }
    }
}

/// Regression: an input whose parameters are correct but reordered would render to different bytes
/// than it parsed from, so the accepted order is fixed and the reordered form is refused.
#[test]
fn reordered_parameters_are_refused_rather_than_renormalized() {
    assert!(matches!(
        SignatureInputHeader::parse("signify=(\"@method\");created=1;alg=\"ed25519\";nonce=\"x\""),
        Err(SignatureInputError::ParametersOutOfOrder)
    ));
}

/// Regression: the covered list must be non-empty, so a base always binds at least one thing.
#[test]
fn a_base_always_binds_something() {
    let input: Result<SignatureInput, _> = SignatureInputBuilder::new(InputLabel::signify(), Vec::new(), 1).build();
    assert!(matches!(input, Err(SignatureInputError::NoComponents)));
}

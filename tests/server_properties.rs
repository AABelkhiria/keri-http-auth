//! Negative and property coverage for the server half.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keri_http_auth::authentication::RequestSigner;
use keri_http_auth::fields::FieldText;
use keri_http_auth::header::{HeaderName, HeaderValue, Headers, MAX_HEADER_VALUE_BYTES};
use keri_http_auth::input::{
    InputLabel, RequestTarget, SignatureComponent, SignatureInputBuilder, SignatureInputError, SignatureInputHeader,
    default_components,
};
use keri_http_auth::server::{Freshness, FreshnessError, KeyLookup, RequestRejection, RequestVerifier, canonical_path};
use proptest::{prelude::*, test_runner::TestCaseError};

const CONTROLLER: &str = "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs";
const TIMESTAMP: &str = "2022-09-24T00:05:48.196795+00:00";
const CREATED: u64 = 1_609_459_200;

#[derive(Clone)]
struct Keys(BTreeMap<String, VerificationKey>);

impl KeyLookup for Keys {
    fn first_current_key(&self, controller: &str) -> Option<VerificationKey> {
        self.0.get(controller).cloned()
    }
}

struct Signed {
    key: VerificationKey,
    verifier: RequestVerifier<Keys>,
    target: RequestTarget,
    headers: Vec<(String, String)>,
}

/// One signed request, built once: Argon2id is deliberately expensive.
fn signed() -> Option<&'static Signed> {
    static SIGNED: OnceLock<Option<Signed>> = OnceLock::new();
    SIGNED
        .get_or_init(|| {
            let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?;
            let signer = salt
                .derive_signer_with_profile(
                    "server",
                    KeyTransferability::Transferable,
                    KeyDerivationProfile::Temporary,
                )
                .ok()?;
            let key = VerificationKey::from_qb64(&signer.verifier().qb64().ok()?).ok()?;
            let signer = RequestSigner::new(signer);
            let target = RequestTarget::new("POST", "/identifiers").ok()?;
            let mut pairs = vec![
                ("Signify-Resource".to_owned(), CONTROLLER.to_owned()),
                ("Signify-Timestamp".to_owned(), TIMESTAMP.to_owned()),
            ];
            let covered = build(&pairs).ok()?;
            let input = signer.signature_input(default_components().ok()?, CREATED).ok()?;
            let authenticated = signer.sign(&input, &target, &covered).ok()?;
            pairs.push(("Signature-Input".to_owned(), authenticated.signature_input().to_owned()));
            pairs.push(("Signature".to_owned(), authenticated.signature().to_owned()));
            Some(Signed {
                verifier: RequestVerifier::new(Keys(BTreeMap::from([(CONTROLLER.to_owned(), key.clone())]))),
                key,
                target,
                headers: pairs,
            })
        })
        .as_ref()
}

fn build(pairs: &[(String, String)]) -> Result<Headers, TestCaseError> {
    let mut headers = Headers::new();
    for (name, value) in pairs {
        let name = HeaderName::new(name.as_str()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let Ok(value) = HeaderValue::new(value) else {
            return Err(TestCaseError::reject("not a header value"));
        };
        headers
            .insert(name, value)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
    }
    Ok(headers)
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

#[test]
fn the_signed_request_verifies() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    let verified = signed
        .verifier
        .verify(&signed.target, &build(&signed.headers)?, at(CREATED))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
    assert_eq!(verified.controller(), CONTROLLER);
    Ok(())
}

#[test]
fn every_required_header_is_required() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    for name in ["Signify-Resource", "Signature-Input", "Signature"] {
        let pairs: Vec<_> = signed.headers.iter().filter(|(key, _)| key != name).cloned().collect();
        let outcome = signed.verifier.verify(&signed.target, &build(&pairs)?, at(CREATED));
        assert!(
            matches!(outcome, Err(RequestRejection::MissingHeader { name: missing }) if missing == name),
            "{name}: {outcome:?}"
        );
    }
    Ok(())
}

/// Answers for every controller, so a changed resource reaches the signature.
struct AnyController(VerificationKey);

impl KeyLookup for AnyController {
    fn first_current_key(&self, _controller: &str) -> Option<VerificationKey> {
        Some(self.0.clone())
    }
}

#[test]
fn the_signature_binds_the_controller() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    let key = signed.key.clone();
    let verifier = RequestVerifier::new(AnyController(key));
    assert!(
        verifier
            .verify(&signed.target, &build(&signed.headers)?, at(CREATED))
            .is_ok()
    );

    let mut pairs = signed.headers.clone();
    let resource = &mut pairs.first_mut().ok_or_else(|| TestCaseError::fail("no resource"))?.1;
    *resource = "EOtherControllerOtherControllerOtherControlle".to_owned();
    let outcome = verifier.verify(&signed.target, &build(&pairs)?, at(CREATED));
    assert!(
        matches!(outcome, Err(RequestRejection::InvalidSignature)),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn received_headers_tolerate_what_a_server_does_not_read() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    let long = "x".repeat(MAX_HEADER_VALUE_BYTES + 1);
    let mut pairs: Vec<(&str, &str)> = signed
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    pairs.extend([
        ("Cookie", "a=1"),
        ("Cookie", "b=2"),
        ("Cookie", "c=3"),
        ("X-Long", &long),
        ("bad name", "x"),
    ]);
    let received = Headers::received(pairs.iter().copied());
    assert!(!received.contains("Cookie"));
    assert!(!received.contains("X-Long"));
    assert!(signed.verifier.verify(&signed.target, &received, at(CREATED)).is_ok());

    // A repeated header the request relies on is not read at all.
    pairs.push(("Signature", "indexed=\"?0\";signify=\"x\""));
    let outcome = signed
        .verifier
        .verify(&signed.target, &Headers::received(pairs.iter().copied()), at(CREATED));
    assert!(
        matches!(outcome, Err(RequestRejection::MissingHeader { .. })),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn a_client_cannot_write_what_a_server_tolerates() -> Result<(), Box<dyn std::error::Error>> {
    for value in [
        r"signify=();created=1",
        r#"signify=("@authority");created=1"#,
        r#"signify=("@method");created=1;expires="soon""#,
    ] {
        assert!(SignatureInputHeader::parse(value).is_err(), "{value}");
        assert!(SignatureInputHeader::parse_received(value).is_ok(), "{value}");
    }
    let unsupported = SignatureComponent::Unsupported(FieldText::new("@authority")?);
    let built = SignatureInputBuilder::new(InputLabel::signify(), vec![unsupported], 1).build();
    assert!(matches!(
        built,
        Err(SignatureInputError::UnknownDerivedComponent { .. })
    ));

    let lenient = SignatureInputHeader::parse_received("signify=();created=1")?;
    let input = lenient.inputs().first().ok_or("no input")?;
    let base = input.signature_base(&RequestTarget::new("GET", "/")?, &Headers::new());
    assert!(matches!(base, Err(SignatureInputError::NoComponents)));
    Ok(())
}

#[test]
fn removing_the_timestamp_breaks_the_signature() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    let pairs: Vec<_> = signed
        .headers
        .iter()
        .filter(|(key, _)| key != "Signify-Timestamp")
        .cloned()
        .collect();
    let outcome = signed.verifier.verify(&signed.target, &build(&pairs)?, at(CREATED));
    assert!(
        matches!(outcome, Err(RequestRejection::InvalidSignature)),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn freshness_is_off_unless_asked_for() -> Result<(), TestCaseError> {
    let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
    let headers = build(&signed.headers)?;
    let years_later = at(CREATED + 100_000_000);
    assert!(signed.verifier.verify(&signed.target, &headers, years_later).is_ok());

    let strict = signed.verifier.clone().with_freshness(Freshness::default());
    let outcome = strict.verify(&signed.target, &headers, years_later);
    assert!(
        matches!(
            outcome,
            Err(RequestRejection::Freshness {
                source: FreshnessError::Stale { .. }
            })
        ),
        "{outcome:?}"
    );
    assert!(strict.verify(&signed.target, &headers, at(CREATED)).is_ok());
    Ok(())
}

#[test]
fn freshness_bounds_a_signature_in_both_directions() {
    let window = Freshness::default();
    let now = at(1_700_000_000);

    assert!(window.check(1_700_000_000, now).is_ok());
    assert!(window.check(1_700_000_000 - 300, now).is_ok());
    assert!(window.check(1_700_000_000 + 60, now).is_ok());

    assert!(matches!(
        window.check(1_700_000_000 - 301, now),
        Err(FreshnessError::Stale { .. })
    ));
    assert!(matches!(
        window.check(1_700_000_000 + 61, now),
        Err(FreshnessError::FromTheFuture { .. })
    ));

    assert!(Freshness::Ignore.check(0, now).is_ok());
    assert!(Freshness::Ignore.check(u64::MAX, now).is_ok());
    assert!(window.check(u64::MAX, now).is_err());
    assert!(window.check(0, now).is_err());
}

#[test]
fn paths_quote_as_python_does() {
    // Each right side is Python's `quote(unquote(left))`.
    for (raw, quoted) in [
        ("/a b", "/a%20b"),
        ("/a%20b", "/a%20b"),
        ("/a:b", "/a%3Ab"),
        ("/a%3Ab", "/a%3Ab"),
        ("/%E2%82%AC", "/%E2%82%AC"),
        ("/%ff", "/%EF%BF%BD"),
        ("/%zz", "/%25zz"),
        ("/%", "/%25"),
        ("/a%2Fb", "/a/b"),
        ("/~a-b_c.d", "/~a-b_c.d"),
        ("/é", "/%C3%A9"),
        ("/a+b", "/a%2Bb"),
        ("/%C3", "/%EF%BF%BD"),
        ("/%e2%82", "/%EF%BF%BD"),
    ] {
        assert_eq!(canonical_path(raw), quoted, "{raw}");
    }
}

proptest! {
    #[test]
    fn a_mutated_header_never_verifies(
        index in 0_usize..4,
        position in any::<prop::sample::Index>(),
        replacement in proptest::char::range('!', '~'),
    ) {
        let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
        let mut pairs = signed.headers.clone();
        let value = &mut pairs.get_mut(index).ok_or_else(|| TestCaseError::fail("index"))?.1;
        let offset = position.index(value.len());
        let original = value.chars().nth(offset).ok_or_else(|| TestCaseError::fail("offset"))?;
        prop_assume!(original != replacement);
        value.replace_range(offset..=offset, &replacement.to_string());

        let Ok(mutated) = build(&pairs) else { return Err(TestCaseError::reject("invalid")) };
        prop_assert!(signed.verifier.verify(&signed.target, &mutated, at(CREATED)).is_err());
    }

    #[test]
    fn a_changed_target_never_verifies(method in "[A-Z]{1,8}", path in "/[a-z]{1,16}") {
        let signed = signed().ok_or_else(|| TestCaseError::fail("setup"))?;
        prop_assume!(method != signed.target.method() || path != signed.target.path());
        let target = RequestTarget::new(&method, &path).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(signed.verifier.verify(&target, &build(&signed.headers)?, at(CREATED)).is_err());
    }

    #[test]
    fn canonical_paths_are_stable(raw in "\\PC{0,64}") {
        let once = canonical_path(&raw);
        prop_assert_eq!(canonical_path(&once), once);
    }
}

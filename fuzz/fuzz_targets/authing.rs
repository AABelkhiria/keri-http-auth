#![no_main]
#![forbid(unsafe_code)]

//! Request authentication runs on whatever a peer sends: the `Signature-Input` parser reads a
//! remote header, the canonicalizer reads remote header values, and the request target comes from
//! a caller. Arbitrary bytes drive all four boundaries at once.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use keri_cesr::crypto::verifier::VerificationKey;
use signify_http::header::{HeaderError, HeaderName, HeaderValue, Headers};
use signify_http::signature::authentication::{AuthenticationError, ResponseVerifier};
use signify_http::signature::input::{
    InputLabel, MAX_SIGNATURE_INPUT_BYTES, RequestTarget, SignatureComponent, SignatureInputBuilder,
    SignatureInputError, SignatureInputHeader,
};

/// The agent key the pinned `test/core/authing.test.ts` response is verified against.
const AGENT_KEY: &str = "DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a";

/// The exact `Signature` header that response carries.
const SIGNATURE: &str =
    r#"indexed="?0";signify="0BDLh8QCytVBx1YMam4Vt8s4b9HAW1dwfE4yU5H_w1V6gUvPBoVGWQlIMdC16T3WFWHDHCbMcuceQzrr6n9OULsK""#;

fn verifier() -> Option<&'static ResponseVerifier> {
    static VERIFIER: OnceLock<Option<ResponseVerifier>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| Some(ResponseVerifier::new(VerificationKey::from_qb64(AGENT_KEY).ok()?)))
        .as_ref()
}

/// Splits the corpus entry into a request path and the material after it, on a character boundary.
fn split(text: &str, selector: u8) -> (&str, &str) {
    let mut offset = usize::from(selector) % text.len().saturating_add(1);
    while offset < text.len() && !text.is_char_boundary(offset) {
        offset = offset.saturating_add(1);
    }
    text.split_at(offset.min(text.len()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let (head, tail) = split(text, selector);

    // 1. The parser reads a remote header. Nothing may panic, every rejection must be typed, and
    //    anything accepted must already be canonical and survive reparsing.
    match SignatureInputHeader::parse(text) {
        Ok(header) => {
            assert!(
                text.len() <= MAX_SIGNATURE_INPUT_BYTES,
                "an oversized signature input was accepted"
            );
            match header.to_header_value() {
                Ok(rendered) => {
                    match SignatureInputHeader::parse(&rendered) {
                        Ok(reparsed) => assert_eq!(reparsed, header, "a signature input did not survive reparsing"),
                        Err(error) => panic!("a rendered signature input failed to parse: {error}"),
                    }
                    // Every input binds something and names its own creation time.
                    for input in header.inputs() {
                        assert!(!input.components().is_empty(), "an input covering nothing was accepted");
                        assert!(
                            rendered.contains(&format!("created={}", input.created())),
                            "the rendered header lost its creation time"
                        );
                    }
                    assert_eq!(
                        rendered.matches(", ").count(),
                        header.inputs().len() - 1,
                        "the rendered header has the wrong member count"
                    );
                }
                Err(error) => panic!("a parsed signature input failed to render: {error}"),
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
        Err(other) => panic!("unexpected signature input error: {other}"),
    }

    // 2. A request target is caller-supplied. An accepted one may never forge a line in the base:
    //    the base always has exactly one line per covered component plus the parameter line.
    if let Ok(target) = RequestTarget::new(head, tail) {
        assert_eq!(target.method(), head, "an accepted method was rewritten");
        assert_eq!(target.path(), tail, "an accepted path was rewritten");
        let components = vec![SignatureComponent::Method, SignatureComponent::Path];
        match SignatureInputBuilder::new(InputLabel::signify(), components, 1).build() {
            Ok(input) => match input.signature_base(&target, &Headers::new()) {
                Ok(base) => {
                    assert_eq!(base.as_str().lines().count(), 3, "a target forged a line in the base");
                    assert!(
                        base.as_str().starts_with(&format!("\"@method\": {head}\n\"@path\": {tail}\n")),
                        "the base did not commit to the target verbatim"
                    );
                }
                Err(SignatureInputError::SignatureBaseTooLong { .. }) => {}
                Err(error) => panic!("a base over an accepted target failed: {error}"),
            },
            Err(error) => panic!("a two-component input failed to build: {error}"),
        }
    }

    // 3. Header names and values are remote text. Anything accepted is already normalized, so a
    //    covered value can never carry a line break into the base.
    if let Ok(value) = HeaderValue::new(tail) {
        assert_eq!(value.as_str(), tail.trim_matches([' ', '\t']), "a value was rewritten");
        assert!(!value.as_str().contains(['\n', '\r']), "a value kept a line break");
    }
    match HeaderName::new(head) {
        Ok(name) => assert!(!name.as_str().starts_with('@'), "a name shadowed a derived component"),
        Err(HeaderError::EmptyName | HeaderError::NameTooLong { .. } | HeaderError::InvalidName { .. }) => {}
        Err(other) => panic!("unexpected header name error: {other}"),
    }

    // 4. End to end: a fuzzed `Signature-Input` reaches the verifier alongside a real signature.
    //    Verification must fail cleanly rather than panic, and must never succeed on this input.
    let (Some(verifier), Ok(target)) = (verifier(), RequestTarget::new("GET", "/identifiers/aid1")) else {
        return;
    };
    let mut headers = Headers::new();
    let entries = [
        ("Signature-Input", text),
        ("Signature", SIGNATURE),
        ("Signify-Resource", "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei"),
        ("Signify-Timestamp", "2023-05-22T00:37:00.248708+00:00"),
    ];
    for (name, value) in entries {
        let (Ok(name), Ok(value)) = (HeaderName::new(name), HeaderValue::new(value)) else {
            return;
        };
        if headers.insert(name, value).is_err() {
            return;
        }
    }
    match verifier.verify(&target, &headers) {
        // The one input that authenticates is the pinned header itself, which the corpus may reach.
        Ok(input) => assert_eq!(input.created(), 1_684_715_820, "an unexpected input verified"),
        Err(
            AuthenticationError::MissingSignatureInput
            | AuthenticationError::MissingSignature
            | AuthenticationError::UnknownLabel { .. }
            | AuthenticationError::SignatureNotFound { .. }
            | AuthenticationError::AmbiguousSignature { .. }
            | AuthenticationError::Verification { .. }
            | AuthenticationError::Input { .. }
            | AuthenticationError::Field { .. }
            | AuthenticationError::Header { .. }
            | AuthenticationError::Crypto { .. },
        ) => {}
        Err(other) => panic!("unexpected authentication error: {other}"),
    }
});

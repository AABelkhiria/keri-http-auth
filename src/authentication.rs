//! Signing a request and verifying a response.
//!
//! This module ports `Authenticater` from `src/keri/core/authing.ts`. It composes the two halves
//! that already exist: [`crate::signature::input`] decides what a signature covers and produces the
//! exact bytes signed, and [`crate::signature::fields`] carries the signature material.
//!
//! ```text
//! Signature-Input: signify=("@method" "@path" "signify-resource" "signify-timestamp");created=…;keyid="…";alg="ed25519"
//! Signature:       indexed="?0";signify="0BCh…"
//! ```
//!
//! # One role per type
//!
//! The reference's `Authenticater` always holds both a private signer and a public verifier, even
//! where only one is used — `createSignedRequest` passes the same key twice. Here [`RequestSigner`]
//! owns the secret and [`ResponseVerifier`] owns the public key, so a value that only checks
//! responses never holds signing capability.
//!
//! Freshness is deliberately not decided here: [`SignatureInput::created`] is returned to the
//! caller, and replay policy is Roadmap 5.5's concern.

use core::fmt;
use std::error::Error;

use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::VerificationKey;

use crate::header::{HeaderError, HeaderName, HeaderValue, Headers};
use crate::signature::fields::{
    FieldText, SIGNATURE_HEADER_NAME, SignageBuilder, SignageMarkers, SignatureFieldError, SignatureHeader,
    UnindexedMarker,
};
use crate::signature::input::{
    ED25519_ALGORITHM, InputLabel, RequestTarget, SIGNATURE_INPUT_HEADER_NAME, SignatureComponent, SignatureInput,
    SignatureInputBuilder, SignatureInputError, SignatureInputHeader,
};

/// Signs requests with one private key.
///
/// ```
/// use keri_cesr::crypto::salt::{Salt, SecurityTier};
/// use keri_cesr::crypto::verifier::KeyTransferability;
/// use signify_http::header::{HeaderName, HeaderValue, Headers};
/// use signify_http::signature::authentication::RequestSigner;
/// use signify_http::signature::input::{RequestTarget, default_components};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // The salt the pinned upstream tests use; it is their own public constant.
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let signer = RequestSigner::new(salt.derive_signer("", KeyTransferability::Transferable)?);
///
/// let headers = Headers::from_pairs([
///     (
///         HeaderName::new("signify-resource")?,
///         HeaderValue::new("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs")?,
///     ),
///     (
///         HeaderName::new("signify-timestamp")?,
///         HeaderValue::new("2022-09-24T00:05:48.196795+00:00")?,
///     ),
/// ])?;
///
/// let input = signer.signature_input(default_components()?, 1_609_459_200)?;
/// let signed = signer.sign(&input, &RequestTarget::new("POST", "/boot")?, &headers)?;
///
/// assert_eq!(
///     signed.signature(),
///     concat!(
///         r#"indexed="?0";signify="0BChvN_BWAf-mgEuTnWfNnktgHdWOuOh9cWc4o0GFWuZ"#,
///         r#"Owra3DyJT5dJ_6BX7AANDOTnIlAKh5Sg_9qGQXHjj5oJ""#,
///     ),
/// );
/// # Ok(())
/// # }
/// ```
pub struct RequestSigner {
    signer: Signer,
    label: InputLabel,
}

impl RequestSigner {
    /// Uses one signer under the `signify` label every KERIA request carries.
    #[must_use]
    pub fn new(signer: Signer) -> Self {
        Self {
            signer,
            label: InputLabel::signify(),
        }
    }

    /// Uses one signer under an explicit label.
    #[must_use]
    pub const fn with_label(signer: Signer, label: InputLabel) -> Self {
        Self { signer, label }
    }

    /// Returns the label this signer writes.
    #[must_use]
    pub const fn label(&self) -> &InputLabel {
        &self.label
    }

    /// Returns the qualified verification key a peer needs to check these signatures.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Crypto`] when the key cannot be encoded and
    /// [`AuthenticationError::Field`] when it is not usable as a parameter value.
    pub fn key_identifier(&self) -> Result<FieldText, AuthenticationError> {
        let key = self.signer.verifier().qb64().map_err(AuthenticationError::crypto)?;
        Ok(FieldText::new(key)?)
    }

    /// Builds the signature input a Signify request carries.
    ///
    /// The `keyid` parameter is this signer's verification key and `alg` is
    /// [`ED25519_ALGORITHM`], exactly as the reference sets them. `created` is a parameter rather
    /// than a clock reading, so the result is reproducible.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Input`] when the components are empty, repeated, or too
    /// many, and the errors of [`RequestSigner::key_identifier`].
    pub fn signature_input(
        &self,
        components: Vec<SignatureComponent>,
        created: u64,
    ) -> Result<SignatureInput, AuthenticationError> {
        Ok(SignatureInputBuilder::new(self.label.clone(), components, created)
            .key_identifier(self.key_identifier()?)
            .algorithm(FieldText::new(ED25519_ALGORITHM)?)
            .build()?)
    }

    /// Signs one request, returning the two headers it must carry.
    ///
    /// The signature covers the base [`SignatureInput::signature_base`] derives, and is attached
    /// as one named unindexed marker — the only shape the reference ever emits.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Input`] when the base cannot be built, most often because a
    /// covered header is absent; [`AuthenticationError::Crypto`] when signing fails; and
    /// [`AuthenticationError::Field`] when the resulting header cannot be rendered.
    pub fn sign(
        &self,
        input: &SignatureInput,
        target: &RequestTarget,
        headers: &Headers,
    ) -> Result<AuthenticatedHeaders, AuthenticationError> {
        let base = input.signature_base(target, headers)?;
        let signature = self
            .signer
            .sign_unindexed(base.as_bytes())
            .map_err(AuthenticationError::crypto)?;

        let marker = UnindexedMarker::named(FieldText::new(self.label.as_str())?, signature)?;
        let signage = SignageBuilder::new(SignageMarkers::Unindexed(vec![marker])).build()?;
        let signature = SignatureHeader::new(vec![signage])?.to_header_value()?;
        let signature_input = SignatureInputHeader::new(vec![input.clone()])?.to_header_value()?;

        Ok(AuthenticatedHeaders {
            signature_input,
            signature,
        })
    }
}

impl fmt::Debug for RequestSigner {
    /// Redacts the signer, whose own `Debug` is redacted for the same reason.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestSigner")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// The two headers a signed request carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedHeaders {
    signature_input: String,
    signature: String,
}

impl AuthenticatedHeaders {
    /// Returns the `Signature-Input` value.
    #[must_use]
    pub fn signature_input(&self) -> &str {
        &self.signature_input
    }

    /// Returns the `Signature` value.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Returns both headers with their names, in the order the reference appends them.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            (SIGNATURE_INPUT_HEADER_NAME, self.signature_input.as_str()),
            (SIGNATURE_HEADER_NAME, self.signature.as_str()),
        ]
        .into_iter()
    }

    /// Adds both headers to a collection.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Header`] when either name is already present, which would
    /// mean the message was signed twice.
    pub fn apply(&self, headers: &mut Headers) -> Result<(), AuthenticationError> {
        for (name, value) in self.iter() {
            headers.insert(HeaderName::new(name)?, HeaderValue::new(value)?)?;
        }
        Ok(())
    }
}

impl<'headers> IntoIterator for &'headers AuthenticatedHeaders {
    type Item = (&'static str, &'headers str);
    type IntoIter = std::array::IntoIter<(&'static str, &'headers str), 2>;

    fn into_iter(self) -> Self::IntoIter {
        [
            (SIGNATURE_INPUT_HEADER_NAME, self.signature_input.as_str()),
            (SIGNATURE_HEADER_NAME, self.signature.as_str()),
        ]
        .into_iter()
    }
}

/// Verifies signed responses against one public key.
#[derive(Clone, Debug)]
pub struct ResponseVerifier {
    key: VerificationKey,
    label: InputLabel,
}

impl ResponseVerifier {
    /// Uses one key under the `signify` label every KERIA response carries.
    #[must_use]
    pub fn new(key: VerificationKey) -> Self {
        Self {
            key,
            label: InputLabel::signify(),
        }
    }

    /// Uses one key under an explicit label.
    ///
    /// The reference hardcodes `signify` and reports any other label as simply unverified, so a
    /// correctly signed message under another label is never checked at all.
    #[must_use]
    pub const fn with_label(key: VerificationKey, label: InputLabel) -> Self {
        Self { key, label }
    }

    /// Returns the key responses are checked against.
    #[must_use]
    pub const fn key(&self) -> &VerificationKey {
        &self.key
    }

    /// Returns the label this verifier looks for.
    #[must_use]
    pub const fn label(&self) -> &InputLabel {
        &self.label
    }

    /// Verifies one message, returning the input its signature covered.
    ///
    /// The `Signature-Input` and `Signature` headers are read from `headers`, as upstream. Every
    /// signage of the `Signature` header is searched for a marker under this verifier's label, and
    /// exactly one must carry it; the reference reads only the first signage, so a signature
    /// carried in a later one is invisible to it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::MissingSignatureInput`] or
    /// [`AuthenticationError::MissingSignature`] when a header is absent — the reference returns
    /// `false` for both, which is indistinguishable from a bad signature;
    /// [`AuthenticationError::UnknownLabel`] when no input carries this label;
    /// [`AuthenticationError::SignatureNotFound`] or [`AuthenticationError::AmbiguousSignature`]
    /// when the marker is missing or repeated; [`AuthenticationError::Input`] when the base cannot
    /// be rebuilt, including when a covered header is absent; and
    /// [`AuthenticationError::Verification`] when the signature does not authenticate the base.
    pub fn verify(&self, target: &RequestTarget, headers: &Headers) -> Result<SignatureInput, AuthenticationError> {
        let input_value = headers
            .get(SIGNATURE_INPUT_HEADER_NAME)
            .ok_or(AuthenticationError::MissingSignatureInput)?;
        let signature_value = headers
            .get(SIGNATURE_HEADER_NAME)
            .ok_or(AuthenticationError::MissingSignature)?;

        let input_header = SignatureInputHeader::parse(input_value)?;
        let input = input_header
            .find(&self.label)
            .ok_or_else(|| AuthenticationError::UnknownLabel {
                label: self.label.as_str().to_owned(),
            })?;

        let signature_header = SignatureHeader::parse(signature_value)?;
        let signature = self.find_signature(&signature_header)?;

        let base = input.signature_base(target, headers)?;
        self.key
            .verify(signature, base.as_bytes())
            .map_err(|_| AuthenticationError::Verification {
                label: self.label.as_str().to_owned(),
            })?;
        Ok(input.clone())
    }

    /// Finds the one signature written under this verifier's label.
    fn find_signature<'header>(&self, header: &'header SignatureHeader) -> Result<&'header [u8], AuthenticationError> {
        let label = self.label.as_str();
        let mut found: Option<&[u8]> = None;
        for signage in header.signages() {
            let raw = match signage.markers() {
                SignageMarkers::Indexed(markers) => markers
                    .iter()
                    .find(|marker| marker.tag() == label)
                    .map(|marker| marker.signature().raw()),
                SignageMarkers::Unindexed(markers) => {
                    let mut matched = None;
                    for marker in markers {
                        if marker.tag()? == label {
                            matched = Some(marker.signature().raw().as_slice());
                            break;
                        }
                    }
                    matched
                }
                // A non-CESR signage carries uninterpreted text, not signature material.
                SignageMarkers::Opaque { .. } => None,
            };
            let Some(raw) = raw else { continue };
            if found.is_some() {
                return Err(AuthenticationError::AmbiguousSignature {
                    label: label.to_owned(),
                });
            }
            found = Some(raw);
        }
        found.ok_or_else(|| AuthenticationError::SignatureNotFound {
            label: label.to_owned(),
        })
    }
}

/// Stable request-authentication failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// The message carries no `Signature-Input` header.
    MissingSignatureInput,
    /// The message carries no `Signature` header.
    MissingSignature,
    /// No signature input carries the expected label.
    UnknownLabel {
        /// The label that was looked for.
        label: String,
    },
    /// No signature marker carries the expected label.
    SignatureNotFound {
        /// The label that was looked for.
        label: String,
    },
    /// More than one signature marker carries the expected label.
    AmbiguousSignature {
        /// The repeated label.
        label: String,
    },
    /// The signature does not authenticate the bytes the input describes.
    ///
    /// No further detail is reported: which step failed is exactly what an attacker probing a
    /// verifier would want to learn.
    Verification {
        /// The label whose signature failed.
        label: String,
    },
    /// The signature input is invalid or its base cannot be built.
    Input {
        /// Underlying failure.
        source: SignatureInputError,
    },
    /// The `Signature` header is invalid.
    Field {
        /// Underlying failure.
        source: SignatureFieldError,
    },
    /// A header name or value is invalid.
    Header {
        /// Underlying failure.
        source: HeaderError,
    },
    /// A cryptographic operation failed.
    Crypto {
        /// Underlying failure.
        source: Box<CryptoError>,
    },
}

impl AuthenticationError {
    fn crypto(source: CryptoError) -> Self {
        Self::Crypto {
            source: Box::new(source),
        }
    }
}

impl From<SignatureInputError> for AuthenticationError {
    fn from(source: SignatureInputError) -> Self {
        Self::Input { source }
    }
}

impl From<SignatureFieldError> for AuthenticationError {
    fn from(source: SignatureFieldError) -> Self {
        Self::Field { source }
    }
}

impl From<HeaderError> for AuthenticationError {
    fn from(source: HeaderError) -> Self {
        Self::Header { source }
    }
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSignatureInput => write!(
                formatter,
                "the message carries no {SIGNATURE_INPUT_HEADER_NAME:?} header"
            ),
            Self::MissingSignature => {
                write!(formatter, "the message carries no {SIGNATURE_HEADER_NAME:?} header")
            }
            Self::UnknownLabel { label } => {
                write!(formatter, "no signature input is labelled {label:?}")
            }
            Self::SignatureNotFound { label } => {
                write!(formatter, "no signature marker is tagged {label:?}")
            }
            Self::AmbiguousSignature { label } => {
                write!(formatter, "more than one signature marker is tagged {label:?}")
            }
            Self::Verification { label } => {
                write!(
                    formatter,
                    "the signature tagged {label:?} does not authenticate the message"
                )
            }
            Self::Input { .. } => formatter.write_str("the signature input is invalid"),
            Self::Field { .. } => formatter.write_str("the signature header is invalid"),
            Self::Header { .. } => formatter.write_str("a header is invalid"),
            Self::Crypto { .. } => formatter.write_str("a cryptographic operation failed"),
        }
    }
}

impl Error for AuthenticationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input { source } => Some(source),
            Self::Field { source } => Some(source),
            Self::Header { source } => Some(source),
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::salt::{Salt, SecurityTier};
    use keri_cesr::crypto::verifier::KeyTransferability;
    use std::error::Error;

    use crate::signature::input::default_components;

    const RESOURCE: &str = "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs";
    const STAMP: &str = "2022-09-24T00:05:48.196795+00:00";
    const CREATED: u64 = 1_609_459_200;

    fn request_signer() -> Result<RequestSigner, Box<dyn Error>> {
        let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
        Ok(RequestSigner::new(
            salt.derive_signer("", KeyTransferability::Transferable)?,
        ))
    }

    fn request_headers() -> Result<Headers, Box<dyn Error>> {
        Ok(Headers::from_pairs([
            (HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?),
            (HeaderName::new("Signify-Resource")?, HeaderValue::new(RESOURCE)?),
            (HeaderName::new("Signify-Timestamp")?, HeaderValue::new(STAMP)?),
        ])?)
    }

    #[test]
    fn a_signed_request_carries_both_headers() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let attached = signer.sign(&input, &target, &request_headers()?)?;

        assert_eq!(
            attached.signature_input(),
            concat!(
                "signify=(\"@method\" \"@path\" \"signify-resource\" \"signify-timestamp\");",
                "created=1609459200;keyid=\"DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt\";alg=\"ed25519\"",
            )
        );
        assert_eq!(
            attached.signature(),
            concat!(
                "indexed=\"?0\";signify=\"0BChvN_BWAf-mgEuTnWfNnktgHdWOuOh9cWc4o0GFWuZ",
                "Owra3DyJT5dJ_6BX7AANDOTnIlAKh5Sg_9qGQXHjj5oJ\"",
            )
        );

        let names: Vec<&str> = attached.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["Signature-Input", "Signature"]);
        assert_eq!((&attached).into_iter().count(), 2);
        assert_eq!(signer.label().as_str(), "signify");
        assert_eq!(
            signer.key_identifier()?.as_str(),
            "DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt"
        );
        Ok(())
    }

    #[test]
    fn a_signed_request_verifies_against_the_signing_key() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let mut headers = request_headers()?;
        signer.sign(&input, &target, &headers)?.apply(&mut headers)?;

        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());
        let checked = verifier.verify(&target, &headers)?;
        assert_eq!(checked, input);
        assert_eq!(checked.created(), CREATED);
        assert_eq!(verifier.label().as_str(), "signify");
        assert_eq!(verifier.key().qb64()?, signer.key_identifier()?.as_str());
        Ok(())
    }

    #[test]
    fn a_changed_method_or_path_fails_verification() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let mut headers = request_headers()?;
        signer.sign(&input, &target, &headers)?.apply(&mut headers)?;
        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());

        for (method, path) in [("GET", "/boot"), ("POST", "/booted")] {
            assert!(matches!(
                verifier.verify(&RequestTarget::new(method, path)?, &headers),
                Err(AuthenticationError::Verification { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn a_changed_covered_header_fails_verification() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let attached = signer.sign(&input, &target, &request_headers()?)?;

        let mut tampered = Headers::from_pairs([
            (HeaderName::new("Signify-Resource")?, HeaderValue::new(RESOURCE)?),
            (
                HeaderName::new("Signify-Timestamp")?,
                HeaderValue::new("2022-09-24T00:05:48.196796+00:00")?,
            ),
        ])?;
        attached.apply(&mut tampered)?;
        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());
        assert!(matches!(
            verifier.verify(&target, &tampered),
            Err(AuthenticationError::Verification { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_covered_header_removed_after_signing_is_refused() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let attached = signer.sign(&input, &target, &request_headers()?)?;

        // Upstream this silently drops the component and then reports the signature invalid; here
        // the cause is named.
        let mut stripped = Headers::from_pairs([(HeaderName::new("Signify-Resource")?, HeaderValue::new(RESOURCE)?)])?;
        attached.apply(&mut stripped)?;
        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());
        assert!(matches!(
            verifier.verify(&target, &stripped),
            Err(AuthenticationError::Input {
                source: SignatureInputError::MissingCoveredHeader { .. },
            })
        ));
        Ok(())
    }

    #[test]
    fn missing_headers_are_distinguishable_failures() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());
        let target = RequestTarget::new("POST", "/boot")?;

        // Upstream both of these return `false`, which is indistinguishable from a bad signature.
        assert!(matches!(
            verifier.verify(&target, &request_headers()?),
            Err(AuthenticationError::MissingSignatureInput)
        ));

        let mut headers = request_headers()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let attached = signer.sign(&input, &target, &headers)?;
        headers.insert(
            HeaderName::new("Signature-Input")?,
            HeaderValue::new(attached.signature_input())?,
        )?;
        assert!(matches!(
            verifier.verify(&target, &headers),
            Err(AuthenticationError::MissingSignature)
        ));
        Ok(())
    }

    #[test]
    fn the_expected_label_must_be_present_on_both_headers() -> Result<(), Box<dyn Error>> {
        let signer = RequestSigner::with_label(
            Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?
                .derive_signer("", KeyTransferability::Transferable)?,
            InputLabel::new("sig0")?,
        );
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let mut headers = request_headers()?;
        signer.sign(&input, &target, &headers)?.apply(&mut headers)?;

        // Upstream a response labelled anything but `signify` is reported unverified rather than
        // checked; here the label is a parameter, so it verifies.
        let verifier = ResponseVerifier::with_label(signer.signer.verifier().clone(), InputLabel::new("sig0")?);
        assert_eq!(verifier.verify(&target, &headers)?, input);

        let other = ResponseVerifier::new(signer.signer.verifier().clone());
        assert!(matches!(
            other.verify(&target, &headers),
            Err(AuthenticationError::UnknownLabel { label }) if label == "signify"
        ));
        Ok(())
    }

    #[test]
    fn the_signature_is_found_in_any_signage_and_only_once() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let attached = signer.sign(&input, &target, &request_headers()?)?;
        let verifier = ResponseVerifier::new(signer.signer.verifier().clone());

        // The reference reads only signage zero, so this signature would be invisible to it.
        let decoy = r#"indexed="?0";x="0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN""#;
        let mut headers = request_headers()?;
        headers.insert(
            HeaderName::new("Signature-Input")?,
            HeaderValue::new(attached.signature_input())?,
        )?;
        headers.insert(
            HeaderName::new("Signature")?,
            HeaderValue::new(format!("{decoy},{}", attached.signature()))?,
        )?;
        assert_eq!(verifier.verify(&target, &headers)?, input);

        // Two markers under the same label are ambiguous rather than first-wins.
        let mut ambiguous = request_headers()?;
        ambiguous.insert(
            HeaderName::new("Signature-Input")?,
            HeaderValue::new(attached.signature_input())?,
        )?;
        ambiguous.insert(
            HeaderName::new("Signature")?,
            HeaderValue::new(format!("{},{}", attached.signature(), attached.signature()))?,
        )?;
        assert!(matches!(
            verifier.verify(&target, &ambiguous),
            Err(AuthenticationError::AmbiguousSignature { .. })
        ));

        // A signage carrying no marker under the label is not a signature at all.
        let mut absent = request_headers()?;
        absent.insert(
            HeaderName::new("Signature-Input")?,
            HeaderValue::new(attached.signature_input())?,
        )?;
        absent.insert(HeaderName::new("Signature")?, HeaderValue::new(decoy)?)?;
        assert!(matches!(
            verifier.verify(&target, &absent),
            Err(AuthenticationError::SignatureNotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn the_signer_never_prints_its_secret() -> Result<(), Box<dyn Error>> {
        let rendered = format!("{:?}", request_signer()?);
        assert!(rendered.contains("RequestSigner"));
        assert!(rendered.contains("signify"));
        assert!(!rendered.contains("0123456789abcdef"));
        Ok(())
    }

    #[test]
    fn applying_the_headers_twice_is_refused() -> Result<(), Box<dyn Error>> {
        let signer = request_signer()?;
        let input = signer.signature_input(default_components()?, CREATED)?;
        let target = RequestTarget::new("POST", "/boot")?;
        let attached = signer.sign(&input, &target, &request_headers()?)?;
        let mut headers = request_headers()?;
        attached.apply(&mut headers)?;
        assert!(matches!(
            attached.apply(&mut headers),
            Err(AuthenticationError::Header {
                source: HeaderError::DuplicateHeader { .. },
            })
        ));
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_sources() {
        for error in [
            AuthenticationError::MissingSignatureInput,
            AuthenticationError::MissingSignature,
            AuthenticationError::UnknownLabel {
                label: "signify".to_owned(),
            },
            AuthenticationError::SignatureNotFound {
                label: "signify".to_owned(),
            },
            AuthenticationError::AmbiguousSignature {
                label: "signify".to_owned(),
            },
            AuthenticationError::Verification {
                label: "signify".to_owned(),
            },
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
        for error in [
            AuthenticationError::from(SignatureInputError::NoInputs),
            AuthenticationError::from(SignatureFieldError::NoMarkers),
            AuthenticationError::from(HeaderError::EmptyName),
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_some());
        }
    }
}

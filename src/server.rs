//! Verifying a request and signing a response.
//!
//! [`RequestVerifier`] accepts what KERIA agents accept: the sender chooses what a signature covers,
//! a covered header that is absent adds nothing, and `keyid` is not read. [`Freshness`] is off until
//! a caller sets one, so a captured request stays valid until the controller's key changes.

use core::fmt;
use std::error::Error;
use std::time::{Duration, SystemTime};

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::VerificationKey;

use crate::authentication::{AuthenticationError, RequestSigner, find_signature};
use crate::fields::{FieldText, SIGNATURE_HEADER_NAME, SignatureHeader};
use crate::header::{HeaderName, HeaderValue, Headers};
use crate::input::{
    ED25519_ALGORITHM, InputLabel, RequestTarget, SIGNATURE_INPUT_HEADER_NAME, SIGNIFY_RESOURCE_HEADER_NAME,
    SIGNIFY_TIMESTAMP_HEADER_NAME, SignatureComponent, SignatureInput, SignatureInputBuilder, SignatureInputHeader,
};
use crate::timestamp::SignifyTimestamp;

/// Finds the key a controller signs requests with.
pub trait KeyLookup {
    /// Returns the controller's first current key, or `None` for an unknown controller or one
    /// whose log is unresolved.
    fn first_current_key(&self, controller: &str) -> Option<VerificationKey>;
}

/// How far either side of now a signature's `created` may sit.
///
/// It has two sides because two machines' clocks disagree in both directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Freshness {
    /// Accept any `created`.
    Ignore,
    /// Accept a `created` between `past` before now and `future` after it.
    Window {
        /// How far behind now a signature may be.
        past: Duration,
        /// How far ahead of now a signature may be, which is tolerance for clock skew.
        future: Duration,
    },
}

impl Default for Freshness {
    /// Five minutes behind, one minute ahead.
    fn default() -> Self {
        Self::Window {
            past: Duration::from_mins(5),
            future: Duration::from_mins(1),
        }
    }
}

impl Freshness {
    /// Checks one `created` against a moment.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError`] when `created` is outside the window or `now` precedes the epoch.
    pub fn check(self, created: u64, now: SystemTime) -> Result<(), FreshnessError> {
        let Self::Window { past, future } = self else {
            return Ok(());
        };
        let now_seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| FreshnessError::UnusableClock)?
            .as_secs();

        if created.saturating_add(past.as_secs()) < now_seconds {
            return Err(FreshnessError::Stale {
                created,
                now: now_seconds,
                allowed: past,
            });
        }
        if created > now_seconds.saturating_add(future.as_secs()) {
            return Err(FreshnessError::FromTheFuture {
                created,
                now: now_seconds,
                allowed: future,
            });
        }
        Ok(())
    }
}

/// Why a `created` is outside a [`Freshness`] window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FreshnessError {
    /// The signature is older than the window allows.
    Stale {
        /// The signature's `created`.
        created: u64,
        /// The moment it was checked, in seconds since the epoch.
        now: u64,
        /// How far behind `now` it may be.
        allowed: Duration,
    },
    /// The signature is newer than the window allows.
    FromTheFuture {
        /// The signature's `created`.
        created: u64,
        /// The moment it was checked, in seconds since the epoch.
        now: u64,
        /// How far ahead of `now` it may be.
        allowed: Duration,
    },
    /// The clock reads before the epoch.
    UnusableClock,
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale { .. } => formatter.write_str("the signature is too old"),
            Self::FromTheFuture { .. } => formatter.write_str("the signature is dated in the future"),
            Self::UnusableClock => formatter.write_str("the clock reads before the epoch"),
        }
    }
}

impl Error for FreshnessError {}

/// A request that authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRequest {
    controller: String,
    input: SignatureInput,
}

impl VerifiedRequest {
    /// Returns the controller named by `Signify-Resource`.
    #[must_use]
    pub fn controller(&self) -> &str {
        &self.controller
    }

    /// Returns the input the signature covered.
    #[must_use]
    pub const fn input(&self) -> &SignatureInput {
        &self.input
    }
}

/// Verifies signed requests against the keys a [`KeyLookup`] returns.
#[derive(Clone, Debug)]
pub struct RequestVerifier<L> {
    lookup: L,
    freshness: Freshness,
}

impl<L: KeyLookup> RequestVerifier<L> {
    /// Verifies with [`Freshness::Ignore`].
    #[must_use]
    pub const fn new(lookup: L) -> Self {
        Self {
            lookup,
            freshness: Freshness::Ignore,
        }
    }

    /// Replaces the freshness policy.
    #[must_use]
    pub const fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Verifies one request, whose path must already be [`canonical_path`].
    ///
    /// Route on that same path, never the raw one: several raw paths share one canonical path, so
    /// they share a signature. Build `headers` with [`Headers::received`].
    ///
    /// # Errors
    ///
    /// Returns a [`RequestRejection`].
    pub fn verify(
        &self,
        target: &RequestTarget,
        headers: &Headers,
        now: SystemTime,
    ) -> Result<VerifiedRequest, RequestRejection> {
        let required = |name: &'static str| headers.get(name).ok_or(RequestRejection::MissingHeader { name });
        let input_value = required(SIGNATURE_INPUT_HEADER_NAME)?;
        let signature_value = required(SIGNATURE_HEADER_NAME)?;
        let controller = required(SIGNIFY_RESOURCE_HEADER_NAME)?;

        let key = self
            .lookup
            .first_current_key(controller)
            .ok_or(RequestRejection::UnknownController)?;

        let label = InputLabel::signify();
        let inputs = SignatureInputHeader::parse_received(input_value).map_err(RequestRejection::malformed)?;
        let input = inputs.find(&label).ok_or(RequestRejection::NoSignifyInput)?;
        let signature = SignatureHeader::parse(signature_value).map_err(RequestRejection::malformed)?;
        let signature = find_signature(&signature, &label).map_err(RequestRejection::malformed)?;
        let base = input
            .received_base(target, headers)
            .map_err(RequestRejection::malformed)?;
        key.verify(signature, base.as_bytes())
            .map_err(|_| RequestRejection::InvalidSignature)?;

        self.freshness
            .check(input.created(), now)
            .map_err(|source| RequestRejection::Freshness { source })?;
        Ok(VerifiedRequest {
            controller: controller.to_owned(),
            input: input.clone(),
        })
    }
}

/// Why a request did not authenticate.
///
/// `Display` is the same for every variant, so showing it to a peer leaks nothing; log `Debug`.
#[derive(Debug)]
#[non_exhaustive]
pub enum RequestRejection {
    /// A required header is absent.
    MissingHeader {
        /// The header.
        name: &'static str,
    },
    /// The controller is unknown or its log is unresolved.
    UnknownController,
    /// No input carries the `signify` label.
    NoSignifyInput,
    /// A header cannot be read.
    Malformed {
        /// Underlying failure.
        source: AuthenticationError,
    },
    /// The signature does not authenticate the request.
    InvalidSignature,
    /// The signature is outside the freshness window.
    Freshness {
        /// Underlying failure.
        source: FreshnessError,
    },
}

impl RequestRejection {
    fn malformed(source: impl Into<AuthenticationError>) -> Self {
        Self::Malformed { source: source.into() }
    }
}

impl fmt::Display for RequestRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the request could not be authenticated")
    }
}

impl Error for RequestRejection {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Malformed { source } => Some(source),
            Self::Freshness { source } => Some(source),
            Self::MissingHeader { .. } | Self::UnknownController | Self::NoSignifyInput | Self::InvalidSignature => {
                None
            }
        }
    }
}

/// Signs responses as one identifier.
pub struct ResponseSigner {
    signer: RequestSigner,
    identifier: FieldText,
}

impl ResponseSigner {
    /// Signs with the identifier's first current key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Field`] when `identifier` is not usable as a parameter value.
    pub fn new(signer: Signer, identifier: &str) -> Result<Self, AuthenticationError> {
        Ok(Self {
            signer: RequestSigner::new(signer),
            identifier: FieldText::new(identifier)?,
        })
    }

    /// Returns the four headers a response carries, for a request's method and [`canonical_path`].
    ///
    /// `Signature-Input` names the identifier as `keyid` and covers `signify-resource`, `@method`,
    /// `@path` and `signify-timestamp`, in that order. Pass [`SignifyTimestamp::created`] as `created`
    /// unless a test needs them apart.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] when a header cannot be built or signing fails.
    pub fn sign(
        &self,
        target: &RequestTarget,
        timestamp: &SignifyTimestamp,
        created: u64,
    ) -> Result<Headers, AuthenticationError> {
        let resource = HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME.to_ascii_lowercase())?;
        let moment = HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME.to_ascii_lowercase())?;
        let components = vec![
            SignatureComponent::Header(resource.clone()),
            SignatureComponent::Method,
            SignatureComponent::Path,
            SignatureComponent::Header(moment.clone()),
        ];
        let input = SignatureInputBuilder::new(InputLabel::signify(), components, created)
            .key_identifier(self.identifier.clone())
            .algorithm(FieldText::new(ED25519_ALGORITHM)?)
            .build()?;

        let mut headers = Headers::new();
        headers.insert(resource, HeaderValue::new(self.identifier.as_str())?)?;
        headers.insert(moment, timestamp.to_header_value()?)?;
        self.signer.sign(&input, target, &headers)?.apply(&mut headers)?;
        Ok(headers)
    }
}

impl fmt::Debug for ResponseSigner {
    /// Redacts the signer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseSigner")
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

/// Returns the form of a path both sides sign: percent-decoded, then percent-encoded again.
///
/// So `:` is `%3A`, `%2F` becomes `/`, and invalid UTF-8 becomes `U+FFFD`.
#[must_use]
pub fn canonical_path(raw: &str) -> String {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut rest = raw.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%'
            && let [high, low, remainder @ ..] = tail
            && let (Some(high), Some(low)) = (char::from(*high).to_digit(16), char::from(*low).to_digit(16))
        {
            decoded.extend(u8::try_from(high.saturating_mul(16).saturating_add(low)));
            rest = remainder;
        } else {
            decoded.push(byte);
            rest = tail;
        }
    }

    let mut quoted = String::with_capacity(raw.len());
    for byte in String::from_utf8_lossy(&decoded).bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'.' | b'-' | b'~') {
            quoted.push(char::from(byte));
        } else {
            quoted.push('%');
            quoted.extend([hex_digit(byte >> 4), hex_digit(byte & 0x0f)]);
        }
    }
    quoted
}

/// Returns the upper-case digit of a value below sixteen.
fn hex_digit(value: u8) -> char {
    char::from_digit(u32::from(value), 16).map_or('0', |digit| digit.to_ascii_uppercase())
}

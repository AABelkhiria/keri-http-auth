//! The `Signature-Input` header and the signature base it describes.
//!
//! A signed request carries two headers. `Signature` holds the signature material and is
//! [`crate::signature::fields`]' concern; `Signature-Input` says *what* that signature covers, and
//! the bytes actually signed — the **signature base** — are derived from it:
//!
//! ```text
//! Signature-Input: signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1609459200;keyid="DN54…";alg="ed25519"
//! ```
//!
//! ```text
//! "@method": POST
//! "@path": /boot
//! "signify-resource": EWJk…
//! "signify-timestamp": 2022-09-24T00:05:48.196795+00:00
//! "@signature-params: (@method @path signify-resource signify-timestamp);created=1609459200;keyid=DN54…;alg=ed25519"
//! ```
//!
//! This module ports `siginput` and `desiginput` from `src/keri/core/httping.ts`.
//!
//! # Two grammars, one value
//!
//! The header and the base spell the same information differently, and the difference is
//! protocol-required rather than accidental: the header quotes each covered component and each
//! textual parameter, while the base leaves both bare, and the base's trailing item puts the
//! opening quote *before* `@signature-params` rather than around it. Both spellings are reproduced
//! exactly.
//!
//! The header is close to an RFC 8941 dictionary but the accepted space is deliberately narrower;
//! `docs/adr/0011-signature-input-canonicalization.md` records why.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

use crate::header::{HeaderError, HeaderName, Headers};
use crate::signature::fields::{FieldText, SignatureFieldError};

/// Name of the header this module formats and parses.
pub const SIGNATURE_INPUT_HEADER_NAME: &str = "Signature-Input";

/// Name of the header carrying the timestamp a KERIA request covers.
pub const SIGNIFY_TIMESTAMP_HEADER_NAME: &str = "Signify-Timestamp";

/// Name of the header carrying the identifier a KERIA request speaks for.
pub const SIGNIFY_RESOURCE_HEADER_NAME: &str = "Signify-Resource";

/// Derived component naming the request method.
pub const METHOD_COMPONENT: &str = "@method";

/// Derived component naming the request path.
pub const PATH_COMPONENT: &str = "@path";

/// Name of the trailing signature-base item that commits to the parameters themselves.
pub const SIGNATURE_PARAMS_COMPONENT: &str = "@signature-params";

/// The `alg` parameter value every Signify signature carries.
pub const ED25519_ALGORITHM: &str = "ed25519";

/// Default label for the one signature input a Signify client emits.
pub const SIGNIFY_LABEL: &str = "signify";

/// Largest `Signature-Input` value this module parses or produces, in bytes.
pub const MAX_SIGNATURE_INPUT_BYTES: usize = 16 * 1024;

/// Largest signature base this module produces, in bytes.
pub const MAX_SIGNATURE_BASE_BYTES: usize = 64 * 1024;

/// Largest label, in bytes.
pub const MAX_LABEL_BYTES: usize = 64;

/// Largest number of covered components in one input.
pub const MAX_COMPONENTS: usize = 64;

/// Largest number of labelled inputs in one header.
pub const MAX_INPUTS: usize = 16;

/// Largest request path, in bytes.
pub const MAX_REQUEST_PATH_BYTES: usize = 4096;

/// Largest request method, in bytes.
pub const MAX_REQUEST_METHOD_BYTES: usize = 64;

/// Largest value an RFC 8941 integer parameter may hold.
pub const MAX_PARAMETER_INTEGER: u64 = 999_999_999_999_999;

/// One validated dictionary label naming a signature input.
///
/// The accepted text is the RFC 8941 dictionary key: a lower-case letter or `*`, then lower-case
/// letters, digits, `_`, `-`, `.`, and `*`. The reference's own serializer refuses anything else,
/// so an upper-case label would produce a header it could not emit.
///
/// ```
/// use signify_http::signature::input::InputLabel;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(InputLabel::signify().as_str(), "signify");
/// assert!(InputLabel::new("Signify").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InputLabel {
    text: String,
}

impl InputLabel {
    /// Returns the `signify` label every Signify client uses.
    #[must_use]
    pub fn signify() -> Self {
        Self {
            text: SIGNIFY_LABEL.to_owned(),
        }
    }

    /// Validates one label.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::InvalidLabel`] for empty input, for a label above
    /// [`MAX_LABEL_BYTES`], or for a byte outside the dictionary-key set.
    pub fn new(text: impl Into<String>) -> Result<Self, SignatureInputError> {
        let text = text.into();
        let invalid = || SignatureInputError::InvalidLabel { label: bounded(&text) };
        if text.is_empty() || text.len() > MAX_LABEL_BYTES {
            return Err(invalid());
        }
        let mut bytes = text.bytes();
        match bytes.next() {
            Some(byte) if byte.is_ascii_lowercase() || byte == b'*' => {}
            _ => return Err(invalid()),
        }
        if !bytes.all(is_key_byte) {
            return Err(invalid());
        }
        Ok(Self { text })
    }

    /// Returns the label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl FromStr for InputLabel {
    type Err = SignatureInputError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl fmt::Display for InputLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns whether a byte may appear after the first character of a dictionary key.
const fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.' | b'*')
}

/// One thing a signature covers.
///
/// The reference accepts any `@`-prefixed name but implements only `@method` and `@path`: every
/// other derived component is listed in the header and then contributes **nothing** to the base, so
/// the header advertises coverage the signature does not provide. Only the two that exist are
/// representable here.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureComponent {
    /// The request method, written `@method`.
    Method,
    /// The request path, written `@path`.
    Path,
    /// One request or response header.
    Header(HeaderName),
}

impl SignatureComponent {
    /// Reads one covered-component name.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::UnknownDerivedComponent`] for an `@`-name other than
    /// `@method` or `@path`, and [`SignatureInputError::Header`] for an invalid field name.
    pub fn new(name: &str) -> Result<Self, SignatureInputError> {
        match name {
            METHOD_COMPONENT => Ok(Self::Method),
            PATH_COMPONENT => Ok(Self::Path),
            _ if name.starts_with('@') => Err(SignatureInputError::UnknownDerivedComponent { name: bounded(name) }),
            _ => Ok(Self::Header(HeaderName::new(name)?)),
        }
    }

    /// Returns the name this component is written under, in the header and in the base.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Method => METHOD_COMPONENT,
            Self::Path => PATH_COMPONENT,
            Self::Header(name) => name.as_str(),
        }
    }

    /// Returns whether two components name the same thing.
    fn is_same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Method, Self::Method) | (Self::Path, Self::Path) => true,
            (Self::Header(left), Self::Header(right)) => left == right,
            _ => false,
        }
    }
}

impl FromStr for SignatureComponent {
    type Err = SignatureInputError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl fmt::Display for SignatureComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Returns the components `Authenticater.DefaultFields` covers, in its order.
///
/// Every KERIA request covers exactly these four: the method, the path, the identifier the request
/// speaks for, and its timestamp. The two header names are lower-case, as upstream, which is also
/// the spelling that interoperates with keripy — see `PORTING.md` §9.
///
/// # Errors
///
/// Returns [`SignatureInputError::Header`] only if the constant names ever stop being valid field
/// names, which the unit tests assert they do not.
pub fn default_components() -> Result<Vec<SignatureComponent>, SignatureInputError> {
    Ok(vec![
        SignatureComponent::Method,
        SignatureComponent::Path,
        SignatureComponent::Header(HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME.to_ascii_lowercase())?),
        SignatureComponent::Header(HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME.to_ascii_lowercase())?),
    ])
}

/// The method and path a signature covers.
///
/// The reference validates neither: a path carrying a newline forges a whole component line in the
/// signature base, since the base joins its items with one. Both are validated here.
///
/// The path must carry no query, matching every upstream call site — the client strips `?` before
/// signing — so a caller cannot accidentally cover a query the peer will not.
///
/// ```
/// use signify_http::signature::input::RequestTarget;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let target = RequestTarget::new("POST", "/boot")?;
/// assert_eq!(target.method(), "POST");
/// assert!(RequestTarget::new("GET", "/a\n\"@method\": DELETE").is_err());
/// assert!(RequestTarget::new("GET", "/identifiers?limit=10").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestTarget {
    method: String,
    path: String,
}

impl RequestTarget {
    /// Validates one method and path.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::InvalidRequestMethod`] for an empty, oversized, or
    /// non-token method, and [`SignatureInputError::InvalidRequestPath`] for a path that is empty,
    /// oversized, does not start with `/`, carries a query or fragment, or holds a byte outside
    /// visible ASCII.
    pub fn new(method: &str, path: &str) -> Result<Self, SignatureInputError> {
        if method.is_empty() || method.len() > MAX_REQUEST_METHOD_BYTES || !method.bytes().all(is_method_byte) {
            return Err(SignatureInputError::InvalidRequestMethod {
                method: bounded(method),
            });
        }
        if path.is_empty()
            || path.len() > MAX_REQUEST_PATH_BYTES
            || !path.starts_with('/')
            || !path.bytes().all(is_path_byte)
        {
            return Err(SignatureInputError::InvalidRequestPath { path: bounded(path) });
        }
        Ok(Self {
            method: method.to_owned(),
            path: path.to_owned(),
        })
    }

    /// Returns the method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the path, which carries no query.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Returns whether a byte may appear in a request method.
const fn is_method_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*' | b'!' | b'~' | b'\'' | b'+' | b'`')
}

/// Returns whether a byte may appear in a covered request path.
const fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'"')
}

/// The exact bytes a signature commits to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureBase {
    text: String,
}

impl SignatureBase {
    /// Returns the base as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the exact bytes signed, which are the UTF-8 encoding of the text.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

impl fmt::Display for SignatureBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One labelled signature input: what a signature covers, and the parameters describing it.
///
/// Build one with [`SignatureInputBuilder`], or recover one by parsing a
/// [`SignatureInputHeader`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureInput {
    label: InputLabel,
    components: Vec<SignatureComponent>,
    created: u64,
    expires: Option<u64>,
    nonce: Option<FieldText>,
    key_identifier: Option<FieldText>,
    context: Option<FieldText>,
    algorithm: Option<FieldText>,
}

impl SignatureInput {
    /// Returns the label this input is written under.
    #[must_use]
    pub const fn label(&self) -> &InputLabel {
        &self.label
    }

    /// Returns the covered components in the order they are signed.
    #[must_use]
    pub fn components(&self) -> &[SignatureComponent] {
        &self.components
    }

    /// Returns the creation time, in seconds since the Unix epoch.
    ///
    /// The reference takes this from the system clock. It is an input here, so a protocol crate
    /// never reads the clock and a signature is reproducible; deciding whether a received value is
    /// fresh enough is a replay policy, which Roadmap 5.5 owns.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }

    /// Returns the expiry time, when one is present.
    #[must_use]
    pub const fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// Returns the nonce, when one is present.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_ref().map(FieldText::as_str)
    }

    /// Returns the key identifier, when one is present.
    ///
    /// For a Signify request this is the signer's qualified verification key.
    #[must_use]
    pub fn key_identifier(&self) -> Option<&str> {
        self.key_identifier.as_ref().map(FieldText::as_str)
    }

    /// Returns the implementation-specific context, when one is present.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_ref().map(FieldText::as_str)
    }

    /// Returns the signature algorithm as written, when one is present.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.algorithm.as_ref().map(FieldText::as_str)
    }

    /// Builds the exact bytes a signature over this input commits to.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::MissingCoveredHeader`] when a covered header is absent — the
    /// reference silently drops it, so the caller gets a weaker signature than it asked for — and
    /// [`SignatureInputError::SignatureBaseTooLong`] above [`MAX_SIGNATURE_BASE_BYTES`].
    pub fn signature_base(
        &self,
        target: &RequestTarget,
        headers: &Headers,
    ) -> Result<SignatureBase, SignatureInputError> {
        let mut items: Vec<String> = Vec::with_capacity(self.components.len().saturating_add(1));
        for component in &self.components {
            let value = match component {
                SignatureComponent::Method => target.method(),
                SignatureComponent::Path => target.path(),
                SignatureComponent::Header(name) => {
                    headers
                        .get(name.as_str())
                        .ok_or_else(|| SignatureInputError::MissingCoveredHeader {
                            name: bounded(name.as_str()),
                        })?
                }
            };
            items.push(format!("\"{}\": {value}", component.as_str()));
        }
        // The opening quote sits before `@signature-params` and the closing one after the last
        // parameter, so the whole parameter list is inside one quoted item. That is the reference's
        // spelling, and changing it would change every signature.
        items.push(format!(
            "\"{SIGNATURE_PARAMS_COMPONENT}: {}\"",
            self.render_parameters(false)
        ));

        let text = items.join("\n");
        if text.len() > MAX_SIGNATURE_BASE_BYTES {
            return Err(SignatureInputError::SignatureBaseTooLong {
                length: text.len(),
                maximum: MAX_SIGNATURE_BASE_BYTES,
            });
        }
        Ok(SignatureBase { text })
    }

    /// Renders the covered list and parameters, quoted for the header or bare for the base.
    fn render_parameters(&self, quoted: bool) -> String {
        let names = self
            .components
            .iter()
            .map(|component| {
                if quoted {
                    format!("\"{}\"", component.as_str())
                } else {
                    component.as_str().to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        let mut rendered = format!("({names});created={}", self.created);
        if let Some(expires) = self.expires {
            rendered.push_str(";expires=");
            rendered.push_str(&expires.to_string());
        }
        for (name, value) in [
            ("nonce", self.nonce.as_ref()),
            ("keyid", self.key_identifier.as_ref()),
            ("context", self.context.as_ref()),
            ("alg", self.algorithm.as_ref()),
        ] {
            let Some(value) = value else { continue };
            rendered.push(';');
            rendered.push_str(name);
            rendered.push('=');
            if quoted {
                rendered.push('"');
                rendered.push_str(value.as_str());
                rendered.push('"');
            } else {
                rendered.push_str(value.as_str());
            }
        }
        rendered
    }

    /// Renders this input as one dictionary member.
    fn render(&self) -> String {
        format!("{}={}", self.label, self.render_parameters(true))
    }
}

/// Builds one [`SignatureInput`].
///
/// ```
/// use signify_http::signature::input::{
///     InputLabel, SignatureInputBuilder, SignatureInputHeader, default_components,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let input = SignatureInputBuilder::new(InputLabel::signify(), default_components()?, 1_609_459_200)
///     .algorithm("ed25519".parse()?)
///     .build()?;
/// let header = SignatureInputHeader::new(vec![input])?;
///
/// assert_eq!(
///     header.to_header_value()?,
///     concat!(
///         r#"signify=("@method" "@path" "signify-resource" "signify-timestamp");"#,
///         r#"created=1609459200;alg="ed25519""#,
///     ),
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct SignatureInputBuilder {
    label: InputLabel,
    components: Vec<SignatureComponent>,
    created: u64,
    expires: Option<u64>,
    nonce: Option<FieldText>,
    key_identifier: Option<FieldText>,
    context: Option<FieldText>,
    algorithm: Option<FieldText>,
}

impl SignatureInputBuilder {
    /// Starts an input from the three things it always has: a label, what it covers, and when it
    /// was created.
    #[must_use]
    pub const fn new(label: InputLabel, components: Vec<SignatureComponent>, created: u64) -> Self {
        Self {
            label,
            components,
            created,
            expires: None,
            nonce: None,
            key_identifier: None,
            context: None,
            algorithm: None,
        }
    }

    /// Sets the expiry time, in seconds since the Unix epoch.
    #[must_use]
    pub const fn expires(mut self, expires: u64) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets the nonce.
    #[must_use]
    pub fn nonce(mut self, nonce: FieldText) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the key identifier, which for a Signify request is the qualified verification key.
    #[must_use]
    pub fn key_identifier(mut self, key_identifier: FieldText) -> Self {
        self.key_identifier = Some(key_identifier);
        self
    }

    /// Sets the implementation-specific context.
    #[must_use]
    pub fn context(mut self, context: FieldText) -> Self {
        self.context = Some(context);
        self
    }

    /// Sets the signature algorithm, which Signify always spells [`ED25519_ALGORITHM`].
    #[must_use]
    pub fn algorithm(mut self, algorithm: FieldText) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Validates the input.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::NoComponents`] when nothing is covered — the reference emits
    /// and accepts a signature binding neither method, path, nor header —
    /// [`SignatureInputError::TooManyComponents`] above [`MAX_COMPONENTS`],
    /// [`SignatureInputError::DuplicateComponent`] when one thing is covered twice;
    /// [`SignatureInputError::ParameterOutOfRange`] when a time exceeds
    /// [`MAX_PARAMETER_INTEGER`], which the header grammar cannot express; and
    /// [`SignatureInputError::InvalidParameterValue`] for a value carrying a backslash, which the
    /// header would escape and the base would not — the reference's own escaping defect.
    pub fn build(self) -> Result<SignatureInput, SignatureInputError> {
        if self.components.is_empty() {
            return Err(SignatureInputError::NoComponents);
        }
        if self.components.len() > MAX_COMPONENTS {
            return Err(SignatureInputError::TooManyComponents {
                count: self.components.len(),
                maximum: MAX_COMPONENTS,
            });
        }
        for (position, component) in self.components.iter().enumerate() {
            if self
                .components
                .iter()
                .take(position)
                .any(|earlier| earlier.is_same(component))
            {
                return Err(SignatureInputError::DuplicateComponent {
                    name: bounded(component.as_str()),
                });
            }
        }
        for (name, value) in [("created", Some(self.created)), ("expires", self.expires)] {
            if value.is_some_and(|value| value > MAX_PARAMETER_INTEGER) {
                return Err(SignatureInputError::ParameterOutOfRange { name });
            }
        }
        // `FieldText` already excludes every byte that would break either grammar except the
        // backslash, which an RFC 8941 string escapes and the signature base does not — so a value
        // carrying one would render a header the parser refuses and bytes the peer never signed.
        for (name, value) in [
            ("nonce", self.nonce.as_ref()),
            ("keyid", self.key_identifier.as_ref()),
            ("context", self.context.as_ref()),
            ("alg", self.algorithm.as_ref()),
        ] {
            if value.is_some_and(|value| value.as_str().contains('\\')) {
                return Err(SignatureInputError::InvalidParameterValue { name });
            }
        }

        Ok(SignatureInput {
            label: self.label,
            components: self.components,
            created: self.created,
            expires: self.expires,
            nonce: self.nonce,
            key_identifier: self.key_identifier,
            context: self.context,
            algorithm: self.algorithm,
        })
    }
}

/// One complete `Signature-Input` header value: a dictionary of labelled inputs.
///
/// A Signify client emits exactly one member; the parser accepts several, as the reference does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureInputHeader {
    inputs: Vec<SignatureInput>,
}

impl SignatureInputHeader {
    /// Name of the header this value belongs to.
    pub const NAME: &'static str = SIGNATURE_INPUT_HEADER_NAME;

    /// Collects one or more inputs into a header value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::NoInputs`] for an empty list,
    /// [`SignatureInputError::TooManyInputs`] above [`MAX_INPUTS`], and
    /// [`SignatureInputError::DuplicateLabel`] for a repeated label — a dictionary keeps only the
    /// last member with a given key, so upstream the earlier input silently disappears.
    pub fn new(inputs: Vec<SignatureInput>) -> Result<Self, SignatureInputError> {
        if inputs.is_empty() {
            return Err(SignatureInputError::NoInputs);
        }
        if inputs.len() > MAX_INPUTS {
            return Err(SignatureInputError::TooManyInputs {
                count: inputs.len(),
                maximum: MAX_INPUTS,
            });
        }
        for (position, input) in inputs.iter().enumerate() {
            if inputs
                .iter()
                .take(position)
                .any(|earlier| earlier.label() == input.label())
            {
                return Err(SignatureInputError::DuplicateLabel {
                    label: bounded(input.label().as_str()),
                });
            }
        }
        Ok(Self { inputs })
    }

    /// Returns the inputs in header order.
    #[must_use]
    pub fn inputs(&self) -> &[SignatureInput] {
        &self.inputs
    }

    /// Returns the input written under one label.
    #[must_use]
    pub fn find(&self, label: &InputLabel) -> Option<&SignatureInput> {
        self.inputs.iter().find(|input| input.label() == label)
    }

    /// Renders the complete header value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::SignatureInputTooLong`] above
    /// [`MAX_SIGNATURE_INPUT_BYTES`].
    pub fn to_header_value(&self) -> Result<String, SignatureInputError> {
        // Two members are separated by a comma and a space, which is what the reference's
        // serializer emits; `fixtures/http-authing/v1.json` pins the exact spelling.
        let rendered = self
            .inputs
            .iter()
            .map(SignatureInput::render)
            .collect::<Vec<_>>()
            .join(", ");
        if rendered.len() > MAX_SIGNATURE_INPUT_BYTES {
            return Err(SignatureInputError::SignatureInputTooLong {
                length: rendered.len(),
                maximum: MAX_SIGNATURE_INPUT_BYTES,
            });
        }
        Ok(rendered)
    }

    /// Parses one complete header value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureInputError::SignatureInputTooLong`] above
    /// [`MAX_SIGNATURE_INPUT_BYTES`], [`SignatureInputError::Malformed`] for anything the narrowed
    /// dictionary grammar does not accept, [`SignatureInputError::MissingCreated`] for an input
    /// without the one required parameter, [`SignatureInputError::UnknownParameter`] for a
    /// parameter the reference would silently ignore, and
    /// [`SignatureInputError::ParametersOutOfOrder`] when the parameters are not in the order both
    /// implementations emit and rebuild them in.
    pub fn parse(value: &str) -> Result<Self, SignatureInputError> {
        if value.len() > MAX_SIGNATURE_INPUT_BYTES {
            return Err(SignatureInputError::SignatureInputTooLong {
                length: value.len(),
                maximum: MAX_SIGNATURE_INPUT_BYTES,
            });
        }
        let mut parser = Parser::new(value);
        let mut inputs = Vec::new();
        loop {
            inputs.push(parser.parse_input()?);
            if !parser.eat(b',') {
                break;
            }
            parser.skip_whitespace();
        }
        if !parser.is_finished() {
            return Err(parser.malformed("trailing material"));
        }
        Self::new(inputs)
    }
}

impl FromStr for SignatureInputHeader {
    type Err = SignatureInputError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for SignatureInputHeader {
    type Error = SignatureInputError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

/// Every parameter name, in the order both implementations write and rebuild them.
const PARAMETER_ORDER: [&str; 6] = ["created", "expires", "nonce", "keyid", "context", "alg"];

/// A cursor over one header value.
struct Parser<'input> {
    bytes: &'input [u8],
    position: usize,
}

impl<'input> Parser<'input> {
    const fn new(value: &'input str) -> Self {
        Self {
            bytes: value.as_bytes(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position = self.position.saturating_add(1);
            return true;
        }
        false
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.position = self.position.saturating_add(1);
        }
    }

    const fn is_finished(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn malformed(&self, reason: &'static str) -> SignatureInputError {
        SignatureInputError::Malformed {
            reason,
            offset: self.position,
        }
    }

    /// Reads a run of bytes satisfying `accept`, returning it as text.
    fn take_while(&mut self, accept: fn(u8) -> bool) -> &'input str {
        let start = self.position;
        while self.peek().is_some_and(accept) {
            self.position = self.position.saturating_add(1);
        }
        // Every accepted byte is ASCII, so the slice is always valid UTF-8.
        self.bytes
            .get(start..self.position)
            .and_then(|slice| core::str::from_utf8(slice).ok())
            .unwrap_or_default()
    }

    /// Reads one `label=(components);parameters` member.
    fn parse_input(&mut self) -> Result<SignatureInput, SignatureInputError> {
        let label = InputLabel::new(self.take_while(|byte| is_key_byte(byte) || byte == b'*'))?;
        if !self.eat(b'=') {
            return Err(self.malformed("a member needs a value"));
        }
        let components = self.parse_components()?;

        let mut created = None;
        let mut expires = None;
        let mut nonce = None;
        let mut key_identifier = None;
        let mut context = None;
        let mut algorithm = None;
        let mut last_position: Option<usize> = None;

        while self.eat(b';') {
            let name = self.take_while(is_key_byte);
            if name.is_empty() {
                return Err(self.malformed("a parameter needs a name"));
            }
            let Some(order) = PARAMETER_ORDER.iter().position(|known| *known == name) else {
                return Err(SignatureInputError::UnknownParameter { name: bounded(name) });
            };
            if last_position.is_some_and(|last| order <= last) {
                return Err(SignatureInputError::ParametersOutOfOrder);
            }
            last_position = Some(order);
            if !self.eat(b'=') {
                return Err(self.malformed("a parameter needs a value"));
            }
            match name {
                "created" => created = Some(self.parse_integer()?),
                "expires" => expires = Some(self.parse_integer()?),
                "nonce" => nonce = Some(self.parse_text()?),
                "keyid" => key_identifier = Some(self.parse_text()?),
                "context" => context = Some(self.parse_text()?),
                _ => algorithm = Some(self.parse_text()?),
            }
        }

        let created = created.ok_or(SignatureInputError::MissingCreated {
            label: bounded(label.as_str()),
        })?;
        let mut builder = SignatureInputBuilder::new(label, components, created);
        if let Some(expires) = expires {
            builder = builder.expires(expires);
        }
        if let Some(nonce) = nonce {
            builder = builder.nonce(nonce);
        }
        if let Some(key_identifier) = key_identifier {
            builder = builder.key_identifier(key_identifier);
        }
        if let Some(context) = context {
            builder = builder.context(context);
        }
        if let Some(algorithm) = algorithm {
            builder = builder.algorithm(algorithm);
        }
        builder.build()
    }

    /// Reads the parenthesized list of covered components.
    fn parse_components(&mut self) -> Result<Vec<SignatureComponent>, SignatureInputError> {
        if !self.eat(b'(') {
            return Err(self.malformed("a covered list must start with `(`"));
        }
        let mut components = Vec::new();
        self.skip_whitespace();
        loop {
            if self.eat(b')') {
                return Ok(components);
            }
            if components.len() >= MAX_COMPONENTS {
                return Err(SignatureInputError::TooManyComponents {
                    count: components.len().saturating_add(1),
                    maximum: MAX_COMPONENTS,
                });
            }
            let name = self.parse_quoted()?;
            components.push(SignatureComponent::new(name)?);
            match self.peek() {
                Some(b' ' | b'\t') => self.skip_whitespace(),
                Some(b')') => {}
                _ => return Err(self.malformed("a covered list needs a space or `)` after a name")),
            }
        }
    }

    /// Reads one quoted string, refusing the escapes the signature base cannot express.
    fn parse_quoted(&mut self) -> Result<&'input str, SignatureInputError> {
        if !self.eat(b'"') {
            return Err(self.malformed("a quoted string must start with `\"`"));
        }
        // A backslash escape renders differently in the header and in the base, so the two would
        // disagree about the bytes signed; it is refused rather than unescaped.
        let text = self.take_while(|byte| matches!(byte, 0x20..=0x7e) && byte != b'"' && byte != b'\\');
        if !self.eat(b'"') {
            return Err(self.malformed("a quoted string is unterminated or holds an escape"));
        }
        Ok(text)
    }

    /// Reads one quoted parameter value.
    fn parse_text(&mut self) -> Result<FieldText, SignatureInputError> {
        let text = self.parse_quoted()?;
        Ok(FieldText::new(text)?)
    }

    /// Reads one non-negative integer parameter.
    fn parse_integer(&mut self) -> Result<u64, SignatureInputError> {
        if self.peek() == Some(b'-') {
            return Err(self.malformed("a time parameter may not be negative"));
        }
        let digits = self.take_while(|byte| byte.is_ascii_digit());
        if digits.is_empty() {
            return Err(self.malformed("a time parameter needs digits"));
        }
        // A leading zero is not the canonical spelling, so it would not re-render unchanged.
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(self.malformed("a time parameter may not carry a leading zero"));
        }
        digits
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= MAX_PARAMETER_INTEGER)
            .ok_or(SignatureInputError::ParameterOutOfRange { name: "time" })
    }
}

/// Copies at most thirty-two characters of rejected text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(32).collect()
}

/// Stable `Signature-Input` and canonicalization failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignatureInputError {
    /// A header value exceeds [`MAX_SIGNATURE_INPUT_BYTES`].
    SignatureInputTooLong {
        /// Actual length in bytes.
        length: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// A signature base exceeds [`MAX_SIGNATURE_BASE_BYTES`].
    SignatureBaseTooLong {
        /// Actual length in bytes.
        length: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// A label is not an RFC 8941 dictionary key.
    InvalidLabel {
        /// Bounded copy of the rejected label.
        label: String,
    },
    /// A derived component other than `@method` or `@path` was named.
    ///
    /// The reference lists it and then covers nothing for it.
    UnknownDerivedComponent {
        /// Bounded copy of the rejected name.
        name: String,
    },
    /// A request method is empty, oversized, or not a token.
    InvalidRequestMethod {
        /// Bounded copy of the rejected method.
        method: String,
    },
    /// A request path is empty, oversized, relative, carries a query, or holds an unusable byte.
    InvalidRequestPath {
        /// Bounded copy of the rejected path.
        path: String,
    },
    /// An input covers nothing, so its signature binds nothing.
    NoComponents,
    /// An input covers more than [`MAX_COMPONENTS`] things.
    TooManyComponents {
        /// Actual count.
        count: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// One thing is covered twice.
    DuplicateComponent {
        /// Bounded copy of the repeated name.
        name: String,
    },
    /// A covered header is absent, so the base cannot be built.
    ///
    /// The reference drops the component instead, silently weakening the signature.
    MissingCoveredHeader {
        /// Bounded copy of the missing name.
        name: String,
    },
    /// A header carries no input.
    NoInputs,
    /// A header carries more than [`MAX_INPUTS`] inputs.
    TooManyInputs {
        /// Actual count.
        count: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// The same label appears twice, where a dictionary keeps only the last.
    DuplicateLabel {
        /// Bounded copy of the repeated label.
        label: String,
    },
    /// An input omits the required `created` parameter.
    MissingCreated {
        /// Bounded copy of the input's label.
        label: String,
    },
    /// A parameter this format does not define was present.
    ///
    /// The reference ignores it, which then makes verification fail with no explanation.
    UnknownParameter {
        /// Bounded copy of the rejected name.
        name: String,
    },
    /// The parameters are not in the order both implementations write them in.
    ParametersOutOfOrder,
    /// A numeric parameter is outside what the header grammar can express.
    ParameterOutOfRange {
        /// Which parameter.
        name: &'static str,
    },
    /// A textual parameter carries a backslash, which the header escapes and the base does not.
    InvalidParameterValue {
        /// Which parameter.
        name: &'static str,
    },
    /// The header value does not match the accepted grammar.
    Malformed {
        /// What the parser expected.
        reason: &'static str,
        /// Byte offset reached.
        offset: usize,
    },
    /// A covered component names an invalid header field.
    Header {
        /// Underlying failure.
        source: HeaderError,
    },
    /// A parameter value holds a byte the header or the base cannot carry unambiguously.
    Field {
        /// Underlying failure.
        source: SignatureFieldError,
    },
}

impl From<HeaderError> for SignatureInputError {
    fn from(source: HeaderError) -> Self {
        Self::Header { source }
    }
}

impl From<SignatureFieldError> for SignatureInputError {
    fn from(source: SignatureFieldError) -> Self {
        Self::Field { source }
    }
}

impl fmt::Display for SignatureInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureInputTooLong { length, maximum } => {
                write!(formatter, "signature input of {length} bytes exceeds maximum {maximum}")
            }
            Self::SignatureBaseTooLong { length, maximum } => {
                write!(formatter, "signature base of {length} bytes exceeds maximum {maximum}")
            }
            Self::InvalidLabel { label } => {
                write!(formatter, "signature input label {label:?} is not a dictionary key")
            }
            Self::UnknownDerivedComponent { name } => write!(
                formatter,
                "derived component {name:?} is not one of {METHOD_COMPONENT:?} or {PATH_COMPONENT:?}"
            ),
            Self::InvalidRequestMethod { method } => {
                write!(formatter, "request method {method:?} is not a token")
            }
            Self::InvalidRequestPath { path } => write!(
                formatter,
                "request path {path:?} must be absolute, query-free, and visible ASCII"
            ),
            Self::NoComponents => formatter.write_str("a signature input covers nothing"),
            Self::TooManyComponents { count, maximum } => {
                write!(
                    formatter,
                    "a signature input covers {count} components, above {maximum}"
                )
            }
            Self::DuplicateComponent { name } => {
                write!(formatter, "component {name:?} is covered more than once")
            }
            Self::MissingCoveredHeader { name } => {
                write!(formatter, "covered header {name:?} is absent from the message")
            }
            Self::NoInputs => formatter.write_str("a signature input header carries no input"),
            Self::TooManyInputs { count, maximum } => {
                write!(
                    formatter,
                    "a signature input header carries {count} inputs, above {maximum}"
                )
            }
            Self::DuplicateLabel { label } => {
                write!(formatter, "signature input label {label:?} appears more than once")
            }
            Self::MissingCreated { label } => {
                write!(formatter, "signature input {label:?} omits the required \"created\"")
            }
            Self::UnknownParameter { name } => {
                write!(formatter, "signature input parameter {name:?} is not defined")
            }
            Self::ParametersOutOfOrder => {
                write!(
                    formatter,
                    "signature input parameters must appear in the order {PARAMETER_ORDER:?}"
                )
            }
            Self::ParameterOutOfRange { name } => write!(
                formatter,
                "signature input parameter {name:?} exceeds maximum {MAX_PARAMETER_INTEGER}"
            ),
            Self::InvalidParameterValue { name } => write!(
                formatter,
                "signature input parameter {name:?} may not carry a backslash"
            ),
            Self::Malformed { reason, offset } => {
                write!(formatter, "malformed signature input at offset {offset}: {reason}")
            }
            Self::Header { .. } => formatter.write_str("a covered component is not a valid header name"),
            Self::Field { .. } => formatter.write_str("a signature input parameter value is invalid"),
        }
    }
}

impl Error for SignatureInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Header { source } => Some(source),
            Self::Field { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HeaderValue;
    use std::error::Error;

    const KEYID: &str = "DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt";
    const RESOURCE: &str = "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs";
    const STAMP: &str = "2022-09-24T00:05:48.196795+00:00";

    fn headers() -> Result<Headers, Box<dyn Error>> {
        Ok(Headers::from_pairs([
            (HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?),
            (HeaderName::new("Signify-Resource")?, HeaderValue::new(RESOURCE)?),
            (HeaderName::new("Signify-Timestamp")?, HeaderValue::new(STAMP)?),
        ])?)
    }

    fn default_input() -> Result<SignatureInput, Box<dyn Error>> {
        Ok(
            SignatureInputBuilder::new(InputLabel::signify(), default_components()?, 1_609_459_200)
                .key_identifier(FieldText::new(KEYID)?)
                .algorithm(FieldText::new(ED25519_ALGORITHM)?)
                .build()?,
        )
    }

    #[test]
    fn the_default_components_are_the_reference_field_list() -> Result<(), Box<dyn Error>> {
        let components = default_components()?;
        let names: Vec<&str> = components.iter().map(SignatureComponent::as_str).collect();
        assert_eq!(names, ["@method", "@path", "signify-resource", "signify-timestamp"]);
        Ok(())
    }

    #[test]
    fn the_base_and_the_header_spell_the_same_input_differently() -> Result<(), Box<dyn Error>> {
        let input = default_input()?;
        let target = RequestTarget::new("POST", "/boot")?;
        let base = input.signature_base(&target, &headers()?)?;

        assert_eq!(
            base.as_str(),
            concat!(
                "\"@method\": POST\n",
                "\"@path\": /boot\n",
                "\"signify-resource\": EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs\n",
                "\"signify-timestamp\": 2022-09-24T00:05:48.196795+00:00\n",
                "\"@signature-params: (@method @path signify-resource signify-timestamp);",
                "created=1609459200;keyid=DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt;alg=ed25519\"",
            )
        );
        assert_eq!(base.as_bytes(), base.as_str().as_bytes());
        assert_eq!(base.to_string(), base.as_str());

        let header = SignatureInputHeader::new(vec![input])?;
        assert_eq!(
            header.to_header_value()?,
            concat!(
                "signify=(\"@method\" \"@path\" \"signify-resource\" \"signify-timestamp\");",
                "created=1609459200;keyid=\"DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt\";alg=\"ed25519\"",
            )
        );
        Ok(())
    }

    #[test]
    fn a_header_round_trips_through_parsing() -> Result<(), Box<dyn Error>> {
        let header = SignatureInputHeader::new(vec![
            SignatureInputBuilder::new(InputLabel::signify(), default_components()?, 1_609_459_200)
                .expires(1_609_545_600)
                .nonce(FieldText::new("0AAxyz")?)
                .key_identifier(FieldText::new(KEYID)?)
                .context(FieldText::new("keria")?)
                .algorithm(FieldText::new(ED25519_ALGORITHM)?)
                .build()?,
        ])?;
        let rendered = header.to_header_value()?;
        let parsed = SignatureInputHeader::parse(&rendered)?;
        assert_eq!(parsed, header);
        assert_eq!(parsed.to_header_value()?, rendered);
        assert_eq!(rendered.parse::<SignatureInputHeader>()?, header);
        assert_eq!(SignatureInputHeader::try_from(rendered.as_str())?, header);

        let input = parsed.find(&InputLabel::signify()).ok_or("no input")?;
        assert_eq!(input.created(), 1_609_459_200);
        assert_eq!(input.expires(), Some(1_609_545_600));
        assert_eq!(input.nonce(), Some("0AAxyz"));
        assert_eq!(input.key_identifier(), Some(KEYID));
        assert_eq!(input.context(), Some("keria"));
        assert_eq!(input.algorithm(), Some(ED25519_ALGORITHM));
        assert_eq!(input.label().as_str(), "signify");
        assert_eq!(input.components().len(), 4);
        assert!(parsed.find(&InputLabel::new("other")?).is_none());
        Ok(())
    }

    #[test]
    fn several_inputs_are_comma_separated() -> Result<(), Box<dyn Error>> {
        let value = "signify=(\"@method\");created=1609459200, other=(\"@path\");created=1609459201";
        let header = SignatureInputHeader::parse(value)?;
        assert_eq!(header.inputs().len(), 2);
        assert_eq!(header.to_header_value()?, value);
        // The comma may arrive without its space when an intermediary rewrites the header.
        assert_eq!(SignatureInputHeader::parse(&value.replace(", ", ","))?, header);
        Ok(())
    }

    #[test]
    fn a_missing_covered_header_is_refused() -> Result<(), Box<dyn Error>> {
        // Upstream the component is silently dropped, so the caller signs less than it asked to.
        let input = SignatureInputBuilder::new(
            InputLabel::signify(),
            vec![SignatureComponent::Method, SignatureComponent::new("x-absent")?],
            1,
        )
        .build()?;
        assert!(matches!(
            input.signature_base(&RequestTarget::new("GET", "/x")?, &headers()?),
            Err(SignatureInputError::MissingCoveredHeader { name }) if name == "x-absent"
        ));
        Ok(())
    }

    #[test]
    fn covered_header_lookup_ignores_case_but_the_base_keeps_it() -> Result<(), Box<dyn Error>> {
        let input = SignatureInputBuilder::new(
            InputLabel::signify(),
            vec![SignatureComponent::new("SIGNIFY-RESOURCE")?],
            1,
        )
        .build()?;
        let base = input.signature_base(&RequestTarget::new("GET", "/x")?, &headers()?)?;
        assert!(base.as_str().starts_with(&format!("\"SIGNIFY-RESOURCE\": {RESOURCE}")));
        Ok(())
    }

    #[test]
    fn only_the_two_implemented_derived_components_exist() -> Result<(), Box<dyn Error>> {
        assert_eq!(SignatureComponent::new("@method")?, SignatureComponent::Method);
        assert_eq!(SignatureComponent::new("@path")?, SignatureComponent::Path);
        assert_eq!(SignatureComponent::from_str("@path")?.to_string(), "@path");
        for name in ["@authority", "@query", "@target-uri", "@"] {
            assert!(
                matches!(
                    SignatureComponent::new(name),
                    Err(SignatureInputError::UnknownDerivedComponent { .. })
                ),
                "{name:?} was accepted",
            );
        }
        assert!(matches!(
            SignatureComponent::new("a b"),
            Err(SignatureInputError::Header { .. })
        ));
        Ok(())
    }

    #[test]
    fn labels_follow_the_dictionary_key_grammar() -> Result<(), Box<dyn Error>> {
        assert_eq!(InputLabel::new("sig0")?.as_str(), "sig0");
        assert_eq!(InputLabel::new("*x")?.to_string(), "*x");
        assert_eq!(InputLabel::from_str("signify")?, InputLabel::signify());
        for label in ["Signify", "0sig", "sig 0", "", "-sig", "sig=0"] {
            assert!(
                matches!(InputLabel::new(label), Err(SignatureInputError::InvalidLabel { .. })),
                "{label:?} was accepted",
            );
        }
        assert!(InputLabel::new("a".repeat(MAX_LABEL_BYTES + 1)).is_err());
        Ok(())
    }

    #[test]
    fn request_targets_cannot_forge_a_base_line() -> Result<(), Box<dyn Error>> {
        let target = RequestTarget::new("POST", "/identifiers/aid1")?;
        assert_eq!(target.method(), "POST");
        assert_eq!(target.path(), "/identifiers/aid1");
        assert_eq!(RequestTarget::new("GET", "/oobi/EB%2Fa")?.path(), "/oobi/EB%2Fa");

        // Upstream all of these are interpolated into the base unvalidated.
        for path in [
            "/a\n\"@method\": DELETE",
            "relative",
            "",
            "/a b",
            "/a?limit=1",
            "/a#top",
            "/a\"b",
        ] {
            assert!(
                matches!(
                    RequestTarget::new("GET", path),
                    Err(SignatureInputError::InvalidRequestPath { .. })
                ),
                "{path:?} was accepted",
            );
        }
        for method in ["", "GET POST", "GE\nT", "G:T"] {
            assert!(
                matches!(
                    RequestTarget::new(method, "/x"),
                    Err(SignatureInputError::InvalidRequestMethod { .. })
                ),
                "{method:?} was accepted",
            );
        }
        assert!(RequestTarget::new("GET", &format!("/{}", "a".repeat(MAX_REQUEST_PATH_BYTES))).is_err());
        assert!(RequestTarget::new(&"A".repeat(MAX_REQUEST_METHOD_BYTES + 1), "/x").is_err());
        Ok(())
    }

    #[test]
    fn empty_and_repeated_coverage_is_refused() -> Result<(), Box<dyn Error>> {
        // Upstream an empty covered list is emitted and parsed, binding nothing at all.
        assert!(matches!(
            SignatureInputBuilder::new(InputLabel::signify(), Vec::new(), 1).build(),
            Err(SignatureInputError::NoComponents)
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=();created=1"),
            Err(SignatureInputError::NoComponents)
        ));
        assert!(matches!(
            SignatureInputBuilder::new(
                InputLabel::signify(),
                vec![
                    SignatureComponent::new("signify-resource")?,
                    SignatureComponent::new("Signify-Resource")?,
                ],
                1,
            )
            .build(),
            Err(SignatureInputError::DuplicateComponent { .. })
        ));
        assert!(matches!(
            SignatureInputBuilder::new(
                InputLabel::signify(),
                vec![SignatureComponent::Method; MAX_COMPONENTS + 1],
                1,
            )
            .build(),
            Err(SignatureInputError::TooManyComponents { .. })
        ));
        Ok(())
    }

    #[test]
    fn headers_hold_at_least_one_input_and_unique_labels() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            SignatureInputHeader::new(Vec::new()),
            Err(SignatureInputError::NoInputs)
        ));
        // Upstream a dictionary keeps the last member, so the earlier input silently disappears.
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1, signify=(\"@path\");created=2"),
            Err(SignatureInputError::DuplicateLabel { .. })
        ));
        let inputs = (0..=MAX_INPUTS)
            .map(|position| {
                Ok(SignatureInputBuilder::new(
                    InputLabel::new(format!("sig{position}"))?,
                    vec![SignatureComponent::Method],
                    1,
                )
                .build()?)
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        assert!(matches!(
            SignatureInputHeader::new(inputs),
            Err(SignatureInputError::TooManyInputs { .. })
        ));
        Ok(())
    }

    #[test]
    fn parameters_are_required_ordered_and_known() {
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");alg=\"ed25519\""),
            Err(SignatureInputError::MissingCreated { .. })
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;alg=\"ed25519\";keyid=\"x\""),
            Err(SignatureInputError::ParametersOutOfOrder)
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;created=2"),
            Err(SignatureInputError::ParametersOutOfOrder)
        ));
        // The reference ignores an unknown parameter, which then makes verification fail silently.
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;tag=\"x\""),
            Err(SignatureInputError::UnknownParameter { name }) if name == "tag"
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=-1"),
            Err(SignatureInputError::Malformed { .. })
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=01"),
            Err(SignatureInputError::Malformed { .. })
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=9999999999999999"),
            Err(SignatureInputError::ParameterOutOfRange { .. })
        ));
    }

    #[test]
    fn malformed_values_are_typed_errors() {
        for value in [
            "",
            "signify",
            "signify=",
            "signify=(",
            "signify=(\"@method\"",
            "signify=(\"@method\")",
            "signify=(@method);created=1",
            "signify=(\"@method\"\"@path\");created=1",
            "signify=(\"@method\");created=1;",
            "signify=(\"@method\");created",
            "signify=(\"@method\");created=1 trailing",
            "signify=(\"a\\\"b\");created=1",
            "signify=(\"@method\");created=1;keyid=x",
            "signify=(\"@method\");created=1;keyid=\"a b\"",
        ] {
            let parsed = SignatureInputHeader::parse(value);
            assert!(
                matches!(
                    parsed,
                    Err(SignatureInputError::Malformed { .. }
                        | SignatureInputError::InvalidLabel { .. }
                        | SignatureInputError::MissingCreated { .. }
                        | SignatureInputError::NoComponents
                        | SignatureInputError::UnknownDerivedComponent { .. }
                        | SignatureInputError::Field { .. })
                ),
                "{value:?} produced {parsed:?}",
            );
        }
    }

    #[test]
    fn oversized_input_is_bounded() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            SignatureInputHeader::parse(&"a".repeat(MAX_SIGNATURE_INPUT_BYTES + 1)),
            Err(SignatureInputError::SignatureInputTooLong { .. })
        ));

        // A base built from many long header values is bounded too.
        let mut headers = Headers::new();
        let mut components = Vec::new();
        for position in 0..MAX_COMPONENTS {
            let name = HeaderName::new(format!("x-{position}"))?;
            headers.insert(name.clone(), HeaderValue::new("v".repeat(MAX_HEADER_VALUE))?)?;
            components.push(SignatureComponent::Header(name));
        }
        let input = SignatureInputBuilder::new(InputLabel::signify(), components, 1).build()?;
        assert!(matches!(
            input.signature_base(&RequestTarget::new("GET", "/x")?, &headers),
            Err(SignatureInputError::SignatureBaseTooLong { .. })
        ));
        Ok(())
    }

    /// A header value long enough that sixty-four of them exceed the base bound.
    const MAX_HEADER_VALUE: usize = 2048;

    #[test]
    fn parameter_values_cannot_forge_a_parameter() {
        // Upstream the header escapes a quote while the base does not, and a semicolon in a value
        // adds a whole parameter to the signed bytes.
        for text in ["a\"b", "a;alg=forged", "a b", "a,b", "a=b"] {
            assert!(FieldText::new(text).is_err(), "{text:?} was accepted");
        }
        // The value parses as a quoted string and is then refused as a parameter value, so the
        // forged `alg` never reaches the signature base.
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;keyid=\"a;alg=forged\""),
            Err(SignatureInputError::Field { .. })
        ));
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;keyid=\"a\\\"b\""),
            Err(SignatureInputError::Malformed { .. })
        ));
    }

    /// Regression: a property test built a nonce of a single backslash. The header escaped it and
    /// the base did not, so the rendered header no longer parsed and the two spellings disagreed
    /// about the bytes signed.
    #[test]
    fn a_parameter_value_may_not_carry_a_backslash() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            SignatureInputBuilder::new(InputLabel::signify(), vec![SignatureComponent::Method], 1)
                .nonce(FieldText::new("\\")?)
                .build(),
            Err(SignatureInputError::InvalidParameterValue { name: "nonce" })
        ));
        for text in ["a\\b", "\\"] {
            assert!(
                SignatureInputBuilder::new(InputLabel::signify(), vec![SignatureComponent::Method], 1)
                    .key_identifier(FieldText::new(text)?)
                    .build()
                    .is_err(),
                "{text:?} was accepted",
            );
        }
        // The parser refuses the same spelling from the wire.
        assert!(matches!(
            SignatureInputHeader::parse("signify=(\"@method\");created=1;nonce=\"\\\""),
            Err(SignatureInputError::Malformed { .. })
        ));
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_sources() {
        for error in [
            SignatureInputError::SignatureInputTooLong {
                length: 1,
                maximum: MAX_SIGNATURE_INPUT_BYTES,
            },
            SignatureInputError::SignatureBaseTooLong {
                length: 1,
                maximum: MAX_SIGNATURE_BASE_BYTES,
            },
            SignatureInputError::InvalidLabel { label: "X".to_owned() },
            SignatureInputError::UnknownDerivedComponent {
                name: "@authority".to_owned(),
            },
            SignatureInputError::InvalidRequestMethod {
                method: "a b".to_owned(),
            },
            SignatureInputError::InvalidRequestPath { path: "x".to_owned() },
            SignatureInputError::NoComponents,
            SignatureInputError::TooManyComponents {
                count: 1,
                maximum: MAX_COMPONENTS,
            },
            SignatureInputError::DuplicateComponent { name: "x".to_owned() },
            SignatureInputError::MissingCoveredHeader { name: "x".to_owned() },
            SignatureInputError::NoInputs,
            SignatureInputError::TooManyInputs {
                count: 1,
                maximum: MAX_INPUTS,
            },
            SignatureInputError::DuplicateLabel {
                label: "signify".to_owned(),
            },
            SignatureInputError::MissingCreated {
                label: "signify".to_owned(),
            },
            SignatureInputError::UnknownParameter { name: "tag".to_owned() },
            SignatureInputError::ParametersOutOfOrder,
            SignatureInputError::ParameterOutOfRange { name: "time" },
            SignatureInputError::InvalidParameterValue { name: "nonce" },
            SignatureInputError::Malformed { reason: "x", offset: 0 },
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }

        let layered = SignatureInputError::from(HeaderError::EmptyName);
        assert!(layered.source().is_some());
        let layered = SignatureInputError::from(SignatureFieldError::EmptyFieldText);
        assert!(layered.source().is_some());
    }
}

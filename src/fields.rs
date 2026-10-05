//! The KERI `Signature` header format.
//!
//! A request carries its signatures in one `Signature` header. The value is a comma-separated list
//! of *signages*, each a semicolon-separated list of `name="value"` items: a required `indexed`
//! flag, optional `signer`, `ordinal`, `digest`, and `kind` parameters, and then one item per
//! signature, whose name is the marker's tag.
//!
//! ```text
//! indexed="?1";signer="EGqH…";kind="CESR";0="AACs…";1="ABDs…"
//! ```
//!
//! This module ports `signature` and `designature` from `src/keri/end/ending.ts`.
//!
//! # Why a dedicated parser
//!
//! The format resembles an RFC 8941 structured-field list but is not one: a signage's leading
//! `indexed="?1"` is a parameter with no bare item in front of it, so no conforming structured-
//! field parser accepts it. `docs/adr/0010-signature-header-fields.md` records the decision to
//! hand-write a strict parser rather than adopt a library.
//!
//! # Strictness
//!
//! Tags and values are validated [`FieldText`], which excludes the delimiters `"`, `;`, `,`, `=`
//! and every space and control byte. The reference validates neither: a tag of `a";b="c` produces
//! a header carrying a forged extra field, and a value of `val";indexed="?0` injects a second
//! `indexed` flag into the signage that quoted it. Both are refused here at construction. The
//! remaining divergences are listed in `PORTING.md` §9 and pinned by `fixtures/http-ending/`.

use core::fmt;
use std::borrow::Cow;
use std::error::Error;
use std::str::FromStr;

use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;

/// Name of the header this module formats and parses.
pub const SIGNATURE_HEADER_NAME: &str = "Signature";

/// Parameter naming whether a signage's markers are indexed signatures.
pub const INDEXED_FIELD: &str = "indexed";
/// Parameter naming the identifier whose keys produced the signatures.
pub const SIGNER_FIELD: &str = "signer";
/// Parameter naming the establishment event's position in the signer's log.
pub const ORDINAL_FIELD: &str = "ordinal";
/// Parameter naming a digest that further identifies the keys used.
pub const DIGEST_FIELD: &str = "digest";
/// Parameter naming the serialization of the markers.
pub const KIND_FIELD: &str = "kind";

/// Every parameter name, which is therefore unusable as a marker tag.
pub const RESERVED_FIELDS: [&str; 5] = [INDEXED_FIELD, SIGNER_FIELD, ORDINAL_FIELD, DIGEST_FIELD, KIND_FIELD];

/// Marker serialization holding qualified CESR signatures; the default when `kind` is absent.
pub const CESR_KIND: &str = "CESR";

/// Wire spelling of an affirmative `indexed` flag.
pub const INDEXED_TRUE: &str = "?1";
/// Wire spelling of a negative `indexed` flag.
pub const INDEXED_FALSE: &str = "?0";

/// Every text the reference's `FALSY` table can match, in table order.
///
/// Its first two entries, `false` and `0`, are a JavaScript boolean and number, which a string
/// parsed out of a header can never equal — so `indexed="0"` is read as **true** upstream. That
/// defect is pinned rather than reproduced; see `PORTING.md` §9.
const FALSE_FLAGS: [&str; 5] = [INDEXED_FALSE, "no", "false", "False", "off"];

/// Every text the reference's `TRUTHY` table can match, in table order.
const TRUE_FLAGS: [&str; 5] = [INDEXED_TRUE, "yes", "true", "True", "on"];

/// Largest header value this module parses or produces, in bytes.
///
/// The reference imposes no bound. A signage carrying three signatures is roughly 300 bytes, and
/// common server limits for a single header are 8 KiB; this ceiling is deliberately generous while
/// still bounding what an untrusted peer can make this module allocate.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Largest tag or parameter value, in bytes.
pub const MAX_FIELD_TEXT_BYTES: usize = 1024;

/// One validated tag or parameter value.
///
/// The accepted bytes are printable ASCII excluding `"`, `;`, `,`, `=`, and space, which is
/// exactly what the header grammar can carry unambiguously. Qualified CESR material, identifier
/// prefixes, digests, and hexadecimal ordinals all satisfy it.
///
/// The `signer`, `ordinal`, and `digest` parameters hold an identifier prefix, a sequence number,
/// and a SAID respectively, but this crate deliberately does not type them as such: those types
/// live in `signify-keri`, and `ARCHITECTURE.md` forbids `signify-http` depending on it. A caller
/// that has them converts to text at this boundary.
///
/// ```
/// use signify_http::signature::fields::FieldText;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let tag = FieldText::new("signify")?;
/// assert_eq!(tag.as_str(), "signify");
///
/// // A tag carrying a delimiter would forge extra header fields; the reference accepts it.
/// assert!(FieldText::new(r#"a";b="c"#).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FieldText {
    text: String,
}

impl FieldText {
    /// Validates one tag or value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::EmptyFieldText`] for empty input,
    /// [`SignatureFieldError::FieldTextTooLong`] above [`MAX_FIELD_TEXT_BYTES`], and
    /// [`SignatureFieldError::InvalidFieldText`] for a byte the header grammar cannot carry.
    pub fn new(text: impl Into<String>) -> Result<Self, SignatureFieldError> {
        let text = text.into();
        if text.is_empty() {
            return Err(SignatureFieldError::EmptyFieldText);
        }
        if text.len() > MAX_FIELD_TEXT_BYTES {
            return Err(SignatureFieldError::FieldTextTooLong { length: text.len() });
        }
        if let Some(offset) = text.bytes().position(|byte| !is_field_byte(byte)) {
            return Err(SignatureFieldError::InvalidFieldText {
                text: bounded(&text),
                offset,
            });
        }
        Ok(Self { text })
    }

    /// Returns the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Consumes the value, returning its text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.text
    }
}

impl FromStr for FieldText {
    type Err = SignatureFieldError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for FieldText {
    type Error = SignatureFieldError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl fmt::Display for FieldText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns whether a byte can appear in a tag or value.
const fn is_field_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'"' | b';' | b',' | b'=')
}

/// One indexed signature and the tag naming it.
///
/// With no explicit tag the signature's own index is used, which is what the reference does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedMarker {
    tag: Option<FieldText>,
    signature: IndexedSignature,
}

impl IndexedMarker {
    /// Names the signature by its own index.
    #[must_use]
    pub const fn new(signature: IndexedSignature) -> Self {
        Self { tag: None, signature }
    }

    /// Names the signature explicitly.
    ///
    /// A tag equal to the signature's own index is the default form, so it is stored as absent:
    /// the two spellings are the same header, and normalizing here keeps them the same value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::ReservedTag`] for a parameter name, which a parser would
    /// read as a parameter rather than as a marker.
    pub fn named(tag: FieldText, signature: IndexedSignature) -> Result<Self, SignatureFieldError> {
        ensure_not_reserved(&tag)?;
        if tag.as_str() == signature.index().to_string() {
            return Ok(Self::new(signature));
        }
        Ok(Self {
            tag: Some(tag),
            signature,
        })
    }

    /// Returns the tag this marker is written under.
    #[must_use]
    pub fn tag(&self) -> Cow<'_, str> {
        self.tag.as_ref().map_or_else(
            || Cow::Owned(self.signature.index().to_string()),
            |tag| Cow::Borrowed(tag.as_str()),
        )
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> &IndexedSignature {
        &self.signature
    }
}

/// One unindexed signature and the tag naming it.
///
/// With no explicit tag the signature's verification key is used, which is what the reference
/// does — so an unnamed marker must carry one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnindexedMarker {
    tag: Option<FieldText>,
    signature: UnindexedSignature,
}

impl UnindexedMarker {
    /// Names the signature by its verification key.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::MissingVerificationKey`] when the signature carries none,
    /// leaving nothing to name it with, and [`SignatureFieldError::Crypto`] when the key cannot be
    /// encoded.
    pub fn new(signature: UnindexedSignature) -> Result<Self, SignatureFieldError> {
        let key = signature
            .verifier()
            .ok_or(SignatureFieldError::MissingVerificationKey)?;
        // Proven encodable now so the tag cannot fail later, when the header is rendered.
        FieldText::new(key.qb64().map_err(SignatureFieldError::crypto)?)?;
        Ok(Self { tag: None, signature })
    }

    /// Names the signature explicitly.
    ///
    /// A tag equal to the signature's own verification key is the default form, so it is stored as
    /// absent, exactly as [`IndexedMarker::named`] normalizes an index tag.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::ReservedTag`] for a parameter name, and
    /// [`SignatureFieldError::Crypto`] when the signature's key cannot be encoded.
    pub fn named(tag: FieldText, signature: UnindexedSignature) -> Result<Self, SignatureFieldError> {
        ensure_not_reserved(&tag)?;
        if let Some(key) = signature.verifier()
            && key.qb64().map_err(SignatureFieldError::crypto)? == tag.as_str()
        {
            return Ok(Self { tag: None, signature });
        }
        Ok(Self {
            tag: Some(tag),
            signature,
        })
    }

    /// Returns the tag this marker is written under.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::Crypto`] when an unnamed marker's key cannot be encoded.
    pub fn tag(&self) -> Result<Cow<'_, str>, SignatureFieldError> {
        if let Some(tag) = &self.tag {
            return Ok(Cow::Borrowed(tag.as_str()));
        }
        let key = self
            .signature
            .verifier()
            .ok_or(SignatureFieldError::MissingVerificationKey)?;
        Ok(Cow::Owned(key.qb64().map_err(SignatureFieldError::crypto)?))
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> &UnindexedSignature {
        &self.signature
    }
}

/// One marker of a non-CESR signage, whose value stays opaque text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueMarker {
    tag: FieldText,
    value: FieldText,
}

impl OpaqueMarker {
    /// Pairs a tag with its uninterpreted value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::ReservedTag`] for a parameter name.
    pub fn new(tag: FieldText, value: FieldText) -> Result<Self, SignatureFieldError> {
        ensure_not_reserved(&tag)?;
        Ok(Self { tag, value })
    }

    /// Returns the tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        self.tag.as_str()
    }

    /// Returns the uninterpreted value.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

/// The markers of one signage, which decide its `indexed` flag.
///
/// The reference takes a separate `indexed` boolean and throws when it disagrees with the marker
/// types — an indexed signature with `indexed` false, or an unindexed one with `indexed` true.
/// Here the flag is derived from the markers, so the disagreement is unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignageMarkers {
    /// Indexed CESR signatures, written with `indexed="?1"`.
    Indexed(Vec<IndexedMarker>),
    /// Unindexed CESR signatures, written with `indexed="?0"`.
    Unindexed(Vec<UnindexedMarker>),
    /// Markers of a non-CESR `kind`, whose values this module does not interpret.
    Opaque {
        /// The flag to write, since nothing about the values implies it.
        indexed: bool,
        /// The markers, in header order.
        markers: Vec<OpaqueMarker>,
    },
}

impl SignageMarkers {
    /// Returns the `indexed` flag these markers imply.
    #[must_use]
    pub const fn is_indexed(&self) -> bool {
        match self {
            Self::Indexed(_) => true,
            Self::Unindexed(_) => false,
            Self::Opaque { indexed, .. } => *indexed,
        }
    }

    /// Returns how many markers there are.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Indexed(markers) => markers.len(),
            Self::Unindexed(markers) => markers.len(),
            Self::Opaque { markers, .. } => markers.len(),
        }
    }

    /// Returns whether there are no markers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether these markers hold CESR signatures.
    #[must_use]
    pub const fn is_cesr(&self) -> bool {
        matches!(self, Self::Indexed(_) | Self::Unindexed(_))
    }

    /// Returns each marker's tag in header order.
    fn tags(&self) -> Result<Vec<Cow<'_, str>>, SignatureFieldError> {
        match self {
            Self::Indexed(markers) => Ok(markers.iter().map(IndexedMarker::tag).collect()),
            Self::Unindexed(markers) => markers.iter().map(UnindexedMarker::tag).collect(),
            Self::Opaque { markers, .. } => Ok(markers.iter().map(|marker| Cow::Borrowed(marker.tag())).collect()),
        }
    }
}

/// One signage: a group of markers with the parameters describing them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signage {
    markers: SignageMarkers,
    signer: Option<FieldText>,
    ordinal: Option<FieldText>,
    digest: Option<FieldText>,
    kind: Option<FieldText>,
}

impl Signage {
    /// Returns the markers.
    #[must_use]
    pub const fn markers(&self) -> &SignageMarkers {
        &self.markers
    }

    /// Returns whether the markers are indexed signatures.
    #[must_use]
    pub const fn is_indexed(&self) -> bool {
        self.markers.is_indexed()
    }

    /// Returns the identifier whose keys produced the signatures.
    #[must_use]
    pub fn signer(&self) -> Option<&str> {
        self.signer.as_ref().map(FieldText::as_str)
    }

    /// Returns the establishment event's position in the signer's log.
    #[must_use]
    pub fn ordinal(&self) -> Option<&str> {
        self.ordinal.as_ref().map(FieldText::as_str)
    }

    /// Returns the digest further identifying the keys used.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_ref().map(FieldText::as_str)
    }

    /// Returns the marker serialization as written.
    ///
    /// `None` means the `kind` parameter is absent, which a parser reads as [`CESR_KIND`]. The
    /// distinction is kept because it changes the header's bytes.
    #[must_use]
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_ref().map(FieldText::as_str)
    }

    /// Renders this signage's items, semicolon-separated.
    fn render(&self) -> Result<String, SignatureFieldError> {
        let flag = if self.markers.is_indexed() {
            INDEXED_TRUE
        } else {
            INDEXED_FALSE
        };
        let mut items = vec![item(INDEXED_FIELD, flag)];
        for (name, value) in [
            (SIGNER_FIELD, self.signer.as_ref()),
            (ORDINAL_FIELD, self.ordinal.as_ref()),
            (DIGEST_FIELD, self.digest.as_ref()),
            (KIND_FIELD, self.kind.as_ref()),
        ] {
            if let Some(value) = value {
                items.push(item(name, value.as_str()));
            }
        }

        match &self.markers {
            SignageMarkers::Indexed(markers) => {
                for marker in markers {
                    let value = marker.signature.qb64().map_err(SignatureFieldError::crypto)?;
                    items.push(item(&marker.tag(), &value));
                }
            }
            SignageMarkers::Unindexed(markers) => {
                for marker in markers {
                    let value = marker.signature.qb64().map_err(SignatureFieldError::crypto)?;
                    items.push(item(&marker.tag()?, &value));
                }
            }
            SignageMarkers::Opaque { markers, .. } => {
                for marker in markers {
                    items.push(item(marker.tag(), marker.value()));
                }
            }
        }
        Ok(items.join(";"))
    }
}

/// Renders one `name="value"` item.
fn item(name: &str, value: &str) -> String {
    format!("{name}=\"{value}\"")
}

/// Builds one [`Signage`].
///
/// ```
/// use keri_cesr::crypto::signature::UnindexedSignature;
/// use keri_cesr::crypto::verifier::VerificationKey;
/// use signify_http::signature::fields::{
///     FieldText, SignageBuilder, SignageMarkers, SignatureHeader, UnindexedMarker,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signature = UnindexedSignature::from_qb64(
///     "0BCsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN",
/// )?;
/// let marker = UnindexedMarker::named(FieldText::new("signify")?, signature)?;
/// let signage = SignageBuilder::new(SignageMarkers::Unindexed(vec![marker])).build()?;
/// let header = SignatureHeader::new(vec![signage])?;
///
/// assert!(header.to_header_value()?.starts_with(r#"indexed="?0";signify="0BCsuf"#));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct SignageBuilder {
    markers: SignageMarkers,
    signer: Option<FieldText>,
    ordinal: Option<FieldText>,
    digest: Option<FieldText>,
    kind: Option<FieldText>,
}

impl SignageBuilder {
    /// Starts a signage from its markers.
    #[must_use]
    pub const fn new(markers: SignageMarkers) -> Self {
        Self {
            markers,
            signer: None,
            ordinal: None,
            digest: None,
            kind: None,
        }
    }

    /// Names the identifier whose keys produced the signatures.
    #[must_use]
    pub fn signer(mut self, signer: FieldText) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Names the establishment event's position in the signer's log.
    #[must_use]
    pub fn ordinal(mut self, ordinal: FieldText) -> Self {
        self.ordinal = Some(ordinal);
        self
    }

    /// Names a digest further identifying the keys used.
    #[must_use]
    pub fn digest(mut self, digest: FieldText) -> Self {
        self.digest = Some(digest);
        self
    }

    /// Writes the `kind` parameter, which is omitted by default.
    ///
    /// CESR markers accept only [`CESR_KIND`], and opaque markers require anything else: a parser
    /// decides how to read the values from this parameter, so the two must agree.
    #[must_use]
    pub fn kind(mut self, kind: FieldText) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Validates the signage.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::NoMarkers`] for an empty signage, which asserts nothing;
    /// [`SignatureFieldError::DuplicateField`] when two markers share a tag, where the reference
    /// silently keeps the last; [`SignatureFieldError::ReservedTag`] when a tag would be read as a
    /// parameter; and [`SignatureFieldError::KindMismatch`] when the `kind` parameter and the
    /// marker kind disagree.
    pub fn build(self) -> Result<Signage, SignatureFieldError> {
        if self.markers.is_empty() {
            return Err(SignatureFieldError::NoMarkers);
        }
        match (&self.markers, self.kind.as_ref().map(FieldText::as_str)) {
            (SignageMarkers::Opaque { .. }, None | Some(CESR_KIND)) => {
                return Err(SignatureFieldError::KindMismatch { kind: CESR_KIND });
            }
            (SignageMarkers::Indexed(_) | SignageMarkers::Unindexed(_), Some(other)) if other != CESR_KIND => {
                return Err(SignatureFieldError::KindMismatch { kind: "non-CESR" });
            }
            _ => {}
        }

        let tags = self.markers.tags()?;
        for (position, tag) in tags.iter().enumerate() {
            if RESERVED_FIELDS.contains(&tag.as_ref()) {
                return Err(SignatureFieldError::ReservedTag {
                    name: bounded(tag.as_ref()),
                });
            }
            if tags.iter().take(position).any(|earlier| earlier == tag) {
                return Err(SignatureFieldError::DuplicateField {
                    name: bounded(tag.as_ref()),
                });
            }
        }

        Ok(Signage {
            markers: self.markers,
            signer: self.signer,
            ordinal: self.ordinal,
            digest: self.digest,
            kind: self.kind,
        })
    }
}

/// One complete `Signature` header value.
///
/// ```
/// use signify_http::signature::fields::SignatureHeader;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let header = SignatureHeader::parse(concat!(
///     r#"indexed="?1";"#,
///     r#"0="AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN""#,
/// ))?;
///
/// assert_eq!(header.signages().len(), 1);
/// assert!(header.signages().first().is_some_and(|signage| signage.is_indexed()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureHeader {
    signages: Vec<Signage>,
}

impl SignatureHeader {
    /// Name of the header this value belongs to.
    pub const NAME: &'static str = SIGNATURE_HEADER_NAME;

    /// Collects one or more signages into a header value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::NoSignages`] for an empty list, which would render as an
    /// empty header.
    pub fn new(signages: Vec<Signage>) -> Result<Self, SignatureFieldError> {
        if signages.is_empty() {
            return Err(SignatureFieldError::NoSignages);
        }
        Ok(Self { signages })
    }

    /// Returns the signages in header order.
    #[must_use]
    pub fn signages(&self) -> &[Signage] {
        &self.signages
    }

    /// Renders the complete header value.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::HeaderTooLong`] above [`MAX_HEADER_BYTES`] and
    /// [`SignatureFieldError::Crypto`] when signature material cannot be encoded.
    pub fn to_header_value(&self) -> Result<String, SignatureFieldError> {
        let mut rendered = String::new();
        for (position, signage) in self.signages.iter().enumerate() {
            if position > 0 {
                rendered.push(',');
            }
            rendered.push_str(&signage.render()?);
            if rendered.len() > MAX_HEADER_BYTES {
                return Err(SignatureFieldError::HeaderTooLong {
                    length: rendered.len(),
                    maximum: MAX_HEADER_BYTES,
                });
            }
        }
        Ok(rendered)
    }

    /// Parses one complete header value.
    ///
    /// Whitespace around the `,` and `;` separators is ignored, which is what an HTTP intermediary
    /// may introduce when it merges repeated headers. Whitespace anywhere else is refused, because
    /// no tag or value can contain it.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureFieldError::HeaderTooLong`] above [`MAX_HEADER_BYTES`],
    /// [`SignatureFieldError::MalformedItem`] for an item that is not exactly one
    /// `name="value"` pair, [`SignatureFieldError::MissingIndexedField`] when a signage omits the
    /// flag, [`SignatureFieldError::InvalidIndexedFlag`] for a flag outside the reference's own
    /// tables, [`SignatureFieldError::DuplicateField`] for a repeated name, and layered
    /// [`SignatureFieldError::Crypto`] failures for signature material that does not parse.
    pub fn parse(value: &str) -> Result<Self, SignatureFieldError> {
        if value.len() > MAX_HEADER_BYTES {
            return Err(SignatureFieldError::HeaderTooLong {
                length: value.len(),
                maximum: MAX_HEADER_BYTES,
            });
        }
        let signages = value.split(',').map(parse_signage).collect::<Result<Vec<_>, _>>()?;
        Self::new(signages)
    }
}

impl FromStr for SignatureHeader {
    type Err = SignatureFieldError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for SignatureHeader {
    type Error = SignatureFieldError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

/// Parses one comma-separated signage.
fn parse_signage(value: &str) -> Result<Signage, SignatureFieldError> {
    let mut items: Vec<(String, String)> = Vec::new();
    for raw in value.split(';') {
        let (name, item_value) = parse_item(raw.trim_matches(is_ascii_space))?;
        if items.iter().any(|(existing, _)| *existing == name) {
            return Err(SignatureFieldError::DuplicateField { name: bounded(&name) });
        }
        items.push((name, item_value));
    }

    let mut take = |field: &str| -> Option<String> {
        let position = items.iter().position(|(name, _)| name == field)?;
        // The parameter names are removed so whatever remains is a marker, as upstream.
        Some(items.remove(position).1)
    };
    let indexed = take(INDEXED_FIELD).ok_or(SignatureFieldError::MissingIndexedField)?;
    let signer = take(SIGNER_FIELD);
    let ordinal = take(ORDINAL_FIELD);
    let digest = take(DIGEST_FIELD);
    let kind = take(KIND_FIELD);

    let indexed = parse_indexed_flag(&indexed)?;
    let markers = parse_markers(indexed, kind.as_deref(), items)?;

    let mut builder = SignageBuilder::new(markers);
    for (value, set) in [
        (signer, &SIGNER_FIELD),
        (ordinal, &ORDINAL_FIELD),
        (digest, &DIGEST_FIELD),
        (kind, &KIND_FIELD),
    ] {
        let Some(value) = value else { continue };
        let value = FieldText::new(value)?;
        builder = match *set {
            SIGNER_FIELD => builder.signer(value),
            ORDINAL_FIELD => builder.ordinal(value),
            DIGEST_FIELD => builder.digest(value),
            _ => builder.kind(value),
        };
    }
    builder.build()
}

/// Splits one `name="value"` item.
fn parse_item(raw: &str) -> Result<(String, String), SignatureFieldError> {
    let mut parts = raw.splitn(2, '=');
    let (Some(name), Some(quoted)) = (parts.next(), parts.next()) else {
        return Err(SignatureFieldError::MalformedItem { item: bounded(raw) });
    };
    // The reference splits with a limit that discards the remainder, so a value containing `=`
    // is silently truncated; keripy keeps it. The two disagree, so it is refused here.
    let unquoted = quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| SignatureFieldError::MalformedItem { item: bounded(raw) })?;
    if name.is_empty() || unquoted.contains(['"', '=']) {
        return Err(SignatureFieldError::MalformedItem { item: bounded(raw) });
    }
    Ok((name.to_owned(), unquoted.to_owned()))
}

/// Reads the `indexed` flag from the reference's own tables.
fn parse_indexed_flag(value: &str) -> Result<bool, SignatureFieldError> {
    if TRUE_FLAGS.contains(&value) {
        Ok(true)
    } else if FALSE_FLAGS.contains(&value) {
        Ok(false)
    } else {
        // The reference treats everything outside its `FALSY` table as true, so a header saying
        // `indexed="0"` or `indexed="maybe"` is read as indexed; see `PORTING.md` §9.
        Err(SignatureFieldError::InvalidIndexedFlag { found: bounded(value) })
    }
}

/// Interprets the remaining items as markers of the kind the signage declares.
fn parse_markers(
    indexed: bool,
    kind: Option<&str>,
    items: Vec<(String, String)>,
) -> Result<SignageMarkers, SignatureFieldError> {
    if matches!(kind, Some(other) if other != CESR_KIND) {
        let markers = items
            .into_iter()
            .map(|(tag, value)| OpaqueMarker::new(FieldText::new(tag)?, FieldText::new(value)?))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(SignageMarkers::Opaque { indexed, markers });
    }

    if indexed {
        let markers = items
            .into_iter()
            .map(|(tag, value)| {
                let signature = IndexedSignature::from_qb64(&value).map_err(SignatureFieldError::crypto)?;
                // `named` records a default tag as absent, so the header re-renders byte for byte.
                IndexedMarker::named(FieldText::new(tag)?, signature)
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(SignageMarkers::Indexed(markers));
    }

    let markers = items
        .into_iter()
        .map(|(tag, value)| {
            let signature = UnindexedSignature::from_qb64(&value).map_err(SignatureFieldError::crypto)?;
            // The default tag is the verification key itself, so a tag that parses as one is
            // attached to the signature rather than kept as a name.
            let signature = match VerificationKey::from_qb64(&tag) {
                Ok(key) => signature.with_verifier(key).map_err(SignatureFieldError::crypto)?,
                Err(_) => signature,
            };
            UnindexedMarker::named(FieldText::new(tag)?, signature)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SignageMarkers::Unindexed(markers))
}

/// Returns whether a character is one of the space bytes an intermediary may insert.
const fn is_ascii_space(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

/// Refuses a tag a parser would read as a parameter.
fn ensure_not_reserved(tag: &FieldText) -> Result<(), SignatureFieldError> {
    if RESERVED_FIELDS.contains(&tag.as_str()) {
        return Err(SignatureFieldError::ReservedTag {
            name: bounded(tag.as_str()),
        });
    }
    Ok(())
}

/// Copies at most thirty-two characters of rejected text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(32).collect()
}

/// Stable `Signature` header failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignatureFieldError {
    /// A header value exceeds [`MAX_HEADER_BYTES`].
    HeaderTooLong {
        /// Actual length in bytes.
        length: usize,
        /// Accepted maximum.
        maximum: usize,
    },
    /// A tag or value is empty.
    EmptyFieldText,
    /// A tag or value exceeds [`MAX_FIELD_TEXT_BYTES`].
    FieldTextTooLong {
        /// Actual length in bytes.
        length: usize,
    },
    /// A tag or value holds a byte the header grammar cannot carry.
    ///
    /// The reference validates neither, so a delimiter in either forges header fields.
    InvalidFieldText {
        /// Bounded copy of the rejected text.
        text: String,
        /// Offset of the first offending byte.
        offset: usize,
    },
    /// An item is not exactly one `name="value"` pair.
    MalformedItem {
        /// Bounded copy of the rejected item.
        item: String,
    },
    /// A signage omits the required `indexed` flag.
    MissingIndexedField,
    /// The `indexed` flag is outside the reference's own truth tables.
    InvalidIndexedFlag {
        /// Bounded copy of the rejected flag.
        found: String,
    },
    /// A parameter name or marker tag appears twice in one signage.
    DuplicateField {
        /// Bounded copy of the repeated name.
        name: String,
    },
    /// A marker tag would be read as a parameter.
    ReservedTag {
        /// Bounded copy of the rejected tag.
        name: String,
    },
    /// A signage carries no markers, so it asserts nothing.
    NoMarkers,
    /// A header carries no signages.
    NoSignages,
    /// The `kind` parameter and the marker kind disagree.
    KindMismatch {
        /// Which side the markers required.
        kind: &'static str,
    },
    /// An unnamed unindexed marker carries no verification key to name it with.
    MissingVerificationKey,
    /// Signature or key material could not be encoded or parsed.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
}

impl SignatureFieldError {
    fn crypto(source: CryptoError) -> Self {
        Self::Crypto {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for SignatureFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooLong { length, maximum } => {
                write!(
                    formatter,
                    "signature header of {length} bytes exceeds maximum {maximum}"
                )
            }
            Self::EmptyFieldText => formatter.write_str("a signature header tag or value is empty"),
            Self::FieldTextTooLong { length } => write!(
                formatter,
                "signature header text of {length} bytes exceeds maximum {MAX_FIELD_TEXT_BYTES}"
            ),
            Self::InvalidFieldText { text, offset } => write!(
                formatter,
                "signature header text {text:?} holds an unusable byte at offset {offset}"
            ),
            Self::MalformedItem { item } => {
                write!(
                    formatter,
                    "signature header item {item:?} is not one name=\"value\" pair"
                )
            }
            Self::MissingIndexedField => {
                write!(formatter, "signature header signage omits the {INDEXED_FIELD:?} field")
            }
            Self::InvalidIndexedFlag { found } => write!(
                formatter,
                "signature header {INDEXED_FIELD:?} flag {found:?} is neither {INDEXED_TRUE:?} nor {INDEXED_FALSE:?}"
            ),
            Self::DuplicateField { name } => {
                write!(formatter, "signature header field {name:?} appears more than once")
            }
            Self::ReservedTag { name } => write!(
                formatter,
                "marker tag {name:?} is reserved as a signature header parameter"
            ),
            Self::NoMarkers => formatter.write_str("a signature header signage carries no markers"),
            Self::NoSignages => formatter.write_str("a signature header carries no signages"),
            Self::KindMismatch { kind } => write!(
                formatter,
                "the {KIND_FIELD:?} parameter contradicts the markers, which require a {kind} kind"
            ),
            Self::MissingVerificationKey => {
                formatter.write_str("an unnamed unindexed marker needs a verification key to name it")
            }
            Self::Crypto { .. } => formatter.write_str("signature or key material is invalid"),
        }
    }
}

impl Error for SignatureFieldError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The three indexed signatures the pinned `test/end/ending.test.ts` asserts.
    const SIGERS: [&str; 3] = [
        "AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN",
        "ABDs7m2-h5l7vpjYtbFXtksicpZK5Oclm43EOkE2xoQOfr08doj73VrlKZOKNfJmRumD3tfaiFFgVZqPgiHuFVoA",
        "ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",
    ];
    /// The same signatures unindexed, and the keys that verify them.
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

    fn indexed_markers() -> Result<Vec<IndexedMarker>, Box<dyn Error>> {
        SIGERS
            .iter()
            .map(|qb64| Ok(IndexedMarker::new(IndexedSignature::from_qb64(qb64)?)))
            .collect()
    }

    fn unindexed_markers() -> Result<Vec<UnindexedMarker>, Box<dyn Error>> {
        CIGARS
            .iter()
            .zip(VERFERS)
            .map(|(qb64, key)| {
                let signature = UnindexedSignature::from_qb64(qb64)?.with_verifier(VerificationKey::from_qb64(key)?)?;
                Ok(UnindexedMarker::new(signature)?)
            })
            .collect()
    }

    fn header(signage: Signage) -> Result<String, Box<dyn Error>> {
        Ok(SignatureHeader::new(vec![signage])?.to_header_value()?)
    }

    #[test]
    fn indexed_markers_default_to_their_own_index() -> Result<(), Box<dyn Error>> {
        let signage = SignageBuilder::new(SignageMarkers::Indexed(indexed_markers()?)).build()?;
        assert_eq!(
            header(signage)?,
            format!(r#"indexed="?1";0="{}";1="{}";2="{}""#, SIGERS[0], SIGERS[1], SIGERS[2])
        );
        Ok(())
    }

    #[test]
    fn unindexed_markers_default_to_their_verification_key() -> Result<(), Box<dyn Error>> {
        let signage = SignageBuilder::new(SignageMarkers::Unindexed(unindexed_markers()?)).build()?;
        assert_eq!(
            header(signage)?,
            format!(
                r#"indexed="?0";{}="{}";{}="{}";{}="{}""#,
                VERFERS[0], CIGARS[0], VERFERS[1], CIGARS[1], VERFERS[2], CIGARS[2]
            )
        );
        Ok(())
    }

    #[test]
    fn parameters_are_written_in_protocol_order() -> Result<(), Box<dyn Error>> {
        let signage = SignageBuilder::new(SignageMarkers::Indexed(indexed_markers()?))
            .signer(FieldText::new(PREFIX)?)
            .ordinal(FieldText::new("0")?)
            .digest(FieldText::new(PREFIX)?)
            .kind(FieldText::new(CESR_KIND)?)
            .build()?;
        let rendered = header(signage)?;
        let names: Vec<&str> = rendered.split(';').filter_map(|item| item.split('=').next()).collect();
        assert_eq!(names, ["indexed", "signer", "ordinal", "digest", "kind", "0", "1", "2"]);
        Ok(())
    }

    #[test]
    fn named_markers_keep_their_names() -> Result<(), Box<dyn Error>> {
        let markers = indexed_markers()?
            .into_iter()
            .enumerate()
            .map(|(position, marker)| {
                IndexedMarker::named(FieldText::new(format!("siger{position}"))?, marker.signature)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signage = SignageBuilder::new(SignageMarkers::Indexed(markers)).build()?;
        let rendered = header(signage)?;
        assert!(rendered.contains(r#"siger0=""#));
        assert!(rendered.contains(r#"siger2=""#));
        Ok(())
    }

    #[test]
    fn a_header_round_trips_through_parsing() -> Result<(), Box<dyn Error>> {
        let signage = SignageBuilder::new(SignageMarkers::Indexed(indexed_markers()?))
            .signer(FieldText::new(PREFIX)?)
            .kind(FieldText::new(CESR_KIND)?)
            .build()?;
        let original = SignatureHeader::new(vec![signage])?;
        let rendered = original.to_header_value()?;
        let parsed = SignatureHeader::parse(&rendered)?;
        assert_eq!(parsed, original);
        assert_eq!(parsed.to_header_value()?, rendered);
        assert_eq!(rendered.parse::<SignatureHeader>()?, original);
        assert_eq!(SignatureHeader::try_from(rendered.as_str())?, original);
        Ok(())
    }

    #[test]
    fn parsing_recovers_the_parameters_and_markers() -> Result<(), Box<dyn Error>> {
        let rendered = format!(
            r#"indexed="?0";signer="{PREFIX}";ordinal="0";digest="{PREFIX}";kind="CESR";{}="{}""#,
            VERFERS[0], CIGARS[0]
        );
        let header = SignatureHeader::parse(&rendered)?;
        let signage = header.signages().first().ok_or("no signage")?;
        assert!(!signage.is_indexed());
        assert_eq!(signage.signer(), Some(PREFIX));
        assert_eq!(signage.ordinal(), Some("0"));
        assert_eq!(signage.digest(), Some(PREFIX));
        assert_eq!(signage.kind(), Some("CESR"));
        assert_eq!(signage.markers().len(), 1);

        // The tag is the verification key, so it is attached to the signature it verifies.
        let SignageMarkers::Unindexed(markers) = signage.markers() else {
            return Err("expected unindexed markers".into());
        };
        let marker = markers.first().ok_or("no marker")?;
        assert_eq!(marker.tag()?, VERFERS[0]);
        assert_eq!(
            marker.signature().verifier().map(VerificationKey::qb64).transpose()?,
            Some(VERFERS[0].to_owned())
        );
        Ok(())
    }

    #[test]
    fn several_signages_are_comma_separated() -> Result<(), Box<dyn Error>> {
        let indexed = SignageBuilder::new(SignageMarkers::Indexed(indexed_markers()?))
            .signer(FieldText::new(PREFIX)?)
            .kind(FieldText::new(CESR_KIND)?)
            .build()?;
        let unindexed = SignageBuilder::new(SignageMarkers::Unindexed(unindexed_markers()?))
            .signer(FieldText::new(PREFIX)?)
            .kind(FieldText::new(CESR_KIND)?)
            .build()?;
        let header = SignatureHeader::new(vec![indexed, unindexed])?;
        let rendered = header.to_header_value()?;
        assert_eq!(rendered.matches(',').count(), 1);
        assert!(rendered.contains(
            r#""ACDVOy2LvGgFINUneL4iwA55ypJR6vDpLLbdleEsiANmFazwZARypJMiw9vu2Iu0oL7XCUiUT4JncU8P3HdIp40F",indexed="?0""#
        ));
        assert_eq!(SignatureHeader::parse(&rendered)?, header);
        Ok(())
    }

    #[test]
    fn opaque_markers_need_a_non_cesr_kind() -> Result<(), Box<dyn Error>> {
        let markers = vec![OpaqueMarker::new(FieldText::new("x")?, FieldText::new("1")?)?];
        let opaque = SignageMarkers::Opaque {
            indexed: false,
            markers: markers.clone(),
        };
        // Without a kind a parser would read the values as CESR signatures.
        assert!(matches!(
            SignageBuilder::new(opaque.clone()).build(),
            Err(SignatureFieldError::KindMismatch { kind: "CESR" })
        ));
        assert!(matches!(
            SignageBuilder::new(opaque.clone())
                .kind(FieldText::new(CESR_KIND)?)
                .build(),
            Err(SignatureFieldError::KindMismatch { kind: "CESR" })
        ));

        let signage = SignageBuilder::new(opaque).kind(FieldText::new("JSON")?).build()?;
        let rendered = header(signage)?;
        assert_eq!(rendered, r#"indexed="?0";kind="JSON";x="1""#);
        let parsed = SignatureHeader::parse(&rendered)?;
        let signage = parsed.signages().first().ok_or("no signage")?;
        assert_eq!(
            signage.markers(),
            &SignageMarkers::Opaque {
                indexed: false,
                markers,
            }
        );
        assert!(!signage.markers().is_cesr());
        Ok(())
    }

    #[test]
    fn cesr_markers_refuse_a_foreign_kind() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            SignageBuilder::new(SignageMarkers::Indexed(indexed_markers()?))
                .kind(FieldText::new("JSON")?)
                .build(),
            Err(SignatureFieldError::KindMismatch { kind: "non-CESR" })
        ));
        Ok(())
    }

    #[test]
    fn field_text_refuses_every_delimiter() -> Result<(), Box<dyn Error>> {
        for text in [r#"a";b="c"#, "a;b", "a,b", "a=b", "a b", "a\tb", "a\nb"] {
            assert!(
                matches!(FieldText::new(text), Err(SignatureFieldError::InvalidFieldText { .. })),
                "{text:?} was accepted",
            );
        }
        assert!(matches!(FieldText::new(""), Err(SignatureFieldError::EmptyFieldText)));
        assert!(matches!(
            FieldText::new("a".repeat(MAX_FIELD_TEXT_BYTES + 1)),
            Err(SignatureFieldError::FieldTextTooLong { length }) if length == MAX_FIELD_TEXT_BYTES + 1
        ));
        // Non-ASCII is refused byte-wise without splitting a character.
        assert!(matches!(
            FieldText::new("é"),
            Err(SignatureFieldError::InvalidFieldText { offset: 0, .. })
        ));
        assert_eq!(FieldText::new(PREFIX)?.as_str(), PREFIX);
        assert_eq!(FieldText::new(PREFIX)?.to_string(), PREFIX);
        assert_eq!(FieldText::new(PREFIX)?.into_string(), PREFIX);
        assert_eq!(FieldText::from_str(PREFIX)?, FieldText::try_from(PREFIX)?);
        Ok(())
    }

    #[test]
    fn reserved_tags_are_refused() -> Result<(), Box<dyn Error>> {
        // Upstream a marker tagged `signer` becomes the signer parameter and vanishes.
        let signature = IndexedSignature::from_qb64(SIGERS[0])?;
        for name in RESERVED_FIELDS {
            assert!(matches!(
                IndexedMarker::named(FieldText::new(name)?, signature.clone()),
                Err(SignatureFieldError::ReservedTag { .. })
            ));
        }
        assert!(matches!(
            OpaqueMarker::new(FieldText::new("kind")?, FieldText::new("x")?),
            Err(SignatureFieldError::ReservedTag { .. })
        ));
        assert!(matches!(
            UnindexedMarker::named(FieldText::new("digest")?, UnindexedSignature::from_qb64(CIGARS[0])?),
            Err(SignatureFieldError::ReservedTag { .. })
        ));
        Ok(())
    }

    #[test]
    fn duplicate_tags_are_refused() -> Result<(), Box<dyn Error>> {
        let signature = IndexedSignature::from_qb64(SIGERS[0])?;
        // Upstream the second silently replaces the first, dropping a signature.
        let markers = vec![IndexedMarker::new(signature.clone()), IndexedMarker::new(signature)];
        assert!(matches!(
            SignageBuilder::new(SignageMarkers::Indexed(markers)).build(),
            Err(SignatureFieldError::DuplicateField { name }) if name == "0"
        ));
        assert!(matches!(
            SignatureHeader::parse(&format!(r#"indexed="?1";0="{}";0="{}""#, SIGERS[0], SIGERS[1])),
            Err(SignatureFieldError::DuplicateField { .. })
        ));
        Ok(())
    }

    #[test]
    fn an_unnamed_unindexed_marker_needs_a_key() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            UnindexedMarker::new(UnindexedSignature::from_qb64(CIGARS[0])?),
            Err(SignatureFieldError::MissingVerificationKey)
        ));
        // Naming it explicitly is enough.
        UnindexedMarker::named(FieldText::new("signify")?, UnindexedSignature::from_qb64(CIGARS[0])?)?;
        Ok(())
    }

    #[test]
    fn empty_signages_and_headers_are_refused() {
        assert!(matches!(
            SignageBuilder::new(SignageMarkers::Indexed(Vec::new())).build(),
            Err(SignatureFieldError::NoMarkers)
        ));
        assert!(matches!(
            SignatureHeader::new(Vec::new()),
            Err(SignatureFieldError::NoSignages)
        ));
        // Upstream both parse into a signage asserting nothing.
        assert!(matches!(
            SignatureHeader::parse(r#"indexed="?1""#),
            Err(SignatureFieldError::NoMarkers)
        ));
        assert!(matches!(
            SignatureHeader::parse(""),
            Err(SignatureFieldError::MalformedItem { .. })
        ));
    }

    #[test]
    fn malformed_items_are_typed_errors() {
        // Upstream this dereferences undefined and throws a TypeError.
        for value in [
            r#"indexed="?1";garbage"#,
            r#"indexed="?1";0=missingquotes"#,
            r#"indexed="?1";0="unterminated"#,
            r#"indexed="?1";="novalue""#,
            // A value containing `=` is truncated upstream and kept by keripy, so it is refused.
            r#"indexed="?1";0="a=b""#,
            // Quotes are stripped from anywhere upstream, silently joining the pieces.
            r#"indexed="?1";0="a"b"c""#,
        ] {
            assert!(
                matches!(
                    SignatureHeader::parse(value),
                    Err(SignatureFieldError::MalformedItem { .. })
                ),
                "{value:?} was accepted",
            );
        }
        assert!(matches!(
            SignatureHeader::parse(r#"0="x""#),
            Err(SignatureFieldError::MissingIndexedField)
        ));
    }

    #[test]
    fn the_indexed_flag_accepts_only_the_reference_tables() -> Result<(), Box<dyn Error>> {
        for (flag, expected) in TRUE_FLAGS.map(|flag| (flag, true)).into_iter().chain(
            FALSE_FLAGS
                .map(|flag| (flag, false))
                .into_iter()
                .filter(|(flag, _)| *flag != INDEXED_FALSE),
        ) {
            let value = format!(r#"indexed="{flag}";0="{}""#, SIGERS[0]);
            let header = SignatureHeader::parse(&value);
            if expected {
                assert!(header?.signages().first().is_some_and(Signage::is_indexed), "{flag}");
            } else {
                // A false flag with an indexed signature value cannot parse as an unindexed one.
                assert!(matches!(header, Err(SignatureFieldError::Crypto { .. })), "{flag}");
            }
        }
        let unindexed = format!(r#"indexed="{INDEXED_FALSE}";{}="{}""#, VERFERS[0], CIGARS[0]);
        assert!(
            SignatureHeader::parse(&unindexed)?
                .signages()
                .first()
                .is_some_and(|signage| !signage.is_indexed())
        );

        // Upstream reads every one of these as `true`, including the numeral meant to be false.
        for flag in ["0", "1", "maybe", ""] {
            assert!(
                matches!(
                    SignatureHeader::parse(&format!(r#"indexed="{flag}";0="{}""#, SIGERS[0])),
                    Err(SignatureFieldError::InvalidIndexedFlag { .. })
                ),
                "{flag:?} was accepted",
            );
        }
        Ok(())
    }

    #[test]
    fn whitespace_around_separators_is_tolerated() -> Result<(), Box<dyn Error>> {
        // An intermediary merging repeated headers inserts a space after the comma; upstream
        // removes only the first one it finds, corrupting every later tag.
        let spaced =
            format!(r#"indexed="?1"; 0="{}", indexed="?1";\t1="{}""#, SIGERS[0], SIGERS[1]).replace("\\t", "\t");
        let header = SignatureHeader::parse(&spaced)?;
        assert_eq!(header.signages().len(), 2);
        assert_eq!(
            header.to_header_value()?,
            format!(r#"indexed="?1";0="{}",indexed="?1";1="{}""#, SIGERS[0], SIGERS[1])
        );
        Ok(())
    }

    #[test]
    fn oversized_input_is_bounded() -> Result<(), Box<dyn Error>> {
        let overlong = "a".repeat(MAX_HEADER_BYTES + 1);
        assert!(matches!(
            SignatureHeader::parse(&overlong),
            Err(SignatureFieldError::HeaderTooLong { length, maximum })
                if length == MAX_HEADER_BYTES + 1 && maximum == MAX_HEADER_BYTES
        ));

        // Rendering is bounded too, so a caller cannot build a header no peer would accept.
        let signature = IndexedSignature::from_qb64(SIGERS[0])?;
        let markers = (0..200)
            .map(|position| IndexedMarker::named(FieldText::new(format!("tag{position}"))?, signature.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let signage = SignageBuilder::new(SignageMarkers::Indexed(markers)).build()?;
        assert!(matches!(
            SignatureHeader::new(vec![signage])?.to_header_value(),
            Err(SignatureFieldError::HeaderTooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_marker_tag_that_names_a_key_must_verify_its_signature() -> Result<(), Box<dyn Error>> {
        // The tag claims which key signed; a mismatched pair is refused rather than recorded.
        let mismatched = format!(r#"indexed="?0";{}="{}""#, VERFERS[1], CIGARS[0]);
        // Both are Ed25519, so the pair is merely wrong rather than incompatible: it parses, and
        // the caller verifies the signature itself.
        let header = SignatureHeader::parse(&mismatched)?;
        assert_eq!(header.to_header_value()?, mismatched);

        // A key of another algorithm cannot be attached to this signature at all, so the claim is
        // refused rather than recorded as a name.
        let incompatible = format!(
            r#"indexed="?0";1AAIA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ="{}""#,
            CIGARS[0]
        );
        assert!(matches!(
            SignatureHeader::parse(&incompatible),
            Err(SignatureFieldError::Crypto { .. })
        ));

        // A tag that is not a key at all stays a plain name.
        let named = format!(r#"indexed="?0";signify="{}""#, CIGARS[0]);
        let header = SignatureHeader::parse(&named)?;
        assert_eq!(header.to_header_value()?, named);
        Ok(())
    }

    /// Regression: the fuzzer built a marker explicitly tagged `0` whose signature already had
    /// index 0, so the rendered header was right but the parsed value differed from the built one.
    #[test]
    fn an_explicit_tag_equal_to_the_default_is_canonical() -> Result<(), Box<dyn Error>> {
        let signature = IndexedSignature::from_qb64(SIGERS[0])?;
        let explicit = IndexedMarker::named(FieldText::new("0")?, signature.clone())?;
        assert_eq!(explicit, IndexedMarker::new(signature));
        assert_eq!(explicit.tag(), "0");

        let signage = SignageBuilder::new(SignageMarkers::Indexed(vec![explicit])).build()?;
        let header = SignatureHeader::new(vec![signage])?;
        assert_eq!(SignatureHeader::parse(&header.to_header_value()?)?, header);

        // The same for an unindexed marker named with its own key.
        let key = VerificationKey::from_qb64(VERFERS[0])?;
        let signature = UnindexedSignature::from_qb64(CIGARS[0])?.with_verifier(key)?;
        let explicit = UnindexedMarker::named(FieldText::new(VERFERS[0])?, signature.clone())?;
        assert_eq!(explicit, UnindexedMarker::new(signature)?);
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_sources() {
        for error in [
            SignatureFieldError::HeaderTooLong {
                length: 1,
                maximum: MAX_HEADER_BYTES,
            },
            SignatureFieldError::EmptyFieldText,
            SignatureFieldError::FieldTextTooLong { length: 9 },
            SignatureFieldError::InvalidFieldText {
                text: "a;b".to_owned(),
                offset: 1,
            },
            SignatureFieldError::MalformedItem { item: "x".to_owned() },
            SignatureFieldError::MissingIndexedField,
            SignatureFieldError::InvalidIndexedFlag { found: "0".to_owned() },
            SignatureFieldError::DuplicateField { name: "0".to_owned() },
            SignatureFieldError::ReservedTag {
                name: "kind".to_owned(),
            },
            SignatureFieldError::NoMarkers,
            SignatureFieldError::NoSignages,
            SignatureFieldError::KindMismatch { kind: "CESR" },
            SignatureFieldError::MissingVerificationKey,
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn error_text_is_bounded() {
        let long = ";".repeat(64);
        match FieldText::new(long) {
            Err(SignatureFieldError::InvalidFieldText { text, .. }) => {
                assert_eq!(text.chars().count(), 32);
            }
            other => assert!(other.is_err(), "long text was accepted"),
        }
    }
}

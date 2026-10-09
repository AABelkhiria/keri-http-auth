//! Validated HTTP header names, values, and a bounded collection of them.
//!
//! Canonicalizing a signature needs to read the headers a message carries, so this module models
//! just enough of an HTTP field collection to do that safely: names are RFC 9110 tokens, values
//! exclude the control bytes that would forge a line in a signature base, and lookup is
//! ASCII-case-insensitive as HTTP requires.
//!
//! # Why not a plain map
//!
//! The reference uses the browser `Headers` collection, which joins repeated fields with a comma
//! and a space. A covered header that arrives twice therefore changes the bytes a signature commits
//! to, silently and without either peer noticing. [`Headers`] refuses a duplicate name instead; see
//! `PORTING.md` §9.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// Largest header name this module accepts, in bytes.
pub const MAX_HEADER_NAME_BYTES: usize = 128;

/// Largest header value this module accepts, in bytes.
///
/// Common server limits for a single header sit at 8 KiB; nothing KERIA sends approaches it.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Largest number of headers one collection holds.
pub const MAX_HEADERS: usize = 128;

/// One validated HTTP field name.
///
/// The accepted bytes are the RFC 9110 `token` set, which excludes `@` — so a header name can never
/// collide with a derived component such as `@method`. The original spelling is preserved because
/// the signature base carries the name exactly as the signer wrote it, while comparison is
/// ASCII-case-insensitive as HTTP requires.
///
/// ```
/// use keri_http_auth::header::HeaderName;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let name = HeaderName::new("Signify-Resource")?;
/// assert_eq!(name.as_str(), "Signify-Resource");
/// assert!(name.matches("signify-resource"));
/// assert!(HeaderName::new("@method").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct HeaderName {
    text: String,
}

impl HeaderName {
    /// Validates one field name.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::EmptyName`] for empty input, [`HeaderError::NameTooLong`] above
    /// [`MAX_HEADER_NAME_BYTES`], and [`HeaderError::InvalidName`] for a byte outside the token
    /// set.
    pub fn new(text: impl Into<String>) -> Result<Self, HeaderError> {
        let text = text.into();
        if text.is_empty() {
            return Err(HeaderError::EmptyName);
        }
        if text.len() > MAX_HEADER_NAME_BYTES {
            return Err(HeaderError::NameTooLong { length: text.len() });
        }
        if let Some(offset) = text.bytes().position(|byte| !is_token_byte(byte)) {
            return Err(HeaderError::InvalidName {
                name: bounded(&text),
                offset,
            });
        }
        Ok(Self { text })
    }

    /// Returns the name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns whether this name is the same field as `other`, ignoring ASCII case.
    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.text.eq_ignore_ascii_case(other)
    }
}

impl PartialEq for HeaderName {
    /// Compares field names the way HTTP does: ignoring ASCII case.
    fn eq(&self, other: &Self) -> bool {
        self.text.eq_ignore_ascii_case(&other.text)
    }
}

impl Eq for HeaderName {}

impl FromStr for HeaderName {
    type Err = HeaderError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for HeaderName {
    type Error = HeaderError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns whether a byte is an RFC 9110 `tchar`.
const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// One validated HTTP field value, with surrounding whitespace already removed.
///
/// Leading and trailing spaces and tabs are stripped at construction, which is both what RFC 9110
/// requires of a recipient and what the reference's `normalize` does before canonicalization — so
/// the stored value is already the one a signature commits to.
///
/// The accepted scalar values are horizontal tab, `U+0020`–`U+007E`, and `U+00A0`–`U+00FF`. That is
/// exactly what an HTTP field value can carry — the reference's field collection is a `ByteString`
/// and refuses any code unit above `U+00FF` outright — minus the control characters, which would
/// otherwise let a value forge a whole line in a signature base.
///
/// ```
/// use keri_http_auth::header::HeaderValue;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(HeaderValue::new("  application/json  ")?.as_str(), "application/json");
/// assert!(HeaderValue::new("a\nb").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderValue {
    text: String,
}

impl HeaderValue {
    /// Validates one field value, trimming surrounding whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::ValueTooLong`] above [`MAX_HEADER_VALUE_BYTES`] and
    /// [`HeaderError::InvalidValue`] for a control character or a scalar an HTTP field cannot
    /// carry. An empty value is accepted, as HTTP allows one.
    pub fn new(text: impl AsRef<str>) -> Result<Self, HeaderError> {
        let text = text.as_ref().trim_matches(is_optional_whitespace);
        if text.len() > MAX_HEADER_VALUE_BYTES {
            return Err(HeaderError::ValueTooLong { length: text.len() });
        }
        if let Some((offset, _)) = text.char_indices().find(|(_, scalar)| !is_field_scalar(*scalar)) {
            return Err(HeaderError::InvalidValue {
                value: bounded(text),
                offset,
            });
        }
        Ok(Self { text: text.to_owned() })
    }

    /// Returns the trimmed value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl FromStr for HeaderValue {
    type Err = HeaderError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for HeaderValue {
    type Error = HeaderError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns whether a character is the optional whitespace HTTP allows around a field value.
const fn is_optional_whitespace(scalar: char) -> bool {
    matches!(scalar, ' ' | '\t')
}

/// Returns whether a scalar value may appear inside a field value.
const fn is_field_scalar(scalar: char) -> bool {
    matches!(scalar, '\t' | '\u{20}'..='\u{7e}' | '\u{a0}'..='\u{ff}')
}

/// The headers of one request or response, in the order they were added.
///
/// Names are unique, ignoring case. Lookup is case-insensitive.
///
/// ```
/// use keri_http_auth::header::{HeaderName, HeaderValue, Headers};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let headers = Headers::from_pairs([
///     (
///         HeaderName::new("Signify-Resource")?,
///         HeaderValue::new("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs")?,
///     ),
///     (HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?),
/// ])?;
///
/// assert_eq!(
///     headers.get("signify-resource"),
///     Some("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"),
/// );
/// assert_eq!(headers.get("absent"), None);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Headers {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl Headers {
    /// Creates an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Collects headers in the given order.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::DuplicateHeader`] for a repeated name and
    /// [`HeaderError::TooManyHeaders`] above [`MAX_HEADERS`].
    pub fn from_pairs(pairs: impl IntoIterator<Item = (HeaderName, HeaderValue)>) -> Result<Self, HeaderError> {
        let mut headers = Self::new();
        for (name, value) in pairs {
            headers.insert(name, value)?;
        }
        Ok(headers)
    }

    /// Adds one header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::DuplicateHeader`] when the name is already present, ignoring case —
    /// the reference joins the two values with a comma instead, which silently changes what a
    /// signature covers — and [`HeaderError::TooManyHeaders`] above [`MAX_HEADERS`].
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) -> Result<(), HeaderError> {
        if self.entries.len() >= MAX_HEADERS {
            return Err(HeaderError::TooManyHeaders { maximum: MAX_HEADERS });
        }
        if self.entries.iter().any(|(existing, _)| *existing == name) {
            return Err(HeaderError::DuplicateHeader {
                name: bounded(name.as_str()),
            });
        }
        self.entries.push((name, value));
        Ok(())
    }

    /// Returns the value of one header, ignoring ASCII case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(existing, _)| existing.matches(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns whether a header is present, ignoring ASCII case.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Returns every header in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }

    /// Returns how many headers there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'headers> IntoIterator for &'headers Headers {
    type Item = (&'headers HeaderName, &'headers HeaderValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'headers, (HeaderName, HeaderValue)>,
        fn(&'headers (HeaderName, HeaderValue)) -> (&'headers HeaderName, &'headers HeaderValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(name, value)| (name, value))
    }
}

/// Copies at most thirty-two characters of rejected text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(32).collect()
}

/// Stable HTTP header failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeaderError {
    /// A field name is empty.
    EmptyName,
    /// A field name exceeds [`MAX_HEADER_NAME_BYTES`].
    NameTooLong {
        /// Actual length in bytes.
        length: usize,
    },
    /// A field name holds a byte outside the RFC 9110 token set.
    InvalidName {
        /// Bounded copy of the rejected name.
        name: String,
        /// Offset of the first offending byte.
        offset: usize,
    },
    /// A field value exceeds [`MAX_HEADER_VALUE_BYTES`].
    ValueTooLong {
        /// Actual length in bytes.
        length: usize,
    },
    /// A field value holds a control character or a scalar HTTP cannot carry.
    InvalidValue {
        /// Bounded copy of the rejected value.
        value: String,
        /// Byte offset of the first offending character.
        offset: usize,
    },
    /// The same field name appears twice, which would make canonicalization ambiguous.
    DuplicateHeader {
        /// Bounded copy of the repeated name.
        name: String,
    },
    /// A collection exceeds [`MAX_HEADERS`].
    TooManyHeaders {
        /// Accepted maximum.
        maximum: usize,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => formatter.write_str("a header name is empty"),
            Self::NameTooLong { length } => write!(
                formatter,
                "header name of {length} bytes exceeds maximum {MAX_HEADER_NAME_BYTES}"
            ),
            Self::InvalidName { name, offset } => write!(
                formatter,
                "header name {name:?} holds a byte outside the token set at offset {offset}"
            ),
            Self::ValueTooLong { length } => write!(
                formatter,
                "header value of {length} bytes exceeds maximum {MAX_HEADER_VALUE_BYTES}"
            ),
            Self::InvalidValue { value, offset } => write!(
                formatter,
                "header value {value:?} holds an unusable character at offset {offset}"
            ),
            Self::DuplicateHeader { name } => {
                write!(formatter, "header {name:?} appears more than once")
            }
            Self::TooManyHeaders { maximum } => {
                write!(formatter, "a message carries more than {maximum} headers")
            }
        }
    }
}

impl Error for HeaderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn headers() -> Result<Headers, Box<dyn Error>> {
        Ok(Headers::from_pairs([
            (
                HeaderName::new("Signify-Resource")?,
                HeaderValue::new("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs")?,
            ),
            (
                HeaderName::new("Signify-Timestamp")?,
                HeaderValue::new("2022-09-24T00:05:48.196795+00:00")?,
            ),
        ])?)
    }

    #[test]
    fn names_compare_and_look_up_without_regard_to_case() -> Result<(), Box<dyn Error>> {
        let headers = headers()?;
        assert_eq!(
            headers.get("SIGNIFY-RESOURCE"),
            Some("EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs")
        );
        assert!(headers.contains("signify-timestamp"));
        assert!(!headers.contains("absent"));
        assert_eq!(HeaderName::new("Content-Type")?, HeaderName::new("content-type")?);
        // The spelling is still preserved, because the signature base carries it verbatim.
        assert_eq!(HeaderName::new("Content-Type")?.as_str(), "Content-Type");
        assert_eq!(HeaderName::new("Content-Type")?.to_string(), "Content-Type");
        Ok(())
    }

    #[test]
    fn a_derived_component_is_not_a_header_name() {
        // `@` is not a token byte, so `@method` can never be built as a field name.
        for name in ["@method", "@path", "@signature-params", "a b", "a:b", "a\"b", ""] {
            assert!(HeaderName::new(name).is_err(), "{name:?} was accepted");
        }
    }

    #[test]
    fn header_names_are_bounded() {
        assert!(matches!(
            HeaderName::new("a".repeat(MAX_HEADER_NAME_BYTES + 1)),
            Err(HeaderError::NameTooLong { length }) if length == MAX_HEADER_NAME_BYTES + 1
        ));
        assert!(matches!(HeaderName::new(""), Err(HeaderError::EmptyName)));
        assert!(matches!(
            HeaderName::new("a@b"),
            Err(HeaderError::InvalidName { offset: 1, .. })
        ));
    }

    #[test]
    fn values_are_trimmed_and_control_free() -> Result<(), Box<dyn Error>> {
        assert_eq!(HeaderValue::new("\t padded \t")?.as_str(), "padded");
        assert_eq!(HeaderValue::new("")?.as_str(), "");
        assert_eq!(HeaderValue::new("a b")?.to_string(), "a b");
        // A newline in a value would forge a whole line in the signature base.
        for value in ["a\nb", "a\rb", "a\u{0}b", "a\u{7f}b", "a\u{85}b"] {
            assert!(
                matches!(HeaderValue::new(value), Err(HeaderError::InvalidValue { .. })),
                "{value:?} was accepted",
            );
        }
        // Latin-1 is what an HTTP field value can actually carry, and the reference accepts it.
        assert_eq!(HeaderValue::new("héllo")?.as_str(), "héllo");
        // Above Latin-1 the reference's own collection refuses the value outright.
        assert!(matches!(
            HeaderValue::new("世界"),
            Err(HeaderError::InvalidValue { offset: 0, .. })
        ));
        assert!(matches!(
            HeaderValue::new("a".repeat(MAX_HEADER_VALUE_BYTES + 1)),
            Err(HeaderError::ValueTooLong { length }) if length == MAX_HEADER_VALUE_BYTES + 1
        ));
        assert_eq!(HeaderValue::from_str(" x ")?, HeaderValue::try_from("x")?);
        Ok(())
    }

    #[test]
    fn duplicate_names_are_refused() -> Result<(), Box<dyn Error>> {
        // The reference joins them with ", ", silently changing the signature base.
        let mut headers = headers()?;
        assert!(matches!(
            headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new("other")?),
            Err(HeaderError::DuplicateHeader { .. })
        ));
        assert_eq!(headers.len(), 2);
        assert!(!headers.is_empty());
        assert!(Headers::new().is_empty());
        Ok(())
    }

    #[test]
    fn collections_are_bounded_and_iterable() -> Result<(), Box<dyn Error>> {
        let mut headers = Headers::new();
        for position in 0..MAX_HEADERS {
            headers.insert(HeaderName::new(format!("x-{position}"))?, HeaderValue::new("1")?)?;
        }
        assert!(matches!(
            headers.insert(HeaderName::new("x-extra")?, HeaderValue::new("1")?),
            Err(HeaderError::TooManyHeaders { maximum }) if maximum == MAX_HEADERS
        ));

        let headers = self::headers()?;
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Signify-Resource", "Signify-Timestamp"]);
        assert_eq!((&headers).into_iter().count(), 2);
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text() {
        for error in [
            HeaderError::EmptyName,
            HeaderError::NameTooLong { length: 9 },
            HeaderError::InvalidName {
                name: "a@b".to_owned(),
                offset: 1,
            },
            HeaderError::ValueTooLong { length: 9 },
            HeaderError::InvalidValue {
                value: "a\nb".to_owned(),
                offset: 1,
            },
            HeaderError::DuplicateHeader { name: "x".to_owned() },
            HeaderError::TooManyHeaders { maximum: MAX_HEADERS },
        ] {
            assert_ne!(error.to_string(), "");
            assert!(error.source().is_none());
        }
    }
}

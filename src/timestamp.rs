//! The `Signify-Timestamp` header value.
//!
//! The reference produces it with one expression in `SignifyClient.fetch`:
//!
//! ```text
//! headers.set(HEADER_SIG_TIME, new Date().toISOString().replace('Z', '000+00:00'))
//! ```
//!
//! `toISOString` yields millisecond precision, and replacing the `Z` appends three zeros — so the
//! value always ends in `000` and **claims a microsecond precision it never had**. That is
//! reproduced exactly, because the header is one of the four components a Signify signature covers
//! and any other spelling would change the bytes the signature commits to.
//!
//! Roadmap 3.10 recorded this value's production as the client's, on the reasoning that a protocol
//! crate never reads a clock. It lands here instead because Roadmap 5.4 made the clock an injected
//! [`Clock`](crate::retry::Clock): the value is a wire format, and keeping it beside the signature
//! that covers it is what lets the two be built from a single reading. A caller still supplies the
//! time.

use core::fmt;
use std::error::Error;
use std::time::{Duration, SystemTime};

use crate::header::{HeaderError, HeaderValue};

/// The exact width of the rendered value, `1970-01-01T00:00:00.000000+00:00`.
pub const TIMESTAMP_WIDTH: usize = 32;

/// The earliest year this renders, and the latest.
///
/// Four digits is what the format has room for, so a time outside this range cannot be written at
/// all rather than being written wrongly.
pub const MIN_YEAR: i64 = 1;
/// See [`MIN_YEAR`].
pub const MAX_YEAR: i64 = 9_999;

/// A `Signify-Timestamp` value, rendered in the reference's own format.
///
/// ```
/// use core::time::Duration;
/// use std::time::SystemTime;
/// use signify_http::signature::timestamp::SignifyTimestamp;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
/// let stamp = SignifyTimestamp::at(at)?;
///
/// // Millisecond precision, three appended zeros, and a written-out UTC offset.
/// assert_eq!(stamp.as_str(), "2023-11-14T22:13:20.123000+00:00");
/// // The `created` parameter of the same signature is the whole second of the same reading.
/// assert_eq!(stamp.created(), 1_700_000_000);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignifyTimestamp {
    text: String,
    created: u64,
}

impl SignifyTimestamp {
    /// Renders the value for one moment.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::BeforeEpoch`] for a time before 1970, which the reference's own
    /// `toISOString` would render with a negative year, and [`TimestampError::OutOfRange`] for a
    /// year the four-digit format cannot hold.
    pub fn at(moment: SystemTime) -> Result<Self, TimestampError> {
        let since_epoch = moment
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TimestampError::BeforeEpoch)?;
        Self::from_unix(since_epoch)
    }

    /// Renders the value for a duration since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] for a year the four-digit format cannot hold.
    pub fn from_unix(since_epoch: Duration) -> Result<Self, TimestampError> {
        let created = since_epoch.as_secs();
        let milliseconds = since_epoch.subsec_millis();
        let seconds = i64::try_from(created).map_err(|_| TimestampError::OutOfRange { year: i64::MAX })?;

        let days = seconds.div_euclid(86_400);
        let seconds_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days).ok_or(TimestampError::OutOfRange { year: i64::MAX })?;
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return Err(TimestampError::OutOfRange { year });
        }

        let hour = seconds_of_day / 3_600;
        let minute = (seconds_of_day % 3_600) / 60;
        let second = seconds_of_day % 60;

        // The three trailing zeros are the reference's, not a rounding: `toISOString` has only
        // milliseconds and `.replace('Z', '000+00:00')` pads the rest.
        let text =
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}000+00:00");
        Ok(Self { text, created })
    }

    /// Returns the rendered value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the whole second of the same reading, which is a signature's `created` parameter.
    ///
    /// The reference derives this separately, from a *second* clock reading inside `siginput`, so
    /// its header and its parameter can disagree by however long the two calls are apart.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }

    /// Returns the value as a header value.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError`] only if the rendered value ever stops being a usable field value,
    /// which its fixed alphabet makes unreachable; the unit tests assert it.
    pub fn to_header_value(&self) -> Result<HeaderValue, HeaderError> {
        HeaderValue::new(&self.text)
    }
}

impl fmt::Display for SignifyTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns the proleptic Gregorian date for a count of days since 1970-01-01.
///
/// Howard Hinnant's `civil_from_days`, the inverse of the `days_from_civil` Roadmap 5.4 uses to
/// *read* an HTTP-date. Exact integer arithmetic with no floating point and no lookup table.
fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = month_position + if month_position < 10 { 3 } else { -9 };
    Some((if month <= 2 { year.checked_add(1)? } else { year }, month, day))
}

/// Stable timestamp-rendering failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimestampError {
    /// The moment is before the Unix epoch.
    BeforeEpoch,
    /// The year does not fit the format's four digits.
    OutOfRange {
        /// The year in question.
        year: i64,
    },
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeEpoch => formatter.write_str("a Signify timestamp may not precede the Unix epoch"),
            Self::OutOfRange { year } => write!(
                formatter,
                "the year {year} is outside the range {MIN_YEAR} to {MAX_YEAR} the format can hold"
            ),
        }
    }
}

impl Error for TimestampError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn at(milliseconds: u64) -> Result<SignifyTimestamp, TimestampError> {
        SignifyTimestamp::from_unix(Duration::from_millis(milliseconds))
    }

    #[test]
    fn the_reference_format_is_reproduced() -> Result<(), Box<dyn Error>> {
        for (milliseconds, expected) in [
            (1_700_000_000_123_u64, "2023-11-14T22:13:20.123000+00:00"),
            (0, "1970-01-01T00:00:00.000000+00:00"),
            // A leap day, and the last second of a year.
            (1_456_747_200_000, "2016-02-29T12:00:00.000000+00:00"),
            (1_704_067_199_999, "2023-12-31T23:59:59.999000+00:00"),
            // A century year that is a leap year.
            (951_782_400_000, "2000-02-29T00:00:00.000000+00:00"),
        ] {
            let stamp = at(milliseconds)?;
            assert_eq!(stamp.as_str(), expected, "{milliseconds}");
            assert_eq!(stamp.to_string(), expected);
            assert_eq!(stamp.as_str().len(), TIMESTAMP_WIDTH);
        }
        Ok(())
    }

    #[test]
    fn the_value_always_ends_in_three_zeros() -> Result<(), Box<dyn Error>> {
        // The reference has millisecond resolution and pads the rest; a caller with microseconds
        // still gets the padded shape, because the header must read as the reference's.
        for milliseconds in [0_u64, 1, 999, 1_000, 1_700_000_000_001] {
            let stamp = at(milliseconds)?;
            assert!(stamp.as_str().ends_with("000+00:00"), "{}", stamp.as_str());
        }
        // Sub-millisecond precision is dropped, exactly as `toISOString` drops it.
        let coarse = SignifyTimestamp::from_unix(Duration::from_nanos(1_700_000_000_123_999_999))?;
        assert_eq!(coarse.as_str(), "2023-11-14T22:13:20.123000+00:00");
        Ok(())
    }

    #[test]
    fn created_is_the_whole_second_of_the_same_reading() -> Result<(), Box<dyn Error>> {
        let stamp = at(1_700_000_000_999)?;
        assert_eq!(stamp.created(), 1_700_000_000);
        assert_eq!(stamp.as_str(), "2023-11-14T22:13:20.999000+00:00");
        // One reading, so the header and the parameter can never disagree.
        assert_eq!(at(1_700_000_000_000)?.created(), stamp.created());
        Ok(())
    }

    #[test]
    fn a_moment_before_the_epoch_is_refused() {
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(SignifyTimestamp::at(before), Err(TimestampError::BeforeEpoch));
        // And the epoch itself is fine.
        assert!(SignifyTimestamp::at(SystemTime::UNIX_EPOCH).is_ok());
    }

    #[test]
    fn a_year_the_format_cannot_hold_is_refused() {
        // 10000-01-01T00:00:00Z is 253402300800 seconds after the epoch.
        const TOO_LATE_SECONDS: u64 = 253_402_300_800;
        let too_late = Duration::from_secs(TOO_LATE_SECONDS);
        assert!(matches!(
            SignifyTimestamp::from_unix(too_late),
            Err(TimestampError::OutOfRange { .. })
        ));
        // One second earlier still renders.
        let latest = SignifyTimestamp::from_unix(Duration::from_secs(TOO_LATE_SECONDS - 1));
        assert_eq!(
            latest.map(|stamp| stamp.as_str().to_owned()).ok(),
            Some("9999-12-31T23:59:59.000000+00:00".to_owned()),
        );
        assert!(matches!(
            SignifyTimestamp::from_unix(Duration::MAX),
            Err(TimestampError::OutOfRange { .. })
        ));
    }

    #[test]
    fn the_value_is_always_a_usable_header_value() -> Result<(), Box<dyn Error>> {
        for milliseconds in [0_u64, 1_700_000_000_123, 253_402_300_799_000] {
            let stamp = at(milliseconds)?;
            assert_eq!(stamp.to_header_value()?.as_str(), stamp.as_str());
        }
        Ok(())
    }

    #[test]
    fn civil_days_round_trip_against_known_dates() {
        for (days, expected) in [
            (0_i64, (1970_i64, 1_i64, 1_i64)),
            (-1, (1969, 12, 31)),
            (11_017, (2000, 3, 1)),
            (19_675, (2023, 11, 14)),
            (-25_567, (1900, 1, 1)),
        ] {
            assert_eq!(civil_from_days(days), Some(expected), "{days}");
        }
    }

    #[test]
    fn errors_carry_readable_text() {
        for error in [TimestampError::BeforeEpoch, TimestampError::OutOfRange { year: 12_345 }] {
            assert_ne!(error.to_string(), "");
            assert!(error.source().is_none());
        }
    }
}

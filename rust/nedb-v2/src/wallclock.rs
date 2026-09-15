// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Wall-clock parsing for `AS OF SYSTEM TIME '<datetime>'`.
//!
//! Zero-dependency by the same rule the daemon keeps: ISO-8601 subsets and
//! unix timestamps are grammar, not an ecosystem. What is accepted:
//!
//! | form | example | meaning |
//! |---|---|---|
//! | RFC 3339 / ISO datetime | `2026-09-15T17:00:00Z`, `2026-09-15 17:00:00` | wall-clock moment |
//! | date only | `2026-09-15` | midnight UTC of that day |
//! | epoch with unit | `1757955600s`, `1757955600000ms` | wall-clock moment (explicit — see below) |
//!
//! A **bare integer stays a sequence number** and never reaches this module:
//! that is the entire backcompat contract. Every query that worked before this
//! existed means the same thing it always did. A unix value must carry an
//! explicit `s`/`ms` suffix — silently reinterpreting `1757955600` as "September
//! 2026" would answer a question about the past with whatever happens to be at
//! seq 1.7 billion, which is the same failure shape as dropping an `AS OF`
//! silently: a confident answer to a question nobody asked.
//!
//! Fractional seconds are accepted in the datetime form. Offsets other than
//! `Z` (`+02:00`) are accepted and normalised; a naive datetime (no offset)
//! is read as **UTC**, stated here rather than guessed per deployment.
//!
//! The resolution rule — "the last write at or before T" — lives with the
//! engine's `ts` index (`Db::seq_at`), not here. This module only turns text
//! into a moment.

/// A parsed wall-clock moment, as epoch seconds (fractional).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WallClock(pub f64);

#[derive(Debug)]
pub enum WallClockError {
    /// Not recognizable as any accepted form.
    Unrecognized(String),
    /// Recognizable shape, impossible value (month 13, day 32, hour 25).
    OutOfRange(&'static str),
}

impl std::error::Error for WallClockError {}

impl std::fmt::Display for WallClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WallClockError::Unrecognized(s) => write!(f, "unrecognized datetime {:?}", s),
            WallClockError::OutOfRange(what) => write!(f, "datetime out of range: {}", what),
        }
    }
}

impl WallClock {
    /// Parse an accepted wall-clock form. `raw` is the UNQUOTED literal text.
    pub fn parse(raw: &str) -> Result<WallClock, WallClockError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(WallClockError::Unrecognized(raw.to_string()));
        }

        // Epoch with explicit unit: `1757955600s` / `1757955600000ms`.
        let lower = s.to_ascii_lowercase();
        if let Some(digits) = lower.strip_suffix("ms") {
            let v: f64 = digits
                .parse()
                .map_err(|_| WallClockError::Unrecognized(raw.to_string()))?;
            return Ok(WallClock(v / 1_000.0));
        }
        if let Some(digits) = lower.strip_suffix('s') {
            if digits
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
            {
                let v: f64 = digits
                    .parse()
                    .map_err(|_| WallClockError::Unrecognized(raw.to_string()))?;
                return Ok(WallClock(v));
            }
        }

        // Datetime forms. Everything else must start with a date.
        let (date_part, rest) =
            split_date(s).ok_or_else(|| WallClockError::Unrecognized(raw.to_string()))?;
        let (y, m, d) = parse_ymd(&date_part)?;

        // Default clock: midnight UTC of the named day.
        let mut sec: f64 = 0.0;
        let mut offset_sec: f64 = 0.0;

        let rest = rest.trim_start();
        if !rest.is_empty() {
            // Separator: 'T', 't', or a single space.
            let rest = rest.strip_prefix(['T', 't', ' ']).unwrap_or(rest);
            if rest.is_empty() {
                // `2026-09-15 ` with trailing space — fine, midnight.
            } else {
                let (hms, tail) = split_time(rest)
                    .ok_or_else(|| WallClockError::Unrecognized(raw.to_string()))?;
                sec = parse_hms(&hms)?;
                let tail = tail.trim();
                if !tail.is_empty() {
                    offset_sec = parse_offset(tail)?;
                }
            }
        }

        let days = days_from_civil(y, m, d).ok_or(WallClockError::OutOfRange("date"))?;
        // days_from_civil returns whole days since 1970-01-01.
        let epoch = days as f64 * 86_400.0 + sec - offset_sec;
        Ok(WallClock(epoch))
    }

    /// The epoch-seconds moment.
    pub fn epoch_secs(&self) -> f64 {
        self.0
    }

    /// The AS OF marker for a wall-clock moment: `WALL_CLOCK_FLAG | epoch_ms`.
    ///
    /// The clause's marker slot is a `u64` the executor reads as a sequence.
    /// A wall-clock moment rides in the same slot but TAGGED with the high
    /// bit, which no real sequence ever sets (a store would need 2^63 writes
    /// to reach it — itcd's production chainstate sits at ~10^6). The layer
    /// between parser and executor — the place holding both the marker and
    /// the `Db` — checks the flag: set, resolve through `Db::seq_at` to a
    /// real seq; clear, pass through untouched. Bare integers keep their
    /// meaning bit-for-bit; that is the backcompat contract.
    pub fn as_marker(&self) -> u64 {
        WALL_CLOCK_FLAG | ((self.0 * 1000.0).round() as u64)
    }

    /// Decode a marker produced by [`as_marker`], if it is one.
    pub fn from_marker(marker: u64) -> Option<WallClock> {
        if marker & WALL_CLOCK_FLAG == 0 {
            return None; // a plain sequence, not a wall-clock moment
        }
        Some(WallClock((marker & !WALL_CLOCK_FLAG) as f64 / 1000.0))
    }
}

/// High bit tagging a marker as a wall-clock moment rather than a sequence.
pub const WALL_CLOCK_FLAG: u64 = 1u64 << 63;

/// Split a leading `YYYY-MM-DD` off; returns the rest after it.
fn split_date(s: &str) -> Option<(&str, &str)> {
    let b = s.as_bytes();
    if b.len() < 10 {
        return None;
    }
    // YYYY-MM-DD exactly (10 chars, digits at the right spots).
    if !(b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit())
    {
        return None;
    }
    Some((&s[..10], &s[10..]))
}

/// Split a leading `HH:MM[:SS[.frac]]` off; returns the rest after it.
fn split_time(s: &str) -> Option<(&str, &str)> {
    let b = s.as_bytes();
    // HH:MM minimum (5 chars), optional :SS(.frac)
    let mut end = 0usize;
    let seen_colon = b.first() != Some(&b':');
    let _ = seen_colon;
    while end < b.len() && (b[end].is_ascii_digit() || b[end] == b':') {
        end += 1;
    }
    if end < 5 {
        return None;
    }
    let mut hms_end = end;
    // A fractional part attaches to seconds: HH:MM.frac is malformed — but
    // accept `HH:MM:SS.frac` by pulling digits/dot that followed the last colon
    // group. The strict shape is validated in parse_hms.
    if end < b.len() && b[end] == b'.' {
        hms_end += 1;
        while hms_end < b.len() && b[hms_end].is_ascii_digit() {
            hms_end += 1;
        }
    }
    Some((&s[..hms_end], &s[hms_end..]))
}

fn parse_ymd(s: &str) -> Result<(i64, u32, u32), WallClockError> {
    let y: i64 = s[0..4]
        .parse()
        .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
    let m: u32 = s[5..7]
        .parse()
        .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
    let d: u32 = s[8..10]
        .parse()
        .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
    if !(1..=12).contains(&m) {
        return Err(WallClockError::OutOfRange("month must be 01–12"));
    }
    if !(1..=31).contains(&d) {
        return Err(WallClockError::OutOfRange("day must be 01–31"));
    }
    Ok((y, m, d))
}

fn parse_hms(s: &str) -> Result<f64, WallClockError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(WallClockError::Unrecognized(s.to_string()));
    }
    let h: f64 = parts[0]
        .parse()
        .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
    if !(0.0..24.0).contains(&h) {
        return Err(WallClockError::OutOfRange("hour must be 00–23"));
    }
    let (m, sec_part) = match parts.len() {
        1 => (0.0, None),
        2 => (
            parts[1]
                .parse::<f64>()
                .map_err(|_| WallClockError::Unrecognized(s.to_string()))?,
            None,
        ),
        _ => (
            parts[1]
                .parse::<f64>()
                .map_err(|_| WallClockError::Unrecognized(s.to_string()))?,
            Some(parts[2]),
        ),
    };
    if !(0.0..60.0).contains(&m) {
        return Err(WallClockError::OutOfRange("minute must be 00–59"));
    }
    let mut total = h * 3600.0 + m * 60.0;
    if let Some(sp) = sec_part {
        // `SS.fraction`
        let mut seg = sp.split('.');
        let ss: f64 = seg
            .next()
            .unwrap_or("0")
            .parse()
            .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
        if !(0.0..60.0).contains(&ss) {
            return Err(WallClockError::OutOfRange("second must be 00–59"));
        }
        total += ss;
        if let Some(frac) = seg.next() {
            let frac_val = format!("0.{}", frac)
                .parse::<f64>()
                .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
            total += frac_val;
        }
    }
    Ok(total)
}

/// Parse a trailing offset: `Z`, `z`, `+HH:MM`, `-HHMM`, `+HH`.
fn parse_offset(s: &str) -> Result<f64, WallClockError> {
    let up = s.to_ascii_uppercase();
    if up == "Z" {
        return Ok(0.0);
    }
    let (sign, body) = match up.strip_prefix('+') {
        Some(b) => (1.0, b),
        None => match up.strip_prefix('-') {
            Some(b) => (-1.0, b),
            None => return Err(WallClockError::Unrecognized(s.to_string())),
        },
    };
    let digits: String = body.chars().filter(|c| c.is_ascii_digit()).collect();
    let (h, m) = match digits.len() {
        2 => (digits.parse::<f64>().unwrap_or(0.0), 0.0),
        4 => {
            let h: f64 = digits[..2]
                .parse()
                .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
            let m: f64 = digits[2..]
                .parse()
                .map_err(|_| WallClockError::Unrecognized(s.to_string()))?;
            (h, m)
        }
        _ => return Err(WallClockError::Unrecognized(s.to_string())),
    };
    if !(0.0..24.0).contains(&h) || !(0.0..60.0).contains(&m) {
        return Err(WallClockError::OutOfRange("offset out of range"));
    }
    Ok(sign * (h * 3600.0 + m * 60.0))
}

/// Days since 1970-01-01 for a proleptic-Gregorian Y/M/D. `None` when the
/// date does not exist (Feb 30, Apr 31, …).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    // Days per month, with the leap rule applied for the actual year.
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_lens = [
        31u32,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let ml = *month_lens.get((m as usize).saturating_sub(1))?;
    if d > ml {
        return None;
    }
    // Howard Hinnant's days_from_civil algorithm.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe: i64 = y2 - era * 400;
    let mp: i64 = m as i64 + if m as i64 > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + (d as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_date_is_zero() {
        assert_eq!(WallClock::parse("1970-01-01").unwrap().epoch_secs(), 0.0);
        assert_eq!(
            WallClock::parse("1970-01-01T00:00:00Z")
                .unwrap()
                .epoch_secs(),
            0.0
        );
    }

    #[test]
    fn a_known_moment_parses() {
        // 2026-09-15T00:00:00Z = 1789459200
        assert_eq!(
            WallClock::parse("2026-09-15").unwrap().epoch_secs(),
            1_789_430_400.0
        );
        assert_eq!(
            WallClock::parse("2026-09-15T00:00:00Z")
                .unwrap()
                .epoch_secs(),
            1_789_430_400.0
        );
        assert_eq!(
            WallClock::parse("2026-09-15 00:00:00")
                .unwrap()
                .epoch_secs(),
            1_789_430_400.0
        );
    }

    #[test]
    fn time_of_day_and_fractions_count() {
        let w = WallClock::parse("2026-09-15T17:00:00Z").unwrap();
        assert_eq!(w.epoch_secs(), 1_789_430_400.0 + 17.0 * 3600.0);
        let w2 = WallClock::parse("2026-09-15T17:00:00.5Z").unwrap();
        assert_eq!(w2.epoch_secs(), 1_789_430_400.0 + 17.0 * 3600.0 + 0.5);
    }

    #[test]
    fn offsets_shift_to_utc() {
        // 17:00+02:00 == 15:00Z
        let w = WallClock::parse("2026-09-15T17:00:00+02:00").unwrap();
        assert_eq!(w.epoch_secs(), 1_789_430_400.0 + 15.0 * 3600.0);
        // -0500 without colon
        let w2 = WallClock::parse("2026-09-15T12:00:00-0500").unwrap();
        assert_eq!(w2.epoch_secs(), 1_789_430_400.0 + 17.0 * 3600.0);
        // lowercase z
        assert_eq!(
            WallClock::parse("2026-09-15T00:00:00z")
                .unwrap()
                .epoch_secs(),
            1_789_430_400.0
        );
    }

    #[test]
    fn explicit_units_are_accepted_and_scaled() {
        assert_eq!(
            WallClock::parse("1757955600s").unwrap().epoch_secs(),
            1_757_955_600.0
        );
        assert_eq!(
            WallClock::parse("1757955600000ms").unwrap().epoch_secs(),
            1_757_955_600.0
        );
        assert_eq!(
            WallClock::parse("1757955600.5s").unwrap().epoch_secs(),
            1_757_955_600.5
        );
    }

    #[test]
    fn impossible_dates_are_range_errors_not_silence() {
        assert!(matches!(
            WallClock::parse("2026-02-30"),
            Err(WallClockError::OutOfRange("date"))
        ));
        assert!(matches!(
            WallClock::parse("2026-13-01"),
            Err(WallClockError::OutOfRange(_))
        ));
        assert!(matches!(
            WallClock::parse("2026-09-15T25:00:00Z"),
            Err(WallClockError::OutOfRange(_))
        ));
        // Leap year works; non-leap Feb 29 fails.
        assert!(WallClock::parse("2024-02-29").is_ok());
        assert!(matches!(
            WallClock::parse("2026-02-29"),
            Err(WallClockError::OutOfRange("date"))
        ));
    }

    #[test]
    fn garbage_is_unrecognized() {
        for bad in ["not a time", "15/09/2026", "sep 15", "2026-9-15", "", "  "] {
            assert!(
                matches!(WallClock::parse(bad), Err(WallClockError::Unrecognized(_))),
                "expected Unrecognized for {:?}",
                bad
            );
        }
        // A unix-looking value WITHOUT a unit is not wall-clock (it never
        // reaches this module in the clause — bare integers are seqs) — but
        // the parser itself should also refuse to bless it as a date.
        assert!(matches!(
            WallClock::parse("1757955600"),
            Err(WallClockError::Unrecognized(_))
        ));
    }
}

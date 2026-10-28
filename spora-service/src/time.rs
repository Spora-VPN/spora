//! The few wall-clock formats this crate writes. Hand-rolled (Howard
//! Hinnant's civil-from-days, as in spora-core's record) rather than a date
//! dependency for three format strings.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn system_time_unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `2026-10-19T12:00:00.123Z`.
pub(crate) fn iso_ms(unix_ms: u64) -> String {
    let c = civil(unix_ms);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.milli
    )
}

/// Unix milliseconds of an ISO 8601 / RFC 3339 timestamp as the API writes
/// them: `2026-10-19T12:00:00Z`, with optional fractional seconds and a
/// `Z` or `±HH:MM` offset. `None` for anything else.
pub(crate) fn parse_iso_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut i = 19;
    let mut milli = 0i64;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = s.get(start..i)?;
        if frac.is_empty() {
            return None;
        }
        let ms = format!("{:0<3}", &frac[..frac.len().min(3)]);
        milli = ms.parse().ok()?;
    }
    let offset_s = match s.get(i..)? {
        "Z" | "z" => 0,
        rest if rest.len() == 6
            && matches!(rest.as_bytes()[0], b'+' | b'-')
            && rest.as_bytes()[3] == b':' =>
        {
            let h: i64 = rest.get(1..3)?.parse().ok()?;
            let m: i64 = rest.get(4..6)?.parse().ok()?;
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (h * 3600 + m * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_s;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000 + milli as u64)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// days-from-civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `20261019T120000123Z`: sorts chronologically as a file-name component.
pub(crate) fn file_stamp(unix_ms: u64) -> String {
    let c = civil(unix_ms);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}{:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.milli
    )
}

/// MS-DOS `(time, date)` as zip headers carry it. The format cannot express
/// anything before 1980, so earlier clocks clamp to its epoch.
pub(crate) fn dos_datetime(unix_ms: u64) -> (u16, u16) {
    let c = civil(unix_ms);
    if c.year < 1980 {
        return (0, (1 << 5) | 1);
    }
    let time = (c.hour << 11) | (c.minute << 5) | (c.second / 2);
    let date = (((c.year - 1980).min(127)) << 9) | (c.month << 5) | c.day;
    (time as u16, date as u16)
}

struct Civil {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    milli: i64,
}

fn civil(unix_ms: u64) -> Civil {
    let secs = (unix_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    Civil {
        year: if m <= 2 { y + 1 } else { y },
        month: m,
        day: d,
        hour: tod / 3600,
        minute: (tod % 3600) / 60,
        second: tod % 60,
        milli: (unix_ms % 1000) as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        // 2026-10-19T12:00:00.123Z
        let t = 1_792_411_200_123;
        assert_eq!(iso_ms(t), "2026-10-19T12:00:00.123Z");
        assert_eq!(file_stamp(t), "20261019T120000123Z");
        assert_eq!(iso_ms(0), "1970-01-01T00:00:00.000Z");
        // 2000-02-29 (leap day) 23:59:59.999
        assert_eq!(iso_ms(951_868_799_999), "2000-02-29T23:59:59.999Z");
    }

    #[test]
    fn iso_timestamps_parse_as_the_api_writes_them() {
        let t = 1_792_411_200_123;
        assert_eq!(parse_iso_ms(&iso_ms(t)), Some(t));
        assert_eq!(
            parse_iso_ms("2026-10-19T12:00:00Z"),
            Some(1_792_411_200_000)
        );
        // Python's isoformat: microseconds, an offset.
        assert_eq!(
            parse_iso_ms("2026-10-19T12:00:00.123456+00:00"),
            Some(1_792_411_200_123)
        );
        assert_eq!(
            parse_iso_ms("2026-10-19T14:00:00+02:00"),
            Some(1_792_411_200_000)
        );
        assert_eq!(
            parse_iso_ms("2000-02-29T23:59:59.999Z"),
            Some(951_868_799_999)
        );
        for bad in [
            "",
            "2026-10-19",
            "2026-10-19T12:00:00",
            "2026-13-19T12:00:00Z",
            "2026-10-19T12:00:00.Z",
            "2026-10-19T12:00:00+0200",
            "yyyy-10-19T12:00:00Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_iso_ms(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn dos_dates() {
        let (time, date) = dos_datetime(1_792_411_200_123);
        assert_eq!(date >> 9, 2026 - 1980);
        assert_eq!((date >> 5) & 0xf, 10);
        assert_eq!(date & 0x1f, 19);
        assert_eq!(time >> 11, 12);
        assert_eq!(dos_datetime(0), (0, 0x21));
    }
}

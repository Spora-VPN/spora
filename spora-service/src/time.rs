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
    fn dos_dates() {
        let (time, date) = dos_datetime(1_792_411_200_123);
        assert_eq!(date >> 9, 2026 - 1980);
        assert_eq!((date >> 5) & 0xf, 10);
        assert_eq!(date & 0x1f, 19);
        assert_eq!(time >> 11, 12);
        assert_eq!(dos_datetime(0), (0, 0x21));
    }
}

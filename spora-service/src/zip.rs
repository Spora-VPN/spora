//! A minimal zip writer: deflate (or stored, when deflate does not help),
//! UTF-8 names, no zip64. The bug report is the only zip this crate makes and
//! its budget keeps it far below the 4 GiB / 65535-entry limits that would
//! need more; flate2 is already here for request bodies, so this costs no
//! dependency beyond it.

use std::io::{self, Write};

use flate2::Compression;
use flate2::write::DeflateEncoder;

const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIR: u32 = 0x0605_4b50;
/// 2.0: deflate.
const VERSION: u16 = 20;
/// Bit 11: the name is UTF-8.
const FLAGS: u16 = 0x0800;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;

struct Entry {
    name: String,
    method: u16,
    time: u16,
    date: u16,
    crc: u32,
    compressed: u32,
    size: u32,
    offset: u32,
}

pub(crate) struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    entries: Vec<Entry>,
}

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "too large for a zip without zip64",
    )
}

fn u32_of(n: u64) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| too_large())
}

impl<W: Write> ZipWriter<W> {
    pub(crate) fn new(out: W) -> Self {
        Self {
            out,
            offset: 0,
            entries: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, name: &str, data: &[u8], modified_unix_ms: u64) -> io::Result<()> {
        if self.entries.len() >= u16::MAX as usize || name.len() > u16::MAX as usize {
            return Err(too_large());
        }
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data)?;
        let deflated = enc.finish()?;
        let (method, payload) = if deflated.len() < data.len() {
            (DEFLATED, deflated.as_slice())
        } else {
            (STORED, data)
        };
        let (time, date) = crate::time::dos_datetime(modified_unix_ms);
        let entry = Entry {
            name: name.to_string(),
            method,
            time,
            date,
            crc: crc.sum(),
            compressed: u32_of(payload.len() as u64)?,
            size: u32_of(data.len() as u64)?,
            offset: u32_of(self.offset)?,
        };

        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        h.extend_from_slice(&VERSION.to_le_bytes());
        h.extend_from_slice(&FLAGS.to_le_bytes());
        h.extend_from_slice(&entry.method.to_le_bytes());
        h.extend_from_slice(&entry.time.to_le_bytes());
        h.extend_from_slice(&entry.date.to_le_bytes());
        h.extend_from_slice(&entry.crc.to_le_bytes());
        h.extend_from_slice(&entry.compressed.to_le_bytes());
        h.extend_from_slice(&entry.size.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        self.out.write_all(&h)?;
        self.out.write_all(payload)?;
        self.offset += (h.len() + payload.len()) as u64;
        self.entries.push(entry);
        Ok(())
    }

    /// Write the central directory and hand back the output.
    pub(crate) fn finish(mut self) -> io::Result<W> {
        let start = self.offset;
        let mut cd = Vec::new();
        for e in &self.entries {
            cd.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
            cd.extend_from_slice(&VERSION.to_le_bytes()); // made by (MS-DOS attrs)
            cd.extend_from_slice(&VERSION.to_le_bytes()); // needed
            cd.extend_from_slice(&FLAGS.to_le_bytes());
            cd.extend_from_slice(&e.method.to_le_bytes());
            cd.extend_from_slice(&e.time.to_le_bytes());
            cd.extend_from_slice(&e.date.to_le_bytes());
            cd.extend_from_slice(&e.crc.to_le_bytes());
            cd.extend_from_slice(&e.compressed.to_le_bytes());
            cd.extend_from_slice(&e.size.to_le_bytes());
            cd.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // extra
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            cd.extend_from_slice(&e.offset.to_le_bytes());
            cd.extend_from_slice(e.name.as_bytes());
        }
        let count = self.entries.len() as u16;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&END_OF_CENTRAL_DIR.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes()); // this disk
        end.extend_from_slice(&0u16.to_le_bytes()); // central directory's disk
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&u32_of(cd.len() as u64)?.to_le_bytes());
        end.extend_from_slice(&u32_of(start)?.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes()); // comment
        self.out.write_all(&cd)?;
        self.out.write_all(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// Reads back what [`ZipWriter`] writes — enough for tests to check a
/// bundle's contents byte for byte, CRCs included.
#[cfg(test)]
pub(crate) fn read_all(zip: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
    let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    let u32_at = |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    if zip.len() < 22 {
        return Err(bad("short"));
    }
    let end = zip.len() - 22;
    if u32_at(zip, end) != END_OF_CENTRAL_DIR {
        return Err(bad("no end of central directory"));
    }
    let count = u16_at(zip, end + 10) as usize;
    let mut at = u32_at(zip, end + 16) as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        if u32_at(zip, at) != CENTRAL_HEADER {
            return Err(bad("central header"));
        }
        let method = u16_at(zip, at + 10);
        let crc = u32_at(zip, at + 16);
        let csize = u32_at(zip, at + 20) as usize;
        let size = u32_at(zip, at + 24) as usize;
        let nlen = u16_at(zip, at + 28) as usize;
        let xlen = u16_at(zip, at + 30) as usize;
        let clen = u16_at(zip, at + 32) as usize;
        let local = u32_at(zip, at + 42) as usize;
        let name =
            String::from_utf8(zip[at + 46..at + 46 + nlen].to_vec()).map_err(|_| bad("name"))?;
        at += 46 + nlen + xlen + clen;

        if u32_at(zip, local) != LOCAL_HEADER {
            return Err(bad("local header"));
        }
        let lnlen = u16_at(zip, local + 26) as usize;
        let lxlen = u16_at(zip, local + 28) as usize;
        let data_at = local + 30 + lnlen + lxlen;
        let payload = &zip[data_at..data_at + csize];
        let data = match method {
            STORED => payload.to_vec(),
            DEFLATED => {
                let mut d = Vec::new();
                flate2::read::DeflateDecoder::new(payload).read_to_end(&mut d)?;
                d
            }
            _ => return Err(bad("method")),
        };
        if data.len() != size {
            return Err(bad("size"));
        }
        let mut c = flate2::Crc::new();
        c.update(&data);
        if c.sum() != crc {
            return Err(bad("crc"));
        }
        out.push((name, data));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut z = ZipWriter::new(Vec::new());
        let text = "hello\n".repeat(1000);
        z.add("a/text.txt", text.as_bytes(), 1_792_411_200_000)
            .unwrap();
        // Incompressible: stored.
        let noise: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        z.add("b/noise.bin", &noise, 0).unwrap();
        z.add("empty", b"", 0).unwrap();
        let bytes = z.finish().unwrap();
        let back = read_all(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[0], ("a/text.txt".to_string(), text.into_bytes()));
        assert_eq!(back[1], ("b/noise.bin".to_string(), noise));
        assert_eq!(back[2], ("empty".to_string(), Vec::new()));
        assert!(bytes.len() < 2000 + 4096, "text entry deflated");
    }
}

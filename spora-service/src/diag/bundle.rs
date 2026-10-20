//! The bug-report bundle: a recent window of both streams — connection
//! records and the diagnostic log — plus crash files, zipped into one file
//! the user sends by their platform's own means (share sheet, mail). Nothing
//! here talks to a server or needs a registered device or uploads switched
//! on: the moment a report matters most is when spora.to is unreachable.
//!
//! `manifest.json` lists every file included and every file left out with
//! why, so a reader never has to guess whether something is missing because
//! it never existed or because a cap cut it. A directory that could not be
//! read is listed as left out too (`"path":"log/"`).
//!
//! The zip is readable by its owner only (Unix), like the files it holds.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use super::crash::is_crash_file;
use super::is_log_file;
use crate::fsutil::{
    FileInfo, create_private_file, list_matching, open_listed, sync_dir, try_list_matching,
};
use crate::time;
use crate::zip::ZipWriter;

pub const FORMAT: u32 = 1;

/// What to bundle and where to put it.
#[derive(Debug, Clone)]
pub struct BundleOptions {
    /// The `.zip` to write. Replaced if it exists; its directory is created.
    pub out: PathBuf,
    /// Connection-record directories (`*.jsonl`).
    pub record_dirs: Vec<PathBuf>,
    /// The diagnostic directory (`diag-*.jsonl`, `crash-*.txt`).
    pub log_dir: Option<PathBuf>,
    /// Files last modified longer ago than this are left out.
    pub window: Duration,
    /// Ceiling on the uncompressed bytes of the files included.
    pub budget_bytes: u64,
    /// The user's own words.
    pub note: Option<String>,
    /// Whatever the platform wants support to know (model, OS version, app
    /// version), copied into the manifest.
    pub platform: BTreeMap<String, String>,
    /// The registered device, if any, so support can find its uploads.
    pub device_id: Option<String>,
}

impl BundleOptions {
    pub fn new(out: impl Into<PathBuf>) -> Self {
        Self {
            out: out.into(),
            record_dirs: Vec::new(),
            log_dir: None,
            window: Duration::from_secs(72 * 60 * 60),
            budget_bytes: 24 * 1024 * 1024,
            note: None,
            platform: BTreeMap::new(),
            device_id: None,
        }
    }
}

/// What [`export`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSummary {
    pub path: PathBuf,
    /// Files bundled (the manifest not counted).
    pub included_files: u32,
    /// Files listed in the manifest as left out (an unreadable directory
    /// counts as one).
    pub omitted_files: u32,
    /// Size of the zip.
    pub bytes: u64,
}

#[derive(Serialize)]
struct Manifest<'a> {
    format: u32,
    created_at: String,
    build: spora_core::record::Build,
    platform: &'a BTreeMap<String, String>,
    device_id: Option<&'a str>,
    note: Option<&'a str>,
    window_hours: u64,
    included: Vec<Included>,
    omitted: Vec<Omitted>,
}

#[derive(Serialize)]
struct Included {
    path: String,
    bytes: u64,
}

#[derive(Serialize)]
struct Omitted {
    path: String,
    bytes: u64,
    why: &'static str,
}

/// Why a file was left out.
const OUTSIDE_WINDOW: &str = "outside_window";
const OVER_BUDGET: &str = "over_budget";
const UNREADABLE: &str = "unreadable";

struct Candidate {
    zip_path: String,
    file: FileInfo,
}

/// Write the bundle. Priority under the budget: every crash file, then
/// records newest first, then logs newest first; a file that does not fit is
/// skipped (and listed) and smaller older ones may still go in. Files still
/// being written are cut back to their last whole line. The zip is written
/// to a fresh temporary file beside `out` and renamed into place, so `out`
/// is never half a file.
pub fn export(opts: &BundleOptions) -> io::Result<BundleSummary> {
    // Lines this process queued a moment ago belong in the report.
    super::flush(Duration::from_secs(2));

    let mut names: Vec<String> = Vec::new();
    let mut omitted: Vec<Omitted> = Vec::new();
    let mut classes: Vec<Vec<Candidate>> = Vec::new();
    let log_dir = opts.log_dir.as_deref();
    classes.push(candidates(
        log_dir.into_iter(),
        "crash",
        is_crash_file,
        &mut names,
        &mut omitted,
    ));
    classes.push(candidates(
        opts.record_dirs.iter().map(PathBuf::as_path),
        "records",
        |n| n.ends_with(".jsonl"),
        &mut names,
        &mut omitted,
    ));
    classes.push(candidates(
        log_dir.into_iter(),
        "log",
        is_log_file,
        &mut names,
        &mut omitted,
    ));

    let cutoff = SystemTime::now()
        .checked_sub(opts.window)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut used: u64 = 0;
    let mut chosen: Vec<Candidate> = Vec::new();
    for class in classes {
        for c in class {
            let why = if c.file.modified < cutoff {
                OUTSIDE_WINDOW
            } else if used + c.file.len > opts.budget_bytes {
                OVER_BUDGET
            } else {
                used += c.file.len;
                chosen.push(c);
                continue;
            };
            omitted.push(Omitted {
                path: c.zip_path,
                bytes: c.file.len,
                why,
            });
        }
    }

    if let Some(parent) = opts.out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let (tmp, file) = create_temp(&opts.out)?;
    let result = write_zip(opts, file, chosen, omitted)
        .and_then(|counts| std::fs::rename(&tmp, &opts.out).map(|()| counts));
    let (included, omitted) = match result {
        Ok(counts) => counts,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Some(parent) = opts.out.parent() {
        sync_dir(parent);
    }
    let bytes = std::fs::metadata(&opts.out)?.len();
    log::info!(
        "diag: bug report {} ({included} files, {omitted} left out, {bytes} bytes)",
        opts.out.display()
    );
    Ok(BundleSummary {
        path: opts.out.clone(),
        included_files: included,
        omitted_files: omitted,
        bytes,
    })
}

/// A new file beside `out` for the zip to be written to: a name of its own
/// (a stale one from an earlier run is no obstacle), created fresh — an
/// existing file or symlink there is never opened — and private on Unix.
fn create_temp(out: &Path) -> io::Result<(PathBuf, File)> {
    let mut last = None;
    for attempt in 0..16u32 {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let mut name = out.as_os_str().to_owned();
        name.push(format!(".{}-{nanos}-{attempt}.tmp", std::process::id()));
        let path = PathBuf::from(name);
        match create_private_file(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no free temporary name")))
}

/// A listed file up to its listed length, cut back to its last line end: a
/// file still being written may end in half a line. Only the file listed
/// ([`open_listed`]): whatever has taken its name since is not read.
fn read_whole_lines(file: &FileInfo) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    open_listed(file)?.take(file.len).read_to_end(&mut buf)?;
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    buf.truncate(end);
    Ok(buf)
}

fn write_zip(
    opts: &BundleOptions,
    file: File,
    chosen: Vec<Candidate>,
    mut omitted: Vec<Omitted>,
) -> io::Result<(u32, u32)> {
    let mut zip = ZipWriter::new(io::BufWriter::new(file));
    let mut included: Vec<Included> = Vec::new();
    for c in chosen {
        // Live files keep growing; the plan's size is what the budget
        // allowed, so that is what is read.
        match read_whole_lines(&c.file) {
            Ok(data) => {
                zip.add(
                    &c.zip_path,
                    &data,
                    time::system_time_unix_ms(c.file.modified),
                )?;
                included.push(Included {
                    path: c.zip_path,
                    bytes: data.len() as u64,
                });
            }
            Err(e) => {
                log::debug!(
                    "diag: bug report: cannot read {} ({e})",
                    c.file.path.display()
                );
                omitted.push(Omitted {
                    path: c.zip_path,
                    bytes: c.file.len,
                    why: UNREADABLE,
                });
            }
        }
    }
    let counts = (included.len() as u32, omitted.len() as u32);
    let now = time::unix_ms();
    let manifest = Manifest {
        format: FORMAT,
        created_at: time::iso_ms(now),
        build: spora_core::record::build_info(),
        platform: &opts.platform,
        device_id: opts.device_id.as_deref(),
        note: opts.note.as_deref(),
        window_hours: opts.window.as_secs() / 3600,
        included,
        omitted,
    };
    let json = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
    zip.add("manifest.json", &json, now)?;
    let out = zip.finish()?;
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(counts)
}

/// Matching files of `dirs`, newest first, each with a unique path in the
/// zip under `prefix/`. A directory that cannot be read (in full) goes into
/// `omitted` as `prefix/`, and whatever it does list is still used.
fn candidates<'a>(
    dirs: impl Iterator<Item = &'a Path>,
    prefix: &str,
    keep: impl Fn(&str) -> bool + Copy,
    names: &mut Vec<String>,
    omitted: &mut Vec<Omitted>,
) -> Vec<Candidate> {
    let mut files: Vec<FileInfo> = Vec::new();
    for d in dirs {
        match try_list_matching(d, keep) {
            Ok(f) => files.extend(f),
            Err(e) => {
                log::debug!("diag: bug report: cannot list {} ({e})", d.display());
                let path = format!("{prefix}/");
                if !omitted.iter().any(|o| o.path == path) {
                    omitted.push(Omitted {
                        path,
                        bytes: 0,
                        why: UNREADABLE,
                    });
                }
                files.extend(list_matching(d, keep));
            }
        }
    }
    files.sort_by(|a, b| b.modified.cmp(&a.modified).then(b.name.cmp(&a.name)));
    files
        .into_iter()
        .map(|file| {
            let mut zip_path = format!("{prefix}/{}", file.name);
            let mut n = 2;
            while names.contains(&zip_path) {
                zip_path = format!("{prefix}/{n}-{}", file.name);
                n += 1;
            }
            names.push(zip_path.clone());
            Candidate { zip_path, file }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, bytes: usize, age: Duration) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        // Whole lines only (a torn last one would be cut), `bytes` in all.
        let mut body = vec![b'x'; bytes];
        if let Some(last) = body.last_mut() {
            *last = b'\n';
        }
        std::fs::write(&p, &body).unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - age))
            .unwrap();
        p
    }

    fn manifest(entries: &[(String, Vec<u8>)]) -> serde_json::Value {
        let (_, m) = entries
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .expect("manifest");
        serde_json::from_slice(m).unwrap()
    }

    const H: Duration = Duration::from_secs(3600);

    #[test]
    fn contents_window_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let rec = tmp.path().join("records");
        let log = tmp.path().join("diag");
        write(&rec, "20261019T100000Z-client-aaaaaaaa.jsonl", 500, H);
        write(&rec, "20261001T100000Z-client-bbbbbbbb.jsonl", 500, 300 * H);
        write(&rec, "notes.txt", 10, H);
        write(&log, "diag-20261019T100000000Z-1.jsonl", 700, 2 * H);
        write(&log, "crash-20261019T100000000Z-rust.txt", 300, 3 * H);
        write(&log, "crash-20260101T100000000Z-kotlin.txt", 300, 200 * H);

        let mut opts = BundleOptions::new(tmp.path().join("out/report.zip"));
        opts.record_dirs = vec![rec.clone()];
        opts.log_dir = Some(log.clone());
        opts.note = Some("it broke".into());
        opts.device_id = Some("dev-1".into());
        opts.platform.insert("model".into(), "Pixel".into());
        let s = export(&opts).unwrap();
        assert_eq!(s.path, opts.out);
        assert_eq!(s.included_files, 3);
        assert_eq!(s.omitted_files, 2);
        assert_eq!(s.bytes, std::fs::metadata(&opts.out).unwrap().len());
        let left: Vec<_> = std::fs::read_dir(tmp.path().join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["report.zip"], "no temporary file left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&opts.out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "as private as the files it holds");
        }

        let bytes = std::fs::read(&opts.out).unwrap();
        let entries = crate::zip::read_all(&bytes).unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"records/20261019T100000Z-client-aaaaaaaa.jsonl"));
        assert!(names.contains(&"log/diag-20261019T100000000Z-1.jsonl"));
        assert!(names.contains(&"crash/crash-20261019T100000000Z-rust.txt"));
        assert!(!names.iter().any(|n| n.contains("notes")));
        let (_, data) = entries.iter().find(|(n, _)| n.starts_with("log/")).unwrap();
        assert_eq!(data.len(), 700);

        let m = manifest(&entries);
        assert_eq!(m["format"], 1);
        assert_eq!(m["window_hours"], 72);
        assert_eq!(m["note"], "it broke");
        assert_eq!(m["device_id"], "dev-1");
        assert_eq!(m["platform"]["model"], "Pixel");
        assert!(m["build"]["version"].is_string());
        assert!(m["created_at"].as_str().unwrap().ends_with('Z'));
        let included = m["included"].as_array().unwrap();
        assert_eq!(included.len(), 3);
        assert!(
            included
                .iter()
                .any(|i| i["path"] == "log/diag-20261019T100000000Z-1.jsonl" && i["bytes"] == 700)
        );
        let omitted = m["omitted"].as_array().unwrap();
        assert!(omitted.iter().all(|o| o["why"] == "outside_window"));
        assert!(omitted.iter().any(|o| o["path"]
            == "records/20261001T100000Z-client-bbbbbbbb.jsonl"
            && o["bytes"] == 500));
        assert!(
            omitted
                .iter()
                .any(|o| o["path"] == "crash/crash-20260101T100000000Z-kotlin.txt")
        );
    }

    #[test]
    fn budget_priority() {
        let tmp = tempfile::tempdir().unwrap();
        let rec = tmp.path().join("records");
        let log = tmp.path().join("diag");
        // Oldest to newest within each class.
        write(&log, "crash-1-rust.txt", 100, 5 * H);
        write(&log, "crash-2-rust.txt", 100, 4 * H);
        write(&rec, "r1.jsonl", 400, 5 * H);
        write(&rec, "r2.jsonl", 400, 4 * H);
        write(&rec, "r3.jsonl", 400, 3 * H);
        write(&log, "diag-1-1.jsonl", 100, 2 * H);
        write(&log, "diag-2-1.jsonl", 100, H);

        let mut opts = BundleOptions::new(tmp.path().join("r.zip"));
        opts.record_dirs = vec![rec];
        opts.log_dir = Some(log);
        // Both crashes (200), the two newest records (800), one log (100).
        opts.budget_bytes = 1100;
        let s = export(&opts).unwrap();
        let entries = crate::zip::read_all(&std::fs::read(&s.path).unwrap()).unwrap();
        let m = manifest(&entries);
        let inc: Vec<&str> = m["included"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            inc,
            [
                "crash/crash-2-rust.txt",
                "crash/crash-1-rust.txt",
                "records/r3.jsonl",
                "records/r2.jsonl",
                "log/diag-2-1.jsonl",
            ]
        );
        let om: Vec<(&str, &str)> = m["omitted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["path"].as_str().unwrap(), o["why"].as_str().unwrap()))
            .collect();
        assert_eq!(
            om,
            [
                ("records/r1.jsonl", "over_budget"),
                ("log/diag-1-1.jsonl", "over_budget"),
            ]
        );
        assert_eq!((s.included_files, s.omitted_files), (5, 2));
    }

    #[test]
    fn half_written_lines_stay_out() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("diag");
        std::fs::create_dir_all(&log).unwrap();
        std::fs::write(
            log.join("diag-20261019T100000000Z-1.jsonl"),
            b"{\"a\":1}\n{\"b\":2}\n{\"c\":",
        )
        .unwrap();
        let mut opts = BundleOptions::new(tmp.path().join("r.zip"));
        opts.log_dir = Some(log);
        let s = export(&opts).unwrap();
        let entries = crate::zip::read_all(&std::fs::read(&s.path).unwrap()).unwrap();
        let (_, data) = entries.iter().find(|(n, _)| n.starts_with("log/")).unwrap();
        assert_eq!(data.as_slice(), b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(manifest(&entries)["included"][0]["bytes"], data.len());
    }

    #[test]
    fn a_stale_temporary_file_is_no_obstacle() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("r.zip");
        // Whatever sits at the old fixed temporary name is left alone.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, tmp.path().join("r.zip.tmp")).unwrap();
        let s = export(&BundleOptions::new(&out)).unwrap();
        assert_eq!(s.path, out);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        let (a, _) = create_temp(&out).unwrap();
        let (b, _) = create_temp(&out).unwrap();
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_listed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let rec = tmp.path().join("records");
        write(&rec, "r1.jsonl", 100, H);
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&rec).is_ok() {
            // Root reads it anyway.
            std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let mut opts = BundleOptions::new(tmp.path().join("r.zip"));
        opts.record_dirs = vec![rec.clone()];
        let s = export(&opts);
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o700)).unwrap();
        let s = s.unwrap();
        assert_eq!((s.included_files, s.omitted_files), (0, 1));
        let entries = crate::zip::read_all(&std::fs::read(&s.path).unwrap()).unwrap();
        let m = manifest(&entries);
        assert_eq!(m["omitted"][0]["path"], "records/");
        assert_eq!(m["omitted"][0]["why"], "unreadable");
    }

    /// A file listed for the bundle and swapped for a symlink before it is
    /// read (root bundling a directory its user controls) is left out as
    /// unreadable: the link's target never reaches the zip.
    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_a_symlink_stays_out() {
        let tmp = tempfile::tempdir().unwrap();
        let rec = tmp.path().join("records");
        let secret = tmp.path().join("secret");
        std::fs::write(&secret, b"root only\n").unwrap();
        let swapped = write(&rec, "r1.jsonl", 100, H);
        write(&rec, "r2.jsonl", 100, H);
        let mut opts = BundleOptions::new(tmp.path().join("r.zip"));
        opts.record_dirs = vec![rec.clone()];
        let (mut names, mut omitted) = (Vec::new(), Vec::new());
        let chosen = candidates(
            std::iter::once(rec.as_path()),
            "records",
            |n| n.ends_with(".jsonl"),
            &mut names,
            &mut omitted,
        );
        std::fs::remove_file(&swapped).unwrap();
        std::os::unix::fs::symlink(&secret, &swapped).unwrap();
        let (tmpzip, file) = create_temp(&opts.out).unwrap();
        assert_eq!(write_zip(&opts, file, chosen, omitted).unwrap(), (1, 1));
        let bytes = std::fs::read(&tmpzip).unwrap();
        let entries = crate::zip::read_all(&bytes).unwrap();
        assert!(
            entries
                .iter()
                .all(|(_, d)| !String::from_utf8_lossy(d).contains("root only"))
        );
        let m = manifest(&entries);
        assert_eq!(m["included"][0]["path"], "records/r2.jsonl");
        assert_eq!(m["omitted"][0]["path"], "records/r1.jsonl");
        assert_eq!(m["omitted"][0]["why"], "unreadable");
    }

    #[test]
    fn works_with_nothing_at_all() {
        let tmp = tempfile::tempdir().unwrap();
        let mut opts = BundleOptions::new(tmp.path().join("empty.zip"));
        opts.record_dirs = vec![tmp.path().join("missing")];
        let s = export(&opts).unwrap();
        assert_eq!((s.included_files, s.omitted_files), (0, 0));
        let entries = crate::zip::read_all(&std::fs::read(&s.path).unwrap()).unwrap();
        let m = manifest(&entries);
        assert_eq!(m["device_id"], serde_json::Value::Null);
        assert_eq!(m["note"], serde_json::Value::Null);
        assert_eq!(m["included"].as_array().unwrap().len(), 0);
    }
}

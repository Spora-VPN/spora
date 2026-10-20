//! The uploader's pass: replicate each local file to the server with a byte
//! cursor per file. The upload format is the on-disk format — append-only
//! JSON Lines (and crash text) — so a pass is literally "send the bytes the
//! server does not have yet", resumable after any interruption and
//! idempotent on the server, which holds the authoritative length of every
//! file and answers each chunk with it.
//!
//! Rules (spora-web implements the other side):
//! - Streams in order crash, record, log; files oldest first (by name, which
//!   every stream stamps with its creation time). A file name is never
//!   reused: a cursor (and the server's length) belongs to a name, so a file
//!   recreated under an old name would be taken for the old one.
//! - Only complete lines are sent. A chunk is at most [`MAX_CHUNK`] bytes and
//!   ends at a line end; a single longer line goes alone if it is at most
//!   [`MAX_LINE`]. A crash file goes whole (a crash's header is its first
//!   line, and the server reads it from the chunk that starts the file).
//! - After every answer the cursor becomes the server's length, or the local
//!   size if the server claims more than exists here; it is persisted after
//!   every chunk. A server that is behind rewinds the cursor and the bytes
//!   are sent again from where it stands.
//! - A refusal of the chunk itself (400 with the API's code for what is
//!   wrong, 413) passes over that file; anything else the server answers
//!   (a missing endpoint, a WAF's 403, 429, 5xx) ends the pass, which backs
//!   off. A file that cannot go at its cursor — refused there, a line longer
//!   than [`MAX_LINE`] (the server only takes data contiguous with what it
//!   has, so there is no skipping past it), unreadable — rests for
//!   [`REFUSAL_REST`] unless its cursor moves: a request a day, not one per
//!   pass.
//! - Cursors of files that no longer exist are dropped, after a listing that
//!   worked (a directory that cannot be read says nothing about what is
//!   gone).
//!
//! The pure parts — which files, which bytes next, which cursor after an
//! answer — are separate functions so they can be tested without a server.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::{Api, ApiError, PLATFORMS};
use crate::diag::crash::is_crash_file;
use crate::diag::is_log_file;
use crate::fsutil::{FileInfo, open_listed, try_list_matching};
use crate::state::{Device, Refusal, ServiceState, StateStore};
use crate::{Error, time};

/// Uncompressed bytes per chunk, at most.
pub const MAX_CHUNK: usize = 256 * 1024;
/// The longest single line that can still be sent (alone).
pub const MAX_LINE: usize = 1024 * 1024;
/// How long a file that could not go at its cursor is left alone.
pub const REFUSAL_REST: Duration = Duration::from_secs(24 * 60 * 60);

/// The three upload streams, in pass order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Crash,
    Record,
    Log,
}

impl Stream {
    pub const ORDER: [Stream; 3] = [Stream::Crash, Stream::Record, Stream::Log];

    pub fn as_str(self) -> &'static str {
        match self {
            Stream::Crash => "crash",
            Stream::Record => "record",
            Stream::Log => "log",
        }
    }

    /// The most bytes one chunk of this stream carries. A crash file (far
    /// below [`MAX_LINE`]) goes in one: split, its tail would reach the
    /// server without the header line.
    fn max_chunk(self) -> usize {
        match self {
            Stream::Crash => MAX_LINE,
            Stream::Record | Stream::Log => MAX_CHUNK,
        }
    }
}

/// The server's `file` rule: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
pub(crate) fn valid_file_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The files of one stream, in upload order. A name the server would refuse
/// is left out, and so is a second file of the same name (cursors are kept
/// per name). The error, if any, says which directory could not be listed:
/// the list is then incomplete.
pub(crate) fn stream_files(
    stream: Stream,
    record_dirs: &[PathBuf],
    log_dir: Option<&Path>,
) -> (Vec<FileInfo>, Option<String>) {
    let mut failed = None;
    let mut list = |dir: &Path, keep: &dyn Fn(&str) -> bool| match try_list_matching(dir, keep) {
        Ok(files) => files,
        Err(e) => {
            failed = Some(format!("cannot list {} ({e})", dir.display()));
            Vec::new()
        }
    };
    let mut files: Vec<FileInfo> = match stream {
        Stream::Record => record_dirs
            .iter()
            .flat_map(|d| list(d, &|n| n.ends_with(".jsonl")))
            .collect(),
        Stream::Log => log_dir.map(|d| list(d, &is_log_file)).unwrap_or_default(),
        Stream::Crash => log_dir.map(|d| list(d, &is_crash_file)).unwrap_or_default(),
    };
    files.retain(|f| valid_file_name(&f.name));
    // Stable: of two same-named files, the first directory's wins.
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files.dedup_by(|b, a| a.name == b.name);
    (files, failed)
}

/// What to send next.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Chunk {
    /// These bytes, from the cursor, ending in `\n`.
    Send(Vec<u8>),
    /// Nothing but an unfinished line remains (it goes once it is finished).
    Incomplete,
    /// The next line is longer than [`MAX_LINE`] and can never be sent.
    Oversize,
}

/// The next chunk of a file from `cursor`, at most `max` bytes unless a
/// single line is longer, reading nothing at or past `size`.
pub(crate) fn next_chunk<R: Read + Seek>(
    r: &mut R,
    cursor: u64,
    size: u64,
    max: usize,
) -> io::Result<Chunk> {
    let avail = size.saturating_sub(cursor);
    if avail == 0 {
        return Ok(Chunk::Incomplete);
    }
    r.seek(SeekFrom::Start(cursor))?;
    let first = avail.min(max as u64) as usize;
    let mut buf = vec![0u8; first];
    r.read_exact(&mut buf)?;
    if let Some(end) = buf.iter().rposition(|b| *b == b'\n') {
        buf.truncate(end + 1);
        return Ok(Chunk::Send(buf));
    }
    if first as u64 == avail {
        return Ok(Chunk::Incomplete);
    }
    // One line longer than a chunk: look for its end, up to MAX_LINE.
    let most = avail.min(MAX_LINE.max(max) as u64) as usize;
    buf.resize(most, 0);
    r.read_exact(&mut buf[first..])?;
    match buf[first..].iter().position(|b| *b == b'\n') {
        Some(i) => {
            buf.truncate(first + i + 1);
            Ok(Chunk::Send(buf))
        }
        None if most as u64 == avail => Ok(Chunk::Incomplete),
        None => Ok(Chunk::Oversize),
    }
}

/// The cursor after the server says it holds `server_len` bytes of a file
/// that is `local_size` bytes here. `true` when the server claims more than
/// exists locally (the cursor is clamped to the local size).
pub(crate) fn next_cursor(server_len: u64, local_size: u64) -> (u64, bool) {
    if server_len > local_size {
        (local_size, true)
    } else {
        (server_len, false)
    }
}

/// The server refused this chunk, not uploads: a 400 naming what is wrong
/// with the request (`invalid` — whose body codes are `empty` and
/// `partial_line` —, `misaligned`, `parse_error`), or 413. Any other 4xx
/// — a missing endpoint, a WAF's 403, an intermediary's page without a
/// code — says nothing about the file and fails the pass, so backoff
/// applies.
pub(crate) fn refuses_chunk(e: &ApiError) -> bool {
    match e {
        ApiError::Status { status: 413, .. } => true,
        ApiError::Status {
            status: 400,
            code: Some(c),
            ..
        } => matches!(
            c.as_str(),
            "invalid" | "misaligned" | "parse_error" | "empty" | "partial_line"
        ),
        _ => false,
    }
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassSummary {
    /// The device registered during this pass.
    pub registered: bool,
    /// The force-telemetry flag was fetched (`GET /v1/devices/me`).
    pub status_checked: bool,
    /// Files that had at least one chunk delivered, a file the pass stopped
    /// in (or passed over after a chunk) included.
    pub files: u32,
    pub chunks: u32,
    /// Uncompressed bytes sent.
    pub bytes_sent: u64,
    /// Bytes the server stored (resent duplicates are sent but not stored).
    pub bytes_accepted: u64,
    /// Files passed over because they could not go (see the log). Each then
    /// rests for [`REFUSAL_REST`].
    pub skipped_files: u32,
    /// The pass ended early: uploads were switched off meanwhile (by another
    /// process sharing the state, say), the uploader was told to stop, or
    /// another process forgot the registration the pass was using (its
    /// server no longer knew it). What it sent until then is counted above.
    pub halted: bool,
    /// Of `chunks`, those of the diagnostic log.
    pub(crate) log_chunks: u32,
}

pub(crate) struct Pass<'a> {
    pub(crate) api: &'a Api,
    pub(crate) store: &'a StateStore,
    pub(crate) platform: &'a str,
    pub(crate) record_dirs: &'a [PathBuf],
    pub(crate) log_dir: Option<&'a Path>,
    pub(crate) status_interval: Duration,
    /// Fetch the force flag whatever its schedule (someone waits on it).
    pub(crate) refresh_status: bool,
    /// Asked before every chunk: `true` ends the pass there (the uploader
    /// is stopping, or the platform wants radio silence).
    pub(crate) halt: &'a dyn Fn() -> bool,
}

enum FileError {
    /// This file cannot go from its cursor (`at`) now; the others still can.
    Skip { at: u64, why: String },
    /// Nothing more can go this pass.
    Fatal(Error),
}

impl From<io::Error> for FileError {
    /// The state, not the file: the pass cannot go on.
    fn from(e: io::Error) -> Self {
        FileError::Fatal(e.into())
    }
}

/// A pass so far.
#[derive(Default)]
struct Progress {
    sum: PassSummary,
    /// The latest file passed over (or directory not listed), for
    /// `last_error`.
    skipped: Option<String>,
    /// An upload answer of this pass has stamped the flag as fresh.
    flag_stamped: bool,
}

impl Pass<'_> {
    /// One pass. `explicit` is a caller asking for it now: with uploads off
    /// that is an [`Error::Off`] rather than a quiet no-op; with them on,
    /// the force flag is fetched whatever its schedule (a user waiting on
    /// it), and resting files get another try.
    pub(crate) fn run(&self, explicit: bool) -> Result<PassSummary, Error> {
        let mut p = Progress::default();
        // This API's registration, if there is one, becomes the active one
        // (one with another API is parked, with its cursors, for when that
        // API is used again). A registration with another API is not this
        // configuration's: its token goes nowhere here.
        let (device, st) = self
            .store
            .modify(|s| (s.activate(|d| self.api.serves(d)), s.clone()))?;
        if !st.upload_enabled && device.is_none() {
            return if explicit { Err(Error::Off) } else { Ok(p.sum) };
        }

        // The force flag is checked for a registered device even while
        // uploads are off: it is what may switch them on.
        if let Some(dev) = &device
            && (self.refresh_status
                || status_due(&st, self.status_interval)
                || (explicit && st.upload_enabled))
        {
            p.sum.status_checked = self.check_status(dev)?;
        }
        let st = self.store.get();
        if !st.upload_enabled {
            return if explicit { Err(Error::Off) } else { Ok(p.sum) };
        }

        // Active or, if another process has made its own active meanwhile,
        // parked: what this pass learns goes to it either way.
        let dev = match st.served(|d| self.api.serves(d)) {
            Some(r) => r.device,
            None => self.register(&mut p.sum)?,
        };

        let outcome = self.upload_streams(&dev, explicit, &mut p);
        // Whatever stopped the pass, what was delivered was delivered.
        let now = time::unix_ms();
        // A pass through every file says what it passed over, or that
        // nothing was (an older note goes); a halted one only adds what it
        // met on the way. A failed one leaves the note to its error.
        let noted = outcome.is_ok() && (!p.sum.halted || p.skipped.is_some());
        let skipped = p.skipped.take();
        self.store.modify(|s| {
            if p.sum.chunks > 0 {
                s.last_upload_unix_ms = Some(now);
            }
            if noted {
                s.last_error = skipped;
            }
        })?;
        outcome.map(|()| p.sum)
    }

    /// Register this device with the configured API, unless another process
    /// sharing the state did so meanwhile (its device is then this one's).
    /// A registration with another API is parked, not replaced.
    fn register(&self, sum: &mut PassSummary) -> Result<Device, Error> {
        if !PLATFORMS.contains(&self.platform) {
            return Err(Error::Config(format!(
                "the API registers {} devices, not {:?}",
                PLATFORMS.join(", "),
                self.platform
            )));
        }
        // Proof that a registration can be kept before obtaining one: a
        // state that cannot be saved would mint a device every pass.
        self.store.rewrite()?;
        let minted = self
            .api
            .register(self.platform)
            .map_err(|e| self.api_error("register", None, e))?;
        let (dev, adopted, parked) = self.store.modify(|s| {
            if let Some(d) = s.activate(|d| self.api.serves(d)) {
                // One device per API: the one saved first stays (the other
                // has sent nothing).
                return (d, true, None);
            }
            let parked = s.device.as_ref().map(|d| d.id.clone());
            s.park();
            s.device = Some(minted.clone());
            (minted.clone(), false, parked)
        })?;
        if adopted {
            log::info!(
                "telemetry: another process registered this device as {}; using that",
                dev.id
            );
            return Ok(dev);
        }
        match parked {
            Some(old) => log::info!(
                "telemetry: registered as device {} with {} (device {old}, registered with \
                 another API, is kept for when that API is used again)",
                dev.id,
                self.api.describe()
            ),
            None => log::info!(
                "telemetry: registered as device {} with {}",
                dev.id,
                self.api.describe()
            ),
        }
        sum.registered = true;
        sum.status_checked = self.check_status(&dev)?;
        Ok(dev)
    }

    fn upload_streams(&self, dev: &Device, explicit: bool, p: &mut Progress) -> Result<(), Error> {
        for stream in Stream::ORDER {
            let (files, failed) = stream_files(stream, self.record_dirs, self.log_dir);
            match failed {
                // Nothing pruned: what could not be listed is not gone.
                Some(why) => p.skipped = Some(format!("{}: {why}", stream.as_str())),
                None => {
                    self.store
                        .modify(|s| s.with_device(dev, |s| prune(s, stream, &files)))?;
                }
            }
            for f in &files {
                match self.upload_file(dev, stream, f, explicit, p) {
                    Ok(true) => {}
                    Ok(false) => return Ok(()),
                    Err(FileError::Skip { at, why }) => {
                        log::warn!(
                            "telemetry: {}/{}: {why}; trying again in a day",
                            stream.as_str(),
                            f.name
                        );
                        p.sum.skipped_files += 1;
                        let now = time::unix_ms();
                        self.store.modify(|s| {
                            s.with_device(dev, |s| {
                                s.refused
                                    .entry(stream.as_str().to_string())
                                    .or_default()
                                    .insert(
                                        f.name.clone(),
                                        Refusal {
                                            at,
                                            unix_ms: now,
                                            why: why.clone(),
                                        },
                                    );
                            })
                        })?;
                        p.skipped = Some(format!("{}/{}: {why}", stream.as_str(), f.name));
                    }
                    Err(FileError::Fatal(e)) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Send what the server lacks of one file. `Ok(false)`: stop the pass
    /// (uploads were switched off meanwhile, [`Pass::halt`], or the state no
    /// longer holds `dev`: another process forgot it).
    fn upload_file(
        &self,
        dev: &Device,
        stream: Stream,
        f: &FileInfo,
        explicit: bool,
        p: &mut Progress,
    ) -> Result<bool, FileError> {
        let name = f.name.as_str();
        // This device's, active or not.
        let Some((mut cursor, refusal)) = self.store.get().with_device(dev, |s| {
            let cursor = s.cursor(stream.as_str(), name);
            (cursor, s.refusal(stream.as_str(), name).cloned())
        }) else {
            p.sum.halted = true;
            return Ok(false);
        };
        if !explicit
            && let Some(r) = refusal
            && r.at == cursor
            && !rest_over(&r)
        {
            return Ok(true);
        }
        // The file listed, not whatever has taken its name since.
        let mut file = match open_listed(f) {
            Ok(file) => file,
            // Gone since the listing; its cursor goes next pass.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(e) => {
                return Err(FileError::Skip {
                    at: cursor,
                    why: format!("cannot read ({e})"),
                });
            }
        };
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                return Err(FileError::Skip {
                    at: cursor,
                    why: format!("cannot read ({e})"),
                });
            }
        };
        if cursor > size {
            log::warn!(
                "telemetry: {}/{name}: cursor {cursor} is past the end ({size}); resetting",
                stream.as_str()
            );
            cursor = size;
            self.store
                .modify(|s| s.with_device(dev, |s| set_cursor(s, stream, name, cursor)))?;
        }
        let mut rewinds = 0;
        let mut sent = false;
        while cursor < size {
            if (self.halt)() || !self.store.get().upload_enabled {
                p.sum.halted = true;
                return Ok(false);
            }
            let data = match next_chunk(&mut file, cursor, size, stream.max_chunk()) {
                Ok(Chunk::Send(d)) => d,
                Ok(Chunk::Incomplete) => break,
                Ok(Chunk::Oversize) => {
                    return Err(FileError::Skip {
                        at: cursor,
                        why: format!(
                            "the line at byte {cursor} is longer than {MAX_LINE} bytes; \
                             the file cannot be uploaded past it"
                        ),
                    });
                }
                Err(e) => {
                    return Err(FileError::Skip {
                        at: cursor,
                        why: format!("cannot read ({e})"),
                    });
                }
            };
            let ack = match self.api.upload(dev, stream.as_str(), name, cursor, &data) {
                Ok(a) => a,
                Err(e) if refuses_chunk(&e) => {
                    return Err(FileError::Skip {
                        at: cursor,
                        why: format!("refused at byte {cursor}: {e}"),
                    });
                }
                Err(e) => return Err(FileError::Fatal(self.api_error("upload", Some(dev), e))),
            };
            let sum = &mut p.sum;
            // Counted at its first delivered chunk, however the file ends.
            if !sent {
                sent = true;
                sum.files = sum.files.saturating_add(1);
            }
            sum.chunks = sum.chunks.saturating_add(1);
            if stream == Stream::Log {
                sum.log_chunks = sum.log_chunks.saturating_add(1);
            }
            sum.bytes_sent = sum.bytes_sent.saturating_add(data.len() as u64);
            sum.bytes_accepted = sum.bytes_accepted.saturating_add(ack.accepted);
            let local = file.metadata().map(|m| m.len()).unwrap_or(size);
            let (next, clamped) = next_cursor(ack.length, local);
            if clamped {
                log::warn!(
                    "telemetry: {}/{name}: the server holds {} bytes, this file has {local}; \
                     treating it as sent",
                    stream.as_str(),
                    ack.length
                );
            }
            // One save per chunk: the cursor, and the flag the answer
            // carries (its freshness stamped once a pass).
            let stamp = (ack.telemetry_required.is_some() && !p.flag_stamped).then(time::unix_ms);
            // To this device, wherever it is kept now: another process may
            // have made its own registration the active one meanwhile.
            let folded = self.store.modify(|s| {
                s.with_device(dev, |s| {
                    set_cursor(s, stream, name, next);
                    fold_required(s, ack.telemetry_required, stamp)
                })
            })?;
            let Some((was, is)) = folded else {
                // Forgotten meanwhile: nothing more can be kept for it.
                p.sum.halted = true;
                return Ok(false);
            };
            p.flag_stamped |= stamp.is_some();
            log_required_change(was, is);
            if next <= cursor {
                rewinds += 1;
                if rewinds > 2 {
                    log::warn!(
                        "telemetry: {}/{name}: the server keeps answering {next} for byte \
                         {cursor}; leaving the file for the next pass",
                        stream.as_str()
                    );
                    break;
                }
                log::debug!(
                    "telemetry: {}/{name}: the server holds {next} bytes, resending from there",
                    stream.as_str()
                );
            }
            cursor = next;
        }
        Ok(true)
    }

    /// Fetch the force flag. `Ok(false)`: the server could not be asked
    /// (anything but a 401); the next attempt waits for the next scheduled
    /// check, and uploads, if on, go anyway (their answers carry the flag
    /// too). A 401 is an error: the device is gone.
    fn check_status(&self, dev: &Device) -> Result<bool, Error> {
        match self.fetch_status(dev) {
            Ok(()) => Ok(true),
            Err(e @ Error::Api(ApiError::Unauthorized)) => Err(e),
            Err(Error::Api(e)) => {
                if matches!(e, ApiError::Transport(_)) {
                    log::info!("telemetry: device status: {e}; asking again at the next check");
                } else {
                    log::warn!("telemetry: device status: {e}; asking again at the next check");
                }
                let now = time::unix_ms();
                self.store
                    .modify(|s| s.with_device(dev, |s| s.status_failed_unix_ms = now))?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// `GET /v1/devices/me`, folded into the state; every failure is an
    /// error.
    pub(crate) fn fetch_status(&self, dev: &Device) -> Result<(), Error> {
        let st = self
            .api
            .me(dev)
            .map_err(|e| self.api_error("device status", Some(dev), e))?;
        let now = time::unix_ms();
        let folded = self.store.modify(|s| {
            s.with_device(dev, |s| fold_required(s, st.telemetry_required, Some(now)))
        })?;
        if let Some((was, is)) = folded {
            log_required_change(was, is);
        }
        Ok(())
    }

    /// A 401 means the server no longer knows the device whose token it was
    /// given: forget that device — active or parked by now, and not one
    /// another process has registered since — along with what belonged to
    /// it there, so the next pass registers afresh (and sends what is on
    /// disk again, under the new id).
    fn api_error(&self, what: &str, dev: Option<&Device>, e: ApiError) -> Error {
        if e == ApiError::Unauthorized
            && let Some(dev) = dev
        {
            log::warn!(
                "telemetry: {what}: device {} is not recognised; registering again next time",
                dev.id
            );
            let _ = self.store.modify(|s| s.forget(dev));
        }
        Error::Api(e)
    }
}

/// Set one file's cursor; an acknowledged chunk also ends its rest.
fn set_cursor(s: &mut ServiceState, stream: Stream, name: &str, at: u64) {
    s.cursors
        .entry(stream.as_str().to_string())
        .or_default()
        .insert(name.to_string(), at);
    if let Some(r) = s.refused.get_mut(stream.as_str()) {
        r.remove(name);
        if r.is_empty() {
            s.refused.remove(stream.as_str());
        }
    }
}

/// Drop the cursors and refusals of a stream's files that no longer exist.
fn prune(s: &mut ServiceState, stream: Stream, files: &[FileInfo]) {
    let listed = |name: &String| files.iter().any(|f| &f.name == name);
    if let Some(c) = s.cursors.get_mut(stream.as_str()) {
        c.retain(|name, _| listed(name));
    }
    s.cursors.retain(|_, c| !c.is_empty());
    if let Some(r) = s.refused.get_mut(stream.as_str()) {
        r.retain(|name, _| listed(name));
    }
    s.refused.retain(|_, r| !r.is_empty());
}

/// Fold a server's force-telemetry flag into the state, and with `stamp`
/// note when it was learned. Becoming required switches uploads on and, on
/// the transition, leaves the UI a notice to show; ceasing to be required
/// leaves the switch as it is and takes back a notice not shown yet.
/// Returns the flag before and after.
fn fold_required(s: &mut ServiceState, required: Option<bool>, stamp: Option<u64>) -> (bool, bool) {
    let was = s.required;
    if let Some(now) = stamp {
        s.status_checked_unix_ms = now;
        s.status_failed_unix_ms = 0;
    }
    match required {
        Some(true) => {
            s.required = true;
            s.upload_enabled = true;
            if !was {
                s.required_notice_pending = true;
            }
        }
        Some(false) => {
            s.required = false;
            s.required_notice_pending = false;
        }
        None => {}
    }
    (was, s.required)
}

fn log_required_change(was: bool, is: bool) {
    if was != is {
        log::info!(
            "telemetry: this device's account {} telemetry",
            if is { "requires" } else { "no longer requires" }
        );
    }
}

/// The flag is due for a refresh: never fetched, or the last attempt —
/// successful or not — is `interval` old.
fn status_due(st: &ServiceState, interval: Duration) -> bool {
    let last = st.status_checked_unix_ms.max(st.status_failed_unix_ms);
    let now = time::unix_ms();
    last == 0 || now < last || now - last >= interval.as_millis() as u64
}

fn rest_over(r: &Refusal) -> bool {
    let now = time::unix_ms();
    now < r.unix_ms || now - r.unix_ms >= REFUSAL_REST.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn file_names() {
        assert!(valid_file_name("20261019T120000Z-client-0123abcd.jsonl"));
        assert!(valid_file_name("diag-20261019T120000123Z-4242.jsonl"));
        assert!(valid_file_name("crash-20261019T120000123Z-kotlin.txt"));
        assert!(!valid_file_name(".hidden.jsonl"));
        assert!(!valid_file_name("a b.jsonl"));
        assert!(!valid_file_name("ä.jsonl"));
        assert!(!valid_file_name(""));
        assert!(valid_file_name(&"a".repeat(128)));
        assert!(!valid_file_name(&"a".repeat(129)));
    }

    #[test]
    fn chunks_end_at_line_ends() {
        let data = b"one\ntwo\nthr";
        let size = data.len() as u64;
        let mut r = Cursor::new(&data[..]);
        assert_eq!(
            next_chunk(&mut r, 0, size, MAX_CHUNK).unwrap(),
            Chunk::Send(b"one\ntwo\n".to_vec())
        );
        assert_eq!(
            next_chunk(&mut r, 4, size, MAX_CHUNK).unwrap(),
            Chunk::Send(b"two\n".to_vec())
        );
        // Only the unfinished line is left.
        assert_eq!(
            next_chunk(&mut r, 8, size, MAX_CHUNK).unwrap(),
            Chunk::Incomplete
        );
        assert_eq!(
            next_chunk(&mut r, 11, size, MAX_CHUNK).unwrap(),
            Chunk::Incomplete
        );
        // `size` is a snapshot: bytes past it are not read.
        assert_eq!(
            next_chunk(&mut r, 0, 6, MAX_CHUNK).unwrap(),
            Chunk::Send(b"one\n".to_vec())
        );
    }

    #[test]
    fn chunks_are_bounded() {
        let line = format!("{}\n", "x".repeat(99));
        let data = line.repeat(5000).into_bytes(); // 500 000 bytes
        let size = data.len() as u64;
        let mut r = Cursor::new(&data[..]);
        let Chunk::Send(c) = next_chunk(&mut r, 0, size, MAX_CHUNK).unwrap() else {
            panic!()
        };
        assert!(c.len() <= MAX_CHUNK);
        assert_eq!(c.len(), MAX_CHUNK / 100 * 100);
        assert_eq!(*c.last().unwrap(), b'\n');
        // A crash file's chunk is the file.
        let Chunk::Send(c) = next_chunk(&mut r, 0, size, Stream::Crash.max_chunk()).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), data.len());
    }

    #[test]
    fn long_lines() {
        // A line longer than a chunk goes alone.
        let mut data = vec![b'a'; MAX_CHUNK + 10];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let size = data.len() as u64;
        let Chunk::Send(c) = next_chunk(&mut Cursor::new(&data[..]), 0, size, MAX_CHUNK).unwrap()
        else {
            panic!()
        };
        assert_eq!(c.len(), MAX_CHUNK + 11);

        // Unfinished, still under the line limit: wait for it.
        let data = vec![b'a'; MAX_CHUNK + 10];
        let size = data.len() as u64;
        assert_eq!(
            next_chunk(&mut Cursor::new(&data[..]), 0, size, MAX_CHUNK).unwrap(),
            Chunk::Incomplete
        );

        // Past the line limit: never sendable, whatever the chunk size.
        let mut data = vec![b'a'; MAX_LINE + 1];
        data.push(b'\n');
        let size = data.len() as u64;
        for max in [MAX_CHUNK, MAX_LINE] {
            assert_eq!(
                next_chunk(&mut Cursor::new(&data[..]), 0, size, max).unwrap(),
                Chunk::Oversize
            );
        }
    }

    #[test]
    fn cursor_follows_the_server_but_not_past_the_file() {
        assert_eq!(next_cursor(100, 200), (100, false));
        assert_eq!(next_cursor(200, 200), (200, false));
        assert_eq!(next_cursor(0, 200), (0, false));
        assert_eq!(next_cursor(300, 200), (200, true));
    }

    #[test]
    fn only_chunk_refusals_pass_over_a_file() {
        let s = |status, code: Option<&str>| ApiError::Status {
            status,
            code: code.map(str::to_string),
            retry_after: None,
        };
        for code in ["invalid", "misaligned", "parse_error"] {
            assert!(refuses_chunk(&s(400, Some(code))), "{code}");
        }
        assert!(refuses_chunk(&s(413, Some("too_large"))));
        assert!(refuses_chunk(&s(413, None)));
        // About the endpoint or the whole API, not the file.
        assert!(!refuses_chunk(&s(400, None)));
        assert!(!refuses_chunk(&s(400, Some("bad_request"))));
        for status in [403, 404, 405, 408, 410, 415, 429, 503] {
            assert!(!refuses_chunk(&s(status, Some("x"))), "{status}");
        }
        assert!(!refuses_chunk(&ApiError::Unauthorized));
    }

    #[test]
    fn stream_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let r1 = tmp.path().join("r1");
        let r2 = tmp.path().join("r2");
        let log = tmp.path().join("diag");
        for (d, n) in [
            (&r1, "b.jsonl"),
            (&r1, "a.jsonl"),
            (&r2, "a.jsonl"),
            (&r2, "c.jsonl"),
            (&r2, "bad name.jsonl"),
            (&r2, "x.txt"),
            (&log, "diag-2-1.jsonl"),
            (&log, "diag-1-1.jsonl"),
            (&log, "crash-1-rust.txt"),
            (&log, "other.jsonl"),
        ] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join(n), b"x\n").unwrap();
        }
        let names = |s: Stream| -> Vec<String> {
            let (files, failed) = stream_files(s, &[r1.clone(), r2.clone()], Some(&log));
            assert_eq!(failed, None);
            files.into_iter().map(|f| f.name).collect()
        };
        assert_eq!(names(Stream::Record), ["a.jsonl", "b.jsonl", "c.jsonl"]);
        assert_eq!(names(Stream::Log), ["diag-1-1.jsonl", "diag-2-1.jsonl"]);
        assert_eq!(names(Stream::Crash), ["crash-1-rust.txt"]);
        let (a, _) = stream_files(Stream::Record, &[r1.clone(), r2.clone()], None);
        assert_eq!(a[0].path, r1.join("a.jsonl"));
        // A directory that is not there has no files; that is a complete
        // listing.
        let (none, failed) = stream_files(Stream::Record, &[tmp.path().join("nope")], None);
        assert!(none.is_empty() && failed.is_none());
    }

    #[test]
    fn the_flag_folds_into_the_state() {
        let mut s = ServiceState::default();
        assert_eq!(fold_required(&mut s, None, None), (false, false));
        assert_eq!(s.status_checked_unix_ms, 0);
        s.status_failed_unix_ms = 5;
        assert_eq!(fold_required(&mut s, Some(true), Some(7)), (false, true));
        assert!(s.upload_enabled && s.required_notice_pending);
        assert_eq!((s.status_checked_unix_ms, s.status_failed_unix_ms), (7, 0));
        // Required again: no second notice once the first was shown.
        s.required_notice_pending = false;
        fold_required(&mut s, Some(true), None);
        assert!(!s.required_notice_pending);
        // No longer required before the notice was shown: it is taken back,
        // and the switch stays.
        s.required = false;
        fold_required(&mut s, Some(true), None);
        assert!(s.required_notice_pending);
        assert_eq!(fold_required(&mut s, Some(false), None), (true, false));
        assert!(!s.required_notice_pending && s.upload_enabled);
    }
}

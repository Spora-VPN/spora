//! Spora's service layer: what a client keeps about itself and what it may
//! send home. Lives outside spora-core (which stays the tunnel and nothing
//! else) and is linked by the platform clients — the FFI for Android and
//! Apple, the CLI — so every client keeps the same files and speaks the same
//! protocol.
//!
//! Collection is unconditional and local; telemetry is nothing but an upload
//! switch over data that is already there. Every device keeps:
//!
//! - **connection records** (spora-core's `record`, written by the core when
//!   the platform gives it a record directory);
//! - **the diagnostic log** ([`diag`]): a rolling JSON-Lines file behind the
//!   `log` crate, joined by the platform's own log lines, stamped with the
//!   open record's run id;
//! - **crash files** ([`diag::install_panic_hook`], [`diag::write_crash`]).
//!
//! A user can always hand all three over by hand ([`diag::bundle`], a zip for
//! the share sheet or a mail client — no server involved). With uploads
//! switched on ([`Telemetry`]) they are replicated to the API in the
//! background, resumably, by byte cursor ([`upload`]).
//!
//! The connection log (spora-core's `connlog`) is deliberately no part of
//! this: it is the sharer's local egress record and never uploads.

pub mod api;
pub mod diag;
pub mod state;
pub mod telemetry;
pub mod upload;

mod fsutil;
mod time;
mod zip;

use std::fmt;
use std::io;

pub use api::{ApiError, DEFAULT_API_BASES};
pub use diag::bundle::{BundleOptions, BundleSummary};
pub use telemetry::{
    REQUIRED_NOTICE, ServiceConfig, Telemetry, TelemetryStatus, UploadTimings, finish, nudge,
    record_subscriber, set_dormant,
};
pub use upload::PassSummary;

/// Errors of the telemetry handle.
#[derive(Debug)]
pub enum Error {
    /// The account requires telemetry, so uploads cannot be switched off.
    /// The UI shows [`REQUIRED_NOTICE`].
    Required,
    /// Uploads are switched off (and an upload was asked for explicitly).
    Off,
    /// The configuration cannot work (e.g. an API base that is not a URL).
    Config(String),
    /// The state directory or the files to upload.
    Io(io::Error),
    /// The server, or the way to it.
    Api(ApiError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Required => f.write_str("the account requires telemetry"),
            Error::Off => f.write_str("uploads are switched off"),
            Error::Config(e) => write!(f, "configuration: {e}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Api(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Api(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::Api(e)
    }
}

#[cfg(test)]
mod fake_server;
#[cfg(test)]
mod tests;

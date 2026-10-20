mod device;

/// Log target of every line that names a tunnelled flow's address (source or
/// destination). Spora-local: it is `spora_core::FLOW_LOG_TARGET`, spelled out
/// because this crate cannot depend on spora-core. Spora keeps that target off
/// its diagnostic log file (the connection log is the only per-flow record);
/// stderr/logcat still show the lines at their levels. Lines that name no
/// address keep this crate's own targets.
pub(crate) const FLOW_TARGET: &str = "spora_core::flow";

mod runner;
pub use runner::Runner;

mod packet;
pub use packet::AnyIpPktFrame;

mod filter;
pub use filter::{IpFilter, IpFilters};

pub mod udp;
pub use udp::UdpSocket;

pub mod tcp;
pub use tcp::{TcpListener, TcpStream};

pub mod stack;
pub use stack::{Stack, StackBuilder};

/// Re-export
pub use smoltcp;

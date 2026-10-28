//! A port a relay-less (`Direct`) share can advertise without anyone naming
//! an address: a random free UDP port, and the public address each family
//! reaches the internet from, as STUN services see that very port.
//!
//! What it cannot tell: whether anything (a host firewall, a cloud security
//! group, a home router) lets a client's packets in. A mapped address that
//! is not one of this host's own means a NAT is in the way; the caller warns,
//! since a 1:1 NAT (most cloud servers) or a port forward still works.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::Duration;

use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use stunclient::StunClient;
use tokio::net::UdpSocket;

/// Where a new port is picked from: above most fixed services, below every
/// platform's ephemeral range (Linux 32768+, Windows and macOS 49152+), so no
/// outgoing socket of another program is handed it later.
pub const PORT_RANGE: RangeInclusive<u16> = 10000..=32767;

/// Ports tried before giving up (each must be free on both families).
const PORT_TRIES: usize = 64;

/// What [`find`] learned about one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPort {
    /// The port. Free when found; bound by nobody once `find` returns.
    pub port: u16,
    /// Each family's public address (IPv4 first), where STUN answered.
    pub found: Vec<PublicAddress>,
    /// Why a family found nothing, one line each.
    pub misses: Vec<String>,
}

/// One family's public address for the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicAddress {
    /// The address and port STUN saw the port send from.
    pub mapped: SocketAddr,
    /// `mapped`'s address is one of this host's own: no NAT in the way.
    pub on_host: bool,
}

impl PublicAddress {
    /// A NAT stands between the port and the internet.
    pub fn behind_nat(&self, port: u16) -> bool {
        !self.on_host || self.mapped.port() != port
    }
}

/// Pick a free port in [`PORT_RANGE`] and ask STUN, from that port, for each
/// family's public address. An error when no port was free or no family got
/// an answer (the misses, joined).
pub async fn find(stun_servers: &[String], query_timeout: Duration) -> Result<DirectPort, String> {
    let (port, v4, v6) = pick_port()?;
    let (r4, r6) = tokio::join!(mapped_address(v4, stun_servers, query_timeout), async {
        match v6 {
            Some(s) => mapped_address(s, stun_servers, query_timeout).await,
            None => Err("no IPv6 on this host".to_string()),
        }
    });
    let mut found = Vec::new();
    let mut misses = Vec::new();
    for (family, result) in [("IPv4", r4), ("IPv6", r6)] {
        match result {
            Ok(mapped) => found.push(PublicAddress {
                mapped,
                on_host: on_host(mapped.ip()),
            }),
            Err(e) => misses.push(format!("{family}: {e}")),
        }
    }
    if found.is_empty() {
        return Err(misses.join("; "));
    }
    Ok(DirectPort {
        port,
        found,
        misses,
    })
}

/// A random port free on IPv4 and, where the host has IPv6, on IPv6 too,
/// with a socket bound to it per family.
fn pick_port() -> Result<(u16, UdpSocket, Option<UdpSocket>), String> {
    let mut last = String::new();
    for _ in 0..PORT_TRIES {
        let port = rand::thread_rng().gen_range(PORT_RANGE);
        let v4 = match bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))) {
            Ok(s) => s,
            Err(e) => {
                last = format!("bind UDP {port}: {e}");
                continue;
            }
        };
        let v6 = match bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last = format!("bind UDP [::]:{port}: {e}");
                continue;
            }
            Err(_) => None,
        };
        return Ok((port, v4, v6));
    }
    Err(format!("no free UDP port in {PORT_RANGE:?} ({last})"))
}

/// A UDP socket on `addr`; IPv6 only for a v6 address, so the two families
/// hold the port side by side.
fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// The address STUN services see `socket` send from: each service in turn
/// (its first address of the socket's family), each given `query_timeout`.
async fn mapped_address(
    socket: UdpSocket,
    stun_servers: &[String],
    query_timeout: Duration,
) -> Result<SocketAddr, String> {
    let v6 = socket.local_addr().map_err(|e| e.to_string())?.is_ipv6();
    let mut last = None;
    for server in stun_servers {
        let resolved =
            match tokio::time::timeout(query_timeout, tokio::net::lookup_host(server.as_str()))
                .await
            {
                Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
                Ok(Err(e)) => {
                    last = Some(format!("resolve {server}: {e}"));
                    continue;
                }
                Err(_) => {
                    last = Some(format!("resolve {server}: timed out"));
                    continue;
                }
            };
        let Some(addr) = resolved.into_iter().find(|a| a.is_ipv6() == v6) else {
            last = Some(format!("{server} has no address of this family"));
            continue;
        };
        let mut client = StunClient::new(addr);
        client.set_timeout(query_timeout);
        // No SOFTWARE attribute: a near-unique cleartext fingerprint.
        client.set_software(None);
        match client.query_external_address_async(&socket).await {
            Ok(mapped) => return Ok(mapped),
            Err(e) => last = Some(format!("{server} ({addr}): {e}")),
        }
    }
    Err(last.unwrap_or_else(|| "no STUN services configured".to_string()))
}

/// The address is assigned to this host (binding to it works).
fn on_host(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A STUN responder that answers every binding request with `answer`'s
    /// address, or the requester's own when `None`. Returns its address.
    async fn responder(answer: Option<SocketAddr>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut request = [0u8; 256];
            while let Ok((len, peer)) = socket.recv_from(&mut request).await {
                if len < 20 {
                    continue;
                }
                let seen = answer.unwrap_or(peer);
                let IpAddr::V4(ip) = seen.ip() else {
                    panic!("test responder answers IPv4");
                };
                let mut response = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
                response.extend_from_slice(&request[8..20]);
                response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
                response.extend_from_slice(&(seen.port() ^ 0x2112).to_be_bytes());
                response.extend_from_slice(&(u32::from(ip) ^ 0x2112_a442).to_be_bytes());
                let _ = socket.send_to(&response, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_host_with_its_own_address_needs_no_nat() {
        let stun = responder(None).await;
        let found = find(&[stun.to_string()], Duration::from_secs(2))
            .await
            .unwrap();
        assert!(PORT_RANGE.contains(&found.port));
        assert_eq!(
            found.found,
            vec![PublicAddress {
                mapped: SocketAddr::from((Ipv4Addr::LOCALHOST, found.port)),
                on_host: true,
            }]
        );
        assert!(!found.found[0].behind_nat(found.port));
        // A v4-only STUN list leaves IPv6 without an answer.
        assert_eq!(found.misses.len(), 1, "{:?}", found.misses);
        assert!(found.misses[0].starts_with("IPv6: "), "{:?}", found.misses);
        // Nothing holds the port once the search is over.
        bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, found.port))).unwrap();
    }

    #[tokio::test]
    async fn an_address_not_of_this_host_is_behind_a_nat() {
        let public: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let stun = responder(Some(public)).await;
        let found = find(&[stun.to_string()], Duration::from_secs(2))
            .await
            .unwrap();
        let v4 = found.found[0];
        assert_eq!(v4.mapped, public);
        assert!(!v4.on_host);
        assert!(v4.behind_nat(found.port));
    }

    #[tokio::test]
    async fn no_answer_is_an_error_naming_each_family() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let err = find(
            &[silent.local_addr().unwrap().to_string()],
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(err.contains("IPv4: ") && err.contains("IPv6: "), "{err}");
    }
}

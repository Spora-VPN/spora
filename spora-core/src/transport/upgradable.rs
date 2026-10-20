use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use std::sync::{Arc, Mutex};

use futures_util::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use log::{debug, info};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::IpTransport;
use crate::record::{Fault, Reason};

/// What ended the router's transport, once it has: the error it forwarded
/// (classified where it was born — a QUIC close reason gives its code back
/// through [`Fault::from_io`]) or the transport's end of stream. The first
/// word wins. The sink side reads it: without it, a send after the router
/// stopped could only say "router task gone", and whoever counts the
/// session's end from that send would count a peer's orderly close as a
/// broken pipe.
type EndCause = Arc<Mutex<Option<Fault>>>;

fn note_end(end: &EndCause, cause: impl FnOnce() -> Fault) {
    let mut slot = end.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(cause());
    }
}

/// The transport's stream ended: what the router notes, and what the
/// keepalive layer notes for the same end seen from the stream side.
fn stream_ended() -> Fault {
    Fault::new(Reason::TransportClosed, "the transport ended")
}

/// How long the router waits for an in-flight upgrade after the inner
/// transport dies before propagating the failure
/// (`Timings::upgrade_rescue_grace`, default 2s).
///
/// The initiator swaps to the direct path and drops its relay-via transport
/// the moment its QUIC client handshake completes, but the responder only
/// learns the new path is good when the auth-stream secret arrives — and
/// that secret races the old connection's CONNECTION_CLOSE, both one flight
/// behind the initiator's swap. The old transport's error must not kill the
/// tunnel that the (imminent) upgrade is about to save: the share side
/// tears the whole session down on a transport error — aborting its own
/// responder mid-conclusion, so no `DirectUpgrade*` event ever fires —
/// which closes the fresh direct connection too and forces a full reconnect
/// cycle that then repeats every ~20s.
///
/// The loser's margin is NOT microseconds: on a jittery high-RTT path the
/// secret's flight gets reorder-PTO'd, arriving a full PTO (~ RTT + 4×rttvar,
/// i.e. hundreds of ms) behind the CONNECTION_CLOSE. The lab's
/// `conditions::latency_jitter` (200ms RTT, ±10ms/hop) failed ~10% of runs
/// with a 250ms grace — three consecutive rescue losses — and 0/17 with 2s.
/// A genuinely dead transport just propagates its error this much later,
/// which every consumer (reconnect dialer, session teardown) is indifferent
/// to; the no-upgrade-possible path (channel closed) still propagates
/// immediately.
///
/// Wait for an upgrade after the inner transport died. `None` means no
/// upgrade arrived (channel closed or grace elapsed) — propagate the death
/// as before.
async fn upgrade_within_grace(
    upgrade_rx: &mut mpsc::UnboundedReceiver<UpgradeRequest>,
    grace: Duration,
) -> Option<UpgradeRequest> {
    match tokio::time::timeout(grace, upgrade_rx.recv()).await {
        Ok(Some(new_transport)) => Some(new_transport),
        _ => None,
    }
}

struct UpgradeRequest {
    transport: IpTransport,
    applied: oneshot::Sender<()>,
}

/// Sender used to push an upgraded transport into the router task. A
/// successful send returns an acknowledgement which resolves only after the
/// old path has been dropped and the router has selected the new transport.
#[derive(Clone)]
pub struct UpgradeSender {
    inner: mpsc::UnboundedSender<UpgradeRequest>,
    /// Cancelled when the router task ends (see [`UpgradeSender::ended`]).
    ended: CancellationToken,
}

#[derive(Debug)]
pub struct UpgradeSendError;

impl UpgradeSender {
    pub fn send(&self, transport: IpTransport) -> Result<oneshot::Receiver<()>, UpgradeSendError> {
        let (applied, receiver) = oneshot::channel();
        self.inner
            .send(UpgradeRequest { transport, applied })
            .map_err(|_| UpgradeSendError)?;
        Ok(receiver)
    }

    pub async fn closed(&self) {
        self.inner.closed().await;
    }

    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// A token cancelled when the router task ends — the session's end,
    /// across any upgrades — for a watcher that must not hold this sender:
    /// a live sender keeps an upgrade possible, so a dead transport would
    /// wait out the rescue grace before its death reached anyone.
    pub fn ended(&self) -> CancellationToken {
        self.ended.clone()
    }
}

/// Create an upgradable transport backed by channel indirection.
///
/// `rescue_grace` is how long the router holds the inner transport's death
/// for an in-flight upgrade (`Timings::upgrade_rescue_grace`; see
/// [`upgrade_within_grace`]).
///
/// Returns:
/// - `UpgradableTransport` — implements `Stream + Sink`, hand this to `run_tunnel`
/// - `UpgradeSender` — send a new `IpTransport` here to hot-swap the inner transport
/// - `JoinHandle` — the background router task; abort it when the tunnel ends
pub fn upgradable_transport(
    initial: IpTransport,
    rescue_grace: Duration,
) -> (UpgradableTransport, UpgradeSender, JoinHandle<()>) {
    let (in_tx, in_rx) = mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (upgrade_tx, upgrade_rx) = mpsc::unbounded_channel::<UpgradeRequest>();
    let ended = CancellationToken::new();
    // Fires however the router ends: returning, or aborted.
    let ended_guard = ended.clone().drop_guard();
    let end: EndCause = Arc::default();
    let router_end = end.clone();

    let handle = tokio::spawn(async move {
        let _ended = ended_guard;
        transport_router(initial, rescue_grace, upgrade_rx, in_tx, out_rx, router_end).await
    });

    let transport = UpgradableTransport { in_rx, out_tx, end };

    (
        transport,
        UpgradeSender {
            inner: upgrade_tx,
            ended,
        },
        handle,
    )
}

/// Background task that bridges between the real transport and the channels.
///
/// When an upgrade arrives, the old transport's split halves are dropped and
/// the new transport takes over. The tunnel (reading from `UpgradableTransport`)
/// is unaware of the swap.
async fn transport_router(
    initial: IpTransport,
    rescue_grace: Duration,
    mut upgrade_rx: mpsc::UnboundedReceiver<UpgradeRequest>,
    in_tx: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    end: EndCause,
) {
    let mut current = initial;
    loop {
        match route_one(
            current,
            rescue_grace,
            &mut upgrade_rx,
            &in_tx,
            &mut out_rx,
            &end,
        )
        .await
        {
            RouteResult::Upgraded { transport, applied } => {
                info!("Transport upgraded to direct connection");
                current = transport;
                let _ = applied.send(());
                // continue loop — will re-split the new transport
            }
            RouteResult::Done => return,
        }
    }
}

enum RouteResult {
    /// Got an upgrade — caller should loop with the new transport.
    Upgraded {
        transport: IpTransport,
        applied: oneshot::Sender<()>,
    },
    /// Stream ended or channels closed — router should exit.
    Done,
}

/// Run the select loop for one transport. Consumes it via `split()`.
///
/// Returns `Upgraded(new)` if an upgrade arrived, or `Done` if the
/// tunnel should end (stream closed, channels closed, etc).
async fn route_one(
    transport: IpTransport,
    rescue_grace: Duration,
    upgrade_rx: &mut mpsc::UnboundedReceiver<UpgradeRequest>,
    in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    out_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    end: &EndCause,
) -> RouteResult {
    let (mut sink, mut stream) = transport.split();

    loop {
        tokio::select! {
            upgrade = upgrade_rx.recv() => {
                match upgrade {
                    Some(upgrade) => {
                        return RouteResult::Upgraded {
                            transport: upgrade.transport,
                            applied: upgrade.applied,
                        };
                    }
                    None => {
                        // UpgradeSender dropped — no more upgrades.
                        // Keep draining with current transport.
                        debug!("Upgrade channel closed, continuing with current transport");
                        drain_loop(&mut sink, &mut stream, in_tx, out_rx, end).await;
                        return RouteResult::Done;
                    }
                }
            }
            pkt = stream.next() => {
                match pkt {
                    Some(Ok(data)) => {
                        if in_tx.send(Ok(data)).is_err() {
                            debug!("Tunnel consumer dropped, router exiting");
                            return RouteResult::Done;
                        }
                    }
                    Some(Err(e)) => {
                        // An inner ERROR around an upgrade is the old path
                        // dying right as the new one comes up — the peer
                        // upgraded first and dropped its relay-via transport,
                        // whose CONNECTION_CLOSE lands here as an error.
                        // Forwarding it would kill the tunnel the upgrade is
                        // about to save (see UPGRADE_WAIT_AFTER_INNER_DEATH),
                        // so give the queued OR in-flight upgrade a grace
                        // window and switch instead.
                        if let Some(upgrade) =
                            upgrade_within_grace(upgrade_rx, rescue_grace).await
                        {
                            debug!(
                                "Inner transport errored but an upgrade arrived; \
                                 switching: {e}"
                            );
                            return RouteResult::Upgraded {
                                transport: upgrade.transport,
                                applied: upgrade.applied,
                            };
                        }
                        note_end(end, || Fault::from_io(&e));
                        if in_tx.send(Err(e)).is_err() {
                            debug!("Tunnel consumer dropped, router exiting");
                            return RouteResult::Done;
                        }
                    }
                    None => {
                        // The inner stream ended — same situation as the
                        // error arm: a simultaneous (or one-flight-behind)
                        // upgrade must win over the old path's death.
                        if let Some(upgrade) =
                            upgrade_within_grace(upgrade_rx, rescue_grace).await
                        {
                            debug!("Inner stream ended but an upgrade arrived; switching");
                            return RouteResult::Upgraded {
                                transport: upgrade.transport,
                                applied: upgrade.applied,
                            };
                        }
                        debug!("Inner transport stream ended, router exiting");
                        note_end(end, stream_ended);
                        return RouteResult::Done;
                    }
                }
            }
            pkt = out_rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = sink.send(data).await {
                            // Same race as the stream arms, seen from the
                            // sending side: an outbound packet hitting the
                            // just-closed old transport must not outrun an
                            // upgrade that is about to replace it.
                            if let Some(upgrade) =
                                upgrade_within_grace(upgrade_rx, rescue_grace).await
                            {
                                debug!("Router sink errored but an upgrade arrived; switching: {e}");
                                return RouteResult::Upgraded {
                                    transport: upgrade.transport,
                                    applied: upgrade.applied,
                                };
                            }
                            end_on_send_error(&mut stream, in_tx, end, e);
                            return RouteResult::Done;
                        }
                    }
                    None => {
                        debug!("Tunnel producer dropped, router exiting");
                        return RouteResult::Done;
                    }
                }
            }
        }
    }
}

/// Continue forwarding without checking for upgrades.
async fn drain_loop(
    sink: &mut futures_util::stream::SplitSink<IpTransport, Vec<u8>>,
    stream: &mut futures_util::stream::SplitStream<IpTransport>,
    in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    out_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    end: &EndCause,
) {
    loop {
        tokio::select! {
            pkt = stream.next() => {
                match pkt {
                    Some(result) => {
                        if let Err(e) = &result {
                            note_end(end, || Fault::from_io(e));
                        }
                        if in_tx.send(result).is_err() {
                            return;
                        }
                    }
                    None => {
                        note_end(end, stream_ended);
                        return;
                    }
                }
            }
            pkt = out_rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = sink.send(data).await {
                            end_on_send_error(stream, in_tx, end, e);
                            return;
                        }
                    }
                    None => return,
                }
            }
        }
    }
}

/// The current transport failed a send and no upgrade is coming to replace
/// it: end the tunnel with the best account of why, rather than just
/// stopping — a consumer that sees the stream merely end can only call it
/// "the transport ended". Whatever the transport's stream already has ready
/// goes first: its reader may have queued the end in its own words (a QUIC
/// close reason) a moment before the send hit the same closed connection.
/// Without such an error, the send's own does.
fn end_on_send_error(
    stream: &mut futures_util::stream::SplitStream<IpTransport>,
    in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    end: &EndCause,
    send_err: io::Error,
) {
    info!("Router: send failed, ending the tunnel: {send_err}");
    while let Some(Some(item)) = stream.next().now_or_never() {
        match item {
            Ok(data) => {
                if in_tx.send(Ok(data)).is_err() {
                    return;
                }
            }
            Err(e) => {
                note_end(end, || Fault::from_io(&e));
                let _ = in_tx.send(Err(e));
                return;
            }
        }
    }
    note_end(end, || Fault::from_io(&send_err));
    let _ = in_tx.send(Err(send_err));
}

/// A `Transport` that delegates to a background router task via channels.
///
/// The router can hot-swap the actual inner transport without this type
/// knowing about it.
pub struct UpgradableTransport {
    in_rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    end: EndCause,
}

impl UpgradableTransport {
    /// The router is gone: why, as far as it knew — a broken pipe that still
    /// carries the transport's own end (see [`EndCause`]).
    fn gone(&self) -> io::Error {
        let cause = self
            .end
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| Fault::new(Reason::TransportClosed, "router task gone"));
        io::Error::new(io::ErrorKind::BrokenPipe, cause)
    }
}

impl Stream for UpgradableTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.in_rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for UpgradableTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.out_tx.is_closed() {
            Poll::Ready(Err(self.gone()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.out_tx.send(item).map_err(|_| self.gone())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::mock_transport;
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;

    /// Rescue grace for the tests below: long enough for a deliberately-late
    /// upgrade to land inside it, short enough to keep the tests fast. The
    /// production default lives in `Timings::upgrade_rescue_grace`.
    const GRACE: Duration = Duration::from_millis(250);

    #[tokio::test]
    async fn upgrade_survives_simultaneous_inner_close() {
        // Stage an inner-close and a pending upgrade so the router sees both in
        // the same poll. The select! is unbiased, so without the None-arm
        // try_recv the upgrade is lost ~half the time (router exits on the
        // stream-None branch). Repeat to make the regression reliable; with the
        // fix every iteration must deliver data on the upgraded transport.
        for _ in 0..16 {
            let (local, handle) = mock_transport();
            let (mut transport, upgrade_tx, _router) = upgradable_transport(Box::new(local), GRACE);
            let (local2, handle2) = mock_transport();

            // Both staged before the router can run (current-thread runtime).
            handle.close();
            upgrade_tx.send(Box::new(local2)).unwrap();
            // Let the router process the (stream=None, upgrade-pending) poll.
            tokio::time::sleep(Duration::from_millis(5)).await;

            // The upgrade must have been taken: data flows on the new transport.
            handle2.send(vec![1, 2, 3]).unwrap();
            let got = tokio::time::timeout(Duration::from_millis(200), transport.next()).await;
            assert!(
                matches!(got, Ok(Some(Ok(ref p))) if p == &vec![1, 2, 3]),
                "upgrade was lost to a simultaneous inner close: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn upgrade_survives_simultaneous_inner_error() {
        // The Err twin of the test above: the old transport ERRORS (the peer
        // upgraded first and dropped its relay-via half, whose
        // CONNECTION_CLOSE arrives as a stream error) while an upgrade is
        // already queued. Forwarding the error would tear the share-side
        // session down; the router must take the upgrade and discard it.
        for _ in 0..16 {
            let (local, handle) = mock_transport();
            let (mut transport, upgrade_tx, _router) = upgradable_transport(Box::new(local), GRACE);
            let (local2, handle2) = mock_transport();

            handle.inject_error(io::Error::other("relay-via connection died"));
            upgrade_tx.send(Box::new(local2)).unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;

            // The error must NOT have been forwarded, and data must flow on
            // the upgraded transport.
            handle2.send(vec![4, 5, 6]).unwrap();
            let got = tokio::time::timeout(Duration::from_millis(200), transport.next()).await;
            assert!(
                matches!(got, Ok(Some(Ok(ref p))) if p == &vec![4, 5, 6]),
                "inner error poisoned a pending upgrade: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn late_upgrade_within_grace_is_rescued() {
        // The production race that flaked conditions::latency_jitter: the old
        // transport dies FIRST (the peer swapped and closed it), and the
        // upgrade arrives only later — in-flight, not queued — because its
        // concluding flight was PTO-delayed. The router must sit out the
        // grace and take the late upgrade instead of propagating the death.
        let (local, handle) = mock_transport();
        let (mut transport, upgrade_tx, _router) = upgradable_transport(Box::new(local), GRACE);
        let (local2, handle2) = mock_transport();

        handle.inject_error(io::Error::other("relay-via connection died"));
        // Let the router enter the grace wait before the upgrade exists.
        tokio::time::sleep(Duration::from_millis(50)).await;
        upgrade_tx.send(Box::new(local2)).unwrap();

        handle2.send(vec![7, 8, 9]).unwrap();
        let got = tokio::time::timeout(GRACE, transport.next()).await;
        assert!(
            matches!(got, Ok(Some(Ok(ref p))) if p == &vec![7, 8, 9]),
            "a late (in-flight) upgrade was not rescued: {got:?}"
        );
    }

    #[tokio::test]
    async fn upgradable_passes_through() {
        let (local, mut handle) = mock_transport();
        let (mut transport, _upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local), GRACE);

        // Inbound: handle → transport
        handle.send(vec![1, 2, 3]).unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), transport.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Outbound: transport → handle
        Pin::new(&mut transport).send(vec![4, 5, 6]).await.unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(pkt, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn upgrade_ack_means_subsequent_traffic_uses_the_new_path() {
        let (local, mut old_handle) = mock_transport();
        let (mut transport, upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local), GRACE);
        let (direct, mut direct_handle) = mock_transport();

        let applied = upgrade_tx.send(Box::new(direct)).unwrap();
        tokio::time::timeout(Duration::from_millis(100), applied)
            .await
            .expect("router did not acknowledge upgrade")
            .expect("router dropped upgrade acknowledgement");

        Pin::new(&mut transport).send(vec![9, 8, 7]).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), direct_handle.recv())
                .await
                .expect("new path received no traffic")
                .unwrap(),
            vec![9, 8, 7]
        );
        let old_path = tokio::time::timeout(Duration::from_millis(20), old_handle.recv()).await;
        assert!(
            !matches!(old_path, Ok(Some(_))),
            "old path received traffic after the upgrade acknowledgement: {old_path:?}"
        );
    }

    #[tokio::test]
    async fn upgradable_switches_on_upgrade() {
        let (local1, handle1) = mock_transport();
        let (mut transport, upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local1), GRACE);

        // Initial transport works
        handle1.send(vec![1, 2, 3]).unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), transport.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Upgrade to new transport
        let (local2, mut handle2) = mock_transport();
        upgrade_tx.send(Box::new(local2)).unwrap();

        // Give router time to process the upgrade
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Data on new handle should arrive
        handle2.send(vec![7, 8, 9]).unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), transport.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();
        assert_eq!(pkt, vec![7, 8, 9]);

        // Outbound goes to new handle
        Pin::new(&mut transport).send(vec![10, 11]).await.unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle2.recv())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(pkt, vec![10, 11]);
    }

    #[tokio::test]
    async fn upgradable_ends_on_stream_close() {
        let (local, handle) = mock_transport();
        let (mut transport, _upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local), GRACE);

        // Close the inner transport. The upgrade sender is still alive, so
        // the router holds the close for the rescue grace before giving up —
        // the timeout must cover that grace.
        handle.close();

        // The UpgradableTransport stream should end
        let result = tokio::time::timeout(
            GRACE + std::time::Duration::from_millis(200),
            transport.next(),
        )
        .await
        .expect("timeout");
        assert!(result.is_none(), "expected stream to end after inner close");
    }

    /// A peer's close, as the QUIC carrier's reader and sender both report
    /// it: an io error that carries its classification.
    fn peer_closed() -> io::Error {
        io::Error::from(Fault::new(Reason::PeerClosed, "closed by peer (code 0)"))
    }

    /// The end a consumer sees, classified the way the keepalive layer
    /// classifies it.
    async fn end_seen(transport: &mut UpgradableTransport) -> Option<Reason> {
        match tokio::time::timeout(GRACE * 4, transport.next()).await {
            Ok(Some(Err(e))) => Some(Fault::from_io(&e).reason),
            other => panic!("expected the tunnel to end with an error, got {other:?}"),
        }
    }

    /// A send that hits the closed transport before its reader reports the
    /// close must not end the tunnel wordlessly: the send's own (classified)
    /// error is the end, for the consumer and for later sends alike —
    /// whether or not an upgrade could still have come.
    #[tokio::test]
    async fn a_failed_send_ends_the_tunnel_with_its_cause() {
        for upgrades_possible in [true, false] {
            let (local, handle) = mock_transport();
            let (mut transport, upgrade_tx, router) = upgradable_transport(Box::new(local), GRACE);
            if !upgrades_possible {
                drop(upgrade_tx);
                tokio::time::sleep(Duration::from_millis(5)).await; // into drain mode
            }
            handle.inject_send_error(peer_closed());
            Pin::new(&mut transport).send(vec![1]).await.unwrap();

            assert_eq!(end_seen(&mut transport).await, Some(Reason::PeerClosed));
            // The router is gone; a send says why.
            router.await.unwrap();
            let err = Pin::new(&mut transport).send(vec![2]).await.unwrap_err();
            assert_eq!(Fault::from_io(&err).reason, Reason::PeerClosed);
        }
    }

    /// The reader had already queued the transport's end when a send failed:
    /// that end — in the transport's own words — reaches the consumer first.
    #[tokio::test]
    async fn a_failed_send_forwards_the_end_the_reader_queued() {
        for upgrades_possible in [true, false] {
            let (local, handle) = mock_transport();
            let (mut transport, upgrade_tx, router) = upgradable_transport(Box::new(local), GRACE);
            if !upgrades_possible {
                drop(upgrade_tx);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            handle.inject_error(peer_closed());
            handle.inject_send_error(io::Error::other("send failed"));
            Pin::new(&mut transport).send(vec![1]).await.unwrap();

            assert_eq!(end_seen(&mut transport).await, Some(Reason::PeerClosed));
            router.await.unwrap();
            let err = Pin::new(&mut transport).send(vec![2]).await.unwrap_err();
            assert_eq!(Fault::from_io(&err).reason, Reason::PeerClosed);
        }
    }

    /// A transport whose stream just ended: a later send says so, instead of
    /// a bare broken pipe that would read as a connection reset.
    #[tokio::test]
    async fn a_send_after_the_stream_ended_says_it_ended() {
        let (local, handle) = mock_transport();
        let (mut transport, upgrade_tx, router) = upgradable_transport(Box::new(local), GRACE);
        drop(upgrade_tx);
        tokio::time::sleep(Duration::from_millis(5)).await;
        handle.close();
        let end = tokio::time::timeout(Duration::from_millis(100), transport.next()).await;
        assert!(matches!(end, Ok(None)), "{end:?}");
        router.await.unwrap();
        let err = Pin::new(&mut transport).send(vec![1]).await.unwrap_err();
        assert_eq!(Fault::from_io(&err).reason, Reason::TransportClosed);
    }

    #[tokio::test]
    async fn inner_close_propagates_immediately_when_no_upgrade_can_come() {
        // With the UpgradeSender dropped the router must NOT wait out the
        // grace window — recv() returns None instantly and the close
        // propagates right away (reconnect latency must not grow for
        // sessions that never upgrade).
        let (local, handle) = mock_transport();
        let (mut transport, upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local), GRACE);
        drop(upgrade_tx);
        // Let the router enter drain mode (upgrade channel closed).
        tokio::time::sleep(Duration::from_millis(5)).await;
        handle.close();

        let result = tokio::time::timeout(Duration::from_millis(100), transport.next())
            .await
            .expect("close must propagate without the grace delay");
        assert!(result.is_none());
    }
}

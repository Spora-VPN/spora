# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spora is a peer-to-peer VPN/tunnel written in Rust. It creates encrypted network tunnels between two peers using UDP hole punching for NAT traversal, with a dumb UDP relay as a fallback when direct connection fails. Primary target is Android (via FFI), with CLI support for Linux and Windows.

## Build Commands

```bash
cargo build                    # Build all workspace crates
cargo build --release          # Release build
cargo test                     # Run tests (includes the spora-lab network suites)
cargo clippy                   # Lint
cargo fmt --check              # What CI's `fmt` job runs (workspace members only; vendor/ is excluded)
./build-ffi.sh                 # Cross-compile for Android + generate Kotlin bindings
```

The FFI build requires Android NDK linkers configured in `~/.cargo/config.toml` and Android targets installed via `rustup target add`.

**Formatting is enforced at commit time.** `.githooks/pre-commit` runs rustfmt
over every staged Rust file (the staged content itself, so partially staged
files keep their unstaged hunks; vendor/ skipped like CI) and refuses a file
rustfmt cannot parse. Enable it once per clone with
`git config core.hooksPath .githooks`; `git commit --no-verify` bypasses it.
CI's macOS and Windows jobs compile code this Linux host cannot
(`cargo check -p spora-cli --target x86_64-pc-windows-gnu` covers Windows; for
darwin, run the job's commands on the lab Mac — see the field-lab notes).

Design docs live in `.local/docs/` — local-only (gitignored, since the repo
went public); a fresh clone has none of them.

**Never contact production from development.** The built-in defaults are
production: the relay (`167.71.66.250`) and the telemetry API
(`spora_service::DEFAULT_API_BASES`, `https://truecdn.net`). Any manual or
scripted `spora share`/`use`/`telemetry` run on a dev machine pins
`SPORA_API` (`http://127.0.0.1:9`, which answers nothing, or a local
spora-web such as `http://api.localhost:8000`) AND a scratch
`XDG_STATE_HOME`: a state directory that ever had uploads switched on
uploads from every later run, to production unless `SPORA_API` says
otherwise. A `SPORA_API` that is set but empty or not UTF-8 is refused (it
never means the default). A device registration is bound to the API that issued it:
one made with the built-in API (no `SPORA_API`) sends its token to any
front the running release lists for that API, and never to a `SPORA_API`
override, even one naming the production URL; an override's token goes
only to the exact bases that minted it. Under any other API that machine
registers anew instead.

### e2e network lab

`cargo test -p spora-lab` runs end-to-end suites (smoke, nat_matrix, resilience,
conditions, record, connlog, ipv6, …) in Linux network namespaces with real kernel NAT (iptables) and tc
netem — no root needed (unprivileged userns; suites self-skip if unavailable;
`SPORA_LAB=skip` opts out). Architecture, NAT recipes, and the product findings
the suites encode live in `.local/docs/lab.md`. Suites are `harness = false` binaries;
filter scenarios with e.g. `cargo test -p spora-lab --test nat_matrix -- cone`.
Protocol timings are configurable via `Config.timings` (`Timings`, prod
defaults); lifecycle events via `Config.event_hook` (`TunnelEvent`); the
machine-readable account of a whole run via `Config.record` (see "Connection
record"); the direct upgrade can be disabled via `Config.enable_direct_upgrade`
— these exist for the lab but are usable by the apps (e.g. path-state
display).
`TunnelEvent::PathActivated` is the exact path-state assertion: it names the
record-vocabulary `Carrier` and `PathKind` for the initial usable transport and
again after an acknowledged direct swap. The CLI renders it as
`path_activated`; UniFFI exposes the corresponding `SporaEvent`.

**Reading suite results reliably.** ERROR log lines interleave between a
scenario's name and its verdict, so `scenario X ... FAILED` is often NOT one
line — never line-grep for that shape. The reliable signals are the per-suite
summary line (`<suite>: ok. N passed` / `<suite>: FAILED. N passed; M failed`)
and the process exit code. Piping `cargo test` through `tail`/`grep` replaces
`$?` with the filter's status (use `pipefail`/`PIPESTATUS`, or write the full
log to a file and inspect that), and a `tail -N` window silently hides
early-suite failures under `--no-fail-fast` — check the whole log. Timing
scenarios (e.g. `conditions::latency_jitter`) are load-sensitive and can flake
at low single-digit percentages: to confirm or chase one, loop the single suite
filtered (`cargo test -p spora-lab --test conditions -- latency`) 20-30×
serially on a quiet machine rather than re-running the full suite a few times.

## Workspace Structure

Workspace members (resolver v3):

- **spora-core** — Core library. Exposes `share()` (sharer mode) and `connect(url)` (client mode). Contains all networking logic.
- **spora-vpn** — Client-side host integration for a tunnel (TUN, routes, resolver, MTU policy, outer-socket bypass, undo-on-exit) on Linux, macOS and Windows: the code behind `spora use`, linked as a library by spora-cli AND by spora-wincore (sibling `../spora-win` repo) so both clients share one implementation.
- **spora-cli** — CLI binary with `spora share` and `spora use <URL>` subcommands, building on Linux, macOS and Windows. A new `spora share` without relay flags is relay-less (its public address from STUN, a random port; see "Identity, shares, persistence"). `spora use` is a full VPN client (see "Client VPN mode"); `spora share --os-routing` enables the privileged netstack bypass (see "Share-side exit modes", Linux only). `--relay <host:port>` (share) and `--stun <host:port>` (share/use) override the built-in endpoints. `spora report` bundles records, the diagnostic log and crash files for a bug report; `spora telemetry status|on|off|upload` is the upload switch (see "Diagnostic log and telemetry").
- **spora-ffi** — Uniffi-based FFI for Android/JNI. Wraps core functions for Kotlin. Builds as `cdylib`.
- **spora-service** — The service layer the platform clients link (spora-cli, spora-ffi), kept out of core: the device identity and relay access (`access`: relay advice + relay token from the API, renewed in the background, pushed to running shares; `seal`: wrap-at-rest of the state's secrets), the diagnostic log (`diag`: a JSON-Lines file sink behind `log`, crash files, bug-report zips) and the telemetry upload switch with its uploader thread, which replicates records, log and crash files to spora-web's API by byte cursor (blocking ureq, rustls/ring). See "Diagnostic log and telemetry".
- **spora-wincore**, **spora-winui** — Windows service + UI.
- **relay** — Dumb UDP relay (both `lib.rs` for use in tests and `main.rs` for the open binary). Forwards packets between peers by inspecting QUIC long-header DCIDs and tracking a small flow table. Speaks no QUIC, holds no TLS keys. Who may register is an `authz::Authorizer`: built in are `Open` and `StaticToken` (`--token-file`); `server::run` is the whole binary minus its flags, so a closed binary (the commercial relay, private repo `../spora-managed-relay`) links this crate and supplies its own authorizer. Tokens are opaque bytes here, end to end.
- **relay-client** — Tiny client of the relay protocol: the wire-protocol constants (`protocol` module), the TCP preambles (`tcp`), a share's credentials (`credential`: `Credential` per relay endpoint, `Credentials` = the share's mutable relay token) and the sharer's `register_loop` helper.
- **spora-lab** — Network-namespace e2e test lab (test-only; see `.local/docs/lab.md`): runs the real sharer/client/relay across netns topologies with iptables NAT flavors and netem conditions, in-process (one pinned thread + current-thread tokio runtime per simulated host).

## Architecture

### High-level flow (Design 2 — dumb relay + end-to-end QUIC)

```
A (sharer) <----- end-to-end QUIC (cert pinned, secret-auth) -----> B (client)
                                  |
                                  v
                              Relay (dumb UDP forwarder)
                              - routes by inspecting QUIC DCID
                              - flow table: (B_addr -> A_addr)
                              - no QUIC, no TLS, no plaintext access
```

There is exactly one QUIC connection — between A and B — even when traffic flows through the relay. The relay is a stateless-ish UDP forwarder: it looks at QUIC long-header packets and routes them by Destination Connection ID; everything after the first match is forwarded by source-address 5-tuple. PMTUD runs end-to-end on the single connection, not per-leg.

### Identity, shares, persistence

Four things with four lifetimes (`spora_core::identity`; the design is `../spora-kb/relay-management-decisions.md`):

- `DeviceIdentity` — the device's ONE P-256 key pair + self-signed cert (valid to 4096). Its **cert hash** = `SHA-256(cert DER)[..20]` identifies the device to relays, the API and clients (who pin the cert by it).
- `Share` — one shared connection, immutable once made: cert hash, **share id** (8 random public bytes), **secret** (16 random bytes, what URL holders present) and its relays as `RelayEntry { endpoint, credential }` (`Credential::None | Static(bytes) | Spora`). The platform stores it as an opaque versioned blob (`Share::to_blob` / `from_blob`, magic `sSHR` v1; unknown versions are errors). The URL is a pure function of it (`Share::url`), so other relays = a new share = a new URL.
- `ShareIdentity` — what a running share serves with (device key/cert + share id, secret, routing hash). `ShareIdentity::new` refuses a share made under another device (`IDENTITY_MISMATCH`).
- **routing hash** = `SHA-256(cert hash || share id)[..20]`: the on-wire form of the routing key (cert hash, share id) — QUIC DCID, nz header prefix, TCP CONNECT key, relay registration key. Not the share id alone: that could be registered by anyone with any key.

`spora_core::share(device, share, config)` takes both by value. Where they live:

- The device identity: spora-service's `service.json` (`device_identity`, minted at the first open; the key sealed when the platform gives a state key — see "Relay access"). It never crosses the FFI. A state without one is read as a fresh device: registrations made before it are forgotten (the API keeps each device's cert hash, set once).
- Share blobs: the platform's store. CLI: `$XDG_CONFIG_HOME/spora/share.bin` (0600, atomic); `--share-file` (alias `--identity-file`, which the field lab still passes) selects another; `--fresh` makes a new share; relay flags differing from the stored share's make a new share (new URL) with a notice; without relay flags a new share is relay-less: `spora_core::direct_port::find` picks a random free UDP port in 10000..=32767 (below every platform's ephemeral range), asks STUN from it per family, and the share gets one `Direct` endpoint per family that answered (the mapped address, the picked port), except a family whose NAT moved the port while another family kept it (nothing forwards a port just picked, and the client's v6-first dial would wait out its timeout there; `relayless_endpoints`); a mapped address not on this host, or a moved port, = a NAT notice (still made: 1:1 cloud NAT and port forwards work); no answer at all = an error naming `--direct`/`--relay`/`--spora-relays`. A stored share served without relay flags gets one check per start, beside the running share (`check_direct_addresses`: `direct_port::public_ip` per family its `Direct` IP literals name, from a fresh socket since the share holds its port): a family now leaving from an address the URL does not name = a notice suggesting `--fresh`; a STUN failure says nothing (info log only); hostnames and runs with `--direct` are not checked. `--spora-relays` puts it on Spora's relays (the API's advice, fetched if none is cached; unreachable API = an error), ahead of the other relay flags' relays; a stored share fits whatever advice it was made with (its leading `Spora` entries), so a new advice never changes its URL. Notices go to stderr under `--json` (`notice!`): stdout carries events only. A share whose device is not this one is remade (CLI) / refused with `IdentityMismatch` (FFI).
- FFI (service-aware, spec S4): `init_service(config)` (returns `InitResult { minted_state_key }`), `refresh_relays()`, `relay_access_status()`, `make_share(own: [RelayEntry], use_spora) -> blob` (offline; `NoRelayAdvice` before any fetch), pure `share_url`/`share_id`/`share_relays(blob)`, `start_share(blob, protector, connlog…, record_dir, stun_servers) -> ShareResult` (no network of its own; the cached relay token; `AlreadyRunning`, `IdentityMismatch`), `stop_share(handle)`. `RelayEntry.endpoint` is the `?r=` form.

### Sharer (A) flow — `spora_core::share(identity, config)` (rolling listener / per-port sessions)

1. Receive the `DeviceIdentity` and the `Share` from the platform layer (already persisted).
2. Bind the generation-0 LISTENER socket (ephemeral port); `try_clone()` it so quinn owns one fd and the registrar uses the other. Spawn its registrar — every 30s a signed `REGISTER_V2` to each UDP relay, each with its endpoint's credential; the relay updates `routing_hash -> A_addr`. One `RegisterSigner` per share (strictly-increasing timestamps) is shared across ALL generations, the nz carrier and the TCP park pool.
3. Per accepted+authenticated session, `run_share_loop` ROLLS: the session keeps the socket/endpoint it arrived on (its own port, its own relay flow, its own quinn endpoint), and a fresh listener socket + registrar generation takes over the routing key (old listener: registrar aborted, `set_server_config(None)`). The relay's binding therefore always points at a flow-free port — no "actively-serving" lockout for dead predecessors, no same-DCID Initial swallow — and a REGISTER from the new port displaces the old binding (no relay changes needed). Demoted endpoints are tracked and closed once no session can use them.
4. `Direct` endpoints get a separate PERMANENT endpoint on the advertised port (never rolls, never registers); direct-dialing clients use random initial DCIDs (the routing-hash DCID exists only for relay routing). The nz carrier rolls its dedicated socket the same way (dispatcher demotes, keeps serving its session, exits when its tables empty); it registers with `REGISTER_NZ_V2`, so a relay serving QUIC and nz on one port keeps the two sockets' registrations apart.
4a. Relay token renewal: `Config.relay_token` is the device's token for `Credential::Spora` endpoints (`None` = degraded start, tokenless registrations). `ShareSession::update_relay_token` (or a clone of `ShareSession.credentials`) replaces it with one write; every registrar of the current generation sends a REGISTER at once and refused TCP park workers (which back off 0.5 s → 60 s) retry at once. Sessions, sockets and the connlog are untouched (`spora-core/tests/relay_token.rs`).
5. Per session: wrap `transport` in `UpgradableTransport → KeepAliveTransport`; spawn `try_direct_upgrade` (responder role, with the identity); spawn the netstack tunnel. New peer kicks previous (two LIVE clients on one URL will alternate at `reconnect_delay` cadence — the fixed delay is the anti-storm pacing; real multi-client is future work, structurally easy now that each session owns an endpoint).

NAT caveat: a listener's NAT mapping is kept alive only by outbound REGISTERs (relay never replies); on NATs with unreplied-UDP timeout <= register interval the mapping can lapse between REGISTERs. Planned fix: relay REGISTER-ACK (see `QuicListenerCtx` doc).

### Client (B) flow — `spora_core::connect(url)`

1. Parse URL to `Token { cert_hash, share_id, secret, relays }`; `token.routing_hash()` derives the routing hash.
2. Resolve the relay address; bind a UDP socket.
3. Build quinn client config that pins the server cert to the URL's cert hash (`CertHashVerifier`; TLS and the nz cert-auth pin the same) and sets `initial_dst_cid_provider` so B's first Initial carries `DCID = routing_hash`.
4. `client_connect` to the relay address — relay routes by DCID to A — QUIC handshake completes end-to-end. B opens a bidi stream and writes the secret; A verifies and accepts.
5. Wrap the resulting `QuicPeerTransport` in `UpgradableTransport → KeepAliveTransport → ReconnectTransport`; spawn `try_direct_upgrade` (initiator role).
6. Stopping: cancelling `ConnectResult.cancel` closes the live session's QUIC connection at once (code 0, "client stopped") and closes the record. `ConnectResult.stopper.stop().await` (`RunStopper`) does the same and waits until that close has been handed to the socket, at most `STOP_FLUSH_GRACE` (500 ms; normally about 1 ms). A process about to exit (the CLI) awaits it, best while it still holds the transport: dropped with its runtime first, the close never goes, and the exit records a session that died (its keepalive gives up ~30 s later) instead of a client that left.

### Direct upgrade (`try_direct_upgrade` in `lib.rs`)

After the relay-via session is up, both sides try to establish a direct path:

- Signaling rides on the bidi QUIC stream that was opened during the auth step (the `SignalChannel` in `signal.rs`, length-framed messages).
- STUN to discover external addresses; exchange endpoints via the signal channel; punch + bidirectional verify.
- Build a fresh `e2e::client_endpoint` / `e2e::server_endpoint` over the new direct socket, pinned to the same cert hash. New QUIC handshake completes end-to-end on the direct path.
- `UpgradeSender` swaps the inner transport from the relay-via QUIC to the direct QUIC. The old relay-via connection drains and times out.
- A failed attempt is retried by the initiator after `Timings.upgrade_retry_delay` (15 s), doubling after each consecutive failure up to `Timings.upgrade_retry_max` (5 min). The streak is per session (`try_direct_upgrade` runs per session, so the reconnect after a network change starts at 15 s again) and starts over on a wake from dormancy (keepalive knob 0 → >0), wherever the wake is seen: before an attempt, at the end of one that began dormant, or during the wait (`UpgradePacing`). Dormant attempts are still limited to 3 before the task parks until a wake. The wait (`wait_before_retry`) ends with its session or the run. Every attempt keeps its record steps.

(Note: quinn 0.11 does NOT expose client-initiated QUIC connection migration. The upgrade is a tear-down + rebuild of QUIC over a new socket, not in-place migration. Inner TCP retransmits cover the brief handshake stall.)

### Share-side exit modes (`Config::exit_mode`)

How the share side turns tunneled IP packets into real traffic:

- **`ExitMode::Netstack`** (default, unprivileged) — userland smoltcp netstack (`server::start_tunnel`): TCP/UDP flows are terminated in-process and re-originated from OS sockets. Used by FFI/Android and the CLI without flags. Inner traffic to local/private destinations is dropped (`block_local`); a blocked UDP or TCP destination is logged at WARN once per session (then trace; at most 256 destinations per protocol at WARN), on the flow target like every per-flow line, because a Windows client's NetBIOS broadcasts or SMB retries would otherwise flood the log.
- **`ExitMode::Custom(SessionHandler)`** — netstack bypass. The handler is called once per accepted session with the composed `IpTransport` and a `CancellationToken` (cancelled when a new peer replaces the session or the share stops). The core still owns accept/registration/direct-upgrade.

The CLI implements OS routing on top of `Custom` (`spora share --os-routing`, plus `--tun-addr`, `--tun-mtu`, `--no-nat`; see `spora-cli/src/os_route.rs`). Requires root/CAP_NET_ADMIN, Linux only. It creates a TUN device and pumps packets transport↔TUN; the kernel forwards/NATs. Key invariants:

- **Keepalive pings must be answered locally.** The client's keepalive layer pings a synthetic private address (10.0.0.2) and declares the tunnel dead without a response; smoltcp answers those in netstack mode, so the pump answers ICMP echo requests to blocked private destinations itself.
- **Client source addresses are learned, not assumed — but must be private.** Each platform picks its own client TUN address (e.g. wincore uses 10.0.85.1), so the pump learns inner source IPs from forwarded packets and installs a `/32` (v6: `/128`) route + scoped MASQUERADE rule per peer (cap 64, shared across families). The source is client-controlled, so it is **restricted to RFC1918/CGNAT** (`is_private_client_source`) for v4 and **ULA fc00::/7 only** (`is_ula_client_source`) for v6; a public source would otherwise install a route that hijacks the sharer's own egress to that address. A learned source that collides with a directly-connected host route (the sharer's own LAN) is also refused (route-table check, per family).
- Destinations matching `is_local_address` are dropped (parity with the netstack's `block_local`) — except UDP/TCP port 53 to the DNS forwarder's synthetic address once its DNAT is in place (see "DNS forwarding"); ICMPv6 echoes to blocked v6 destinations are answered locally like the v4 ones (mandatory pseudo-header checksum). IPv6 is carried in **both** directions; the host→client pump filters frames whose v6 src/dst is link-local or multicast (the kernel's RS/NS/MLD/DAD chatter must not leak to the peer). The TUN gets a ULA from `--tun-addr6` (default `fd00:5350::1/64`).
- NAT setup at startup applies v4+v6 forwarding sysctls, FORWARD accepts, and TCP MSS clamp to the TUN MTU (v6 clamp = MTU−60) via iptables AND ip6tables; the per-peer scoped MASQUERADE is added lazily in `learn_peer` when each client source is first seen. All of it is undone on exit; `--no-nat` skips it. Cleanup runs from `OsRoute`'s `Drop`, so it fires on Ctrl+C (SIGINT), SIGTERM, SIGHUP (the terminal closed, the SSH session dropped), error returns, and panics.

### DNS forwarding (`spora-core/src/dns.rs`)

Clients resolve through the sharer's own resolvers without ever learning what they are. It is a convention, not a negotiation: the client sets `100.64.0.53` (`dns::PROXY_ADDR`, port 53) as its resolver; the exit intercepts UDP/TCP flows to that address AHEAD of the `block_local` check and forwards each query byte-for-byte to an *upstream* of its own choosing, answering from the synthetic address. `Config.dns_forwarder: Option<Arc<DnsForwarder>>`, default `DnsForwarder::system()` (default-on in core: nothing touches disk); `None` = off, the address is then just another dropped private destination. Key facts:

- **Why a synthetic address and a rewrite**: the sharer's resolvers are almost always private (the router, a carrier resolver on 10.x/ULA, resolved's loopback stub) — exactly what `is_local_address` blocks. A sharer-chosen upstream keeps that policy intact, leaks no LAN address, and lets the upstreams change mid-session. CGNAT space rather than the keepalive's `10.0.0.2`: a desktop client's LAN routes stay ahead of the tunnel routes (wg-quick model), so a `10.0.0.0/24` home LAN would swallow queries to a 10.x resolver, whereas the keepalive ping bypasses OS routing entirely. No DNS parsing anywhere: EDNS, DNSSEC, all record types and TTLs survive.
- **Upstreams**: `DnsUpstream::System` (resolv.conf on Unix, re-read every 30s; `GetAdaptersAddresses` on Windows; nothing on Android — the app passes `LinkProperties.getDnsServers()` through `set_share_dns_servers`, re-passed on `onLinkPropertiesChanged`) or `DnsUpstream::Servers` (CLI `--dns-upstream`, exclusive: no fallback). Health per upstream: a refusal/send error quarantines at once, 3 unanswered attempts (2s each) quarantine for 30s, an answer heals; `pick(tried)` = first live configured → first live fallback → oldest-dead as a probe. `PUBLIC_FALLBACK` (8.8.8.8, 1.1.1.1) answers when nothing else does, so the client always has a working resolver and the worst case is today's behaviour.
- **Per query, not per NAT entry**: each UDP query is its own task + connected socket with up to 3 attempts across upstreams; `MAX_INFLIGHT` (256) per session is the rate cap. TCP/53 is the same rewrite on the stream (`dial_dns_upstream`, early client bytes carried across attempts). The socket wait is on `Interest::READABLE | ERROR`: tokio's readable interest never wakes for the `ECONNREFUSED` an ICMP unreachable leaves on a connected UDP socket, which would turn every refusal into a full attempt timeout.
- **Exits**: the netstack (`server.rs`) rewrites inline; `--os-routing` binds `dns::serve_udp`/`serve_tcp` on the TUN address and DNATs the synthetic address to them (`OsRoute::start_dns_forwarder`; unavailable under `--no-nat`, and `classify_with` forwards port-53 packets for the synthetic address only once the DNAT exists). Connlog: the netstack logs one flow per query with the upstream as destination and the egress source; the OS-routing meter sees only the synthetic address (the real upstream is not per-session knowledge there).
- **Known defect — encrypted system DNS**: Android Private DNS (strict), Apple encrypted-DNS profiles, Windows per-adapter DoH: the OS resolves over TLS/HTTPS while the forwarder sends plain UDP to the same servers. Queries resolve, but the user's transport choice is bypassed; a server that only speaks encrypted DNS gets quarantined and the fallback takes over. The fix is the OS raw-query APIs (`DnsResolver.rawQuery`, `DnsQueryRaw`, `DNSServiceQueryRecord`). systemd-resolved with `DNSOverTLS=` is fine — the forwarder talks to the stub.
- Client side: `spora use` defaults `--dns` to the synthetic address (`vpn::DEFAULT_DNS`, asserted equal to `dns::PROXY_ADDR`), excludes it from the private-resolver warning, and routes it as a host route in split-tunnel mode; the FFI exposes `dns_forwarder_address()` for the Android client's `addDnsServer`.
- e2e coverage: `cargo test -p spora-lab --test dns` (UDP, TCP, refused/silent failover, forwarder off); unit tests in `dns.rs` (health, resolv.conf, serve_*), `server.rs` (rewrite past `block_local`) and `os_route.rs` (`classify_with`).

### Client VPN mode (`spora use`, crate `spora-vpn`)

Without `--tun-name`, `spora use` is a turnkey VPN client on Linux, macOS and
Windows (privileged: root / Administrator). The bring-up is two-phase, exactly
like the Android client: TUN with address+MTU but NO routes → `connect()` (the
relay dial and STUN use the normal network) → routes + DNS. One managed
instance at a time: a session-long `flock` (`/run/spora/use.lock`,
`/var/db/spora/use.lock`; Windows: the exclusive adapter name) gates the
startup sweep — flock dies with the process, so leftovers become sweepable
exactly when sweeping is safe. Key invariants:

- **The host's default route is never modified.** Linux: routes live in table
  0x5350 behind two policy rules (`pref 21327` = main-table-minus-default,
  `pref 21328` = `not fwmark 0x5350` → table; the wg-quick model). macOS and
  Windows: half-default routes (`0/1`+`128/1`, `::/1`+`8000::/1`) that win by
  prefix length. Stale rules/DNS from a crashed run are swept at next start.
- **Every outer socket the core opens goes through `Config.protector`** and is
  kept off the tunnel *by mechanism, not by destination* (the punched peer is
  not known when routes are installed): `SO_MARK 0x5350` on Linux,
  `IP_BOUND_IF` (macOS) / `IP_UNICAST_IF` (Windows) to the uplink interface,
  which is re-detected on every `Reconnecting` event. `SocketProtector` takes
  a `SocketHandle` (fd on Unix, `SOCKET` on Windows) for this. On macOS the
  bind alone is NOT enough under the half-default routes: a bound socket gets
  a *scoped* route lookup, `0.0.0.0/1` on the utun becomes the best match for
  every public address (XNU's default-route fallback even resolves `0.0.0.0`
  to it), and every send fails with `ENETUNREACH` — cached routes included,
  since any table change invalidates them. So the macOS backend also keeps a
  default route *scoped to the uplink* (`route add default <gw> -ifscope
  en0`, v6 alike): installed before the tunnel routes, re-pointed on every
  reconnect, removed on exit unless it pre-existed. `route(8)` exits 0 on
  refusals, so its output text is the verdict.
- **MTU follows `Config.mtu_callback`** (the carrier's datagram budget,
  re-reported after a direct upgrade): TUN MTU = report, floored at 576 — or
  at 1280 while the TUN carries IPv6 (below that the kernel disables v6; the
  tunnel layer fragments what the carrier can't fit). `--mtu` pins it. JSON
  events: `path_mtu` (reported) and `tun_mtu` (applied).
- **DNS defaults to the sharer's DNS forwarder** (`100.64.0.53`, see "DNS
  forwarding"; any other resolver must be public — the exit drops private
  destinations); in split-tunnel mode the resolvers'
  host routes are installed alongside the `--route` prefixes so DNS never
  leaves in cleartext. Linux tiers: systemd-resolved (`resolvectl`, only
  when resolved demonstrably owns resolv.conf) → `resolvconf` (verified to
  actually change resolv.conf — loopback-forwarder setups count — else fall
  through) → replace `/etc/resolv.conf` in place with a marker + backup (in
  `/etc`, or `/run/spora` when `/etc` is unwritable; symlinked resolv.conf
  survives the round trip). macOS: `networksetup -setdnsservers` per service
  with a `/var/db/spora` state file for crash recovery (raw strings, so
  zone-scoped resolvers survive). Windows: `SetInterfaceDnsSettings` on the
  adapter. `src_valid_mark` is set but — like wg-quick — never restored
  (global shared state other mark-routing VPNs rely on).
- **Everything is undone in reverse on exit** (an undo stack; `Drop` +
  SIGINT/SIGTERM/SIGHUP, and the Windows console-close events — also while
  `spora use` is still connecting), while what a SIGKILL would leak is
  either process-lifetime (the interface) or recovered at the next start
  (rules sweep, resolv.conf backup, macOS DNS state file).
- **Windows: duplicate address detection is off on the wintun adapter**
  (`DadTransmits = 0`, set BEFORE the addresses are added, as WireGuard does).
  With DAD on, the address is Tentative for ~3 s; once the half-default routes
  make the adapter the DNS client's first-choice interface, every name lookup
  on the host fails instantly for the rest of that window (the query is built
  on the tentative interface and Windows does not fall back to the uplink) —
  core's STUN lookups, ~80 ms after session-up, always lost the first direct
  attempt to it (direct path 15 s late). Found on the Windows test box,
  2026-09-08. NetBIOS over TCP/IP is switched off for the adapter as well
  (`NetbiosOptions = 2` under its NetBT interface key, written after the
  adapter exists — NetBT resets the key at bind — and before the address is
  added, which is when NetBT re-reads it): otherwise Windows broadcasts its
  NetBIOS name registrations into the tunnel (UDP 137, a dozen packets per
  bring-up) for the exit to drop.
- **`--tun-name <name>` attaches to a pre-created TUN and touches NOTHING
  else** — a Linux-only product feature used by the in-tree `cli_vpn` lab
  test: caller owns address, MTU, routes, cleanup. Attach mode installs no
  protector, so the caller must not route the relay endpoint into the TUN.
  The field lab no longer drives it; it runs the ordinary VPN mode as root
  with split-tunnel host routes (`--route <ip>/32`) and `--no-dns`.
- e2e coverage: `cargo test -p spora-lab --test cli_vpn` (spawns the real
  binary in netns; needs `target/debug/spora-cli` built first). The macOS and
  Windows backends are compile-checked (`--target aarch64-apple-darwin` needs
  only a stub crate; `--target x86_64-pc-windows-gnu` checks the real crate)
  and their pure logic (parsers, MTU policy, DNS files) is unit-tested on
  every host.

### Wire protocol — relay control & QUIC routing (see `relay_client::protocol`, `relay_client::tcp`)

- Sharer registration (UDP): `[0x80, 's', 'p', 'R', type | share_id(8) | ts(8, ms) | cert_len(2) | cert | sig_len(2) | sig | token…]`, type `REGISTER_V2` (0x02, the QUIC listener) or `REGISTER_NZ_V2` (0x03, the nz socket). The signature (ECDSA P-256, the device key) covers a per-use domain string plus everything from share id through cert; the token runs to the end of the packet, unsigned, opaque. The leading `0x80` has the QUIC "fixed bit" clear, so QUIC parsers will not mistake control traffic for QUIC. The relay derives the routing hash from cert + share id, verifies, requires `ts` strictly above the last it accepted for (routing hash, type), then asks its `Authorizer`; registrations are keyed by (routing hash, type).
- TCP: sharer park `[spT2 | 0x03 | signed registration (park domain) | token_len(2) | token]`, with its own per-routing-hash timestamp guard (pruned after 120 s); client `[spT2 | 0x02 | routing_hash(20)]`.
- QUIC long-header packets (Initial, Handshake): the relay parses out the DCID at byte offset 6, matches against registered routing hashes, and installs a bidirectional `(B_addr, A_addr)` flow. nz first packets: the leading 20 bytes. nz handshake loss (`transport/noise.rs`): B repeats msg1 every 250 ms until it has both msg2 and the cert-auth, telling the two apart by msg2's exact length (`NZ_MSG2_LEN`: both start with idx_B); A answers a repeated msg1 of an accepted session with both again (to its own peer address, ≤ 1 per 100 ms, until B is first heard).
- QUIC short-header (1-RTT) packets: routed by 5-tuple via the flow table that was installed when the first Initial arrived. The authorizer is never on the forwarding path: a lapsed token stops new registrations, live flows run until idle.

### Token / URL format

```
https://spora.to/s/<base64url(version(1)=1 || cert_hash(20) || share_id(8) || secret(16))>?r=<host>:<port>[&r=<host>:<port>...]
```

45 bytes → 60 base64url chars. An IPv6 relay literal is bracketed (`?r=[2001:db8::1]:443`); `Token::from_url` strips the brackets, so each `RelayEndpoint::host` is a bare hostname/literal. One `?r=` per relay (`Token::relays: Vec<RelayEndpoint>`). A 36-byte (pre-share-id) link is refused.

### Multiple relays

`Config.relays` / `Token.relays` carry one or more relay endpoints (in preference order). The model is fully generic — used for dual-stack reachability AND censorship-fallback:

- **Sharer registers with ALL relays of the share** on one socket (each with its own credential). The socket is dual-stack (`::`, `IPV6_V6ONLY` off) when the relay set includes any v6 endpoint, so it reaches both families and accepts client Initials forwarded by any relay (v4 relays appear v4-mapped); a pure-v4 relay set keeps a plain `0.0.0.0` socket, and so does a host with no IPv6 stack at all (`ipv6.disable=1`: `bind_share_udp` falls back instead of failing the share). `register_loop` takes its targets and tolerates per-relay send failures (a v4-only host skips a v6 relay), logging a warning once per address per process when sending there starts failing and once when it works again (debug in between: the failure repeats every interval and from every rolled listener).
- **Client tries relays IPv6-first** (`resolve_relays_preferring_v6`), each with a family-matched socket, under `Timings.relay_dial_timeout` (default 8s), until one bootstraps a relay-via session. The list is re-resolved and re-ordered on every (re)dial (`resolve_for_dial`), so DNS changes and censorship failover take effect on reconnect; a lookup that fails falls back to the last addresses that resolved — a poisoned resolver must not cost the client the addresses it already had — and both the failure and the fallback land in the connection record. Regression test: `cargo test -p spora-lab --test record -- redial`. Preferring a v6 relay is the lever that drives a v6 hole punch (`path_ipv6` comes from the chosen relay's family), which succeeds far more often (firewall-only, no NAT). A dead relay, a censored one, and a relay the sharer never registered with (family mismatch) all look identical — a dropped Initial — and all fail over to the next. A relay this host has no route to (a v6 relay on a network without IPv6) fails over at once instead: quinn-udp takes send errors (the kernel's ENETUNREACH) for loss, so a QUIC dial would wait out its timeout; `quic_dial` asks the kernel first (`check_udp_route`: a UDP `connect()` on a throwaway socket through the same protector, nothing sent; only a no-route answer fails the dial, as `no_route`). nz and TCP see their send/connect errors already. Regression test: `cargo test -p spora-lab --test ipv6 -- without_v6_route`. A relay that went silent (its dial timed out) while a later one of the same pass came up is tried last on the run's redials (`SilentRelays`, per run), so a relay that does not hold the sharer costs its timeout once per run, not on every reconnect; a pass where nothing answered teaches nothing, and an entry is back in place when it brings a session up or the host sends to it from another local address (a new network: a v6 relay silent on one Wi-Fi may be the best path on cellular). Regression test: `cargo test -p spora-lab --test record -- silent_relay`.
- **A relay listed by both its addresses** (every Spora relay: one dual-stack process, one registration table keyed by routing hash, not family) serves both families from either registration: a sharer without IPv6 registers over v4 only and v6 clients still find it. A dual-stack sharer's two REGISTERs overwrite each other every round (the later, v4 as listed, wins), so the relay's leg to the sharer runs over v4 even for a v6 client; the direct upgrade is unaffected (the sharer punches in the family the client signals). Lab: `cargo test -p spora-lab --test ipv6 -- relay_listed v4_only_sharer`.
- **A hostname with A+AAAA records expands to two endpoints** at resolve time (`resolve_one_relay` returns every resolved address), independently on each side — so it behaves exactly as if both IPs were listed.
- The relay itself is unchanged: each does its dumb DCID-routed forwarding; the sharer's registrations and the clients' flows are per-relay and independent.

### IPv6

Both axes are supported and lab-tested (`cargo test -p spora-lab --test ipv6`; needs ip6tables, skips cleanly without):

- **Outer transport over v6**: relay endpoints are resolved per family (see "Multiple relays" — the client tries v6 first, the sharer registers with all). STUN is queried in the relay-path family first (`pierce_keep_socket(.., prefer_ipv6)`), so punch + direct QUIC run on v6 when the session does. The endpoint exchange is one candidate per side — a cross-family pairing fails fast (`address family mismatch`, transient) instead of burning the punch timeout. The relay binary binds `::` dual-stack by default (one socket, one flow table; v4 peers appear v4-mapped; `--bind 0.0.0.0` for v4-only hosts). The deployed default relay is still a v4 literal, so v6 outer paths need a v6-capable relay host in the URL (or a dual-stack hostname).
- **Inner v6 in the tunnel**: the netstack terminates v6 TCP/UDP and re-originates from family-matched OS sockets (`Domain::for_address`); the vendored netstack walks v6 extension-header chains. Oversized inner packets fragment at the tunnel layer per family (IPv4 header fragmentation / RFC 8200 Fragment header, shared 32-bit id counter); `IpReassembler` (share side) and the lab pump reassemble both. The keepalive stays a v4 ICMP ping (10.0.0.2): injected below inner traffic, answered by every exit mode — works unchanged on v6-carrying tunnels.
- **Address hygiene**: `is_local_address` judges v4-mapped destinations by the v4 rules (a dual-stack egress socket would otherwise reach the LAN via `::ffff:192.168.x.x`) and blocks `::`, ULA, link-local, `ff00::/8`; `neg::is_valid_punch_target` and `relay::is_relayable` canonicalize v4-mapped forms before their policy checks.

### Connection log (`spora-core/src/connlog.rs`, see `.local/docs/connection-logging.md`)

The sharer keeps a local NetFlow-style per-flow record ("which client connected to destination IP X during [T1,T2]") — the sharer's egress accountability record for abuse/LE queries. `Config.conn_log: Option<ConnLogConfig>`; core defaults to off, **platforms enable by default** (CLI: `$XDG_STATE_HOME/spora/connlog/<routing-hash>/` (one per share), `--no-conn-log` to disable; FFI: `conn_log_dir` param; wincore: proto fields, `%PROGRAMDATA%\Spora\connlog\<rk>`). Key facts:

- Storage is SQLite (WAL) on a dedicated writer thread fed by a bounded channel — hooks never block the tunnel; overflow/IO trouble becomes visible `log_gap` marks (plus `clock_jump`, `share_start/stop`, `flow_throttle`), because an absence of records must be distinguishable from absence of traffic. `share()` fails loudly if the log dir is unwritable.
- Two meters, one log: the netstack exit logs flows at its re-origination points (TCP/UDP, byte counts via `CountedIo`/NAT-entry counters, and `getsockname()` as the **egress source address** — the attribution-critical field; forwarded DNS is one flow per query, against the upstream actually used); `ExitMode::Custom` gets a passive `MeteredTransport` wrapped around the handler's transport (records marked `confirmed=false`, "offered to tunnel"); `--os-routing` enriches those with the post-MASQUERADE port via a conntrack lookup. Flow records are rate-limited per session (token bucket; suppression summarized in marks). `FlowGuard` is a Drop-guard, so abort-driven teardown still closes records.
- Session records carry four address kinds of different evidentiary weight: `reported` (client-asserted, never to be read as an observation), `punch_verified` (address-validated; captured even when the direct QUIC build fails), `verified` (direct connection), `sharer_public` (own STUN). A relay-via-only session never directly observes the client's IP — documented limitation.
- Retention default 90 days, swept in the writer; `spora log hold` pins ranges (preservation requests); logs are deliberately NOT deleted with the identity. Query via `spora log query --ip ... --from ... --to ... [--json]`.
- e2e coverage: `cargo test -p spora-lab --test connlog`.

### Connection record (`spora-core/src/record.rs`, see `.local/docs/diagnostic-record.md`)

A structured, versioned account of ONE RUN of `connect()`/`share()`: every step
timestamped, every failure carrying a code from a **closed vocabulary** (never
free text), quality samples while the tunnel is up, and a terminal outcome.
Counting is the point — a reworded `format!` must not be able to change what a
failure counts as. `Config.record: Option<RecordConfig>`; core defaults to off
(the CLI turns it on: `$XDG_STATE_HOME/spora/records/`, `--no-record` to
disable; the FFI when the app passes `record_dir` to `connect`/`connect_utun`/
`share`). Read it with `spora record list|show|export [--json]`. Key facts:

- Vocabularies: `StepKind`, `Reason`, `StepOutcome` (incl. `skipped` and
  `abandoned`), `Carrier` (quic/tcp_tls/nz) x `PathKind`
  (relay/direct_advertised/direct_punched), `Outcome`, `MtuSource`,
  `NetworkKind`. Adding a code does NOT bump `FORMAT_VERSION`; unknown codes
  degrade to `unknown` in an older reader instead of failing the parse.
- Network availability: a coarse, platform-reported `NetworkState { kind:
  NetworkKind (none/wifi/cellular/ethernet/other), validated: Option<bool> }`
  of the network UNDERNEATH (never a VPN on it), so a run with no STUN-learned
  address still tells "no usable network" from "network up, everything
  blocked". The start state is `RecordConfig.network` → `open.network`;
  changes are instantaneous `network` steps (repeats of the last state and
  reports after close record nothing). A platform with several runs reports
  through a shared `record::NetworkFeed` (`RecordConfig::with_network_feed`;
  `feed.set(state)`): a run opens on the feed's current state and takes every
  later report until it closes — including reports that arrive while
  `connect()`/`share()` is still dialing, which a handed-back recorder cannot
  catch. A record's subscriber hears those steps with the feed locked, so it
  must never report into the feed. `Recorder::network(state)` on the recorder
  `ConnectResult.record` / `ShareSession.record` hands back stays for a
  single run. Never carries the local interface address. The FFI keeps one
  process-wide feed (`set_network_state`, Android); the CLI reports none.
- Classification happens where the error is BORN: `record::Fault { reason,
  detail }` is the crate-internal error type in the dial/handshake/upgrade
  paths (`e2e*.rs`, `carrier.rs`, `noise.rs`), and `impl From<Fault> for String`
  keeps the old `Result<_, String>` boundaries source-compatible. By the time an
  error reaches `io::Error::other`, its kind is gone.
- On disk: append-only JSON Lines, one file per run, flushed per entry on a
  dedicated writer thread behind a bounded channel (overflow → visible `gap`
  entries). A step is written twice — `started`, then its conclusion — and a
  LATER ENTRY SUPERSEDES AN EARLIER ONE WITH THE SAME `seq`, so a record that
  ends at a `started` entry is a record of something still running (spora-web's
  telemetry tables fold steps by that rule too: never change it). Records
  close on Drop, so an unplanned exit still gets an ending, and nothing is
  recorded after the close. An ending nobody asked for while the process is
  panicking is reason `crashed`: `std::thread::panicking()` on the dropping
  thread, or `record::note_process_panic()`, which spora-service's panic hook
  calls for a main-thread panic (a `#[tokio::main]` runtime tears its tasks
  down on worker threads that are not panicking).
- Numbers: traffic/probe counters live in `KeepAliveTransport` (`LinkCounters`)
  — the one layer on every carrier and on both sides of a path swap, so one
  series survives the upgrade; carrier stats (QUIC rtt/cwnd/lost/MTU) are added
  when available. Probe RTT and probe loss are the only carrier-agnostic
  figures. `mtu_src` distinguishes `discovered` from `declared`. Each
  session's sampler lives as long as the session (`UpgradeSender::ended()`),
  not the run; sample rates are per session (none on a session's first
  sample); the close's `tx_bytes`/`rx_bytes` are the run's total over all its
  sessions, read from their counters at close.
- How a session ends: a deliberate end closes its QUIC connection with
  application code 0 (a client stopping, an exit stopping or taking a newer
  client, a transport's drop); an end that found the session dead closes it
  first with `transport::quic::SESSION_DEAD_CODE` (2, "session-dead": the
  keepalive giving up in either role via `KeepAliveConfig.on_dead`, the
  client's reconnect layer seeing its transport die, an exit whose handler
  or netstack stopped on its own). The QUIC reader and sender classify the
  close where they see it (`Fault::from_quinn_session`): only code 0 is
  `peer_closed`; any other code, a transport-level close or this end's own
  close is `transport_closed`. `session_end` concludes `ok` with
  `peer_closed`, or with `replaced` / `local_shutdown` when this end ended
  it, and `failed` otherwise (the first cause the keepalive layer saw, else
  `transport_closed`), so one end's failure is a failure in the other's
  record too. A run with no session up closes `closed_by_peer` when its last
  `session_end` was `peer_closed`, `closed_locally` when `local_shutdown`,
  else `lost`. No new codes; `TunnelEvent::SessionEnded` and the connlog's
  `end_reason` still say `transport_closed` for an orderly leave.
- When a run came up but the host would not take it (`spora use`: TUN
  attach refused, route/resolver activation failed; either role: the
  `--json` stream unwritable), the CLI closes the record itself before
  ending the session: `closed_locally` (`never_connected` if no session ever
  existed), reason `permission_denied` (EPERM/EACCES) or `misconfigured`,
  the error as detail; then it stops the session and undoes the host changes.
- Honest limits are part of the design, not omissions: a relay-via session
  never observes the peer's address; REGISTER is unacknowledged so `register`
  records intent, not receipt; `no_response` is used ONLY where the code can
  prove nothing arrived (nz handshake, punch) — QUIC timeouts are
  `handshake_timeout`; the two ends' records are not automatically joinable.
- e2e coverage: `cargo test -p spora-lab --test record`; session endings:
  `cargo test -p spora-core --test session_end` (both ends' records over a
  loopback relay: leaves with traffic in flight both ways, one-way loss, a
  failing exit handler, a process exiting right after `stopper.stop()`;
  ~1 min) and the `cli_vpn` lab suite (a SIGTERM'd `spora use` → the
  sharer's record says `peer_closed` and closes `closed_by_peer`).

### Relay access (`spora-service::access`, spec S1/S3/S6)

- `GET /v1/relays` → `{relays: [{protocol, host, port}], token: {value (base64url, opaque), subject (hex cert hash), expires_at, renew_after} | null}`; registration (`POST /v1/devices`) names the device's `cert_hash` (hex). Both are cached per registration in `service.json` (`relay_access`: advice, token, last success/failure); a failed request keeps both; `token: null` (not entitled) clears the token.
- Renewal rides the service thread: due when never fetched, past the token's `renew_after`, or 6 h after a `null` token; scheduled like a nudge, so it never cuts a backoff short; it registers if need be and runs whatever the upload switch says, only while the configuration manages relays (`ServiceConfig.relays`, or `Telemetry::set_relay_access(true)` — the CLI's `share` and the FFI's `start_share` turn it on for a share with a `Spora` credential). A renewal failure fails the pass (backoff) but not its uploads.
- Running shares register their `Credentials` (`Telemetry::register_share(share_id, …)`, `unregister_share`); every renewal pushes the new token to all of them (`ShareSession::update_relay_token` semantics). `Telemetry::relay_token()` is the cached token unless expired; `make_share(own, use_spora)` = advice as `Spora` entries, then `own`.
- Sealing (`spora-service::seal`): `ServiceConfig.state_key` = `Plaintext` (CLI, tests) | `Provided(32 bytes)` | `Mint` (the service mints one and hands it back: `Telemetry::minted_state_key`). Field-level AES-256-GCM (`sealed:v1:<b64url(nonce‖ct)>`, the field kind as AAD) over the device key, device tokens and relay tokens; cursors, cert and advice stay readable. A sealed field that does not open is state loss (file moved to `service.json.corrupt`, fresh device), never a rotation. Clear fields are taken as they are and sealed on the next save.
- Tests: `cargo test -p spora-service` (fake API: `cert_hash` required at registration, `/v1/relays`), `spora-cli/tests/process.rs` (`spora_relays_put_a_share_on_the_advised_relays`; the relay-less default: `a_share_without_relay_flags_is_relayless`, `a_relayless_share_behind_a_nat_says_so_off_the_event_stream`, against a fake STUN service).

### Diagnostic log and telemetry (`spora-service`, see `.local/docs/telemetry-design.md`)

Collection is unconditional and local; telemetry is one upload switch (per
device, default OFF) over files that are already there. Three streams: the
connection records (`record`), the diagnostic log (`log`) and crash files
(`crash`). The connection log (`connlog`) is no part of it and never uploads.
Key facts:

- **Diagnostic log** (`spora_service::diag`): `diag::init(file, secondary)`
  installs a composite `log` logger — the file plus the platform's own logger
  (env_logger / android_logger / oslog), each with its own filter. The file's
  filter is fixed (`file_level`): `spora_core::flow` and `spora_core::stats`
  never (see "Conventions"); `spora*`/`relay*`/`app` at Debug; quinn,
  smoltcp, rustls, ureq… at Warn; else Info. `diag::WITHHELD_TARGETS`
  (`ureq_proto`: raw request bytes, bearer token included) reach NO sink at
  any level; a process logging through a plain logger applies that list
  itself. JSON Lines `diag-<stamp>-<pid>.jsonl` (+ an empty
  `diag-<pid>.lock` per live writer, exclusively locked for its life — std's
  file lock, `flock(2)` on Android where std has none — so another process's
  sweep spares its file; the sweep probes it through a read+write descriptor
  that never creates the file, as a read-only one fails on NFS whether or not
  it is held; where locks are unsupported a writer deletes its lock file at
  once and nothing is spared), rotated at 1 MiB, capped at 16 MiB / 14 days, written by a thread
  behind a bounded channel; callers never block. Each call site has a budget
  (burst 60, then one line per 10 s; a platform tag 4x): what a site holds
  back, a full queue drops or a failing disk loses is summarized in a
  `src:"diag"` line (`suppressed N lines from <site>`, `dropped N lines`,
  `lost N lines`) whose `dropped` field counts the lines the file is missing
  there. A line carries the open record's id as `run` only while exactly ONE
  record is open (`diag::run_tracker()` / `spora_service::record_subscriber()`
  on the `RecordConfig`); with none or several open it carries none rather
  than a wrong one. Share-URL secrets (`/s/` + 40 or more base64url chars, in
  any case, JSON-escaped or percent-encoded) are redacted before anything
  reaches disk; nothing else is (addresses of peers, relays and resolvers
  are diagnostics). Platform code joins the file through `diag::log_line`
  (FFI `log_line`). Crash files (`crash-<stamp>-<source>.txt`, a JSON header
  line + text, at most 256 KiB = one upload chunk, newest 20 / 30 days) come
  from `install_panic_hook` — one per panic location per process, repeats
  counted in the log's `E` line, none for std's lost-stdout panic — and from
  `write_crash` (FFI, for Kotlin's uncaught exceptions), same directory.
- **Bug report** (`diag::bundle::export`; CLI `spora report`, FFI
  `export_bug_report`): a zip (0600) of the last 72 h of records, log and
  crash files (24 MiB budget: crashes, then records, then logs, newest first;
  each file cut back to its last whole line) with a `manifest.json` listing
  everything included and everything left out with why (an unreadable
  directory too). Needs no server, no registration, uploads off. It and the
  uploader open a listed file without following a symlink (`O_NOFOLLOW`,
  `O_NONBLOCK` against a FIFO) and only while it is still the regular file
  listed (same device and inode) — else the bundle lists it `unreadable` and
  the uploader skips it — which matters when root bundles a directory its
  user controls.
- **The switch** (`Telemetry`, state in `<state_dir>/service.json`: switch,
  device id + bearer token + which API issued it (`builtin`, and the bases
  it registered at), cached force flag, per-file cursors; 0600, never
  backed up — a restored token clones a device). Every change is a
  read-modify-write under an advisory lock on `.service.lock`, so
  processes sharing the file (a `share`, a `use`, a `telemetry off` from
  another shell) never undo each other; a file that
  exists but cannot be read is an error, never a fresh state. The uploader is
  a plain `std::thread` (no caller runtime): a pass at start, ~2 s after a
  nudge (record close, network change), every 15 min; after a failure,
  backoff 1 min → 1 h; a server's `Retry-After` is honoured up to 24 h
  (spora-web's quota window). A nudge does not cut short a backoff the server
  answered with; after no answer at all it may retry a minute after the
  failure. Switching on (and a refused switch-off, which wants the flag) goes
  through regardless. `spora_service::set_dormant` (radio silence: no pass at
  all; leaving it nudges) and `spora_service::finish(timeout)` (one last pass
  now, then stop the thread; for a process about to exit; one that times out
  withdraws its request, so a later `start` gets a lasting uploader) are the
  process-wide controls. `PassSummary.halted`: the pass stopped early
  (uploads switched off meanwhile, the uploader stopping or dormant, its
  registration forgotten by another process); what it sent is still counted.
- **Wire protocol** (spora-web): `POST /v1/devices`, `GET /v1/devices/me`
  (`telemetry_required`, at most daily), `POST
  /v1/telemetry/upload?stream=&file=&offset=` — whole lines only, ≤ 256 KiB
  per chunk (gzip when that is smaller; a single longer line of up to 1 MiB
  goes alone, a crash file goes whole); the server's `length` is
  authoritative and becomes the cursor (resend-safe, idempotent). A chunk the
  server refuses (400/413), a line over 1 MiB or an unreadable file rests for
  a day; any other error ends the pass. The server takes at most 1 MiB per
  upload (as sent and decoded) and 20,000 lines in a record or log body (a
  crash body has no line cap); its daily quota (64 MiB, 500 new files)
  counts each upload as at least 4 KiB; it answers 503 + `Retry-After` while
  its spool runs short of disk space or inodes. Registration is lazy (first
  pass with uploads on) and bound to its API, which is either the BUILT-IN
  API (the configuration named no bases: the CLI without `SPORA_API`, an
  app with empty `ServiceConfig.api_bases`) or an OVERRIDE (an explicit
  list: `SPORA_API`, `--api`, a non-empty FFI list, even one equal to the
  production URL); `Device.builtin` records which. Built-in list = one API:
  a built-in device's token goes to every front of the RUNNING release's
  `DEFAULT_API_BASES`, so fronts can be added or swapped between releases
  with no new registration and nothing resent (its `api_bases` only note
  where it registered); an override device's token goes only to the bases
  that minted it; neither ever reaches the other kind (`Api::serves`, and
  per base in `Api::request`). A device stored without `builtin` (earlier
  dev builds of this rework only) is an override's, so a built-in
  configuration registers once more. Any other API means a new device
  there — the earlier registration is parked in `service.json`'s `parked`
  list (at most 4, oldest dropped) with its own cursors, refusals and flag,
  and a process configured for a parked one's API makes it active again
  with no new registration and nothing resent (processes sharing the file but not the
  API take turns instead of re-registering and resending every pass). A
  pass writes cursors and flags only to its own registration, wherever it is
  kept by then. A 401 drops that registration (active or parked) and the
  next pass registers anew and sends everything on disk again under the new
  id — analytics dedupe such a history by `record_id` (the tables keep
  `device_id` in their keys). No environment proxy, no redirects followed.
  Uploads are NOT protected from the VPN: with a tunnel up they ride it.
- **Off** means nothing is uploaded — but a device registered earlier still
  asks `/v1/devices/me` once a day, because the account's force flag
  (`telemetry_required`) is what may switch uploads back on (that same pass
  then uploads). The flag also makes switching off fail with
  `Error::Required` (the UI shows `REQUIRED_NOTICE` verbatim);
  `required_notice_pending` is set when the flag goes false→true. The flag
  binds only the configuration whose API issued the registration:
  `Telemetry::status()` (`TelemetryStatus::for_api`) reports that
  registration's device and flag (active or parked), and only that flag —
  or one stored with no registration at all — refuses a switch-off.
- CLI: every command installs the composite logger (stderr as the
  secondary, with `WITHHELD_TARGETS` off); share/use also keep the log file
  in `$XDG_STATE_HOME/spora/log/` (`--no-diag-log`) and the panic hook, run
  the uploader in-process, and at exit — after teardown and the record's
  close — make one last pass via `spora_service::finish` (at most 5 s, only
  with uploads on). share/use watch stop signals from process start
  (`Shutdown` in main.rs; SIGINT/SIGTERM/SIGHUP, on Windows Ctrl+C,
  Ctrl+Break, close/logoff/shutdown), counted: the first stops the run
  wherever it is (a `use` dial stopped so exits 0, its record
  `never_connected` with `abandoned` steps), the second skips the final
  upload (even pressed during teardown), the third exits at once with
  status 130 and no cleanup (for a run stuck in a blocking call). State in
  `$XDG_STATE_HOME/spora/service/`; `spora telemetry status|on|off|upload`
  (`status` names the configured API, `built-in (<bases>)` or the
  `SPORA_API` bases, and shows its registration and flag and the other
  APIs' registrations; `--json` gives each API as `{"builtin": bool,
  "bases": [...]}`, the bases being where its tokens go, a built-in one's
  this release's built-in list; `off`, refused by the account flag,
  refreshes it and retries on the state the refresh left — a 401 forgets the device and its
  flag); `spora report [--record-dir DIR]…`. API base: `$SPORA_API`
  (comma-separated; set but empty or not UTF-8 is refused) >
  `DEFAULT_API_BASES` (production), and `--api` on `spora telemetry upload`
  only. The uploader
  sends only the DEFAULT records and log directories (all processes sharing
  `service.json` must list the same files). State is per user, and root
  never writes into a user's home: the state directory is
  `$XDG_STATE_HOME/spora` when that is absolute; else, for a run with sudo
  (euid 0, `SUDO_USER` set and not `root`), `<root's home from the password
  database (getpwuid_r(0))>/.local/state/spora` even where sudo kept the
  user's `HOME` (macOS, `sudo -E`); else `$HOME/.local/state/spora`
  (Windows: `%LOCALAPPDATA%\spora`). The identity file still follows
  `XDG_CONFIG_HOME`/`HOME`. Banners, hints and "found nothing" errors name
  `sudo spora report` / `sudo spora telemetry` / `sudo spora record|log`;
  the `sudo chown -R "$USER" <state dir>` hint is offered only for an
  unreadable path inside the user's own state dir. Records and connlog that
  earlier versions' sudo runs left in `~/.local/state/spora` stay there
  (docs-site `reference/files.md` says how to read or reclaim them).
  `app_version` is `<version>+<commit12>[.dirty]`.
- FFI (`spora-ffi/src/service.rs`): `init_logging`, `log_line`,
  `write_crash`, `init_service`, `telemetry_status`, `set_telemetry_enabled`,
  `acknowledge_telemetry_notice`, `telemetry_nudge`, `export_bug_report`
  (works without a running service, from the config `init_service` was
  offered). In `spora-ffi/src/lib.rs`: `set_network_state` (the process-wide
  `NetworkFeed`; a change, not a repeat, nudges the uploader), and
  `set_keepalive`/`disconnect` drive `set_dormant` — no uploads while at
  least one client tunnel exists and every one has keepalive 0.
- Tests never touch the production API: `cargo test -p spora-service` runs
  against an in-process fake of the API; whatever spawns `spora` gives it
  `SPORA_API=http://127.0.0.1:9` and a scratch `XDG_STATE_HOME` (the
  `cli_vpn` lab suite and `spora-cli/tests/process.rs` do; `cli_vpn` checks
  the real binaries' logs: header, `run` stamps, no secret, no flow or stats
  line). `process.rs` runs the real binary against loopback-only fakes:
  share stopped by SIGINT/SIGHUP/SIGTERM (record close + final upload), a
  second signal skipping the upload, a `use` dial stopped by a signal, a
  `use` that cannot attach its TUN, `telemetry off` against a revoked
  device, the sudo state path (uid 0 in an `unshare -r` user namespace; skips
  without one), no chown advice outside the user's own state.
  `spora-service/src/fake_server.rs` follows spora-web's limits and error
  codes, but not its quota or disk guards.

### Transport Layer (`spora-core/src/transport/`)

The `Transport` trait = `Stream<Item=io::Result<Vec<u8>>> + Sink<Vec<u8>>`. Implementations:

- `QuicPeerTransport` (in `transport/quic.rs`) — wraps a `quinn::Connection`'s datagram channel as IP packets. Uses quinn **BBR** to pace datagrams to the bottleneck (replaced `NoopCc`, which paced nothing and let the share-side smoltcp download sender burst the path into congestion collapse — see `.local/docs/lab.md`). Used by both relay-via and direct paths.
- `UpgradableTransport` (in `transport/upgradable.rs`) — wraps any transport; can be swapped to a new inner transport via `UpgradeSender`. Its router never ends silently when a send fails: it forwards the end the reader already queued, else the classified send error, and later sends after the router is gone return that cause (`io::ErrorKind::BrokenPipe` carrying a `Fault`, see `Fault::from_io`). The QUIC carrier classifies `send_datagram`'s `ConnectionLost` like its reader (`Fault::from_quinn_session`).
- `KeepAliveTransport` (in `transport/keepalive.rs`) — injects ICMP Echo Requests at configurable intervals. This is the SINGLE, transport-agnostic keepalive of record for all carriers (QUIC/nz/TCP): quinn's own `keep_alive_interval` was removed (only `max_idle_timeout` remains, as a passive reaper) so there is one knob-honoring control point. **Client** side is `Adaptive` (atomic knob: 0 = dormant/screen-off/radio-silent, >0 = probe every N s). **Share** side is reactive `Periodic` with an `active_window`: it pings only while it has heard from the client recently, and goes quiet once the client goes dormant — so a dormant client is never forced to ACK share-side pings (true radio silence). Cooperate-with-sleep: a dormancy longer than the idle timeout drops the connection (`max_idle_timeout` reaps it) and it reconnects on wake — cheap now via per-port. A failed send is recorded as the session's end like a stream error (`LinkCounters::ended_by`), and `KeepAliveConfig.on_dead` runs when the layer declares the peer dead, before the stream ends (lib.rs closes the connection with `SESSION_DEAD_CODE` there).
- `ReconnectTransport` (in `transport/mod.rs`) — wraps any transport; on error/close, re-dials via a closure. Parks (does not redial) while the app is dormant (keepalive knob 0), waking on `set_keepalive(N>0)` — a screen-off phone stays radio-silent instead of spinning the radio on a dead tunnel.
- `MeteredTransport` (in `transport/meter.rs`) — share side, `ExitMode::Custom` only: passive connection-log flow meter (see "Connection log").

Composition (client side): `QuicPeerTransport → UpgradableTransport → KeepAliveTransport → ReconnectTransport`. Server side omits the outermost `ReconnectTransport` (a new peer just opens a new QUIC connection at the QUIC server endpoint).

### Key Constants

- STUN servers, in fallback order: `stun.cloudflare.com:3478`, `global.stun.twilio.com:3478`, `stun.relay.metered.ca:80`, `stun.cloudflare.com:53`, `stun.l.google.com:19302`
- Default relay: `167.71.66.250:443` (UDP, not TLS now — the relay speaks no protocol other than the magic-prefix control packets and QUIC pass-through)
- Default telemetry API: `https://truecdn.net` (`spora_service::DEFAULT_API_BASES`, the built-in API's fronts; a release may change them without devices re-registering) — PRODUCTION; dev runs pin `SPORA_API` (see "Never contact production from development").
- Telemetry: uploader every 15 min, nudged passes ~2 s after the nudge, backoff 1 min → 1 h (a server's `Retry-After` honoured up to 24 h), force flag fetched at most daily, at most 4 parked registrations; chunks ≤ 256 KiB, a line ≤ 1 MiB; refused files rest 24 h. Diagnostic log: 1 MiB files, 16 MiB / 14 days in all, per call site 60 lines then 1 per 10 s. Bug report: 72 h, 24 MiB.
- Routing-hash and cert-hash length: 20 bytes (fits in a QUIC v1 DCID); share id 8 bytes
- Secret length: 16 bytes
- Register interval: 30s. Relay registration timeout: 120s. Flow timeout: 60s.
- DNS forwarder: synthetic resolver `100.64.0.53:53` (CGNAT space, never a LAN); 2s per attempt, 3 attempts per query, 3 strikes → 30s quarantine, system list re-read every 30s; public fallback 8.8.8.8 + 1.1.1.1.
- QUIC: initial_mtu=1200, PMTUD enabled, BBR, idle 30s. NO quinn keep-alive (the ICMP `KeepAliveTransport` is the single keepalive; `Timings.quic_keep_alive` now sets the SHARE-side ICMP interval, not a quinn setting).
- QUIC application close codes: 0 = deliberate end; 1 = handshake refusals (auth-error, auth-timeout, bad-secret, ack-failed); 2 = session-dead (`transport::quic::SESSION_DEAD_CODE`). Client stop flush grace: 500 ms (`STOP_FLUSH_GRACE`).
- Direct-upgrade retry (initiator): 15 s after the first failed attempt (`Timings.upgrade_retry_delay`), doubling per consecutive failure, capped at 5 min (`Timings.upgrade_retry_max`); per session, reset on a wake from dormancy; 3 dormant attempts, then parked until a wake.

## Conventions

- Edition 2024 across the workspace (spora-core now too). A crate's target-gated
  dependencies live in ITS manifest: a `cfg(target_os = "macos")` file that
  moves between crates takes its deps along, or only the macOS CI job notices.
  (spora-service's `libc` is `cfg(unix)`: `O_NOFOLLOW` differs per
  architecture, and Android needs `flock(2)`; spora-cli's is `cfg(unix)` for
  `geteuid`/`getpwuid_r`.)
- Async throughout using tokio with full features.
- `spora-core/build.rs` stamps the git commit + a dirty flag into the binary
  (overridable with `SPORA_BUILD_COMMIT`/`SPORA_BUILD_DIRTY` for release
  pipelines); every connection record names the build that produced it.
- Logging via `log` crate, behind spora-service's composite logger (the
  diagnostic log file + env_logger / android_logger / oslog as the
  secondary) in the CLI and the FFI. The file keeps `spora*` targets at Debug
  on every platform, so a per-packet `debug!` is a per-packet file write:
  keep those at `trace!`. Two targets never reach the file, whatever the
  level, and keep their levels on stderr/logcat: **every line that names a
  client flow's source or destination** logs with `target:
  spora_core::FLOW_LOG_TARGET` (`spora_core::flow`) — the connection log is
  the only per-flow record and it never leaves the machine — and **periodic
  per-connection statistics and per-probe lines** with `target:
  spora_core::STATS_LOG_TARGET` (`spora_core::stats`; e.g. QUIC path stats:
  `RUST_LOG=spora_core::stats=debug`). `spora-core/tests/flow_log_target.rs`
  guards the flow lines. The vendored netstack follows the same rule: it logs
  through `tracing`'s `log` bridge, which carries an event's `target:` over,
  and every line of its that names a flow's address (malformed-packet errors
  with src/dst and payload, per-flow traces, the latest refused SYN of the
  socket cap) logs on `spora_core::flow` through its crate-private
  `FLOW_TARGET` (spelled out: it cannot depend on spora-core). Only the
  rate-limited TCP-socket-cap warning itself (cap and count, no addresses)
  stays on `netstack_smoltcp::tcp` at Warn and reaches the file.
  `flow_log_target.rs` covers the netstack's lines too. To see them on
  stderr, enable `spora_core::flow`; `RUST_LOG=netstack_smoltcp=trace` alone
  no longer shows them.
- Public API error type is currently `Result<T, String>`.
- The companion Android app lives in a sibling `../spora-android/` repo.

# relay

The Spora **relay** is a rendezvous and fallback forwarder. It lets a sharer behind NAT be reachable, and provides a fallback path when a direct connection can't be punched. Its defining property: it **never terminates the peers' end-to-end encryption** — it holds no keys, runs no handshake, and reads no plaintext. It only matches the two sides and shuttles bytes between them.

Shares use Spora's relays by default, so most users never run one. Run your own to avoid depending on the default, to hold the accountability record yourself, or to serve a particular network. (If your exit is on an Internet-routable machine you can skip the relay altogether — see `--direct` in the top-level README.)

## What it forwards

Every carrier pairs a sharer and client by a share's **public 20-byte routing hash**, `SHA-256(cert hash || share id)[..20]`, which a client computes from the share URL (it carries the sharer's device cert hash and the share's id). The sharer registers `routing_hash -> its address`; a client presents the routing hash, and the relay splices the two together. It never needs — or gets — anything secret to do this.

- **UDP / QUIC** (default). The client's first packet is a QUIC Initial whose DCID *is* the routing hash. The relay reads the DCID out of the long header, looks up the sharer, installs a bidirectional flow `(client <-> sharer)`, and forwards every later packet (long- or short-header) by source address.
- **UDP / Noise (`nz`)**. A non-QUIC-shaped carrier for networks that fingerprint or throttle QUIC. The client's first packet is `routing_hash(20) | session index(4) | Noise NNpsk0 msg1(48)`; the relay routes on the leading 20-byte prefix — the same public value it reads from a QUIC DCID — then forwards by flow. It's checked even when a packet happens to look QUIC-shaped but matches no registered DCID. A share registers its QUIC listener and its nz socket separately (they are different sockets), so one port serves both carriers.
- **TCP / TLS** (`--tcp-port`). For networks that block UDP/QUIC entirely. Sharers *park* a small pool of TCP connections for a share; a client CONNECTs with the routing hash, and the relay pops one and blind-splices the pair with `copy_bidirectional`. The end-to-end TLS runs through the splice, so — as with the UDP carriers — the relay sees no plaintext.

Only one client is served per share at a time. A second client that merely knows the (public) routing hash can't displace an established one; a short grace window around the sharer's keep-alive keeps a live-but-idle session protected.

## Registration & trust

Sharer registrations are **signed and replay-guarded**, on every carrier. A UDP REGISTER and a TCP park both carry the share id, a timestamp, the sharer's device cert and a signature (and then a token). The relay verifies the signature, derives the routing hash from the cert and the share id itself (so a registration can only claim a routing hash of a key its sender holds), and requires a strictly increasing timestamp per routing hash (a captured registration or park preamble can't be replayed). The relay stores no secret — it only verifies.

By default the relay is **open**: any validly signed registration is accepted. Pass `--token-file <path>` (or `--token <value>`) to admit only sharers that present that token:

```bash
head -c 24 /dev/urandom | base64 > relay.token   # any text works; whitespace is trimmed
relay --token-file relay.token
spora share --relay your.host:443 --relay-token relay.token
```

The token is a bearer secret compared in constant time; it is kept in the sharer's share, never in its URL. Key *possession* is still proven end-to-end by the pinned cert during the peers' own handshake. Spora's own relays check signed, expiring tokens instead: that is a binary of its own that links this crate and supplies an `Authorizer` (`relay::authz`); this crate treats tokens as opaque bytes.

## Session log

By default the deployed relay keeps a **session log**: its own accountability record of each matched flow (client address ↔ the share's routing hash and the sharer's device cert hash, with timing and byte counts), separate from the sharer's connection log. Retention defaults to 90 days. A log written by an older relay keeps its sessions in a table of their own, `sessions_v1`.

- `--no-session-log` disables it.
- `--session-log <path>` / `--session-log-retention-days <n>` configure it.
- Under systemd, set `StateDirectory=` and the log lands in `$STATE_DIRECTORY` automatically. The relay opens the log **before** binding and exits loudly if the path isn't writable, so a misconfiguration never becomes a silent gap.

## Running it

```bash
relay                          # UDP/443, dual-stack (::); binding :443 needs privilege
relay --port 51820             # unprivileged port
relay --bind 0.0.0.0           # v4-only host
relay --tcp-port 443           # also serve the TCP/TLS carrier
relay --token-file relay.token # admit only sharers presenting this token
```

Point sharers at it with `spora-cli share --relay <host>:<port>` (repeat for several). 443 is the default port because it blends with HTTPS; a real deployment usually wants it there (and behind a hardened systemd unit with `StateDirectory=`).

# Run your own relay

A new share is relay-less by default: clients connect straight to the
sharing machine, so it needs a public address. A relay lets clients reach
a sharer behind a NAT. `spora share --spora-relays` uses Spora's; running
your own instead is a small job: the relay is a deliberately dumb UDP
forwarder. It carries
encrypted packets between the two ends without being able to read them,
holds no keys, and speaks no protocol of its own beyond a registration
message.

The relay ships as its own tarball in the same GitHub release
(`spora-relay-…`, which contains the `spora-relay` binary) and builds from
the same repository (where a source build names the binary plain
`relay`).

```bash
# on a machine with a public address
spora-relay --port 51820

# on the sharing machine
spora share --relay your.host:51820
```

The relay's address is baked into the share URL, so clients need nothing
extra. Repeat `--relay` to register with several relays; clients try them
IPv6-first, then in listed order, which makes a second relay a cheap
fallback. A hostname with
both A and AAAA records counts as one relay per address family, and gives
you IPv6 connectivity for free.

## Skipping the relay entirely

If the sharing machine itself has a public, reachable address, no relay is
needed at all. That is the default for a new share without relay flags: the
sharer finds its public address with STUN and picks a port. To name the
address and port yourself:

```bash
spora share --direct your.public.host:51820
```

Clients then dial the sharer directly. Combine with `--relay` to offer
both and let clients fall back.

## Restricting who may use your relay

An open relay forwards for any sharer that registers. To limit yours to
sharers you have given a token, start it with one:

```bash
spora-relay --port 51820 --token-file relay.token

spora share --relay your.host:51820 --relay-token relay.token
```

The token stays on the sharing machine, in the share; it is not part of
the URL. The repository's
[relay/README.md](https://github.com/Spora-VPN/spora/blob/main/relay/README.md)
covers the alternative TCP and Noise carriers for networks that block UDP
or fingerprint QUIC, and the relay's own session log.

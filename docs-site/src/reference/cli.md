<!-- GENERATED FILE, do not edit: this page is rendered from the clap
     definitions in spora-cli/src/main.rs. Change the doc comments there,
     then run: SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference -->

# Command reference

The complete surface of the `spora` command line, rendered from the same
definitions the binary is built from. `spora <command> --help` prints the
same text.

## `spora share`

Share over a tunnel. Loads (or creates on first run) a persistent identity at $XDG_CONFIG_HOME/spora/identity.bin so the share URL stays the same across invocations

```text
spora share [OPTIONS]
```

**`--identity-file <IDENTITY_FILE>`**  
Override the identity file path

**`--fresh`** *(default `false`)*  
Generate a fresh identity for this run and overwrite the persisted one

**`--os-routing`** *(default `false`)*  
Bypass the userland netstack: write client packets to a TUN device and let the kernel route/NAT them. Requires root (or CAP_NET_ADMIN). Linux only

**`--tun-addr <TUN_ADDR>`** *(default `10.213.0.1/24`)*  
TUN interface address in CIDR form (with --os-routing)

**`--tun-addr6 <TUN_ADDR6>`** *(default `fd00:5350::1/64`)*  
TUN interface IPv6 address in CIDR form (with --os-routing). Must be a ULA (fc00::/7): clients may only source inner v6 traffic from ULA space, so a global address here would shadow a real prefix without ever being reachable

**`--tun-mtu <TUN_MTU>`** *(default `1280`)*  
TUN MTU (with --os-routing)

**`--no-nat`** *(default `false`)*  
With --os-routing: don't touch ip_forward or iptables. You are responsible for forwarding + NAT; per-client return routes on the TUN are still installed

**`--relay <RELAY>`** *(repeatable)*  
Override the relay address(es) (host:port) used for registration and baked into the share URL. Repeat the flag for multiple relays (the sharer registers with all; the client tries them IPv6-first then in order). A hostname with both A and AAAA records counts as two relays

**`--direct <DIRECT>`** *(repeatable)*  
Advertise a relay-less DIRECT endpoint (host:port) clients can dial straight to this sharer: no relay, no relay bandwidth. The sharer binds this port, so it must be publicly reachable. Repeat for several advertised addresses (they must share one port). Combine with --relay for a mix, or use alone for pure relay-less sharing

**`--tcp-relay <TCP_RELAY>`** *(repeatable)*  
Advertise a TCP/TLS relay endpoint (host:port): a TCP relay carrying end-to-end TLS, for networks that block UDP/QUIC. The sharer connects out and parks connections at it. Repeat for several; combine with --relay to offer both (the client tries them in preference order)

**`--nz-relay <NZ_RELAY>`** *(repeatable)*  
Advertise a Noise UDP (`nz`) relay endpoint (host:port): the dumb UDP relay carrying an end-to-end Noise datagram session, a high-entropy, non-QUIC-shaped transport for networks that fingerprint or throttle QUIC. Point it at a relay on a non-443 UDP port. Repeat for several; combine with --relay to offer both (the client tries them in order)

**`--stun <STUN>`** *(repeatable)*  
Override the ordered STUN servers (host:port) used for direct-upgrade endpoint discovery. Repeat for fallbacks

**`--no-direct-upgrade`** *(default `false`)*  
Keep the session on its initial relay/carrier path instead of attempting a direct upgrade

**`--relay-token <RELAY_TOKEN>`**  
Capability token authorizing this sharer to use the relay(s), when the relay requires one. Accepts a base64url token (as printed by `spora-issuer issue`) or a path to a file containing it. Not needed for open-mode relays

**`--no-conn-log`** *(default `false`)*  
Disable the connection log. By default the sharer keeps a local per-flow record (who connected to which destination, when) at $XDG_STATE_HOME/spora/connlog/\<routing-key\>/ (in root's home for a run with sudo), the sharer's own egress accountability record for answering abuse reports

**`--dns-upstream <DNS_UPSTREAM>`** *(repeatable)*  
Answer clients' DNS queries from these servers (ip or ip:port, repeatable, in preference order) instead of this host's own resolvers. Used exclusively: no public fallback

**`--no-dns-forwarder`** *(default `false`)*  
Don't answer clients' DNS queries at all: queries to the tunnel's resolver address (100.64.0.53) are dropped like any other private destination, so clients must bring public resolvers of their own

**`--conn-log-dir <CONN_LOG_DIR>`**  
Override the connection-log directory

**`--conn-log-retention-days <CONN_LOG_RETENTION_DAYS>`** *(default `90`)*  
Connection-log retention in days; older records are deleted (unless pinned by `spora log hold`)

**`--conn-log-sessions-only`** *(default `false`)*  
Log sessions only (who was connected and when), without per-flow destination records

**`--no-record`** *(default `false`)*  
Don't keep a diagnostic record of how each connection went

**`--record-dir <RECORD_DIR>`**  
Override the diagnostic-record directory (default: $XDG_STATE_HOME/spora/records/, in root's home for a run with sudo). Uploads only take the default directory; `spora report --record-dir` bundles another

**`--record-label <RECORD_LABEL>`**  
Label this machine in every record it writes

**`--record-id <RECORD_ID>`**  
Tie the records from this run to something outside it: a ticket, a test run

**`--no-diag-log`** *(default `false`)*  
Don't write the diagnostic log to disk. By default it is also kept at $XDG_STATE_HOME/spora/log/ (in root's home for a run with sudo; at most 16 MiB and 14 days, with any crash reports), so `spora report` can bundle it

**`--json`** *(default `false`)*  
Emit newline-delimited JSON lifecycle events on stdout

## `spora use`

Connect through a share URL. By default this is a full VPN client: it brings up the tunnel interface, routes traffic through it, sets the resolver, follows the path's MTU, and restores everything on exit. Needs root (Administrator on Windows), except with --tun-name

```text
spora use [OPTIONS] <URL>
```

**`<URL>`** *(required)*  
The share URL (https://spora.to/s/...) received from the sharer

**`--stun <STUN>`** *(repeatable)*  
Override the ordered STUN servers (host:port) used for direct-upgrade endpoint discovery. Repeat for fallbacks

**`--no-direct-upgrade`** *(default `false`)*  
Keep the session on its initial relay/carrier path instead of attempting a direct upgrade

**`--tun-name <TUN_NAME>`**  
Attach to this pre-created TUN instead of bringing up the tunnel interface yourself. The caller owns its address, MTU, routes and cleanup; nothing else on the host is touched (Linux only)

**`--tun-addr <TUN_ADDR>`** *(default `10.11.0.2/24`)*  
Address of the tunnel interface, in CIDR form. Must be private (RFC1918/CGNAT): sharers refuse other client sources

**`--tun-addr6 <TUN_ADDR6>`** *(default `fd00:5350::2/64`)*  
IPv6 address of the tunnel interface, in CIDR form (must be a ULA, fc00::/7)

**`--no-ipv6`** *(default `false`)*  
Carry no IPv6 in the tunnel: no v6 address, no v6 routes. On a v6-capable host, v6 traffic then bypasses the tunnel

**`--route <ROUTE>`** *(repeatable)*  
Route only this prefix into the tunnel (repeatable) instead of everything. The host's more specific routes (its LANs) still win

**`--no-routes`** *(default `false`)*  
Bring the interface up with its address and MTU but install no routes and leave the resolver alone: you route into it yourself

**`--dns <DNS>`** *(repeatable)*  
Resolver to use while connected (repeatable). The default, 100.64.0.53, is the sharer's DNS forwarder, which answers from the sharer's own resolvers. Anything else is reached through the tunnel, so it must be public

**`--no-dns`** *(default `false`)*  
Leave the host's resolver configuration alone

**`--mtu <MTU>`**  
Pin the interface MTU (576..=1500) instead of following the path's discovered budget

**`--no-record`** *(default `false`)*  
Don't keep a diagnostic record of how the connection went

**`--record-dir <RECORD_DIR>`**  
Override the diagnostic-record directory (default: $XDG_STATE_HOME/spora/records/, in root's home for a run with sudo). Uploads only take the default directory; `spora report --record-dir` bundles another

**`--record-label <RECORD_LABEL>`**  
Label this machine in every record it writes

**`--record-id <RECORD_ID>`**  
Tie this run's record to something outside it: a ticket, a test run

**`--no-diag-log`** *(default `false`)*  
Don't write the diagnostic log to disk. By default it is also kept at $XDG_STATE_HOME/spora/log/ (in root's home for a run with sudo; at most 16 MiB and 14 days, with any crash reports), so `spora report` can bundle it

**`--json`** *(default `false`)*  
Emit newline-delimited JSON lifecycle events on stdout

## `spora build-info`

Print the source/build identity embedded in this executable

```text
spora build-info [OPTIONS]
```

**`--json`** *(default `false`)*  
Emit the complete build identity as JSON

## `spora log`

Inspect the share's connection log: which client reached which destination, and when. It stays on this machine

```text
spora log <COMMAND>
```

## `spora log query`

Query flows: "who connected to destination IP X during [from, to]". Prints matching flows, the sessions they belong to (with everything known about the client's outer address), and any log gaps or clock jumps overlapping the window

```text
spora log query [OPTIONS]
```

**`--ip <IP>`**  
Destination IP to match

**`--port <PORT>`**  
Destination port to match

**`--from <FROM>`**  
Window start: RFC3339 (2026-06-12T10:00:00Z), a date (2026-06-12), or unix seconds/milliseconds

**`--to <TO>`**  
Window end (same formats as --from)

**`--json`** *(default `false`)*  
Machine-readable JSON output (for export/handover)

**`--dir <DIR>`**  
Log directory (default: derived from the identity file; overrides --identity-file when both are given)

**`--identity-file <IDENTITY_FILE>`**  
Identity file used to locate the default log directory

## `spora log sessions`

List sessions with their address records

```text
spora log sessions [OPTIONS]
```

**`--dir <DIR>`**  

**`--identity-file <IDENTITY_FILE>`**  

## `spora log hold`

Manage legal holds: time ranges pinned against retention expiry (e.g. after receiving a preservation request)

```text
spora log hold <COMMAND>
```

## `spora log hold add`

Pin [from, to] against the retention sweep

```text
spora log hold add [OPTIONS] --from <FROM> --to <TO>
```

**`--from <FROM>`** *(required)*  

**`--to <TO>`** *(required)*  

**`--note <NOTE>`**  
Why this hold exists (e.g. the case/reference number)

**`--dir <DIR>`**  
Log directory; overrides --identity-file when both are given

**`--identity-file <IDENTITY_FILE>`**  
Identity file used to locate the default log directory

## `spora log hold list`

List active holds

```text
spora log hold list [OPTIONS]
```

**`--dir <DIR>`**  

**`--identity-file <IDENTITY_FILE>`**  

## `spora log hold remove`

Remove a hold by id (records it pinned become subject to retention again on the next sweep)

```text
spora log hold remove [OPTIONS] <ID>
```

**`<ID>`** *(required)*  

**`--dir <DIR>`**  

**`--identity-file <IDENTITY_FILE>`**  

## `spora log hold help`

Print this message or the help of the given subcommand(s)

```text
spora log hold help [COMMAND]
```

## `spora log hold help add`

Pin [from, to] against the retention sweep

```text
spora log hold help add
```

## `spora log hold help list`

List active holds

```text
spora log hold help list
```

## `spora log hold help remove`

Remove a hold by id (records it pinned become subject to retention again on the next sweep)

```text
spora log hold help remove
```

## `spora log hold help help`

Print this message or the help of the given subcommand(s)

```text
spora log hold help help
```

## `spora log help`

Print this message or the help of the given subcommand(s)

```text
spora log help [COMMAND]
```

## `spora log help query`

Query flows: "who connected to destination IP X during [from, to]". Prints matching flows, the sessions they belong to (with everything known about the client's outer address), and any log gaps or clock jumps overlapping the window

```text
spora log help query
```

## `spora log help sessions`

List sessions with their address records

```text
spora log help sessions
```

## `spora log help hold`

Manage legal holds: time ranges pinned against retention expiry (e.g. after receiving a preservation request)

```text
spora log help hold [COMMAND]
```

## `spora log help hold add`

Pin [from, to] against the retention sweep

```text
spora log help hold add
```

## `spora log help hold list`

List active holds

```text
spora log help hold list
```

## `spora log help hold remove`

Remove a hold by id (records it pinned become subject to retention again on the next sweep)

```text
spora log help hold remove
```

## `spora log help help`

Print this message or the help of the given subcommand(s)

```text
spora log help help
```

## `spora record`

Read the diagnostic records of past connections: what was attempted, what failed, and why

```text
spora record <COMMAND>
```

## `spora record list`

One line per record: when, which end, how it ended, and the first thing that failed

```text
spora record list [OPTIONS]
```

**`--dir <DIR>`**  
Record directory (default: $XDG_STATE_HOME/spora/records/, in root's home for a run with sudo)

**`--count <COUNT>`** *(default `20`)*  
How many records to list, newest first

**`--json`** *(default `false`)*  
Machine-readable JSON output

## `spora record show`

The full story of one record: every step, in order, with its verdict

```text
spora record show [OPTIONS] [ID]
```

**`<ID>`**  
Record id (or its first characters). Defaults to the newest

**`--dir <DIR>`**  

**`--json`** *(default `false`)*  
Machine-readable JSON output: the whole record, folded

**`--samples`** *(default `false`)*  
Include the quality samples taken while the tunnel was up

## `spora record export`

Write records out as JSON, for handing to someone else

```text
spora record export [OPTIONS]
```

**`--dir <DIR>`**  

**`--count <COUNT>`** *(default `20`)*  
How many records to export, newest first

**`--out <OUT>`**  
Write to this file instead of standard output

## `spora record help`

Print this message or the help of the given subcommand(s)

```text
spora record help [COMMAND]
```

## `spora record help list`

One line per record: when, which end, how it ended, and the first thing that failed

```text
spora record help list
```

## `spora record help show`

The full story of one record: every step, in order, with its verdict

```text
spora record help show
```

## `spora record help export`

Write records out as JSON, for handing to someone else

```text
spora record help export
```

## `spora record help help`

Print this message or the help of the given subcommand(s)

```text
spora record help help
```

## `spora report`

Bundle the recent diagnostic records, diagnostic log and crash reports of this machine into one zip file to send with a bug report. Works offline and whether or not telemetry is on; manifest.json inside lists everything included and everything left out. The files of runs made with sudo (such as `sudo spora use`) belong to root: bundle those with `sudo spora report`

```text
spora report [OPTIONS]
```

**`--out <OUT>`**  
Where to write the zip (default: spora-report-\<time\>.zip in the current directory)

**`--note <NOTE>`**  
A few words for whoever reads the report: what you were doing, what went wrong

**`--hours <HOURS>`** *(default `72`)*  
How far back to look, in hours

**`--record-dir <RECORD_DIR>`** *(repeatable)*  
Also bundle the records in this directory: one a run's --record-dir pointed at. The default directory is always included

## `spora telemetry`

Telemetry: whether this machine sends its diagnostic records, diagnostic log and crash reports to Spora. They show where and how networks block Spora, and help fix problems. They include network addresses: the public address your network shows, the addresses of the peers, relays and other servers this machine connects with, and the address each upload comes from. Off unless you turn it on. Either way everything is still kept on this machine, for `spora report`. For runs made with sudo (such as `sudo spora use`), use `sudo spora telemetry`

```text
spora telemetry <COMMAND>
```

## `spora telemetry status`

Whether uploads are on, whether your account requires them, this machine's device id, and how the last upload went

```text
spora telemetry status [OPTIONS]
```

**`--json`** *(default `false`)*  
Machine-readable JSON output

## `spora telemetry on`

Turn uploads on. `spora share` and `spora use` send what is pending in the background (running ones within 15 minutes) and once more as they stop

```text
spora telemetry on
```

## `spora telemetry off`

Turn uploads off: nothing more is uploaded. A machine registered earlier still asks the API once a day whether its account requires telemetry. Refused while your account requires telemetry

```text
spora telemetry off
```

## `spora telemetry upload`

With uploads on, send everything not sent yet, now, and say what went. Registers this machine with the API first if it has not been. Without --api or $SPORA_API that is Spora's built-in API, and its registration keeps working at whatever addresses later versions give that API. --api and $SPORA_API name another API, even at the built-in address: this machine registers anew there, the token it gets goes only to the addresses that issued it, and the other registration is kept for when its API is used again

```text
spora telemetry upload [OPTIONS]
```

**`--api <API>`** *(repeatable)*  
API base URL (repeat for fallbacks, tried in order). Overrides $SPORA_API (a comma-separated list) and the built-in API

## `spora telemetry help`

Print this message or the help of the given subcommand(s)

```text
spora telemetry help [COMMAND]
```

## `spora telemetry help status`

Whether uploads are on, whether your account requires them, this machine's device id, and how the last upload went

```text
spora telemetry help status
```

## `spora telemetry help on`

Turn uploads on. `spora share` and `spora use` send what is pending in the background (running ones within 15 minutes) and once more as they stop

```text
spora telemetry help on
```

## `spora telemetry help off`

Turn uploads off: nothing more is uploaded. A machine registered earlier still asks the API once a day whether its account requires telemetry. Refused while your account requires telemetry

```text
spora telemetry help off
```

## `spora telemetry help upload`

With uploads on, send everything not sent yet, now, and say what went. Registers this machine with the API first if it has not been. Without --api or $SPORA_API that is Spora's built-in API, and its registration keeps working at whatever addresses later versions give that API. --api and $SPORA_API name another API, even at the built-in address: this machine registers anew there, the token it gets goes only to the addresses that issued it, and the other registration is kept for when its API is used again

```text
spora telemetry help upload
```

## `spora telemetry help help`

Print this message or the help of the given subcommand(s)

```text
spora telemetry help help
```

## `spora help`

Print this message or the help of the given subcommand(s)

```text
spora help [COMMAND]
```

## `spora help share`

Share over a tunnel. Loads (or creates on first run) a persistent identity at $XDG_CONFIG_HOME/spora/identity.bin so the share URL stays the same across invocations

```text
spora help share
```

## `spora help use`

Connect through a share URL. By default this is a full VPN client: it brings up the tunnel interface, routes traffic through it, sets the resolver, follows the path's MTU, and restores everything on exit. Needs root (Administrator on Windows), except with --tun-name

```text
spora help use
```

## `spora help build-info`

Print the source/build identity embedded in this executable

```text
spora help build-info
```

## `spora help log`

Inspect the share's connection log: which client reached which destination, and when. It stays on this machine

```text
spora help log [COMMAND]
```

## `spora help log query`

Query flows: "who connected to destination IP X during [from, to]". Prints matching flows, the sessions they belong to (with everything known about the client's outer address), and any log gaps or clock jumps overlapping the window

```text
spora help log query
```

## `spora help log sessions`

List sessions with their address records

```text
spora help log sessions
```

## `spora help log hold`

Manage legal holds: time ranges pinned against retention expiry (e.g. after receiving a preservation request)

```text
spora help log hold [COMMAND]
```

## `spora help log hold add`

Pin [from, to] against the retention sweep

```text
spora help log hold add
```

## `spora help log hold list`

List active holds

```text
spora help log hold list
```

## `spora help log hold remove`

Remove a hold by id (records it pinned become subject to retention again on the next sweep)

```text
spora help log hold remove
```

## `spora help record`

Read the diagnostic records of past connections: what was attempted, what failed, and why

```text
spora help record [COMMAND]
```

## `spora help record list`

One line per record: when, which end, how it ended, and the first thing that failed

```text
spora help record list
```

## `spora help record show`

The full story of one record: every step, in order, with its verdict

```text
spora help record show
```

## `spora help record export`

Write records out as JSON, for handing to someone else

```text
spora help record export
```

## `spora help report`

Bundle the recent diagnostic records, diagnostic log and crash reports of this machine into one zip file to send with a bug report. Works offline and whether or not telemetry is on; manifest.json inside lists everything included and everything left out. The files of runs made with sudo (such as `sudo spora use`) belong to root: bundle those with `sudo spora report`

```text
spora help report
```

## `spora help telemetry`

Telemetry: whether this machine sends its diagnostic records, diagnostic log and crash reports to Spora. They show where and how networks block Spora, and help fix problems. They include network addresses: the public address your network shows, the addresses of the peers, relays and other servers this machine connects with, and the address each upload comes from. Off unless you turn it on. Either way everything is still kept on this machine, for `spora report`. For runs made with sudo (such as `sudo spora use`), use `sudo spora telemetry`

```text
spora help telemetry [COMMAND]
```

## `spora help telemetry status`

Whether uploads are on, whether your account requires them, this machine's device id, and how the last upload went

```text
spora help telemetry status
```

## `spora help telemetry on`

Turn uploads on. `spora share` and `spora use` send what is pending in the background (running ones within 15 minutes) and once more as they stop

```text
spora help telemetry on
```

## `spora help telemetry off`

Turn uploads off: nothing more is uploaded. A machine registered earlier still asks the API once a day whether its account requires telemetry. Refused while your account requires telemetry

```text
spora help telemetry off
```

## `spora help telemetry upload`

With uploads on, send everything not sent yet, now, and say what went. Registers this machine with the API first if it has not been. Without --api or $SPORA_API that is Spora's built-in API, and its registration keeps working at whatever addresses later versions give that API. --api and $SPORA_API name another API, even at the built-in address: this machine registers anew there, the token it gets goes only to the addresses that issued it, and the other registration is kept for when its API is used again

```text
spora help telemetry upload
```

## `spora help help`

Print this message or the help of the given subcommand(s)

```text
spora help help
```


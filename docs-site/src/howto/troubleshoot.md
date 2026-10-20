# Find out why a connection failed

You do not have to reproduce a failure with more logging: every run of
`share` and `use` keeps a diagnostic record of what it attempted, what
failed, and why. When someone says "it did not work", the record is the
thing to look at, and `spora report` is how to send it (see below).

A run made with sudo (`sudo spora use`, `sudo spora share --os-routing`)
keeps its files in root's home, so read them with sudo too: `sudo spora
record list`. (Records that earlier versions left in your own home are
covered in [Files and directories](../reference/files.md).)

```bash
spora record list
```

```text
when                  id         role   outcome              took  first failure
2026-08-28 18:53:04Z  6a9ec9d2   client never_connected      8.0s  relay_dial connect_timeout
2026-08-28 14:02:11Z  0c81d7a2   client closed_locally     541.2s  punch punch_timeout
```

`spora record show` walks the newest record step by step; `show <id>`
picks one. Failures carry a reason code from a fixed vocabulary, so two
people looking at two records can compare them meaningfully.

```bash
spora record show 6a9ec9d2
spora record export -o run.json     # one record, as JSON, for someone else
```

## Reading the common outcomes

**`never_connected`, with a failed `relay_dial` step.** The client never
reached the sharer. The reason code says how it died: `connect_timeout`
means nothing answered at all (the share is not running, the relay in the
URL is unreachable, or the network drops UDP); `handshake_timeout` means
something answered but the session never completed. If the sharer
advertises a TCP carrier, the client falls back to it automatically;
otherwise ask the sharer to add one.

**Connected, but the `punch` steps failed.** The session worked but stayed
on the relay: the record ends `closed_locally` (or `closed_by_peer`), the
`punch` steps show `punch_timeout` or similar, and there is no
`direct path after` line in `spora record show`. That is the designed
fallback, not an error: some NAT combinations (notably symmetric NAT on
both ends) cannot be punched. Expect the relay's bandwidth, not
direct-path bandwidth.

**Outcome `lost`, or repeated `reconnecting`.** The path keeps dying. Look
at the quality samples (`spora record show --samples`): probe loss and
round trip time while the tunnel was up are recorded, and tell you whether
the problem is the path or the endpoints.

**`closed_locally` with reason `permission_denied` or `misconfigured`.**
The tunnel came up, but this machine would not take it: a TUN interface
it may not attach, a route or resolver change that was refused. The
record's detail quotes the error. The network is not at fault.

**`unknown (cut)` in `spora record list`.** The record has no ending: the
process was killed outright (SIGKILL, a crash of the whole machine, a
power cut) before it could write one. Ctrl+C, SIGTERM and SIGHUP all end
a run properly, at any point.

**`spora use` refuses to start.** The error names the cause directly:
missing privileges (run with sudo, or elevate the console), another
running instance (only one managed tunnel at a time), or on Windows a
missing `wintun.dll`.

## When you report a problem

```bash
sudo spora report --note "use stopped connecting after the router restarted"
```

This writes one zip file with the records, the diagnostic log and any
crash reports of the last three days (`--hours` changes that), plus the
exact build. Email it to support@spora.to with the command line you ran.
It needs no account and no network, and telemetry does not have to be on.
If uploads are on, the report names this machine's device id, so support
can also find what has reached Spora already.

Run it the way you ran the failing command: `sudo spora report` for
`sudo spora use` (the zip then belongs to root, and the command prints how
to hand it to your own account), plain `spora report` for a `spora share`
started without sudo. On Windows an elevated console keeps your own
files, so plain `spora report` covers both. A run that kept its records
somewhere else (`--record-dir`) needs that directory named again:
`spora report --record-dir ~/spora-runs`. So do the records that runs
with sudo left in your own home under earlier versions (on macOS, say):
`sudo spora report --record-dir ~/.local/state/spora/records`.

If the report could not read a directory, it says which one and why, and
its `manifest.json` lists it as left out.

When you ask the person at the other end instead, send them the record
(`spora record export`), the exact command line, and `spora build-info
--json` from both ends. The build info names the exact source the binary
was built from, so nobody debugs the wrong version.

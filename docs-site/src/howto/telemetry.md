# Send diagnostics to Spora

Every run of `share` and `use` keeps three things on your machine: a
diagnostic record of each connection (what was attempted, what failed,
and why), a diagnostic log, and crash reports, if any. Telemetry is one
switch: whether these also go to Spora, in the background. They show
where and how networks block Spora, and help fix problems. It is off
unless you turn it on.

```bash
spora telemetry on
spora telemetry status
spora telemetry off
```

## What is sent

The diagnostic records, the diagnostic log and the crash reports in the
default directories (see [Files and directories](../reference/files.md)).
They include network addresses: the public address your network shows,
the addresses of the peers, relays and other servers your machine connects
with, and the address each upload comes from.

What is not sent: the connection log a sharer keeps (which client reached
which destination) never leaves the machine, and the per-flow log lines
(one for each connection a client makes) are kept out of the diagnostic
log in the first place. Records a run kept elsewhere (`--record-dir`) are
not sent either.

## When it is sent

`spora share` and `spora use` send what is pending when they start,
every 15 minutes while they run, and once more as they stop: for at most
5 seconds, and another Ctrl+C after the one that stopped the run skips
it. `spora telemetry upload` sends everything now and says what went. An
upload that is cut short resumes where it stopped the next time. Uploads
go out directly (they ignore `HTTP_PROXY` and similar settings), or
through the tunnel while one is up.

## Turning it off

With uploads off nothing is uploaded. A machine that was registered
earlier still asks Spora once a day whether its account requires
telemetry; deleting `service.json` (see
[Files and directories](../reference/files.md)) stops that too, and
forgets the registration.

If your account requires telemetry, `spora telemetry off` is refused and
says so:

> Your account requires that telemetry is enabled (most likely because
> you've signed up to a promotion). You can keep it enabled, sign in to a
> different account, or contact support.

## Runs made with sudo

`sudo spora use` runs as root and uses root's files in root's home,
including root's telemetry switch, also where sudo keeps your `HOME` (as
it does on macOS). So `sudo spora telemetry on` is the switch for runs
made with sudo, and `sudo spora report` bundles them. The commands print a
reminder of this when you run them without sudo. On Windows an elevated
console keeps your own files and switch.

## Without telemetry

A bug report does not need telemetry, an account, or any Spora server:
`spora report` writes the same files into one zip for you to send. See
[Find out why a connection failed](troubleshoot.md).

## Another API

`--api` (on `spora telemetry upload`) and the `SPORA_API` environment
variable point uploads at another API, such as a test server. A
`SPORA_API` that is set but empty, or not valid UTF-8, is an error rather
than Spora's own API.

Without either, uploads go to Spora's built-in API. A registration with it
keeps working at whatever addresses later versions of Spora use for that
API: its token goes to any of them, and nothing is registered or sent
again. An API named with `--api` or `SPORA_API` is another API, even at
Spora's own address. Its token goes only to the exact addresses that
issued it, and the two never mix: the built-in registration's token is
never sent to another API, nor another API's token to the built-in one.

With another API the machine registers anew there, and the earlier
registration is kept, with what it has sent, for when its API is used
again: switching back neither registers again nor resends anything. An
account that requires telemetry binds only the API it belongs to: `spora
telemetry off` under another API is not refused because of it. `spora
telemetry status` names the API in use (`built-in`, or the addresses in
`SPORA_API`) and shows its registration and account, and the other
registrations kept.

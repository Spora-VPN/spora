# Quickstart

Two machines, two commands: `share` on the machine whose connection you want
to use, `use` on the machine that should tunnel through it.

## Install

On Linux and macOS:

```bash
curl -fsSL https://spora.to/docs/install.sh | sh
```

On Windows, in PowerShell:

```powershell
irm https://spora.to/docs/install.ps1 | iex
```

The script downloads the latest release for your system from GitHub, checks
it against the release's checksums and installs it. On Linux and macOS the
binary goes to `/usr/local/bin/spora`, and `sudo` may ask for your password
for that one step. On Windows, `spora.exe` goes to
`%LOCALAPPDATA%\Programs\Spora`, which is added to your `PATH`. Run the same
command again to upgrade.

Both scripts are short, so read them first if you like:
[install.sh](https://github.com/Spora-VPN/spora/blob/main/docs-site/src/install.sh),
[install.ps1](https://github.com/Spora-VPN/spora/blob/main/docs-site/src/install.ps1).
The comment at the top of each says how to pin a version or install
somewhere else.

### Install by hand

Download the archive for your system from the
[releases page](https://github.com/Spora-VPN/spora/releases):

- **Linux**: `spora-<version>-linux-<arch>.tar.gz`, a single static
  binary named `spora`.
- **macOS**: `spora-<version>-macos-<arch>.tar.gz` (`aarch64` for Apple
  silicon, `x86_64` for Intel), a single binary named `spora`. It is not
  notarized yet, so if a browser downloaded the archive, macOS will refuse
  to run the binary until you clear the quarantine flag
  (`xattr -d com.apple.quarantine spora`).
- **Windows**: `spora-<version>-windows-<arch>.zip`, containing `spora.exe`
  plus `wintun.dll`. `spora use` loads the DLL from next to the executable,
  so keep the two files together, in a folder on your `PATH`.

On Linux and macOS, unpack the archive and put the binary in
`/usr/local/bin`, where `sudo` finds it too (`spora use` runs as root):

```bash
tar -xzf spora-*.tar.gz
sudo install -m 755 spora /usr/local/bin/spora
```

### Build from source

A Rust toolchain is the only requirement:

```bash
git clone https://github.com/Spora-VPN/spora.git
cd spora
cargo build --release -p spora-cli
# the binary is target/release/spora-cli; rename or alias it to `spora`
```

For a source build on Windows, `spora use` also needs `wintun.dll` from
[wintun.net](https://www.wintun.net/) next to the executable.

## Share

On the sharing machine:

```bash
spora share
```

It prints a link:

```text
Share this URL with the peer that wants to connect:
https://spora.to/s/2m5cRp…?r=167.71.66.250:443
```

Send that link to the person who should connect. Treat it like a key to
your connection: anyone who has it can use it. The link stays the same
across restarts, and a local connection log records what your connection
was used for. Leave the process running; Ctrl+C stops sharing.

## Connect

On the connecting machine, paste the link (quote it, the `?` matters to the
shell). The client needs privileges to set up the tunnel: root on Linux and
macOS, an elevated console on Windows.

```bash
sudo spora use "https://spora.to/s/2m5cRp…?r=167.71.66.250:443"
```

You will see something like:

```text
Tunnel up on spora0 (10.11.0.2/24, fd00:5350::2/64), MTU 1280 (follows the path).
Routing all traffic through the tunnel.
Resolver: 100.64.0.53 (set via resolvectl; restored on exit).
Press Ctrl+C to disconnect.
```

That is a full VPN: all traffic now leaves through the sharer's connection.
Check it with `curl ifconfig.me`: you should see the sharer's IP. Behind
the scenes the two machines also try to establish a direct path to each
other and switch over when it works: your traffic then stops sharing the
relay's bandwidth and usually takes a shorter path.

Ctrl+C disconnects and puts routing and DNS back exactly as they were.

## Where to go next

- [Share your connection](howto/share.md): identities, the connection log,
  and running a share permanently.
- [Connect through a friend](howto/connect.md): what the client changes on
  your machine and how to shape it.
- [Find out why a connection failed](howto/troubleshoot.md): every run
  keeps a diagnostic record you can read afterwards.

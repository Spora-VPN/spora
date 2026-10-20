# Files and directories

The CLI follows the XDG conventions on Linux and macOS and the profile
directories on Windows. Overriding environment variables (`XDG_CONFIG_HOME`,
`XDG_STATE_HOME`) are honored. The `~/.local/state/spora/` paths below are
root's own for a run made with sudo (see the notes).

| what | Linux and macOS | Windows |
|---|---|---|
| Identity (key material behind the share URL) | `~/.config/spora/identity.bin` | `%APPDATA%\spora\identity.bin` |
| Connection log (per share identity) | `~/.local/state/spora/connlog/<routing-key>/` | `%LOCALAPPDATA%\spora\connlog\<routing-key>\` |
| Diagnostic records | `~/.local/state/spora/records/` | `%LOCALAPPDATA%\spora\records\` |
| Diagnostic log and crash reports | `~/.local/state/spora/log/` | `%LOCALAPPDATA%\spora\log\` |
| Telemetry state | `~/.local/state/spora/service/` | `%LOCALAPPDATA%\spora\service\` |

Notes:

- The identity file is the secret behind a stable share URL: mode `0600`,
  written atomically. Copy it to move a share; delete it (or use
  `--fresh`) to revoke the URL. `--identity-file` selects another path.
- The connection log is SQLite; read it with `spora log`, not by hand, and
  note that deleting the identity does not delete the log. It is your
  record of what your connection was used for, and it outlives the URL on
  purpose.
- Records are plain JSON Lines, one file per run; `--record-dir` moves
  them and `--no-record` disables them.
- The diagnostic log holds what `share` and `use` log, as JSON Lines, at
  fixed levels that are more detailed than the terminal's default (but not
  their printed banner, nor the per-flow lines, one for each connection a
  client makes: the connection log is the only per-flow record). A new
  file per run and per MiB, at most 16 MiB and 14 days in all. Crash
  reports sit beside it. `--no-diag-log` keeps a run from writing either.
  `spora report` bundles the log, the records and the crash reports of the
  last few days into one zip file for a bug report.
- `service/service.json` holds the telemetry switch (`spora telemetry`)
  and, once uploads have been on, this machine's device registration with
  each API it has uploaded to (see
  [Another API](../howto/telemetry.md#another-api)), access tokens
  included (mode `0600`). Delete it to forget the registrations: uploads
  are then off until `spora telemetry on`, which
  registers a new device. Uploads only ever send the default records and
  log directories above, never a `--record-dir` elsewhere (`spora report
  --record-dir` bundles one), and never the connection log.
- Runs made with sudo (`sudo spora use`, `sudo spora share --os-routing`)
  are root's: their records, log, telemetry state and connection log live
  in root's home, `/root/.local/state/spora/` on Linux and
  `/var/root/.local/state/spora/` on macOS. That holds where sudo keeps
  your `HOME` as well (macOS's sudo does, and so does `sudo -E`): a run
  with sudo never writes its state into your home, unless it is handed an
  `XDG_STATE_HOME`, which is honored. `sudo spora record`, `sudo spora
  report`, `sudo spora telemetry` and `sudo spora log` reach those files;
  the same commands without sudo do not. The identity file is not part of
  this: a run finds it through `XDG_CONFIG_HOME` or `HOME`, as sudo leaves
  them. On Windows an elevated console keeps your own directories.
- Earlier versions of the CLI kept the records and connection log of runs
  made with sudo in your own `~/.local/state/spora/` wherever sudo kept
  your `HOME` (on macOS, with `sudo -E`, and on Ubuntu before 19.10).
  Those files stay there, owned by root. Name the directory to read them:
  `sudo spora record list --dir ~/.local/state/spora/records`,
  `sudo spora report --record-dir ~/.local/state/spora/records`,
  `sudo spora log sessions --dir ~/.local/state/spora/connlog/<routing-key>`.
  Or give the directory back to your account with
  `sudo chown -R "$USER" ~/.local/state/spora`, which is also what a
  command run without sudo suggests when it cannot read its state there.
  It suggests that for your own state directory only: a directory
  elsewhere that it cannot read (root's home, a service's directory) is
  not yours to take over, and the same command with sudo reads it.
- `spora use` in VPN mode also keeps small runtime files (an instance
  lock, resolver backups) under `/run/spora/` on Linux and
  `/var/db/spora/` on macOS; they are cleaned up automatically.
- On Windows, `spora use` expects `wintun.dll` next to `spora.exe`.

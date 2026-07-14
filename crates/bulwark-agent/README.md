# bulwark-agent

[![crates.io](https://img.shields.io/crates/v/bulwark-agent.svg)](https://crates.io/crates/bulwark-agent)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/vietanhdev/bulwark/blob/main/LICENSE)

> **Status: placeholder.** This crate currently contains no functionality — it reserves the
> `bulwark-agent` name on crates.io while the daemon is being extracted. Don't depend on it yet.

Part of [Bulwark](https://github.com/vietanhdev/bulwark), a Linux host security scanner.

`bulwark-agent` will become Bulwark's background monitoring daemon: the periodic re-scan loop
and the filesystem watcher on the sensitive paths the rule pack actually reads (`sshd_config`,
systemd units, sudoers, cron, `authorized_keys`), so an edit to one of those triggers an
immediate re-check instead of waiting for the next tick. That logic exists today inside the
desktop app; the point of this crate is to lift it into one process both the CLI and the GUI
can share. It will speak to its clients using the types in
[`bulwark-proto`](https://crates.io/crates/bulwark-proto).

## What to use today

| Crate | Role |
|---|---|
| [`bulwarkctl`](https://crates.io/crates/bulwarkctl) | CLI — scan a Linux host from a terminal or over SSH |
| [`bulwark-core`](https://crates.io/crates/bulwark-core) | The engine: collectors, rule engine, findings, store, ClamAV |

Continuous monitoring is available now in the
[desktop app](https://github.com/vietanhdev/bulwark), and `bulwarkctl scan` runs fine from cron.

## License

Apache-2.0. See [`LICENSE`](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).

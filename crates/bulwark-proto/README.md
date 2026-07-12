# bulwark-proto

[![crates.io](https://img.shields.io/crates/v/bulwark-proto.svg)](https://crates.io/crates/bulwark-proto)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](https://github.com/vietanhdev/bulwark/blob/main/LICENSE)

> **Status: placeholder.** This crate currently contains no types — it reserves the
> `bulwark-proto` name on crates.io while the agent protocol is being designed. Don't depend on
> it yet.

Part of [Bulwark](https://github.com/vietanhdev/bulwark), a Linux host security scanner.

`bulwark-proto` will hold the shared wire types — the request/response messages that
[`bulwarkctl`](https://crates.io/crates/bulwarkctl) and the desktop app use to talk to
[`bulwark-agent`](https://crates.io/crates/bulwark-agent), Bulwark's background monitoring
daemon. It exists as a separate crate so that a client can depend on the protocol without
pulling in the daemon.

## What to use today

| Crate | Role |
|---|---|
| [`bulwarkctl`](https://crates.io/crates/bulwarkctl) | CLI — scan a Linux host from a terminal or over SSH |
| [`bulwark-core`](https://crates.io/crates/bulwark-core) | The engine: collectors, rule engine, findings, store, ClamAV |

The finding, rule, and scan-run types you'd actually want to serialize today already live in
`bulwark_core::models` and implement `serde::Serialize`/`Deserialize`.

## License

AGPL-3.0-or-later. See [`LICENSE`](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).

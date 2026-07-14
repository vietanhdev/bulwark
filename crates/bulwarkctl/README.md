# bulwarkctl

[![crates.io](https://img.shields.io/crates/v/bulwarkctl.svg)](https://crates.io/crates/bulwarkctl)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/vietanhdev/bulwark/blob/main/LICENSE)

The command-line front-door to [Bulwark](https://github.com/vietanhdev/bulwark), a Linux host
security scanner. Audits a machine's configuration against a declarative rule pack — SSH
hardening, systemd/cron persistence, sudoers, kernel/sysctl hardening, file permissions,
logging, rootkit indicators, file integrity — and explains every finding in plain language with
a concrete fix.

Scriptable, cron-friendly, JSON output, no display session required — it runs happily over SSH
on a headless server. The [desktop app](https://github.com/vietanhdev/bulwark) is the other
front-door over the same engine ([`bulwark-core`](https://crates.io/crates/bulwark-core)).

## Install

```bash
cargo install bulwarkctl
```

Or grab a `.deb`/`.rpm` from the
[releases page](https://github.com/vietanhdev/bulwark/releases) — those ship the rule pack to
`/usr/share/bulwark/rules`, which `bulwarkctl` finds automatically. With `cargo install`, pass
`--rules-dir` or run from a checkout that has a `rules/` directory.

## Usage

```bash
# Scan the host and print a findings table
bulwarkctl scan

# Machine-readable output for a cron job or a pipeline
bulwarkctl scan --json | jq '.findings[] | select(.severity == "high")'

# Include checks that need root (sudoers, /etc/shadow). Refuses unless actually
# run under sudo — bulwarkctl never self-elevates.
sudo bulwarkctl scan --privileged

# Opt into rules tagged for a particular kind of host
bulwarkctl scan --needs server,developer

# Inspect the rule pack
bulwarkctl rules list
bulwarkctl rules validate rules/ssh-remote-access/

# Past runs, and file-integrity baselining
bulwarkctl history
sudo bulwarkctl fim baseline --privileged
```

Global flags: `--rules-dir <DIR>` (defaults to an auto-detected `./rules`, then
`/usr/share/bulwark/rules`) and `--db-path <FILE>` (defaults to
`~/.local/share/bulwark/bulwark.db`).

### File-integrity baselines

`bulwarkctl fim baseline` records the current state of monitored critical files as known-good.
It is deliberately never automatic: a baseline established after a compromise would just
enshrine the compromised state as "known good." Run it explicitly, while you trust the host.

## Adding a check

Rules are YAML files under `rules/<category>/`, not Rust code:

```yaml
id: BLWK-SSH-004
title: SSH X11 forwarding is enabled
category: ssh-remote-access
severity: low
collector: sshd_config
condition: x11_forwarding == "yes"
explain: "X11Forwarding is set to \"{{ sshd.x11_forwarding }}\" in sshd_config..."
fix: "Set 'X11Forwarding no' in /etc/ssh/sshd_config and run 'systemctl restart sshd'."
references: [CIS-5.2.4]
```

Validate it with `bulwarkctl rules validate <path>` before shipping. Full condition grammar and
collector list: [bulwark.nrl.ai](https://bulwark.nrl.ai).

## License

Apache-2.0. See [`LICENSE`](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).

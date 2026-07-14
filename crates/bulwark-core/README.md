# bulwark-core

[![crates.io](https://img.shields.io/crates/v/bulwark-core.svg)](https://crates.io/crates/bulwark-core)
[![docs.rs](https://img.shields.io/docsrs/bulwark-core)](https://docs.rs/bulwark-core)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/vietanhdev/bulwark/blob/main/LICENSE)

The engine behind [Bulwark](https://github.com/vietanhdev/bulwark), a Linux host security
scanner. This crate holds everything the two front-doors share: the collectors that read a
host's real configuration, the rule engine that evaluates declarative YAML rules against it,
the finding model, the SQLite store, and ClamAV integration.

If you want to *use* Bulwark rather than build on it, install the CLI
([`bulwarkctl`](https://crates.io/crates/bulwarkctl)) or the desktop app — both are thin
layers over this crate.

## What's in it

- **Collectors** (`collectors`) — read facts from the host: `sshd_config`, systemd units, cron,
  sudoers, `authorized_keys`, sysctl, kernel module blacklists, listening ports, file
  permissions, login.defs, GRUB, logging config, MAC (AppArmor/SELinux), shell history,
  process accounting, ClamAV presence, and file-integrity baselines. Each collector declares
  which OSes it supports and whether it needs root, so a check is never silently skipped.
- **Rule engine** (`engine`) — loads a directory of YAML rules, evaluates each one's condition
  against the collected facts, and emits findings. A rule that fails to parse is reported as a
  `RuleLoadError`, never silently dropped.
- **Condition DSL** (`condition`) — the small expression language rules are written in:
  `==`, `!=`, `in`, `contains`, `matches`, `<`/`>`/`<=`/`>=`, `and`/`or`/`not`.
- **Store** (`store`) — SQLite persistence for scan runs and findings, including
  reconciliation across runs so a recurring issue keeps its `first_seen` instead of appearing
  as new every scan.
- **Antivirus** (`av_scan`) — drives a real `clamscan` (one-shot or streaming) and parses its
  output into structured detections.

The bundled rule pack (59 rules across 11 categories, each with a severity, a plain-language
explanation, a one-line fix, and CIS/MITRE ATT&CK references) lives in the
[repository](https://github.com/vietanhdev/bulwark/tree/main/rules), not in this crate — point
the engine at whichever rules directory you want.

## Usage

```toml
[dependencies]
bulwark-core = "0.1"
```

```rust
use bulwark_core::{all_collectors, run_scan, Profile};
use std::path::Path;

let collectors = all_collectors();
// `privileged: false` — collectors needing root are skipped and listed in the result,
// rather than failing. The library never self-elevates.
let scan = run_scan(Path::new("rules"), &collectors, false, &Profile::current_host());

for finding in &scan.findings {
    println!("[{:?}] {} — {}", finding.severity, finding.rule_id, finding.title);
    println!("  fix: {}", finding.fix_hint);
}

for skipped in &scan.privileged_collectors_skipped {
    eprintln!("skipped (needs root): {skipped}");
}
```

Persisting a run and getting back only the findings that are genuinely new:

```rust
use bulwark_core::Store;

let mut store = Store::open(Path::new("bulwark.db"))?;
let new_findings = store.persist_and_reconcile(&scan)?;
# Ok::<(), anyhow::Error>(())
```

## Writing a rule

Rules are YAML, no Rust required:

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

See the [architecture guide](https://bulwark.nrl.ai) for the full condition grammar, the
profile/OS gating model, and the collector contract.

## Related crates

| Crate | Role |
|---|---|
| [`bulwarkctl`](https://crates.io/crates/bulwarkctl) | CLI front-door — scan a host from a terminal or over SSH |
| [`bulwark-agent`](https://crates.io/crates/bulwark-agent) | Background monitoring daemon (name reserved, in progress) |
| [`bulwark-proto`](https://crates.io/crates/bulwark-proto) | Agent wire types (name reserved, in progress) |

## License

Apache-2.0. See [`LICENSE`](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).

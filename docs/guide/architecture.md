---
description: >-
  How Bulwark's native Rust rule engine, collector model, and OS/profile system work — the
  architecture behind a Linux host security scanner built as a GUI-native alternative to
  Lynis and rkhunter.
---

# Bulwark — Linux Host Security Scanner

![Bulwark architecture: two front-doors over one Rust engine — collectors, the AI-assistant scanner, the log scanner and ClamAV feed a YAML rule engine; findings are explained, scored and stored locally; remote machines are scanned over SSH and alerts go to Telegram or e-mail](/diagrams/architecture.svg)

## TL;DR

Bulwark is a Tauri + Rust desktop app that scans a Linux host for security misconfigurations, intrusion indicators, and hardening gaps, using a native Rust engine that evaluates declarative YAML rules against collected system facts, then explains findings in plain language with a one-line fix. The single most important design decision: rules are native and declarative (a Sigma/Falco-style condition DSL), not a wrapper around Lynis/rkhunter — so the rule set can grow without recompiling, stays open to community contribution, and can cover attack patterns (like tunnel-service egress) that no existing tool names as a control.

## Status update

This document was written before implementation and has been revised to describe what actually shipped, not just what was planned. As of 0.15:

- **109 rules across 15 categories** (developer-tool settings — Git, SSH client, npm/yarn, pip and Docker options that switch a security check off — SSH/remote access, persistence, privilege escalation, defense evasion, credential exposure (plaintext credential stores, added in 0.11), filesystem permissions, network egress, kernel/sysctl hardening, logging/auditing, accounts & services, rootkit/malware indicators, file integrity, macOS hardening, Windows hardening), plus a dedicated 23-rule AI agent-security pass covering two dozen coding agents.
- **Both front-doors work end-to-end**: `bulwarkctl` (scan, rules list/validate, history) and `bulwark-app` (Tauri v2 + React GUI), sharing one `bulwark-core` engine and one local SQLite store, exactly as designed in §4.
- **Real ClamAV integration** — not a placeholder: live streamed per-file scan progress, real engine/database version and staleness reporting, and a distro-aware install command shown when ClamAV isn't installed at all.
- **File-integrity monitoring** for a curated set of security-relevant files, plus a background monitoring loop that re-scans on an interval and reconciles findings across runs.
- **A system tray icon** so closing the window hides the app instead of killing the monitoring loop — verified live against the real `org.kde.StatusNotifierWatcher` D-Bus registration, not just "no error thrown."
- **A Lynis-style hardening index** score on the Compliance view, computed the same way Lynis computes its own: only checks the stored scan records as evaluated (`rules_evaluated`) count, so a skipped, privileged-only or other-OS check is neither a pass nor a fail, and with no such record there is no score.
- **A profile system (OS + opt-in "needs")** is now built into the rule/collector model, and macOS and Windows have real collectors and their own checks (BLWK-MAC-*, BLWK-WIN-*) — see §17.

Sections below are the original design reasoning, updated in place where the as-shipped decision differs from the draft (notably §16's color decision). Section numbers are preserved since other project docs (`AGENTS.md`) reference them by number.

---

## 1. Problem

### What's broken today
Linux desktops are compromised through a well-worn, well-documented playbook: persistence via a rogue systemd unit tunneling remote access out through a service like ngrok, a remote-desktop service (VNC) left exposed with no password, SSH brute-forced after password auth gets quietly re-enabled, browser/OS-keyring credential theft, and exfiltration of cloud and API secrets sitting in plaintext `.env` files and shell history. Every one of these leaves static, after-the-fact traces — but is rarely caught *at the time*, because the tools that could catch it (Lynis, rkhunter, auditd, Wazuh) are individually solid yet CLI-only, snapshot-oriented, and not something a non-SOC developer actually installs and reads day to day. The gap isn't detection technology — it's that none of it is a friendly, GUI-native tool this audience will actually run.

### Who feels it
- **Primary:** solo Linux desktop developers and AI power users — people running increasingly capable local tooling and AI agents on their own machines, with no SOC, no existing HIDS deployment, but technical enough to act on a finding once it's explained.
- **Secondary:** future OSS adopters with the same profile, across more distros than just Debian/Ubuntu.

### Why now
The research groundwork is already done — a checklist grounded in Lynis's test categories, MITRE ATT&CK, and HackTricks/linPEAS (`research/2026-07-11-linux-security-checklist/report.md`) is directly enumerable into rules today. The marginal cost of starting now vs. later is pure execution time, not more research.

---

## 2. Goals and non-goals

### Goals (ranked)
1. **Catch real-world intrusion indicators with plain-language, actionable output** — breadth grounded in established frameworks (Lynis, MITRE ATT&CK Persistence/Credential Access/Defense Evasion, HackTricks/linPEAS), not a narrow, ad hoc list. See the research page.
2. **Be genuinely usable by a non-SOC developer** — GUI-native, explains *why* a finding matters and *how* to fix it.
3. **Ship as a real, installable, personal-tool-first OSS project** — `.deb`/`.rpm`/AppImage builds, without needing a team to maintain it.

**Update:** all three goals were met for v0.1 — see the Status update above and the research page for the sourced comparison.

### Non-goals (explicit)
- Real-time eBPF/syscall monitoring in v1 (Falco-class complexity) — v1 is on-demand/periodic scanning, "Lynis with a GUI."
- A full EDR/antivirus replacement — shells out to the system's own ClamAV installation for signature-based malware rather than reimplementing it.
- Wrapping Lynis/rkhunter as a backend — native Rust checks only (§13, Option A).
- Working macOS/Windows support in v1 — v1 was Linux desktop only, Debian/Ubuntu-first packaging. **No longer a non-goal:** the rule/collector *model* was made OS-aware (§17) so this could change without an engine rewrite, and it has: macOS and Windows now have a native CLI, a desktop app and a first set of checks, each verified on a real machine of that OS.
- A hosted/cloud dashboard or telemetry phone-home — fully local, no data leaves the machine, ever.
- **Sandboxed untrusted-code execution and autonomous "agents" are explicitly out of v1 scope**, but the architecture (crate boundaries, a generic executor pattern, Channel-based event streaming) is deliberately shaped so adding them later is a new workspace member, not a rewrite. See §4 and §14. Still true as of this update — neither has been started.

### Success metrics
- **Rule coverage** — v1 ships rules across all 11 categories in the research checklist. **Met**: 65 rules, 11/11 categories (73 rules in 12 categories as of 0.11; 91 in 14 with the macOS and Windows checks; 100 in 15 with the developer-tool settings).
- **Time-to-first-finding** — an unprivileged baseline scan completes and renders results in under 10 seconds; this explicitly excludes any time spent on a human entering a `pkexec`/`sudo` password, which is outside the app's control (see §10).
- **Dogfooding** — a fixture set of known attack-pattern indicators (rogue systemd persistence, exposed VNC, re-enabled SSH password auth, browser credential exposure, etc.) is encoded as rule unit tests and run against real machines.

---

## 3. Constraints

| Constraint | Value / limit |
|------------|---------------|
| Deadline | None fixed — personal tool sharpened into OSS, no external deadline pressure |
| Team / headcount | Solo-maintained |
| Budget | $0 — OSS; distribution via GitHub Releases |
| Existing stack | Tauri + Rust backend, React + Vite frontend. Cargo workspace ships both a GUI (`bulwark-app`) and a CLI (`bulwarkctl`) over the same `bulwark-core` library, so headless/SSH-only boxes are scannable without a display session. |
| Compliance / security | No formal compliance target, but findings reference CIS/MITRE ATT&CK IDs where applicable, leaving headroom for compliance-mapping later |
| SLA | None — desktop app, no uptime commitment |

---

## 4. High-level architecture

### System context (C4 L1)

```mermaid
flowchart TB
  user(["Linux desktop user"])
  sys["Bulwark<br/>scans, evaluates, explains"]
  os[["Linux host OS<br/>files, processes, config"]]
  polkit[["polkit / pkexec<br/>privileged elevation only"]]

  user -->|"runs scans, reviews findings"| sys
  sys -->|"reads system state<br/>(mostly unprivileged)"| os
  sys -->|"requests elevation"| polkit
```

### Container view (C4 L2)

```mermaid
flowchart LR
  ui["React UI (Tauri webview)"] -->|"IPC commands"| shell["Tauri Rust shell<br/>(bulwark-app)"]
  term["Terminal / SSH session"] -->|"args, stdout, exit code"| cli["bulwarkctl"]
  shell -->|"Secrets page: names and storage only"| access["bulwark-access<br/>passive readers"]
  access -->|"reads each tool's own files"| stores["AWS CLI, Docker, Git,<br/>npm, PyPI, kubeconfig…"]
  vault["aws-vault<br/>(preview, off by default)"] -->|"metadata only, no persistence"| access
  shell -->|"invoke scan"| core["bulwark-core"]
  cli -->|"invoke scan"| core
  core -->|"loads"| rules["rules/<br/>(YAML rule pack)"]
  core -->|"elevated collectors"| pkexec["pkexec (GUI)<br/>or sudo (CLI, see below)"]
  core -->|"findings stream"| channel["Tauri Channel"]
  channel --> ui
  cli -->|"findings<br/>(table or --json)"| term
  core -->|"persist (Diesel)"| db[("local SQLite<br/>~/.local/share/bulwark")]
  db -->|"shared history / diffing"| shell
  db -->|"shared history / diffing"| cli
```

**The Secrets page:** `bulwark-access` is a separate crate used only by the GUI. Its readers parse
each developer tool's own credential files into names, storage kind and expiry, never a value, and
keep the result in UI memory. It does not join the scanner, the SQLite store, background
monitoring, or any authentication path. See [Secrets](/guide/secrets) and the
[workbench section](#_18-the-desktop-workbench) below.

`bulwark-core` is not one engine but four, sharing a finding model and a store. Each answers a
question the others structurally cannot:

```mermaid
flowchart TD
  subgraph core["bulwark-core"]
    direction LR
    cfg["Config engine<br/>collectors → facts → YAML rules"]
    agent["Agent scanner<br/>ai_scan/"]
    av["Antivirus<br/>av_scan/ (shells out to ClamAV)"]
    logs["Log pipeline<br/>logs/ (decode → detect → correlate)"]
  end
  cfg --> store[("Store (Diesel)")]
  agent --> store
  logs --> store
  av -.->|"live results, not persisted"| ui2["UI / CLI"]
  store --> ui2
```

**Why the agent scanner and the antivirus are *not* collectors.** A collector is a fast,
sub-second read of a fixed host path, evaluated against a boolean YAML condition. Neither of those
two fits: `av_scan` shells out to a minutes-long ClamAV pass, and `ai_scan` walks a *discovered*,
machine-specific set of project directories, matches secrets with capturing regexes to compute
redaction spans, parses MCP JSON, and inspects files for invisible Unicode. None of that is
expressible in the condition DSL, and forcing it in would mean either breaking the "a scan is
under 10 seconds" budget or growing the DSL into a general-purpose language. They keep the *shape*
of a rule (id, severity, plain-language explanation, one-line fix, references) without pretending
to be one.

**`bulwark-core` has zero UI/Tauri/CLI-specific code.** Both `bulwark-app` (Tauri GUI) and `bulwarkctl` are thin front-doors over the same library crate — same collectors, same rule engine, same `Finding`/`Rule`/`ScanRun` model, same local SQLite history. A scan run from the CLI shows up in the GUI's history and vice versa, since they share one on-disk store rather than each keeping their own. This also means the CLI can ship and be dogfooded before the GUI is polished, and it's the only form factor that can reach a headless box (`ssh host 'bulwarkctl scan'`) — the case that matters most for catching lateral movement on a local network.

**Privilege model decision:** the GUI uses `pkexec` with a bundled polkit policy (`auth_admin`, so each privileged scan prompts — chosen over `auth_admin_keep` because caching authorization for the generic `org.freedesktop.policykit.exec` action would leave a several-minute window in which any `pkexec` could run without a fresh prompt; for a security tool an explicit prompt per elevation is the right trade). The exact binary run as root is pinned app-side (`resolve_cli_binary` resolves only the sidecar beside the app executable, no env/PATH override), since pkexec's generic action does not itself pin the target. The CLI does **not** use `pkexec` — `pkexec` depends on a running polkit authentication agent, which is normally GUI-session-bound and typically absent on a box reached only over SSH. Instead `bulwarkctl` requires the elevated subset to be run as `sudo bulwarkctl scan --privileged`; unprivileged checks run either way without elevation. This is a deliberate, resolved decision, not an open question — `sudo` has no GUI-agent dependency and is the one elevation path guaranteed to work identically in a local terminal and over plain SSH. When root is reached through `sudo` or `pkexec`, the CLI also refuses a findings database that another account can write to (the file, SQLite's side files, or any folder above them): a database is input a root process parses, and with a preserved `HOME` the default one sits in the invoking user's home. `--no-persist` or a root-only `--db-path` are the ways out; a real root login is not affected.

**Since v0.1 (implemented, not just reserved):** a system tray icon (`apps/bulwark-app/src-tauri/src/tray.rs`) keeps the app resident when the window is closed — the window's `CloseRequested` event is intercepted and the window is hidden rather than destroyed, so a background monitoring loop that's mid-interval keeps running. The monitoring loop periodically re-invokes the same `bulwark-core` scan path used by a manual "Scan" click and reconciles findings across runs (see §5).

**Future extension seam (still not built, deliberately):** `bulwark-sandbox` is not started, and `bulwark-agent` exists only as an empty placeholder crate in the workspace. `bulwark-core`'s executor and event-streaming pattern (a Tauri Channel for the GUI, a plain iterator/stream for the CLI) is written generically enough that a sandboxed-execution job or an agent action could plug into the same pattern instead of requiring a parallel system — see §14.

**Remote scanning and monitoring over SSH** (`bulwarkctl scan --ssh [user@]host` for a one-off, `bulwarkctl hosts …` and the GUI's **Remote hosts** page for scheduled monitoring) lives in the CLI front-door (`crates/bulwarkctl/src/remote.rs`, `hosts.rs`), **never** in `bulwark-core` — the core's no-network invariant (§10) is what backs the "fully local, no telemetry" claim, so anything that crosses the network is a front-door concern. What *can* be decided without a socket — the machine registry and its validation, scheduling and backoff, failure classification and its plain-language hints, health, and which events deserve an alert — is `bulwark_core::fleet`, so both front-doors share one set of rules. The GUI never links an SSH client: its `machines.rs` reads and edits the registry through core and runs the bundled CLI sidecar (`bulwark hosts test|trust|setup-key|scan --json`) for anything that connects. User-facing guide: [Monitoring other machines](/guide/remote-monitoring).

The model is **agentless by design** — this is the line between Bulwark and agent-based fleet platforms such as Wazuh. No agent runs on, and nothing listens on, a monitored machine between scans (a Linux machine needs nothing installed at all; a Mac or Windows machine needs Bulwark installed, which runs only when a scan asks for it); there is no manager server; findings stay on the operator's computer. That rules out real-time telemetry and SIEM-style correlation, and is meant to: the target is a developer or small team with a handful to a few dozen machines.

Transport is the system `ssh`/`scp`, which reuses the operator's `~/.ssh/config`, agent, jump hosts and multiplexing and keeps a security tool from reimplementing auth. The target is always one argv element after `--`, and is validated (`fleet::validate_spec`) so it can never be read as an option — `-oProxyCommand=…` would run a local command, and a scheduler replaying stored targets makes that a real surface. For the same reason a registered machine cannot carry free-form `-o` options (only port, key file and a validated ProxyJump chain); anything else goes in `~/.ssh/config`. Unattended runs force `BatchMode=yes`, `StrictHostKeyChecking=yes`, connect/keep-alive timeouts and a hard deadline per command, so nothing ever waits on a prompt, and an unknown or changed host key is refused. Host keys the user approves in Bulwark go to Bulwark's own `known_hosts` (added via `GlobalKnownHostsFile`, so the user's `UserKnownHostsFile` setting is untouched); `~/.ssh` is never edited. Approval reads the key from ssh's own handshake with **every authentication method disabled**, so no credential is offered to an unverified machine, and it works through jump hosts and aliases where `ssh-keyscan` cannot; the user compares the fingerprint, and only a key whose fingerprint they confirmed — re-fetched at that moment — is written. A password-only account can be switched to Bulwark's dedicated ed25519 key, installed as `restrict …` (no forwarding, no PTY), with the password passed once through a `0600` askpass file and never stored. When a key file is set, `IdentitiesOnly=yes` stops a full agent from tripping `MaxAuthTries` before the named key is offered — a failure found only against a real sshd.

The engine is untouched: we run the *same* `bulwarkctl scan --json` on the far side and deserialize its stdout back into a `ScanRun`. One probe round-trip reports the installed engine (and its version), CPU arch, OS and — if root checks are on — whether `sudo -n` works and whether it is blanket `NOPASSWD: ALL`; bootstrap is "prefer installed, else push" (arch-checked, into a `mktemp -d`, removed afterwards). The connection check turns those facts into security advice (dedicated key, non-root login, scoped sudo, installed engine) — flexible about what works, explicit about what is better.

Because the `findings` table has no host column (the local DB is single-host by design), a remote scan **must not** persist into it — reconciliation would resolve local findings whose rules the remote run happened to evaluate. Each registered machine persists to its own database (`remotes/<machine-id>.db`, beside the main one), keyed by a stable id so renaming a machine keeps its history. Two more guards protect that history: a scan that loaded zero rules is refused (as locally), and a machine is pinned to the hostname it reported on its first successful scan — if the address later answers as a different machine, the scan is refused and nothing is merged until the user accepts the new identity.

Health is derived from the **last attempt**, not the last stored findings, so a machine that stops answering is shown as unreachable (after three consecutive failures) or stale, never as clean. Connectivity failures back off (interval doubled per failure, capped at 6 h); failures that need a person do not. The registry is migration `2026-11-01-000000_remote_hosts`.

```mermaid
flowchart LR
  subgraph local["Operator's computer"]
    gui["GUI machines.rs<br/>(scheduler, 3 at a time)"] -->|"bulwark hosts scan --json"| cli["bulwarkctl hosts"]
    cron["cron: hosts scan --due"] --> cli
    cli --- fleet["bulwark_core::fleet<br/>(registry, health, alerts)"]
    cli --> reg[("bulwark.db<br/>remote_hosts")]
    cli --> perhost[("remotes/&lt;id&gt;.db")]
    cli -->|"alerts (curl)"| out["Telegram / SMTP"]
  end
  cli -->|"probe: engine, arch, sudo"| host["remote machine"]
  cli -->|"installed? run it : scp → run → rm -rf"| host
  host -->|"scan --json stdout"| cli
```

**Alerts** (`bulwarkctl notify …`, GUI Settings → Alerts) are the one other place Bulwark sends anything off the machine, and only once the user configures a channel. `fleet::alerts_for_attempt` decides *when* (new issues above a severity, unreachable after three failures — not every blip — back online, and identity/host-key changes immediately), the CLI delivers through the system `curl` (Telegram Bot API over HTTPS; SMTP with TLS required except to a localhost relay), and a round of scans produces one message per channel. Settings are in the database; the bot token and SMTP password are in a separate `0600` `notify-secrets.json` and reach curl over stdin, never argv. A delivery failure never fails a scan; it is recorded and shown in the app.

**Autofixes** (`bulwarkctl fix …`, plus `ssh protect` and `ai redact`) turn the safe, mechanical subset of each finding's one-line `fix` into a one-command remediation. The logic is in `bulwark-core::remediation` (filesystem-only, still no network): `permissions.rs` tightens over-permissive modes for `~/.ssh` (user-scoped) and sensitive `/etc` files (root), and `sshd.rs` hardens `sshd_config`. Every fixer follows the same discipline the existing `ssh_keys` passphrase fix and `ai_scan` redaction already do — **dry-run by default**, reversible (permission changes record the prior mode; the sshd rewrite keeps a backup and validates with `sshd -t` before keeping it, rolling back on failure), never widens access, never follows a symlink, and fails loud. The sshd rewrite inserts an idempotent `# BEGIN/END bulwark-hardening` block at the **top** of the file so that under OpenSSH's first-value-wins semantics it beats any `Include` drop-in without editing them, and only writes a directive when the effective config is actually insecure per the matching `BLWK-SSH-*` rule. It plans against the config as sshd reads it now, managed block included, so a second run writes nothing; when it does rewrite the block it keeps every line already there, and each rewrite is backed up under a new timestamped name. A directive set in a `Match all` block is out of its reach (sshd copies those values over the global ones) and is reported, not written. The two directives that can lock an operator out of a password-only box (`PasswordAuthentication no`, `PermitRootLogin no`) are gated behind an explicit `--include-auth` and excluded from `fix all`.

---

## 5. Data model

`Rule` is YAML source, not DB-stored — modeled here alongside the two real tables for the
engine's sake, since a `Finding` is what you get when a `Rule`'s condition matches a fact row
from a given `ScanRun`.

```mermaid
erDiagram
    Rule ||--o{ Finding : "matches produce"
    ScanRun ||--o{ Finding : "contains"

    Finding {
        uuid id PK
        text rule_id FK "e.g. BLWK-SSH-001"
        enum severity "critical, high, medium, low, info"
        text title
        text explanation "rendered from the rule's template"
        text fix_hint "suggested command or action"
        json context "raw fact snippet that triggered the rule"
        timestamptz first_seen
        timestamptz last_seen
        enum status "open, acknowledged, resolved"
        uuid scan_run_id FK
    }

    ScanRun {
        uuid id PK
        timestamptz started_at
        timestamptz finished_at
        text host_fingerprint "hostname plus kernel version"
        int rules_loaded
        int rules_failed "never silent, always surfaced"
        int collectors_failed "never silent, always surfaced"
    }

    Rule {
        text id PK "e.g. BLWK-SSH-001, YAML file, not DB-stored"
        text title "becomes Finding dot title"
        text category "one of 15 categories"
        enum severity
        text collector "which collector produces the fact this rule reads"
        expr condition "boolean condition over the collector output"
        text explain "plain-language template"
        text fix "suggested command or action"
        list references "CIS and MITRE ATT&CK IDs"
    }
```

### Ignores and custom rules

What a user hides is stored next to the findings, never instead of them: whole rules in
`rule_suppressions`, single findings in `finding_ignores` keyed on `(rule_id, location)` (the file,
`port N on ADDR`, or the title — no line numbers, so an ignore survives edits). Both need a reason and
both append to `rule_suppression_events`. One predicate (`Ignores::covers`) partitions findings
everywhere they are counted or alerted on. User-written rules load from `~/.config/bulwark/rules`
beside the shipped pack through the same parser; `BLWK-` ids and ids the pack already uses are
refused, and root scans never read that folder implicitly. See the guide page
[Choosing what Bulwark checks](/guide/custom-checks).

### Condition grammar (v1)

A condition is a boolean expression over the named fields a collector produces — no cross-collector joins in v1 (one rule reads one collector's output; matches Sigma's per-logsource scoping). Grammar: field references (`sshd.password_authentication`), comparison operators (`==`, `!=`, `in`, `contains`, `matches` for regex, and `<` `>` `<=` `>=` for numeric thresholds like password-aging policy), and boolean combinators (`and`, `or`, `not`), parenthesized for precedence — deliberately a subset of Falco's filter syntax, not a new language.

```yaml
id: BLWK-SSH-001
title: SSH password authentication is enabled
category: ssh-remote-access
severity: critical
collector: sshd_config
condition: sshd.password_authentication == "yes"
explain: >
  PasswordAuthentication is set to "{{ sshd.password_authentication }}" in sshd_config,
  which allows brute-force login attempts.
fix: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd."
references: [CIS-5.2.10, ATTACK-T1110]
```

A collector's output is a flat map of fields (`{password_authentication: "yes", permit_root_login: "yes", ...}`), so writing a new rule against an existing collector never touches collector code, only YAML. Collectors that produce lists (listening ports, cron entries) expose them the same way, evaluated one row at a time. <code v-pre>{{ }}</code> interpolation applies to both `explain` and `title` — templating `title` too (not just `explain`) was added after list-shaped rules sharing one static title read as duplicates in the UI even though each row was a genuinely distinct finding.

### Reconciliation (implemented)

A finding is considered "the same" across scan runs if its previously-stored `context` is a **subset** of the newly-collected `context` (`store::is_context_subset`), not exact equality. This tolerates a collector gaining new fact fields over time — extending a collector no longer silently breaks identity-matching for its existing rules and producing a spurious duplicate row, which is exactly what happened before this was fixed: `login_defs.rs` gained two new fields and the exact-string match immediately started duplicating `BLWK-ACCT-002`. On a match, both `last_seen`/`scan_run_id` and `context` are updated (previously only the former), so a finding's displayed context always reflects its most recent scan.

### Access patterns
- **Read path:** the UI/CLI queries the latest `ScanRun`'s findings, grouped by severity/category; prior runs are diffed to show new-vs-resolved findings over time.
- **Write path:** the scan engine emits `Finding`s over a stream as they're produced (streamed, not batched); on completion, findings are persisted to local SQLite in one transaction.
- **Index strategy:** local SQLite via **Diesel**, indexed on `(rule_id, status)` and `(scan_run_id)` — single-host scale, at most a few thousand rows; nothing heavier is needed.
- **Why an ORM.** Queries go through Diesel's typed DSL rather than SQL strings, so the columns a query touches are checked against `schema.rs` at *compile time*: renaming a column fails the build at every site that needed updating, instead of at runtime on a user's machine. That is not hypothetical — it is how a column previously drifted out of sync with the code reading it. The only raw SQL left is `PRAGMA` and schema introspection, neither of which is a query *over* the schema. The pre-ORM schema-detection helper allows `clippy::redundant_field_names`: its local Diesel `QueryableByName` derive emits a redundant initializer that Rust 1.99 flags. The allowance is confined to that helper so it covers the generated implementation; workspace Clippy still denies warnings.
- **Migrations are embedded and append-only** (`crates/bulwark-core/migrations/`). A database already stamped with a migration will never re-run it, so editing one silently splits users into two different schemas depending on when they first installed. Add a new migration directory instead.
- **Foreign keys are enabled explicitly** per connection. SQLite leaves them *off* by default, which had quietly made `findings.scan_run_id → scan_runs.id` decoration rather than a constraint.

### Log-analysis pipeline (decode → detect → correlate)

The config scanner above answers "is this machine's *state* wrong right now." A second, parallel pipeline (`bulwark-core::logs`, driven by `bulwarkctl logs scan`) answers "what *happened* over time" — the class of intrusion signals that only exist in logs: SSH brute-force, invalid-user scans, sudo/su abuse, direct root logins. It is modeled on OSSEC's decode→detect→correlate design (the part of OSSEC that aged well and Wazuh kept) while deliberately avoiding OSSEC's dated internals (XML rule language, a single global backward-scanned event list, mutable counters on shared rule objects, `frequency + 2` semantics).

Three stages, each stage reusing the config engine's machinery where it fits:

- **Source** (`logs::source`) — a `LogSource` trait yielding normalized `RawEvent`s. `JournaldSource` shells out to `journalctl -o json` (the shipped driver on a systemd host; no `libsystemd` linkage); `SyslogLinesSource` parses classic `Mon DD HH:MM:SS host prog[pid]: msg` from any reader, powering `--from-file`, tests, and a future offset-tracking file tailer.
- **Decode** (`logs::decoder`) — YAML decoders under `decoders/` own "get `srcip`/`user` out of *this* vendor's line": a coarse `program` bucket (with `program_aliases` for a daemon that logs under several names: OpenSSH 9.8 and later log logins as `sshd-session`, not `sshd`) → optional cheap `prematch` guard → ordered capture-regex `patterns` (named captures become fact fields; the matched pattern's `tags` become the event's `tags` array). A decoded line **is a `Fact`** — the same `BTreeMap<String, Value>` collectors produce — so the detect stage is pure reuse.
- **Detect + correlate** (`logs::rule`, `logs::correlate`, `logs::run_log_scan`) — YAML log rules under `log-rules/` match decoded facts with the **existing condition DSL, unchanged** (`tags contains "authentication_failed"` is OSSEC's `if_group`, no new operator). A rule with no `correlate` block fires per matching event; with one, matches feed a **keyed sliding-window correlator**: `(rule_id, group_key) → VecDeque<event_timestamp>`, evict older than `now − window_secs`, fire when the window reaches `count`. That's an honest group-by (per-`srcip`, per-`user`), O(1) amortized per event, and shardable — not OSSEC's O(history) global scan. **The clock is always the event's own timestamp, never wall-clock**, so replaying a batch of old logs correlates exactly as it would have live, and every test is deterministic. `suppress_secs` gives per-key flood control; `MissingField` on a rule's condition is a non-match (log events are heterogeneous), not an error.

Output is a `LogScanRun` of `LogFinding`s (event-shaped: timestamped, carrying the correlation key and count), persisted to their own `log_scan_runs`/`log_findings` tables (schema migration V3) and reconciled on `(rule_id, group_key)` — a recurring brute-force from one IP is one row whose `occurrences` climbs, not a flood of duplicates. Kept separate from the config `scan_runs`/`findings` because the two have genuinely different lifecycles (config findings persist until fixed; log alerts recur) and reconciliation identities.

**Scope (v1):** one-shot batch only, and *threshold* correlation (N events per key in a window). Deliberately deferred: **sequence** correlation (A-then-B across groups, e.g. "auth failures *followed by* a success"); continuous **follow mode** — which is just `run_log_scan` driven by a following `JournaldSource`, and is the concrete first job of the currently-empty `bulwark-agent` daemon; a persisted-offset file tailer; and any active response (log findings stay advisory, like every other Bulwark finding).

---

## 6. API / contracts

There's no network API — the "client" and "server" are the same process, exposed two ways.

### Tauri IPC commands (GUI)

| Command | Purpose | Auth |
|---------|---------|------|
| `secrets_detect` | Which secrets managers this build offers and whether each has files here (existence checks only) | none |
| `secrets_inventory` | One manager's inventory: names, storage kind, expiry; `provider` is matched against a fixed list | local user; no value is read |
| `access_aws_snapshot` | Preview, off unless `BULWARK_AWS_VAULT_PREVIEW=1`: AWS Vault profile metadata through a fixed, bounded subprocess | local user; authenticate separately in a terminal |
| `scan_start` | Kick off a scan; streams findings via Channel as they're produced | none (local single-user) |
| `history_list` / `history_count` | The 50 most recent `ScanRun`s for History, and the total number of runs | none |
| `dashboard_snapshot` | What a newly opened window shows: the stored open findings and the last scan, so the app never starts blank after a background scan | none |
| `finding_ignore` / `finding_unignore` / `rule_suppress` / `rule_unsuppress` / `suppressions_list` / `suppression_audit` | Ignore one finding or turn a whole check off (a reason is required), undo either, and read the audit trail | none |
| `rules_list` | List the loaded rules (built-in and your own) with their `explain`/`fix` text for the Rule catalog; `custom_rules_info` reports rules that were refused or failed to load | none |
| `scan_privileged` | Runs the bundled CLI as `pkexec <cli> scan --privileged --json` and replaces the finding list with its result; no collector logic is duplicated in the app | polkit prompt |
| `run_virus_scan` | Streams ClamAV progress (`FileScanned`/`ThreatFound`/`Complete`/`Error`) via Channel | none |
| `clamav_info` | Reports installed engine/database version, or a distro-aware install command if absent | none |
| `monitoring_get_status` / `monitoring_set_enabled` / `monitoring_set_interval_minutes` | Query/configure the background re-scan loop | none |
| `machines_list` / `machine_add` / `machine_update` / `machine_remove` / `machine_findings` / `machines_set_enabled` | The Remote page's registry and stored results, read and written through `bulwark_core` (no network) | none |
| `machine_test` / `machine_trust` / `machine_setup_key` / `machine_scan_now` / `machines_scan_all` | Anything that connects — run through the bundled CLI (`bulwark hosts … --json`) | none (remote `sudo -n` only) |
| `ssh_suggestions` | Host aliases from `~/.ssh/config` and key files in `~/.ssh`, for the add-machine form | none |
| `notify_status` / `notify_configure` / `notify_test` / `notify_report` / `notify_telegram_chats` | Telegram / e-mail alert settings (secrets write-only) and delivery via the CLI | none |

### CLI commands (`bulwarkctl`)

| Command | Purpose | Exit code |
|---------|---------|-----------|
| `bulwarkctl scan` | Run unprivileged checks only and print a short report (`crates/bulwarkctl/src/report.rs`): one line per problem, grouped by check, worst first, with why it matters and the first fix step; low/info items folded behind a count; a footer saying what the scan could *not* check (admin-only areas, checks that couldn't run, failures, ignores) — a clean result reads "nothing to fix from the checks that ran", never "all clear". Colour only on a terminal, never with `NO_COLOR` | `0` clean, `1` findings ≥ medium, `2` findings ≥ critical (CI-friendly; ignored findings don't count) |
| `bulwarkctl scan --all` | Same, plus low-priority items and every place each problem was found | same as above |
| `bulwarkctl --rules-dir <dir> …` | Use a rules folder instead of the pack built into the binary (also `BULWARK_RULES_DIR`; `--log-rules-dir`/`--decoders-dir` for `logs scan`). Without it, the binary uses the rule pack compiled into it — it is a single file that runs from anywhere | — |
| `bulwarkctl scan --privileged` | Full scan; must be run under `sudo` (see §4) | same as above |
| `bulwarkctl scan --json` | Same as `scan`, machine-readable output | same as above |
| `bulwarkctl rules list` | List loaded rules, including load failures | `0` / `1` if any rule failed to load |
| `bulwarkctl rules validate <path>` | Lint a rule file without running a scan (used in CI for the bundled pack) | `0` valid / `1` invalid |
| `bulwarkctl fim baseline` | Record the current hashes of the watched files as the known-good baseline. Never runs automatically — a baseline taken *after* a compromise would enshrine it as clean | `0` |
| `bulwarkctl fim baseline --privileged` | Also baseline the root-only paths (`/etc/shadow`, `/etc/sudoers`); refuses unless run as root | `0` |
| `bulwarkctl history [--limit N]` | List past scans (shared with the GUI's history): date, how many checks ran, whether it had admin rights, findings by severity | `0` |
| `bulwarkctl scan --ssh [user@]host` | One-off scan of another machine over SSH; results in that machine's own history | like `scan` |
| `bulwarkctl hosts add\|list\|set\|remove\|show` | Manage the machines Bulwark monitors (shared with the GUI's Remote page) | `0` |
| `bulwarkctl hosts test <machine>` | Step-by-step connection check with the fix for each failure, plus connection-security advice | `0` ready / `3` not ready |
| `bulwarkctl hosts trust <machine> [--fingerprint F [--replace]]` | Show / approve a machine's host key into Bulwark's own known_hosts | `0` |
| `bulwarkctl hosts setup-key <machine> [--password-stdin]` | Install Bulwark's restricted monitoring key, signing in once | `0` / `3` |
| `bulwarkctl hosts scan <machine…> \| --all \| --due` | Scan and record; `--due` for cron | like `scan`, `3` if any machine couldn't be scanned |
| `bulwarkctl notify telegram\|email\|status\|test\|report\|disable` | Configure and use Telegram / e-mail alerts | `0` / `3` if delivery failed |
| `bulwarkctl logs scan` | Decode + correlate the current boot's journal (or `--since=<spec>` / `--from-file <path>`); `--json` for machine-readable output | `0` clean / `1` ≥medium / `2` critical, like `scan`; `2` also when nothing could be analysed (no events read, none understood, or no decoders/rules), with no check mark |
| `bulwarkctl logs rules list` / `rules validate <path>` | Inspect the log-rule pack; `validate` also cross-checks each rule's `decoder:` names a real decoder | `0` / `1` |
| `bulwarkctl logs decoders list` / `decoders validate <path>` | Inspect the decoder pack | `0` / `1` |

There is no traditional authn/authz layer — this is a single-user local app; the OS login session is the trust boundary, and `pkexec` (GUI) / `sudo` (CLI) are the only elevation gates (see §10).

### Streamed event shape
```json
{
  "event": "finding",
  "data": {
    "rule_id": "BLWK-SSH-001",
    "severity": "critical",
    "title": "SSH password authentication is enabled",
    "explanation": "PasswordAuthentication is set to 'yes' in sshd_config, which allows brute-force login attempts.",
    "fix_hint": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd.",
    "context": { "file": "/etc/ssh/sshd_config", "line": 42, "value": "yes" }
  }
}
```

### Error shapes
Collector failures (e.g. `sshd_config` unreadable, elevation denied) surface as explicit `collector_error` events alongside findings, never a silent drop — a check that fails silently is worse than a check that doesn't exist, because it creates false confidence.

---

## 7. Sequence flow — happy path

```mermaid
sequenceDiagram
  actor User
  participant UI as React UI
  participant Shell as Tauri shell
  participant Core as bulwark-core
  participant Pol as pkexec
  participant DB as local SQLite

  User->>UI: click "Scan"
  UI->>Shell: invoke scan_start
  Shell->>Core: run(rules, collectors)
  Core->>Core: run unprivileged collectors (parallel)
  Core->>Pol: request elevation for privileged collectors
  Pol-->>Core: granted (one-time)
  Core->>Core: evaluate rules against collected facts
  loop per finding
    Core-->>Shell: finding (via Channel)
    Shell-->>UI: finding (streamed, animated in)
  end
  Core->>DB: persist ScanRun + Findings
  Core-->>Shell: scan_complete
  Shell-->>UI: scan_complete (summary)
```

The CLI path is identical minus the Tauri/React layer: `bulwarkctl` calls `bulwark-core` directly and prints each finding as it arrives instead of streaming it over a Channel. The background monitoring loop reuses this exact same path on a timer, so there is no separate "monitoring" code path to keep in sync with the manual scan path.

---

## 8. Failure modes

| Failure | Likelihood | Impact | Detection | Mitigation |
|---------|------------|--------|-----------|------------|
| Privileged collector's elevation denied or not run (`sudo` omitted on CLI, polkit prompt denied on GUI) | Medium | Partial scan — some categories skipped | Explicit "N checks skipped (no privilege)" banner/line, never silent | Re-run just the privileged subset without a full rescan |
| Rule file has invalid YAML/condition syntax | Low-medium (rises as community rules grow) | That rule silently fails to load | Rule-load validation at startup; `rules_failed` count surfaced in `ScanRun` | `bulwarkctl rules validate` (§6); CI lint on the bundled rule pack |
| A collector hangs (e.g. a spawned process never returns) | Low | Whole scan stalls | Per-collector timeout (5s default) | Collector reported as timed-out; scan continues without it |
| Host has an unusual layout (non-systemd init, non-Debian distro) | Medium (v1 targets Debian/Ubuntu) | Irrelevant checks or false negatives | Each collector declares its own applicability precondition (e.g. "requires systemd") | Collector skips gracefully, excluded from coverage stats — never reported as false "clean" |
| A collector's fact shape changes (new fields added) | Realized once, fixed | Would silently duplicate existing findings on the next scan | Reconciliation tests (`reconcile_tolerates_a_collector_gaining_new_context_fields`) | Subset-match reconciliation (§5), not exact-string context equality |
| An sshd drop-in the scan may not read (`sshd_config.d/50-cloud-init.conf` is mode `600` on cloud images) | Realized, fixed | The unreadable file was skipped, so an ordinary scan reported the SSH settings of the *other* files as the whole truth and closed the findings a root scan had opened | A matched `Include` file that cannot be read fails the collector; a permission error on an unprivileged scan is listed under `privileged_collectors_skipped` ("needs admin rights"), any other read error is a collector error | The SSH rules are not evaluated for that scan, so nothing is reported and nothing is resolved |
| **The rule pack can't be found** — mistyped `--rules-dir`, emptied directory, mispackaged build | Realized, fixed | A scan of *nothing* reported as a clean host: exit 0, empty findings, no error — and persisting it resolved every open finding, wiping the dashboard | `rules_loaded == 0` is now a hard error in both front-doors (`rules_dir_guard.rs`) | An explicit `--rules-dir`/`BULWARK_RULES_DIR` that isn't a directory fails outright rather than falling back to the auto-detected pack |

That last row is the invariant of §8 in its purest form. "0 findings" from a scan that evaluated
nothing is not a clean bill of health — it is the *absence of an opinion*, and it is
indistinguishable from a genuinely healthy host, which makes it the most dangerous thing this tool
can say. The log pipeline had guarded against it since it shipped; the config scan did not, and a
rules directory that simply wasn't there produced a confident, silent, green result. Both front-doors
now refuse.

### How `sshd_config` is read

The SSH rules judge the value sshd uses, not the text of one file, so the collector applies sshd's
own rules. Each was taken from `sshd_config(5)` and OpenSSH's `servconf.c` and checked against
`sshd -T` on a real server (the two `ssh-includes-*` end-to-end fixtures keep a sample of them).

```mermaid
flowchart TD
  L["Next line"] --> T["Split it like sshd: quotes removed,<br/>trailing comment dropped, Key Value or Key=Value,<br/>keyword in any case"]
  T --> M{"Match line?"}
  M -->|"Match all"| GA["Lines below apply to every connection<br/>and override the global value"]
  M -->|"any other Match"| C["Lines below are conditional:<br/>skipped until the next Match"]
  M -->|"no"| I{"Include?"}
  I -->|"yes"| G["Expand every pattern on the line:<br/>glob wildcards, relative to /etc/ssh,<br/>files in name order"]
  G -->|"a matched file cannot be read"| U["Result undetermined:<br/>SSH rules are not evaluated"]
  G -->|"read"| L
  I -->|"no"| V["Keep the first value seen<br/>for the keyword"]
```

- A directive that is absent has OpenSSH's compiled-in default, so `PasswordAuthentication` is
  `yes` on a file that never mentions it.
- A conditional `Match` block (one user, group or address) never changes the host-wide value. A
  `Match` inside an included file ends with that file.
- `Match all` matches every connection. sshd copies what such a block sets over the global values,
  so `PasswordAuthentication no` followed by `Match all` and `PasswordAuthentication yes` accepts
  passwords. Keywords that are not allowed in a `Match` block (`StrictModes`,
  `PermitUserEnvironment`) are the exception: there the first line wins as usual.
- Bytes that are not UTF-8 are replaced, not refused: one Latin-1 character in a comment must not
  hide the lines around it.
- Each value the rules read carries the file that set it (`password_authentication_from`, or
  "OpenSSH's built-in default"), so a finding says where to change it.

### Vendor configuration in `/usr/etc`

openSUSE Tumbleweed and Leap 16 keep a package's defaults under `/usr/etc` (PAM's under
`/usr/lib/pam.d`) and leave `/etc` for what the administrator changes. There, `/etc/ssh/sshd_config`,
`/etc/sudoers` and `/etc/login.defs` do not exist, and the collectors used to call themselves "not
applicable": every SSH check, the passwordless-sudo check and the password-age checks silently did
not run. `crate::etc` now answers "which file does this program read" in one place, with rules
measured with the programs themselves (`sshd -T`, `sudo -l`, `useradd`, a PAM service set to deny):

```mermaid
flowchart LR
  E{"/etc copy exists?"} -->|"yes"| W["Read it, and only it<br/>(the vendor file is ignored whole)"]
  E -->|"no"| V["Read the /usr/etc copy"]
  W --> D["login.defs only: then apply *.defs drop-ins<br/>/usr/etc/login.defs.d first, /etc/login.defs.d after,<br/>later file wins key by key"]
  V --> D
```

- **sshd, sudo**: the `/etc` file replaces the vendor file whole, its `Include` lines with it. The
  vendor files include the `/etc` drop-in folder before their own, so a drop-in in `/etc` wins.
- **login.defs** through libeconf (openSUSE, and Fedora too): drop-ins are `*.defs`, not `*.conf`;
  within one file the first line for a key wins. Without libeconf (Debian, Ubuntu) only
  `/etc/login.defs` is read and the last line wins. The collector tells the two apart by whether
  `useradd` links libeconf, reading the program without running it.
- **PAM**: each service file is looked for in `/etc/pam.d`, then `/usr/lib/pam.d`, then
  `/usr/etc/pam.d`.

The fixers never write under `/usr/etc` (the next package update replaces it) and never create the
missing `/etc` file (it would replace every vendor setting). On such a system `fix sshd` and
`fix login-defs` show their plan and say which drop-in to create; `--apply` refuses. The
file-integrity watch covers both copies of each file.

---

## 9. Scalability

Reframed as rule-set and scan-performance growth, since there's no multi-tenant traffic.

- **Current load:** single host, 109 rules.
- **Expected load:** community-contributed rules could grow into the hundreds over time — Lynis's own documentation describes "hundreds" of individual tests, a directionally useful reference ceiling.
- **Breaking point:** naively re-running a collector for every rule that references it duplicates work once dozens of rules share one collector (e.g. many SSH rules all reading `sshd_config`).
- **Scale-out plan:** not distributed — collectors are memoized per scan run (collect once, evaluate N rules against the cached fact), and independent collectors run concurrently.

The config scan is cheap and bounded (tens of files, ~0.1s). The AI scan is the one that has to
scale, because its input is the user's whole history: a developer with a year of Claude Code use has
~1,800 transcripts and ~900 MB of them, and every one gets run through a 261-rule secret pack.

### The leading-wildcard trap (realized, fixed)

Most rules in the vendored gitleaks pack open with an *optional variable-length wildcard*:

```text
(?i)[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|:)…([a-zA-Z0-9]{40})
     ^^^^^^^^^^^^^ matches no useful text — and costs ~6000× the runtime
```

That prefix exists only to pull neighbouring characters into the reported match, but it is
catastrophic for the `regex` crate: a pattern that *begins* with a variable-length character class
has no literal prefix, so the engine cannot build a memchr/Teddy prefilter and must attempt a match
at every byte offset, while the nested bounded repeats blow out the lazy-DFA cache until it falls
back to a far slower engine. Measured on one real 4 MB transcript, a single such rule took **2.9 s**;
with the prefix stripped it took **0.5 ms** and found exactly the same matches. Across ~40 candidate
rules and ~1,800 transcripts that was the difference between a scan that finishes in seconds and one
that pegs half the machine's cores for hours — the actual "Bulwark eats my CPU" bug.

`secrets::drop_leading_wildcard` removes that prefix when the pack is built, so the vendored rule
file stays pristine and re-syncable with upstream gitleaks. The rewrite is sound because the prefix
is optional and leading: for an unanchored search, `PQ` matches iff `Q` matches, so no detection can
appear or disappear — only the *start offset* of the whole match moves, and that offset feeds nothing
but overlap dedup, where a narrower span can suppress strictly fewer findings. The secret itself is
capture group 1 and is untouched.

The danger of an optimisation like this is a scanner that silently stops finding keys, so it is
pinned by a differential test (`rewriting_a_pattern_never_changes_what_it_matches`) that compiles
**both** the original and rewritten form of every rule and asserts they capture identical secrets at
identical offsets over a corpus built to make the pack fire. Anything not matching the exact expected
shape — a required (`{5,50}`) prefix, an exact count, a rule with no capture group whose whole match
*is* the reported secret — is left alone: a rule that stays slow is a bug, a rule that quietly stops
matching is a vulnerability.

### Validating the rule pack (and what that surfaced)

262 vendored regexes are not self-evidently correct, and until recently nothing checked that any
individual rule still *worked*. `every_bundled_rule_compiles` proved a pattern parses — it said
nothing about whether the rule could still catch its own key. Two tests, modelled on gitleaks'
`Validate(rule, tps, fps)`, close that:

```mermaid
flowchart LR
  R[Rule's own regex] -->|rand_regex| TP[Generated secret]
  TP --> P{The pack}
  FP[(gitleaks false positives<br/>378 fixtures, 79 rules)] --> P
  P -->|must fire| OK[Detection coverage]
  P -->|must stay silent| NO[No false positives]
```

- **True positives are generated, never written down.** A secret is synthesised *from each rule's own
  pattern* (`rand_regex`, mirroring gitleaks' `secrets.NewSecret`), dropped into the kind of line it
  really leaks in, and the pack must report it. Every rule gets a real sample, the corpus re-syncs
  itself when the pack does, and — because a 40-character high-entropy literal sitting next to the
  word `aws` is indistinguishable from a live key to every scanner on earth, GitHub's push protection
  included — nothing secret-shaped is ever committed.
- **False positives are vendored** (`tests/data/gitleaks_false_positives.toml`): the placeholders,
  documentation keys, wrong-length tokens and low-entropy dummies gitleaks records for each rule. A
  scanner that flags everything is as useless as one that flags nothing, and the way a rule usually
  breaks is by getting *broader* — which every "does it catch the key" test in the world will pass.

The first run of these tests failed, and each failure was a real defect:

| Defect | Consequence | Fix |
|---|---|---|
| The pack's **allowlists were never parsed** | Every rule inherited gitleaks' false positives without gitleaks' suppression: `curl -u "${user}:${pass}"` reported as leaked credentials, Google's published `AIzaSy…` doc keys reported as live GCP keys | `Allowlist` — the `regexes`/`stopwords` were shipping in `secret_rules.toml` and read by nobody |
| One allowlist regex **silently failed to compile** | gitleaks writes RE2, where a literal <code v-pre>{{</code> is legal; Rust's `regex` rejects it. The one pattern suppressing <code v-pre>${{ env.PASS }}</code> was dropped by a `filter_map(…ok())` | `literalize_braces`, plus `every_allowlist_regex_compiles` — a dropped allowlist is a *silent false positive*, which is why it's an assertion and not a log line |
| **`path` conditions were ignored** | `nuget-config-password` means something in a `nuget.config` and nothing anywhere else; applied to every file, any `sk_…`-shaped string in a chat transcript was a "leaked credential" | `Rule::applies_to` — the scan and redaction now both pass the artifact's real path |

On a real home directory the result is ten fewer false positives — every one of them a placeholder or
a test fixture quoted inside a transcript (`-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...`, a dummy
`ghp_0123…uvwxyz`) — with no true positive lost.

A later dogfooding pass found one more, of a different kind. The keyword index is a **file-level**
prefilter: a rule runs if its keyword appears *anywhere* in the file. That is fine for a rule whose
pattern carries its own marker (`ghp_…`, `AKIA…`), but `sourcegraph-access-token` also accepts a bare
40-hex string — the exact shape of a git commit SHA. In an agent transcript, one mention of
Sourcegraph plus a session's worth of commit hashes produced eight "leaked Sourcegraph tokens", none
of them secrets. A provider match is now reported only when one of the rule's keywords is inside it or
within 128 bytes before it on the same line (`keyword_near`); a real legacy token still matches next
to its variable name. The generated-sample test proves the cost: the same 255 rules catch their own
key before and after the change.

```mermaid
flowchart LR
  F[File text] --> K{Keyword anywhere<br/>in the file?}
  K -- no --> X[Rule skipped]
  K -- yes --> R[Rule regex]
  R --> E{Entropy, allowlists,<br/>doc examples}
  E -- fail --> X
  E -- pass --> N{Keyword in the match<br/>or just before it?}
  N -- no --> X
  N -- yes --> H[Reported, high confidence]
```

---

## 10. Security & privacy

- **Authn:** N/A — single local user; OS-level login is the trust boundary.
- **Authz:** privilege boundary via `pkexec`/polkit (GUI) or `sudo` (CLI), scoped per-collector — root is only required for specific operations, never for the whole app.
- **Data classification:** a finding's context can itself contain sensitive material (a finding may quote the exact secret pattern it detected). Never logged externally, never transmitted — local SQLite only, no network calls from `bulwark-core` by design (a hard invariant, not just a default).
- **Threat model:** Bulwark is itself an attractive target if compromised — broad read access across the system, and elevated write access for any future "apply fix" action. Rule files (and any future "apply fix") are a supply-chain-sensitive surface; signed/provenance-checked rule packs are required before any "install rules from the internet" feature ships (see §14).
- **Reading a home folder as root.** A privileged scan reads dotfiles in the invoking user's home, and that user controls every name in it. `bulwark-core::homefs` is the one way collectors and the Secrets readers open such a file: it resolves every link (in the file name and in the folders above it), requires the result to stay inside the home folder, opens once without blocking, and then decides from the open descriptor — a regular file, really located in that home, owned by the home's owner. A link that leaves the home folder, a named pipe, or a file swapped mid-read is refused, and the row is reported as "could not check `<path>`", never as clean. Links that stay inside the home folder (how dotfile managers work) are followed.
- **Nothing from the scanned machine is trusted as text.** Values substituted into a finding are made display-safe (control, bidirectional and invisible characters replaced, long values cut). A value placed in a rule's `fix` text must be one plain word, or it is replaced by a stand-in, so a file named `id; curl … | sh` can never become part of a command a user copies. A URL from a config file is reduced to scheme, host and port, because registry URLs carry credentials.
- **YAML is parsed in one place, under fixed limits.** Rule packs, the compliance mappings and the YAML config of AI agents all go through `bulwark-core::yaml`. The agent files are written by the owner of the scanned home and read by a root scan, so the limits apply to every document. See [Reading YAML someone else wrote](#reading-yaml-someone-else-wrote) below.
- **Known limitation — root-level compromise:** Bulwark cannot defend against an attacker who already has root on the machine it's running on. Such an attacker can disable rules, tamper with the local SQLite findings store, or replace the Bulwark binary itself, exactly as easily as they'd disable any other local defense — a local-only tool cannot be tamper-evident against the privilege level it's trying to detect. This is a structural limit of the v1 design (no phone-home, see Non-goals), not an oversight; it's stated here explicitly rather than left implicit. A future opt-in mode that ships scan results to a destination the same attacker doesn't control (e.g. remote syslog) would close this gap but is out of v1 scope.
- **Network use is opt-in and lives in the front-doors.** Two features cross the network, both only when the user sets them up and both outside `bulwark-core`: monitoring other machines over SSH (to machines the user registers, with host keys verified) and alerts to Telegram / an SMTP server (machine names, severities and issue titles only — never evidence or secrets). Nothing is sent to the Bulwark project. See §4 and [Monitoring other machines](/guide/remote-monitoring).
- **Audit logging:** every decision to hide something (ignoring a finding, turning a check off, turning it back on) is appended with its reason and time to `rule_suppression_events`, viewable in the app and with `bulwarkctl rules suppressions --audit`. Bulwark keeps no log of its own for privileged scans. Both are subject to the same limitation above if the attacker already has root.

### Reading YAML someone else wrote

```mermaid
flowchart LR
  packs["rules/, log-rules/, decoders/<br/>and custom rules<br/>(1 MiB per file)"] --> y
  std["compliance standards<br/>(built in)"] --> y
  home["agent config in a scanned home<br/>Goose, Continue, Aider, Open Interpreter<br/>(4 MiB per file)"] --> y
  y["bulwark-core::yaml"] -->|"one thread per document<br/>16 MiB of stack"| p["serde-saphyr<br/>128 levels, 250,000 values,<br/>8 MiB of text"]
  p -->|"typed struct"| typed["Rule, LogRule,<br/>Decoder, Standard"]
  p -->|"JSON value"| det["MCP and settings<br/>detectors"]
  p -->|"one line: reason, line, column"| err["RuleLoadError,<br/>or the text-only checks"]
```

The parser is `serde-saphyr`, written in safe Rust. It replaced `serde_yaml`, which was no longer
maintained and parsed with a C library translated to unsafe Rust. Moving was also a matter of what
a hostile file could do. Measured on the old parser in an unoptimised build: a 68 KB file that
names one anchored value 500 times became 32 MB of text, and nothing but the file size limited the
factor; a 14 KB file became four million values; and 400 KB of `{a: ` took 98 seconds to refuse.

| Limit | Value | Why |
|---|---|---|
| Nesting | 128 levels | Reading recurses once per level. The old parser allowed the same depth. |
| Values in the result | 250,000 | Counted after aliases are expanded, so an alias bomb stops here. |
| Text in the result | 8 MiB | Also counted after aliases: twice the largest file a caller hands over. |
| Parser stack | 16 MiB, on its own thread | An unoptimised build needs about 23 KiB of stack per level. A worker thread has 2 MiB and the main thread on Windows 1 MiB, so the depth limit would not be safe on the caller's stack. A panic in the parser ends that thread and is returned as an error. |

The parser is built without its `include` and `properties` features, so a document cannot name a
file to read or a variable to expand. Every hostile document in the test corpus ends within a few
seconds in an unoptimised build, with an error or a result inside the limits.

**What a document means is unchanged for everything Bulwark ships.** All 124 shipped YAML files
(109 rules, 8 log rules, 4 decoders, 3 standards) were parsed with both parsers before the old one
was removed and gave identical values. The options keep the old reading where the two parsers
differ by default: `yes`, `no`, `on` and `off` are text, `0644` is text and `0o644` is a number,
`<<` is an ordinary key, and a key given twice keeps its last value. Unit tests in `yaml.rs` pin
each of these.

The two parsers do not agree on every file, and the differences are worth knowing because an
agent's YAML that cannot be parsed is not reported as an error: the detectors fall back to the
checks that work on the text alone.

- **Read now, refused before:** a file that starts with a byte-order mark, a value with an
  application tag (`!secret x`), an integer too large for 64 bits, and a JSON-style surrogate
  pair in a quoted string. A mapping key written `~` is read as the key `null`.
- **Refused now, read before**, because the YAML specification forbids them and the old parser
  did not check: a quoted value continued on a line indented no deeper than its key, a `#` comment
  directly after a closing quote or bracket, and a lone `-` as a value inside `[ ]` or `{ }`.
- **Still read in a rule file:** a bare `explain:`, `fix:`, `references:`, `profiles:` or
  `skip_on:` loads as empty, as before (`models::blank_as_empty`). The parser itself refuses a
  blank value for a text field or a list; the other fields (`id`, `title`, `condition`, …) are
  refused when blank, with the line.

---

## 11. Observability

- **Metrics:** none exported — no telemetry, by design (non-goal). Local-only counters (scan duration, rules loaded, collectors failed) shown in-app only.
- **Logs:** Bulwark writes no log file of its own. Errors go to the terminal (CLI) or are shown in the app, and each scan's own record is kept in the local SQLite database.
- **Traces:** N/A — single-process desktop app, not a distributed system.
- **Alerts:** a desktop notification on new findings from a manual scan or a background monitoring run, via Tauri's notification API. Telegram and e-mail alerts are opt-in and were added with remote monitoring (§4).

---

## 12. Rollout plan

Reframed as release channels, since there's no %-traffic rollout for a desktop app.

| Step | What | Status |
|------|------|--------|
| 1 | `bulwarkctl` only, dogfood on real machines, including over SSH | ✅ Done |
| 2 | v0.1 GitHub Release, CLI binary only (`.deb`/`.rpm`/tarball) | ✅ `bulwark-core` stable, CLI builds clean |
| 3 | `bulwark-app` (Tauri GUI) joins the release, full `.deb`/`.rpm`/AppImage line-up | ✅ GUI built, packaged, and dogfooded end-to-end including the `pkexec` privileged path and tray icon |
| 4 | Public announce (README only, no paid promo) | ✅ The repository and its releases are public |

Shipping the CLI first validated `bulwark-core` — the actual hard part — fast, with far less UI work, and it's the only form factor that can reach a headless/remote box at all.

### Rollback
Uninstalling via the package manager removes the binary only. The local SQLite findings DB and logs under `~/.local/share/bulwark/` (`%LOCALAPPDATA%\com.vietanhdev.bulwark\` on Windows) are never auto-deleted, since scan history has ongoing forensic value — cleanup is always a deliberate user action, never automatic.

---

## 13. Alternatives considered

### Option A — Wrap Lynis/rkhunter as a backend
- **Pros:** instant access to Lynis's large, battle-tested test suite; far less initial engineering.
- **Cons:** GPLv3 coupling; can't easily add checks Lynis doesn't have (e.g. tunnel-service egress detection — this project's most differentiated check); output-parsing is brittle against Lynis version drift.
- **Why rejected:** the whole point is covering patterns no surveyed tool names as a control, and community extensibility is a ranked goal — a rule engine you can extend beats a report parser you can't.

### Option B — Full policy language (OPA/Rego)
- **Pros:** more expressive than a flat condition DSL, handles complex hierarchical policy composition, proven at scale in Kubernetes/cloud security.
- **Cons:** steep learning curve for a "personal tool sharpened into OSS" whose contribution bar should be "add a YAML file," not "learn a new declarative logic language."
- **Why rejected:** over-engineered for the actual rule shape needed (mostly flat "does fact X match condition Y" checks); Sigma/Falco's simpler condition-expression model covers the real cases with far less contributor friction.

### Option C — Real-time eBPF monitoring (Falco-style) as v1
- **Pros:** catches persistence/exfil at the moment it happens, not on the next scan.
- **Cons:** major engineering lift (kernel-level event capture, an always-on daemon, much higher blast radius if buggy); works against goal #3 (ship something real, soon).
- **Why rejected:** explicitly deferred to v2. Every indicator in the attack-pattern fixture set (§2) is still detectable after the fact from static host state — v1's periodic-scan model already covers what matters, without daemon complexity. Still deferred as of this update.

---

## 14. Open questions

- [ ] Exact workspace crate boundaries for the future sandbox/agent extension (`bulwark-sandbox`, `bulwark-agent`) — still only reserved as a direction. Safely sandboxing untrusted code on Linux (namespaces/seccomp/cgroups, or a microVM approach) is a materially different privilege model than per-collector elevation, and deserves its own design doc once it becomes real scope.
- [ ] Rule-signing/provenance story for community-contributed rules — still deferred until there's an actual external contributor, but §10 flags it as required before any "install rules from the internet" feature ships.
- [ ] Whether findings context needs at-rest encryption in the local SQLite store, or whether OS-level disk encryption is the sufficient boundary — still leaning toward the latter, not yet decided.
- [ ] Exact collector memoization/caching strategy across rules — flagged as necessary in §9, not designed in detail.
- [x] ~~A compliance-coverage view (HIPAA/ISO27001/PCI-DSS-style, mirroring Lynis's own compliance-testing angle)~~ — **implemented**, in two layers. The Compliance view groups findings by the `references` field every rule already carries, and shows a Lynis-style hardening index headline score (passing / evaluated, excluding privileged-and-skipped checks — same convention Lynis itself uses so skipped tests don't count against the score). On top of that, `bulwark-core::compliance` carries real, editorially-owned mappings onto **PCI DSS 4.0.1, the HIPAA Security Rule and ISO 27001:2022** (control definitions embedded via `include_str!`, covering 61 of the 109 rules), scored per standard and surfaced through the `compliance_report` command in "Rule catalog → Framework compliance".

  Three constraints shape that view, and all three are deliberate rather than incidental:

  1. **A skipped check is not a passing one.** A control is scored only when one of its mapped rules is in the scan's `rules_evaluated` set; otherwise it is `NotAssessed` and leaves the denominator entirely. The failure this prevents is an unprivileged scan — which skips most collectors — scoring *higher* than a privileged one, i.e. the score rising as visibility falls. That set was in-memory-only until the `2026-07-19-000000_scan_rules_evaluated` migration persisted it; a database predating that migration reports no evidence and is rendered as "not assessed", never as a clean bill of health.
  2. **No score is shown without its denominator and scope.** `StandardReport` carries `scope_note`, `mapped_controls`, `catalog_size`, `assessed` and `not_assessed`, and the UI renders them in the same glance as the percentage. None of these standards is mostly host-testable — HIPAA and ISO 27001 are largely administrative — so a bare "PCI DSS 87%" would be a compliance verdict a host scanner cannot produce.
  3. **HIPAA's `standard` / `required` / `addressable` distinction is preserved.** Under 45 CFR §164.306(c)–(d) an *addressable* implementation specification may be satisfied by a documented equivalent alternative, so a failing addressable control is a prompt to produce that documentation rather than automatically a violation — and the UI must not present it identically to a failing required one.

  **CIS is mapping only.** CIS control IDs appear as coverage annotations on rules and are never given a compliance percentage or level, which CIS's non-member terms forbid representing. MITRE ATT&CK likewise carries no ratio: it is a technique taxonomy, not a compliance standard.
- [ ] An `sshd -T` (effective-config, defaults-resolved) collector path. The `sshd_config` collector reads the files itself and applies sshd's own rules (see "How `sshd_config` is read" in §8): compiled-in defaults, first value wins, `Include` patterns, `Match all`. It was compared with `sshd -T` on OpenSSH 9.6 case by case, but it still cannot see a default a distribution patched into its sshd binary, or a keyword a newer OpenSSH adds. Asking the installed `sshd` would close that; not yet done.
- [x] ~~Real macOS/Windows collectors~~ — **implemented**, each verified on a real machine of that OS; see §17. One Windows collector (registry Run keys) is still a skeleton.
- [ ] Persisting the GUI's active profile ("needs") selection across restarts, and threading it through to the background monitoring loop (which currently always scans with the default profile — see §17 and `monitoring.rs`'s `run_tick`).

---

## 15. Decisions referenced

- ADR-0001 — Native Rust rule engine over wrapping Lynis/rkhunter (§13, Option A)
- ADR-0002 — Sigma/Falco-style condition DSL over OPA/Rego (§13, Option B)
- ADR-0003 — Tauri Channels over the global event system for finding-stream delivery, per Tauri's documented guidance on ordered, high-throughput streaming
- ADR-0004 — `sudo` (not `pkexec`) as the CLI's elevation path, since `pkexec` depends on a GUI-session-bound polkit agent that's typically absent over plain SSH (§4)

---

## 16. Visual design & interaction language (addendum)

*Not part of the standard template — included because "a GUI-native alternative to Lynis" is core to this project's reason for existing, so the interaction model is a first-class design decision, not a styling afterthought.*

**Primary color: a deliberate blue/green synthesis (teal), not a coin flip between the two.** The draft version of this document argued for plain blue, reasoning that green was already claimed as a *status* color (pass/safe) across nearly every dashboard convention and would collide with severity color-coding. In practice, a pure blue read as generic and undifferentiated once built. The shipped primary is a deep teal (`oklch` hue ~194 — roughly halfway between blue's ~255 and green's ~149 in this token set): it keeps blue's calm, professional read while leaning toward green's trust association, and sits far enough in hue from the "resolved" status green (~149) that the original brand/status collision concern still doesn't reoccur, even though both are technically in the blue-green family. Flat/no-gradient throughout the app UI (the docs site's hero text is the one deliberate exception, as a way to differentiate marketing surfaces from the product itself).

**Motion principles:**
- Findings stream in one at a time as a scan runs (via the Tauri Channel in §4); each animates in with a short (150–200ms) fade + slide — not a jarring pop — so a fast scan doesn't read as an unreadable flicker of rows.
- Status changes (e.g. marking a finding "resolved") animate the row's color/icon transition rather than an instant swap, so the state change registers as an event, not a silent re-render.
- No animation on content the user is actively reading or scrolling — motion is reserved for state transitions, never decorative idle motion.
- `prefers-reduced-motion` is respected everywhere — all micro-animations degrade to instant state changes when the OS signals reduced motion.

**As shipped:** shadcn/ui (Radix primitives) + Tailwind v4, styled entirely off the token system above rather than shadcn's default palette. Screens: three tabs, Scan, Secrets and Tools, plus Settings (§18 lists what each holds) — a frameless window with a custom title bar, and a system tray icon for background residency (§4). A dedicated animation/motion tuning pass (beyond the principles above being followed ad hoc per component) remains open — see `AGENTS.md`'s current-status notes.

---

## 17. Profiles — OS and needs (addendum)

*Also not part of the standard template — added when the rule/collector model was extended to be OS-aware, since it changes how every future rule and collector gets authored, not just one feature.*

Every rule and collector in v0.1 was implicitly Linux-only. This section documents the extension that makes "implicitly" explicit and adds a second, orthogonal axis on top of it — without changing behavior for any of the original rules by default.

### Two axes, not one

- **`os`** (hard filter) — which operating system(s) a rule or collector targets: `linux`, `macos`, or `windows`. A rule tagged `os: [macos]` never runs on a Linux host, full stop, regardless of anything else. Defaults to `[linux]` on a `Rule` with no `os` field, so every pre-existing rule file needed zero changes.
- **`profiles`** (opt-in "needs") — free-form tags like `server`, `desktop`, `developer` that a user opts into. A rule with no `profiles` tag is universal and always runs (once its `os` matches). A rule tagged `profiles: [server]` only runs when "server" is in the active profile's `needs` — e.g. `BLWK-LOG-003` (kernel-level process accounting) is real but mostly a server-hardening concern, not something a laptop user needs surfaced by default. There's deliberately no fixed enum of valid tags — adding a new need is a YAML change, matching the "no Rust required to add a rule" philosophy that already governs everything else about the rule format.

```yaml
id: BLWK-PERSIST-003
title: "Suspicious LaunchAgent/LaunchDaemon: {{ launchd_persistence.label }}"
collector: launchd_persistence
os: [macos]
profiles: [desktop]
condition: recognized == false
...
```

### Where the gate lives

Both axes are enforced in `engine::run_scan`, via a `Profile { os, needs }` passed alongside the existing `privileged: bool` parameter:

- Rules are filtered before anything else: `rule.os.contains(&profile.os) && (rule.profiles.is_empty() || rule.profiles.iter().any(|p| profile.needs.contains(p)))`.
- Collectors get a second, independent gate: `Collector::supported_os()` (default `[linux]`) is checked before `is_applicable()`/`collect()` are ever called — so a macOS-only collector's `collect()` is structurally unreachable on a Linux host, not just conventionally skipped by a well-behaved rule author. Defense in depth: even a rule that's mistagged can't cause a collector to run facts-gathering code for the wrong OS.

`Profile::default()` (host OS, no opted-in needs) reproduces the exact pre-profile scan behavior bit-for-bit on a Linux host, which is why this shipped with zero regressions against the existing rule test suite.

### What's real today, and what's a skeleton

- The **schema, engine filtering, and collector gate are fully real** — tested (`crates/bulwark-core/src/engine.rs`'s `rule_matches_profile`, plus per-collector tests), and live in both front-doors: the CLI's `bulwarkctl scan --needs server,...` flag and the GUI's **Checks → Change** on the Scan page (a "Server checks" switch, the one opt-in need the app offers).
- **`macos_security::MacosSecurityCollector`** reads the Mac posture settings with the tools Apple ships (`fdesetup`, `spctl`, `csrutil`, `socketfilterfw`, `defaults`), unprivileged, each value paired with a `*_known` flag so a failed or unrecognised read is "unknown", never "off" (BLWK-MAC-001…006). `credential_stores` and `ssh_private_keys` only read files in the home directory and now run on macOS too (`LINUX_AND_MACOS`); their rules carry `os: [linux, macos]`. Detection was verified on a real Mac against a throw-away `HOME` holding a test key and a dummy credential file.
- **`macos_launchd::LaunchdPersistenceCollector` is real** (the first non-Linux collector), built and verified against a real Mac reached through remote monitoring. It reads every LaunchAgent/LaunchDaemon plist with `plutil` (binary plists included) and flags the *shapes* persistence malware takes — a program in a world-writable or hidden directory, an interpreter running inline code, a job that downloads on start, a readable plist that can't be parsed — rather than "anything not from Apple", which on a developer's Mac would be dozens of legitimate updaters. Three real-machine cases are deliberately not findings: dangling plist symlinks and empty `{}` plists left behind by uninstallers (launchd can't run either), and root-only `0600` daemon plists during an unprivileged scan (recorded as unreadable — "couldn't look" is not "looks malicious"). Each of those cases came up on a real machine before it was handled, which is why they are covered by unit tests.
- **`windows_security::WindowsSecurityCollector`** is real (BLWK-WIN-001…010): one PowerShell invocation reads Defender, the firewall profiles, BitLocker on the system drive, UAC, Remote Desktop/NLA, SMBv1, the Guest account, a stored automatic sign-in password and the days since the last update into one JSON object, each read in its own `try`, so an unreadable setting (BitLocker without elevation) is `null` — "unknown" — and never fires a rule. Verified on a real Windows 11 machine: the first seven checks all evaluated, with zero findings on a hardened box; the three added later were verified the same way. The Windows CLI and desktop app cross-compile from Linux (`x86_64-pc-windows-gnu`, MinGW) and build natively on `windows-2022` in `release.yml`; `build.rs` stages the sidecar with its `.exe` suffix (it used to look for `bulwarkctl` without one and would have shipped the empty placeholder).
- **WSL is Linux, minus what Windows owns.** `RoleEvidence::wsl` (a Microsoft kernel in `/proc/version`, or the WSL interop handler) adds a `wsl` host trait; rules carry `skip_on: [wsl]` for checks about the WSL2 kernel, its network stack, auditd and console banners. Skipped rules are listed in `ScanRun::rules_not_applicable` — not evaluated, so never evidence of a pass — and the reconciler closes findings they raised before, so a check that stopped applying doesn't leave a finding open forever.
- **`windows_persistence::WindowsRunKeysCollector`** is still an intentionally-honest skeleton: it declares its target OS, `is_applicable()` returns `false`, and `collect()` returns an explicit "not yet implemented" error rather than fabricating facts. `BLWK-PERSIST-004` exists so the OS-tagging pipeline keeps end-to-end coverage, and it never fires. Because the collector reports `implemented() == false`, the engine lists that rule under `rules_not_applicable`, so a Windows scan is not told on every run that one check "couldn't run here". The other Windows checks, and remote monitoring of a Windows machine, do not depend on it (see [Monitoring other machines](/guide/remote-monitoring)).
- **Support grows one OS at a time, honestly.** A remote scan that evaluated no rules is recorded as *nothing assessed* — never persisted as a clean scan — and a shell that is neither a Unix shell nor Windows' cmd or PowerShell as *unsupported OS*; both show as a neutral "Not supported yet", are retried daily and never alerted on. Every machine view carries how many checks its last scan ran. `engine::host_fingerprint` uses `gethostname`/`uname` where `/etc/hostname` and `/proc` don't exist, so the remote-identity pin works on a Mac.
- Turning a skeleton into a real collector is "implement `collect()` against real OS APIs, verified on a real machine of that OS" — it does not require touching the engine, the rule schema, or any existing Linux collector.

### Not done as part of this

- Eleven rules carry a `profiles` tag today (nine as `server`: login banners, password ageing, auditd, remote log forwarding, process accounting, ICMP redirects, martian logging and the usb-storage module; the macOS and Windows persistence rules as `desktop`). A full pass deciding which of the other Linux rules are genuinely server-only or desktop-only is future work — mistagging a broadly-relevant rule as opt-in-only would be a real regression (it would silently stop running for most users by default), so this was deliberately left conservative rather than guessed at in bulk.
- The GUI's active-needs selection isn't persisted across restarts, and the background monitoring loop doesn't know about it yet (see §14).
- `ci.yml` does not run the test suite on macOS or Windows runners. The release workflow builds the CLI and the desktop app natively on `macos-15` and `windows-2022`, and the parsers behind each collector are pure functions, so their unit tests run on Linux with the rest. A collector's read of the live system is checked on a real machine by hand, not in CI.

## 18. The desktop workbench

```mermaid
flowchart LR
  subgraph app["Desktop app"]
    scan["Scan<br/>run, read, Fix now"]
    secrets["Secrets<br/>inventory per tool"]
    tools["Tools<br/>Configuration, File changes, Malware scan,<br/>Remote hosts, Rule catalog, History"]
  end
  scan -->|scan_start / ai_scan_start| core["bulwark-core<br/>collectors + rules + AI detectors"]
  secrets -->|secrets_inventory| access["bulwark-access<br/>passive readers"]
  secrets -.->|"Review in Scan"| scan
  access -->|token files| core
```

- **Scan** is the default tab and owns the run, its results and **Fix now**. Before the first
  scan it shows a four-step guide instead of an empty state. The top-level pages carry no visible
  title: the selected tab already names them.
- **Secrets** is an inventory, not a checker. Each supported tool is one passive reader in
  `bulwark-access::inventory` (AWS CLI, Docker, Git, GitHub CLI, npm, PyPI, Kubernetes) plus a
  "Tool tokens" view built from `bulwark_core::collectors::token_files`,
  so the inventory and the scan rule share one parser. On first run every detected tool is added;
  file-based tools are re-read each time the page opens. Readers keep names, storage kind and
  expiry, never a value, and follow a symlink only when its target stays inside the home folder.
- **Whether storage is safe is a Scan rule**: `BLWK-CRED-001..010` (credential files, shell startup
  files, package-registry tokens, kubeconfig, tool token files, and keys saved in shell history),
  `BLWK-SSH-014` (weak keys), `BLWK-SSH-015` (a key other accounts may open), and `BLWK-DEV-010/011` (npm install scripts; no release waiting
  period for npm, bun or uv — each read from the user-level config only, so they are low-severity
  suggestions). `BLWK-AI-012` covers three kinds of hidden text in instruction files: bidi
  controls, Unicode Tag characters (decoded in the finding) and long runs of invisible characters.
- **Motion budget**: motion only where it carries information — a spinner or the single task
  mark while work runs, and the disclosure chevron. No idle loops, tab-switch fades, slide-ins or
  hover scaling; one stable activity phrase. A browser test fails if anything loops while idle.


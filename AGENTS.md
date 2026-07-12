# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## What this is

Bulwark scans a Linux host for security misconfigurations and intrusion indicators using a native Rust rule engine over declarative YAML rules, and explains findings in plain language with a suggested fix. Design rationale, architecture, and alternatives-considered all live in `docs/guide/architecture.md` — read that before making an architectural change, not just this file. Background research grounding the rule checklist (Lynis, MITRE ATT&CK, HackTricks) is in `research/2026-07-11-linux-security-checklist/report.md`.

## Build & development commands

```bash
# Core + CLI
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all                        # cargo fmt --all -- --check in CI
cargo run -p bulwark-cli -- scan
cargo run -p bulwark-cli -- rules validate rules/

# GUI (from apps/bulwark-app/)
npm install
cargo tauri dev                        # hot reload for frontend; Rust/tauri.conf.json changes need a restart
cargo tauri build                      # produces .deb, .rpm, .AppImage in target/release/bundle/
npx tsc --noEmit                       # type-check the frontend
npm run lint                           # eslint
npm run format:check                   # prettier --check

# Docs site (from docs/)
npm install
npm run dev                            # local preview
npm run build                          # static build to docs/.vitepress/dist

# Packaging (from workspace root, after a release build)
cargo build --release -p bulwark-cli
cargo deb -p bulwark-cli --no-build    # requires `cargo install cargo-deb`
```

CI (`.github/workflows/ci.yml`) runs fmt-check, clippy `-D warnings`, `cargo test --workspace`, `rules validate rules/`, and a frontend typecheck — run all of these locally before considering a change done.

### Pre-commit hooks

Native git hooks, not husky/pre-commit-framework, so a pure-Rust contributor never needs Node and a pure-frontend contributor never needs the full Cargo toolchain. One-time setup per clone:

```bash
git config core.hooksPath .githooks
```

Runs gitleaks (staged-secret scan), `cargo fmt --all -- --check` (only if staged `.rs` files), and prettier/eslint/tsc (only if staged files under `apps/bulwark-app/`). Deliberately skips `cargo test`/`cargo clippy` — comprehensive but slow on this workspace; CI is the backstop for those.

## Architecture

Cargo workspace, three members:

- **`crates/bulwark-core`** — pure library, zero UI/CLI-specific code. Fact collectors (`src/collectors/`), the condition-DSL parser/evaluator (`src/condition.rs`), the rule-loading + scan engine (`src/engine.rs`), the `Finding`/`Rule`/`ScanRun` model (`src/models.rs`), SQLite persistence (`src/store.rs`).
- **`crates/bulwark-cli`** — thin CLI front-door (`clap`). `scan`, `rules list`, `rules validate`, `history`.
- **`apps/bulwark-app`** — thin Tauri v2 + React front-door. `scan_start` streams findings over a Tauri Channel; `scan_privileged` shells out to `pkexec bulwark scan --privileged --json` and deserializes the result — it does **not** duplicate collector logic.

Both front-doors share one on-disk SQLite history (`~/.local/share/bulwark/bulwark.db`) and one rule pack (`rules/`, bundled as a Tauri resource for the GUI, installed to `/usr/share/bulwark/rules` for the CLI's `.deb`).

### Adding a new check

1. If no existing collector produces the fact you need, add one under `crates/bulwark-core/src/collectors/` implementing the `Collector` trait (see any existing collector for the pattern — `is_applicable()` for graceful skip, `requires_privilege()` if it needs root, return one `Fact` row per item for list-shaped data).
2. Register it in `collectors/mod.rs::all_collectors()`.
3. Write a YAML rule under `rules/<category>/BLWK-<CATEGORY>-<NNN>.yaml` (see any existing rule for the exact schema; condition grammar is documented in `docs/guide/architecture.md` §5 — `==` `!=` `in` `contains` `matches` `<` `>` `<=` `>=`, `and`/`or`/`not`, one collector per rule, no cross-collector joins).
4. Run `cargo run -p bulwark-cli -- rules validate rules/` and `cargo test --workspace`.
5. Write a collector unit test with a fixture, **and** — if the rule's condition itself is non-trivial (especially anything with a regex) — a test asserting it does *not* false-positive on a plausible benign input. A backslash-escaping bug in `BLWK-ACCT-001`'s regex once flagged every ordinary `.sh` cron script as critical; it was only caught by testing against a real machine, not by the rule loading without error.

### Privilege model

Two different mechanisms, deliberately: the GUI uses `pkexec` with `polkit/com.bulwark.policy` (`auth_admin_keep`, one prompt per session — see `install-polkit.sh`); the CLI uses `sudo bulwark scan --privileged` directly and refuses to run privileged without an actual root EUID. `pkexec` depends on a GUI-session-bound polkit agent that's normally absent over plain SSH, which is the whole reason the CLI doesn't use it (`docs/guide/architecture.md` §4, ADR-0004). Don't unify these into one mechanism without re-reading that reasoning.

## Current status (2026-07-12)

Done and verified (not just implemented — actually run, tested, and in most cases packaged and inspected): core engine, CLI, 57 rules across all 11 categories, GUI with a working end-to-end `pkexec` privileged path, real ClamAV virus scanning (now with live streamed progress — see below), file-watcher-based near-real-time monitoring, a compliance view (now with a Lynis-style hardening index score), a History timeline view, file-integrity monitoring, a promiscuous-network-interface rootkit check, real `.deb`/`.rpm`/AppImage builds, a README with a sourced comparison against Lynis/rkhunter/chkrootkit/AIDE/OpenSCAP/Wazuh/CrowdStrike Falcon/SentinelOne plus a fully hands-on benchmark (`research/2026-07-12-bulwark-vs-lynis-benchmark/` — all 5 open-source tools actually installed and executed with real captured output, the latter four via a disposable `docker run` container for genuine root), CI pipeline verified locally, a system tray icon (verified live via the real `org.kde.StatusNotifierWatcher` D-Bus registration, not just "no error thrown") so closing the window hides it instead of killing the monitoring loop, and a docs site (`docs/`, VitePress) publishing the architecture doc and research.

**Latest pass** (rule expansion + 3 real bugs found and fixed by dogfooding, not by review): 7 more rules mined from this project's own Lynis benchmark (banners, min password age, login.defs hashing-rounds/umask, process accounting, rare-protocol/usb-storage module blacklisting, GRUB password), each sanity-checked against this machine first. Along the way: (1) the banner heuristic missed `/etc/issue.net` entirely (no getty escape codes there, unlike `/etc/issue`) until a live scan showed only 1 of 2 expected findings; (2) a real, more serious bug — `persist_and_reconcile` matched on exact-string context equality, so extending `login_defs.rs` with two new fields silently broke reconciliation for the *existing* `BLWK-ACCT-002` rule and produced a duplicate row on the next scan; fixed by making the identity check a subset-match (`store::is_context_subset`) instead of exact equality, with regression tests covering both "collector gains a field" and "list-shaped collector's rows must still not merge"; (3) list-shaped rules (`BLWK-BANN-001`, `BLWK-KERNEL-020`, all `BLWK-FIM-*`) shared identical titles across genuinely distinct findings, reading as duplicates in the UI even though storage was correct — fixed by extending `{{ }}` templating to `title`, not just `explain`. Also fixed: switching sidebar tabs used to unmount the active view and lose any in-progress scan state (App.tsx now keeps visited views mounted, hidden via CSS, instead of conditionally rendering); ClamAV scanning now streams live per-file progress over a Channel instead of blocking silently for minutes; five views (Rules/Compliance/Monitoring/History/Antivirus) were widened and restructured into responsive grids instead of a narrow centered column; Threats was renamed to Antivirus and paired with proactive ClamAV status.

Deliberately deferred as v1 non-goals (`docs/guide/architecture.md` §2, §13 Option C) — not gaps, decisions: real-time eBPF/syscall monitoring, and sandboxed untrusted-code execution / an agent framework. The architecture (crate boundaries, the `Collector` trait, Channel-based event streaming) is shaped so either could become a new workspace member later without a rewrite, but neither should be started without its own design doc first — sandboxing especially, since a rushed implementation of a security-isolation boundary is a worse outcome than not having the feature.

Not yet done, and genuinely open (as opposed to the above): visual/animation polish pass per `docs/guide/architecture.md` §16 (motion currently exists but hasn't had a dedicated tuning pass); rule-signing/provenance story for community-contributed rules (needed before any "install rules from the internet" feature, not before that); an `sshd -T` (effective-config, defaults-resolved) collector path — the current `sshd_config` collector only sees directives explicitly written to the file, so a directive relying on its OpenSSH-compiled-in default is invisible to every SSH rule, including the new ones. Not implemented because it needs a real `sshd` binary to verify against and this dev environment has none installed — a real gap, not an oversight, and worth a dogfooded pass on a machine that actually runs sshd before landing it (mapping `sshd -T`'s smashed-together lowercase keys like `clientaliveinterval` to this codebase's snake_case field names is exactly the kind of silent-mismatch risk the `to_snake_case` bug already burned once).

## Rules

- Never add an AI/agent co-author to git commits — human contributor only.
- Don't commit or push unless explicitly asked, even mid-task — this project's history includes long unattended implementation stretches; committing without being asked is not an exception to make just because a lot of work happened.
- Before trusting that packaging works, actually build the artifact and inspect its contents (`dpkg-deb --contents`) or run it — `cargo deb`/`cargo tauri build` succeeding only proves the metadata is syntactically valid, not that the runtime paths inside it are correct. This caught a real bug once (`bulwark-cli`'s rules-directory resolver only worked inside the dev workspace, not when installed).
- A collector or rule that fails should be visible (a `CollectorError`, a `RuleLoadError`, a `privileged_collectors_skipped` entry) — never a silent drop. This is a hard invariant, not a style preference; see `docs/guide/architecture.md` §8.
- `bulwark-core` has zero UI/CLI-specific code and no network calls. Keep it that way — both front-doors' value depends on staying thin wrappers over one real engine, and the no-network-calls invariant is load-bearing for the "fully local, no telemetry" claim in `docs/guide/architecture.md` §10.

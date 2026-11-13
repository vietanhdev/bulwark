use anyhow::Context;
use bulwark_core::{
    all_collectors, engine, fim_baseline_path, fim_establish_baseline, load_decoders,
    load_log_rules, models::Severity, run_log_scan, JournalRange, JournaldSource, LogSource,
    Profile, Store, SyslogLinesSource, FIM_PRIVILEGED_WATCHED_PATHS,
    FIM_UNPRIVILEGED_WATCHED_PATHS,
};
use clap::{Parser, Subcommand};
use std::io::BufReader;
use std::path::{Path, PathBuf};

mod agent;
#[cfg(unix)]
mod db_guard;
mod fix;
mod hosts;
mod notify;
mod place;
mod proc;
mod remote;
mod report;
mod term;

pub(crate) use term::{term_safe, term_safe_lines};

#[derive(Parser)]
#[command(
    name = "bulwarkctl",
    version,
    about = "Linux host security scanner — CLI front-door over bulwark-core"
)]
struct Cli {
    /// Directory containing YAML rule files (defaults to the pack built into this binary)
    #[arg(long, global = true)]
    rules_dir: Option<PathBuf>,

    /// Your own rules, loaded next to the shipped pack (default: ~/.config/bulwark/rules, or
    /// %APPDATA%\bulwark\rules on Windows). Custom ids can't start with BLWK- or reuse a built-in id.
    #[arg(long, global = true)]
    custom_rules_dir: Option<PathBuf>,

    /// Don't load your own rules folder for this run
    #[arg(long, global = true)]
    no_custom_rules: bool,

    /// SQLite findings database path (defaults to ~/.local/share/bulwark/bulwark.db)
    #[arg(long, global = true)]
    db_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a scan and print findings
    Scan {
        /// Show low-priority items too, and every place each problem was found
        #[arg(long)]
        all: bool,
        /// Machine-readable JSON output instead of the report
        #[arg(long)]
        json: bool,
        /// Skip persisting this run to the local findings database
        #[arg(long)]
        no_persist: bool,
        /// Don't send Telegram/e-mail alerts for new issues (see `bulwarkctl notify`)
        #[arg(long)]
        no_notify: bool,
        /// Also run collectors that need root (e.g. sudoers). Refuses unless actually
        /// running under sudo — see architecture doc §4 ADR-0004: the CLI never self-elevates.
        #[arg(long)]
        privileged: bool,
        /// Comma-separated opt-in need tags (e.g. "server", "developer"). A rule with no
        /// `profiles` tag always runs regardless of this; a rule tagged `profiles: [server]`
        /// only runs when "server" is listed here. When omitted, the host's detected roles are
        /// used — see the Profiles section of the architecture doc.
        #[arg(long, value_delimiter = ',')]
        needs: Vec<String>,
        /// Scan a REMOTE host over SSH instead of this machine. Takes a `[user@]host` spec (or a
        /// `Host` alias from ~/.ssh/config). Prefers a bulwark installed on the remote; otherwise
        /// pushes this binary + rule pack to a temp dir there, runs, and cleans up. Results are
        /// shown here and kept in a per-host history DB, never mixed with this machine's findings.
        #[arg(long, value_name = "[USER@]HOST")]
        ssh: Option<String>,
        /// SSH port for `--ssh` (default: ssh's own default / ~/.ssh/config).
        #[arg(long, requires = "ssh")]
        ssh_port: Option<u16>,
        /// Identity (private key) file for `--ssh`, passed to ssh/scp as `-i`.
        #[arg(long, requires = "ssh", value_name = "KEYFILE")]
        ssh_identity: Option<PathBuf>,
        /// Extra `-o Key=Value` ssh option for `--ssh` (repeatable), e.g.
        /// `--ssh-opt StrictHostKeyChecking=accept-new`.
        #[arg(long = "ssh-opt", requires = "ssh", value_name = "OPT")]
        ssh_opts: Vec<String>,
    },
    /// Inspect the loaded rule pack
    Rules {
        #[command(subcommand)]
        action: ConfigRulesAction,
    },
    /// List past scan runs: when, how many checks were loaded, and what they found
    History {
        /// How many of the most recent runs to list
        #[arg(long, default_value_t = 20, value_name = "N")]
        limit: u32,
    },
    /// File-integrity baseline management
    Fim {
        #[command(subcommand)]
        action: FimAction,
    },
    /// Analyze system logs for intrusion indicators (SSH brute force, sudo abuse, ...)
    Logs {
        #[command(subcommand)]
        action: LogsAction,
    },
    /// Scan AI coding-assistant artifacts (.claude, CLAUDE.md, MCP configs, transcripts, ...)
    /// for leaked secrets and dangerous agent configuration
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },
    /// Give AI coding agents (Claude Code, Codex, Copilot, Gemini CLI, OpenCode, Cursor) the
    /// Bulwark skill, so they can run these checks when asked and ask before fixing anything
    Agent {
        #[command(subcommand)]
        action: agent::AgentAction,
    },
    /// Monitor other machines over SSH: register them, check the connection, scan on a
    /// schedule. Agentless — nothing is installed on or listens on a monitored machine.
    Hosts {
        #[command(subcommand)]
        action: hosts::HostsAction,
    },
    /// Send alerts and reports to Telegram or e-mail (opt-in; nothing is sent until configured)
    Notify {
        #[command(subcommand)]
        action: notify::NotifyAction,
    },
    /// Protect SSH private keys (e.g. add a passphrase to every unencrypted key at once)
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
    /// Apply safe, reversible autofixes for issues a scan reports (file permissions, sshd and
    /// kernel network settings, login banners, password aging). Dry-run by default — every
    /// subcommand previews and touches nothing without `--apply`.
    Fix {
        #[command(subcommand)]
        action: FixAction,
    },
}

#[derive(Subcommand)]
enum FixAction {
    /// Preview every available autofix for this host without changing anything.
    List,
    /// Tighten permissions in ~/.ssh (dir 700, private keys / config / authorized_keys 600).
    /// User-scoped; needs no privilege. Only ever removes access, never adds any. Works on the
    /// ~/.ssh of the account it runs as, so run it without sudo to fix your own.
    SshPerms {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
    },
    /// Tighten permissions on sensitive /etc files (shadow 640, sudoers 440, sshd_config 600, ...):
    /// any access beyond those modes is removed, none is ever added. Needs root when applying —
    /// re-run under sudo. With sshd_config at 600, scans without sudo can no longer read it.
    EtcPerms {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one. This is what the GUI's
        /// privileged fix path parses back out of `pkexec bulwark fix …`.
        #[arg(long)]
        json: bool,
    },
    /// Harden /etc/ssh/sshd_config to clear the SSH rule findings (X11/TCP forwarding off,
    /// MaxAuthTries, ...). Needs root when applying; keeps a backup and validates with `sshd -t`.
    Sshd {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
        /// Also apply the two lockout-risky directives (PasswordAuthentication no, PermitRootLogin
        /// no). ONLY do this once you have confirmed key-based login works — it can lock you out of
        /// a password-only host.
        #[arg(long)]
        include_auth: bool,
        /// Operate on this config file instead of /etc/ssh/sshd_config (for testing or a
        /// non-default path). `Include` drop-ins are still resolved relative to /etc/ssh.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Persist kernel network hardening to /etc/sysctl.d/ (ICMP redirects off, martian logging
    /// on) and apply them to the running system. Needs root when applying. Writes a durable
    /// drop-in, not just /proc/sys. Exits non-zero if a setting could not be applied (in a
    /// container, kernel settings belong to the host).
    Sysctl {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
    },
    /// Replace the distribution's default /etc/issue and /etc/issue.net with a legal warning
    /// banner. Needs root when applying. A banner someone wrote, or a file someone emptied, is
    /// reported and left exactly as it is; a link is replaced by a file, never written through.
    Banner {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
    },
    /// Set password-aging policy in /etc/login.defs (PASS_MAX_DAYS 90, PASS_MIN_DAYS 1). Needs
    /// root when applying; backs the file up and replaces directives in place rather than appending.
    LoginDefs {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
        /// Operate on this file instead of /etc/login.defs (for testing).
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Apply the changes that cannot surprise, in one pass: ~/.ssh permissions, /etc permissions,
    /// the sshd settings that cannot lock you out, and the kernel network settings (the last
    /// three need root). Fixes that change wording or policy — `fix banner`, `fix login-defs` —
    /// are listed, not applied: run those by name. Never touches the lockout-risky sshd auth
    /// settings or key passphrases. Under sudo, ~/.ssh is root's: run `fix ssh-perms` without
    /// sudo for your own.
    All {
        /// Actually apply the changes. Without this, only previews.
        #[arg(long)]
        apply: bool,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
        /// Skip the user-scoped `~/.ssh` part and run only the fixes that need root. The GUI uses
        /// this: it must not run the `~/.ssh` fixer under `pkexec`, because pkexec resets `HOME` to
        /// root's, which would silently tighten `/root/.ssh` and leave the real user's untouched.
        #[arg(long)]
        root_only: bool,
    },
}

#[derive(Subcommand)]
enum SshAction {
    /// Add ONE passphrase to every unencrypted private key in ~/.ssh, in a single pass. A single
    /// password across the set is far better than leaving plaintext keys on disk. Already-encrypted
    /// keys, and keys whose status can't be read, are left untouched; each modified key is backed
    /// up (0600) first.
    Protect {
        /// Read the passphrase from stdin (for scripting) instead of prompting with no echo.
        #[arg(long)]
        stdin: bool,
        /// Machine-readable JSON output instead of a table
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AiAction {
    /// Discover and scan AI-assistant artifacts across your workspaces and home directory
    Scan {
        /// Machine-readable JSON output instead of the report
        #[arg(long)]
        json: bool,
        /// Show low-priority items too, and every file each problem was found in
        #[arg(long)]
        all: bool,
        /// Skip persisting this run to the local findings database. (A --target run is never
        /// saved: only a whole-machine scan replaces the stored results.)
        #[arg(long)]
        no_persist: bool,
        /// Extra directory to sweep for workspaces (repeatable). Adds to the built-in common
        /// code roots (~/Workspaces, ~/Projects, ~/src, ...).
        #[arg(long = "root", value_name = "DIR")]
        roots: Vec<PathBuf>,
        /// Leave out this directory and everything under it (repeatable). A relative path is
        /// taken from the current directory, and ~ is your home folder.
        #[arg(long = "exclude", value_name = "DIR")]
        excludes: Vec<PathBuf>,
        /// Scan exactly this workspace directory instead of auto-discovering (repeatable).
        /// Suppresses the whole-machine sweep — only the given folders are examined. The folder
        /// must exist. The result is shown but not saved, so it never replaces what the last
        /// whole-machine scan found.
        #[arg(long = "target", value_name = "DIR")]
        targets: Vec<PathBuf>,
    },
    /// Remove leaked secrets from AI context files. Dry-run by default — prints what would
    /// change and touches nothing; pass --apply to rewrite the files (a 0600 backup of each is
    /// kept — it still holds the secret, so delete it when you have checked the result — and file
    /// permissions are preserved). Exits 1 when --apply left a secret in a file it meant to clean.
    Redact {
        /// Actually rewrite the files. Without this flag, redact only previews.
        #[arg(long)]
        apply: bool,
        /// Also rewrite files changed in the last 30 seconds. By default those are left alone: a
        /// session that is still running may be writing to them, and replacing a file under it
        /// can lose what it writes next.
        #[arg(long, requires = "apply")]
        include_active: bool,
        /// Restrict redaction to these workspace directories (repeatable). Defaults to the same
        /// auto-discovered set `ai scan` uses.
        #[arg(long = "target", value_name = "DIR")]
        targets: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LogsAction {
    /// Decode and correlate a batch of log events, printing any findings
    Scan {
        /// Machine-readable JSON output instead of the report
        #[arg(long)]
        json: bool,
        /// Show low-priority items too, and every place each problem was found
        #[arg(long)]
        all: bool,
        /// Skip persisting this run to the local findings database
        #[arg(long)]
        no_persist: bool,
        /// Read the current boot's systemd journal (the default when neither --since nor
        /// --from-file is given)
        #[arg(long)]
        boot: bool,
        /// Read the journal at/after a `journalctl --since` spec (e.g. "-1h",
        /// "2026-07-12 00:00:00"). Relative specs start with '-', so pass them with '='
        /// (`--since=-1h`) or quoted.
        #[arg(long, conflicts_with = "from_file", allow_hyphen_values = true)]
        since: Option<String>,
        /// Read a classic syslog-format file (e.g. /var/log/auth.log) instead of journald —
        /// works on non-systemd hosts and for offline analysis
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Directory of decoder YAML files (defaults to the pack built into this binary)
        #[arg(long)]
        decoders_dir: Option<PathBuf>,
        /// Directory of log-rule YAML files (defaults to the pack built into this binary)
        #[arg(long)]
        log_rules_dir: Option<PathBuf>,
    },
    /// Inspect the loaded log-rule pack
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Inspect the loaded decoder pack
    Decoders {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Subcommand)]
enum FimAction {
    /// Record the current state of monitored critical files as the known-good baseline.
    /// Run this explicitly, while you trust the host's current state — never automatic,
    /// since an auto-established baseline recorded after a compromise would just enshrine
    /// the compromised state as "known good."
    Baseline {
        /// Also baseline the root-only files (/etc/shadow, /etc/sudoers). Refuses unless
        /// actually running under sudo, same rule as `scan --privileged`.
        #[arg(long)]
        privileged: bool,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// List loaded rules, including any that failed to load
    List,
    /// Validate a rule file or directory without running a scan
    Validate {
        /// The YAML file, or the folder of YAML files, to check
        path: PathBuf,
    },
}

/// Config-scan rule actions. A superset of [`RulesAction`] — suppression is meaningful for config
/// rules (a host state you've decided to accept) but not for log rules or decoders, so those keep
/// the smaller shared enum rather than exposing suppress/unsuppress subcommands that do nothing.
#[derive(Subcommand)]
enum ConfigRulesAction {
    /// List loaded rules, including any that failed to load
    List,
    /// Validate a rule file or a folder of rules without running a scan: the same checks loading
    /// applies. In your own rules folder that includes the id rules (no `BLWK-` prefix, no id a
    /// built-in check already uses). A missing or empty folder is an error, not "0 valid".
    Validate {
        /// The YAML file, or the folder of YAML files, to check
        path: PathBuf,
    },
    /// Accept the risk a rule reports, so its findings stop counting against you.
    ///
    /// The rule keeps running on every scan — this only changes how its findings are
    /// presented. Nothing is deleted and no check is turned off, so lifting the
    /// suppression shows you the current truth rather than a stale one.
    Suppress {
        /// Rule to suppress, e.g. BLWK-BANN-001
        rule_id: String,
        /// Why this risk is acceptable. Required — an unexplained suppression is
        /// unauditable, and the person who will need this is future you.
        #[arg(long)]
        reason: String,
        /// Only this one finding, by its place. `bulwarkctl scan --all` lists each place on a line
        /// starting with `·` under the problem: a file path, `port N on ADDR`, a name such as
        /// `module=dccp`, or (for a finding about the machine as a whole) its title. You are told,
        /// with the places that exist, if nothing is found at the place you give.
        #[arg(long)]
        place: Option<String>,
    },
    /// Withdraw a risk acceptance and let the rule count against you again
    Unsuppress {
        rule_id: String,
        /// Only the single-finding ignore at this place
        #[arg(long)]
        place: Option<String>,
        /// Why the acceptance no longer holds. Required: this is an auditable decision
        /// too, and "why did this alert come back?" is a question someone will ask.
        #[arg(long)]
        reason: String,
    },
    /// Show active suppressions and the append-only audit trail behind them
    Suppressions {
        /// Show the full history (including lifted suppressions), not just what's active
        #[arg(long)]
        audit: bool,
        /// Scope the audit trail to one rule
        #[arg(long)]
        rule_id: Option<String>,
    },
}

/// Root reached from another account (sudo sets SUDO_USER, pkexec sets PKEXEC_UID), as opposed
/// to a real root login.
fn elevated_from_another_user() -> bool {
    std::env::var_os("SUDO_USER").is_some_and(|v| !v.is_empty())
        || std::env::var_os("PKEXEC_UID").is_some_and(|v| !v.is_empty())
}

/// The user's own rules folder for this run: an explicit `--custom-rules-dir`, else the default
/// location when it exists; nothing with `--no-custom-rules`.
fn custom_rules(explicit: Option<PathBuf>, disabled: bool) -> Option<PathBuf> {
    if disabled {
        return None;
    }
    // An explicit folder is passed through even if it's missing, so the engine reports the typo;
    // the default one is simply optional.
    explicit.or_else(|| bulwark_core::paths::custom_rules_dir().filter(|d| d.is_dir()))
}

/// The packs compiled into this binary by `build.rs`: `EMBEDDED_RULES`, `EMBEDDED_LOG_RULES`,
/// `EMBEDDED_DECODERS`.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_packs.rs"));
}

/// A resolved content pack: a folder, or the one built into this binary.
#[derive(Debug, Clone)]
pub(crate) enum Pack {
    Dir(PathBuf),
    BuiltIn(&'static [(&'static str, &'static str)]),
}

impl Pack {
    pub(crate) fn source(&self) -> bulwark_core::PackSource<'_> {
        match self {
            Pack::Dir(d) => bulwark_core::PackSource::Dir(d),
            Pack::BuiltIn(files) => bulwark_core::PackSource::Embedded(files),
        }
    }
    pub(crate) fn describe(&self) -> String {
        self.source().describe()
    }
}

/// The config rule pack for this run. See [`resolve_pack`].
pub(crate) fn resolve_rules_dir(explicit: Option<PathBuf>) -> anyhow::Result<Pack> {
    resolve_pack(
        explicit,
        "BULWARK_RULES_DIR",
        "rules",
        "--rules-dir",
        embedded::EMBEDDED_RULES,
    )
}

/// Where a pack comes from, in order: an explicit flag, the environment variable, then **the pack
/// built into this binary**. The built-in pack is exactly the one this binary was built and tested
/// with, so it wins over anything merely found on disk — a binary copied to `~/.local/bin` on a
/// machine with an older package installed must not quietly scan with that package's older rules.
/// The on-disk search (a workspace checkout, `/usr/share/bulwark/<subdir>`, beside the executable)
/// is kept only for a binary built without its packs.
///
/// An explicitly named folder (flag or variable) that isn't there is an error, never a fallback:
/// silently scanning a *different* rule set than the one asked for is its own kind of lie, and a
/// missing folder used to produce a scan that loaded nothing and reported "no findings".
fn resolve_pack(
    explicit: Option<PathBuf>,
    env_var: &str,
    subdir: &str,
    flag: &str,
    builtin: &'static [(&'static str, &'static str)],
) -> anyhow::Result<Pack> {
    if let Some(p) = explicit {
        if !p.is_dir() {
            anyhow::bail!("{flag} {} is not a directory", p.display());
        }
        return Ok(Pack::Dir(p));
    }
    if let Some(p) = std::env::var_os(env_var).filter(|v| !v.is_empty()) {
        let p = PathBuf::from(p);
        if !p.is_dir() {
            anyhow::bail!("{env_var} {} is not a directory", p.display());
        }
        return Ok(Pack::Dir(p));
    }
    if !builtin.is_empty() {
        return Ok(Pack::BuiltIn(builtin));
    }
    // A binary built without its packs: look on disk, as releases before the built-in pack did.
    let mut candidate = std::env::current_dir()?;
    for _ in 0..4 {
        let dir = candidate.join(subdir);
        if dir.is_dir() {
            return Ok(Pack::Dir(dir));
        }
        if !candidate.pop() {
            break;
        }
    }
    let installed = PathBuf::from("/usr/share/bulwark").join(subdir);
    if installed.is_dir() {
        return Ok(Pack::Dir(installed));
    }
    // The GUI bundles this binary as its sidecar and ships the packs in its resource directory.
    if let Some(dir) = exe_relative_dir(subdir) {
        return Ok(Pack::Dir(dir));
    }
    anyhow::bail!("couldn't find a '{subdir}' directory — pass {flag} explicitly or set {env_var}")
}

/// A content directory shipped alongside this executable, for the Tauri-sidecar layout
/// (`<prefix>/bin/bulwark` with its content under `<prefix>/lib/bulwark/<subdir>`). Also
/// accepts `<exe dir>/<subdir>`, which is what the extracted release tarball looks like.
///
/// The `lib/bulwark` segment is the GUI's Tauri resource directory, named after `productName` in
/// `tauri.conf.json`. That name is lowercase `bulwark` — kept in sync with this path — while the
/// app's *display* name stays "Bulwark" via a `desktopTemplate`. If `productName` ever changes,
/// this must follow; a mismatch would only cost the sidecar its standalone fallback (the GUI passes
/// `--rules-dir` explicitly regardless), never correctness of a scan.
fn exe_relative_dir(subdir: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?;
    let candidates = [
        bin_dir.join(subdir),
        bin_dir.join("../lib/bulwark").join(subdir),
        // macOS app bundle: Bulwark.app/Contents/MacOS/bulwark beside Contents/Resources/<subdir>.
        bin_dir.join("../Resources").join(subdir),
    ];
    candidates
        .into_iter()
        .find(|c| c.is_dir())
        .and_then(|c| c.canonicalize().ok())
}

/// Where the findings database is, before asking whether this process may use it.
fn db_path_as_named(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        // `BULWARK_DB_PATH`, then `XDG_DATA_HOME`, then `~/.local/share` — one resolver shared with
        // the GUI (see `bulwark_core::paths`). XDG_DATA_HOME matters inside a Flatpak, where $HOME
        // is the real, read-only home and only XDG_DATA_HOME is writable.
        None => bulwark_core::paths::default_db_path(),
    }
}

/// Why this process must not open the database at `path`, if it must not.
///
/// Root on someone else's behalf never opens a database that account can write to: with a
/// preserved HOME (`sudo -E`, or macOS) the default one sits in their home folder, and a database
/// is input SQLite parses. A real root login chose its own files and is left alone, as is a
/// container that simply runs everything as root.
fn db_refusal(path: &Path) -> Option<String> {
    #[cfg(unix)]
    if engine::is_running_as_root() && elevated_from_another_user() {
        return db_guard::exposure(path, 0)
            .map(|why| format!("refusing to use {} as root: {why}", path.display()));
    }
    let _ = path;
    None
}

/// Says, once per run, that a database named with `--db-path` sits in a folder every account can
/// write to (`/tmp`). Bulwark no longer changes such a folder's permissions — it used to turn
/// `/tmp` into `0700` — so the folder stays as open as its owner made it. The database and the
/// files SQLite keeps beside it are private either way; the note is there because other accounts
/// can still see that it exists and could have put a file of that name there first.
fn note_shared_folder(db: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        static ONCE: std::sync::Once = std::sync::Once::new();
        let dir = match db.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        if std::fs::metadata(dir).is_ok_and(|m| m.mode() & 0o002 != 0) {
            ONCE.call_once(|| {
                eprintln!(
                    "note: every account on this computer can write to {}. The database is \
                     readable only by you, but a folder only you can write to is a safer place \
                     for it.",
                    dir.display()
                );
            });
        }
    }
    #[cfg(not(unix))]
    let _ = db;
}

fn resolve_db_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let named = explicit.is_some();
    let path = db_path_as_named(explicit)?;
    if named {
        note_shared_folder(&path);
    }
    if let Some(refusal) = db_refusal(&path) {
        anyhow::bail!(
            "{refusal}, so it could feed a root process whatever it likes. Use --no-persist to \
             scan without saving, or --db-path with a location only root can write to"
        );
    }
    Ok(path)
}

/// Who to attribute a suppression to in the audit trail. `SUDO_USER` wins over `USER` so a
/// suppression made under `sudo` is credited to the human who ran it, not to root — the audit log
/// is about accountability, and "root did it" is exactly the answer it exists to improve on.
pub(crate) fn current_actor() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

pub(crate) fn exit_code_for(worst: Option<Severity>) -> i32 {
    match worst {
        Some(Severity::Critical) => 2,
        Some(s) if s >= Severity::Medium => 1,
        _ => 0,
    }
}

/// The profile a local scan runs under: the host's detected roles, or exactly the tags given with
/// `--needs`. An empty `--needs` used to replace the detected roles with nothing, so a plain
/// `bulwarkctl scan` silently skipped every `profiles:`-tagged rule (all the server checks on
/// Linux, the launchd check on macOS) while the app, which uses the detected roles, ran them.
fn scan_profile(needs: Vec<String>) -> Profile {
    Profile::with_needs(needs)
}

fn main() {
    // `bulwarkctl … | head -1` must end quietly, not with a panic and exit code 101.
    term::exit_quietly_when_the_reader_goes_away();
    if let Err(e) = run() {
        // An error can quote a file's contents or another machine's answer, so it goes through
        // the same filter as a report. The shape is the one `main` returning an error prints.
        let text = term_safe_lines(&format!("{e:?}"));
        eprintln!("Error: {}", term::for_locale(&text));
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    // SSH_ASKPASS mode, used only by `hosts setup-key --password-stdin`: ssh runs this binary to
    // ask for the one-time password. Both variables are set by `remote::install_key` on that one
    // ssh process; `sudo` and `pkexec` strip unknown variables, so this can't be reached from a
    // privileged invocation.
    if let (Ok(secret), Ok(_)) = (
        std::env::var(remote::ASKPASS_ENV),
        std::env::var("SSH_ASKPASS_REQUIRE"),
    ) {
        std::process::exit(remote::askpass_main(&secret));
    }
    let cli = parse_cli();

    match cli.command {
        Commands::Scan {
            json,
            no_persist,
            no_notify,
            privileged,
            needs,
            all,
            ssh,
            ssh_port,
            ssh_identity,
            ssh_opts,
        } => {
            // Remote path: run the same scan over SSH and bring the results home. `--privileged`
            // here refers to the *remote* scan needing root, so we deliberately do NOT gate on local
            // root — the remote invocation uses `sudo -n` on the far side (see remote::run_scan_cmd).
            if let Some(spec) = ssh {
                // Elevated through sudo or pkexec, never open SSH: `--ssh-opt` takes arbitrary ssh
                // options (ProxyCommand runs a command), so it would be a way out of any rule that
                // lets a user run `bulwarkctl scan` as root. A real root login is not an escalation
                // and may scan other machines; everyone else scans them as themselves.
                if engine::is_running_as_root() && elevated_from_another_user() {
                    anyhow::bail!(
                        "refusing to scan another machine through sudo/pkexec — run `bulwarkctl scan \
                         --ssh` as your own user (root checks on the far side use sudo there)"
                    );
                }
                let worst = run_ssh_scan(
                    remote::RemoteTarget::interactive(spec, ssh_port, ssh_identity, ssh_opts),
                    privileged,
                    &needs,
                    if json {
                        ScanOutput::Json
                    } else {
                        ScanOutput::Report { all }
                    },
                    no_persist,
                    cli.rules_dir,
                    cli.db_path,
                )?;
                std::process::exit(exit_code_for(worst));
            }

            if privileged && !engine::is_running_as_root() {
                anyhow::bail!(
                    "--privileged requires root — re-run as: sudo bulwarkctl scan --privileged"
                );
            }
            // Decided before the scan, not after it: a database this run may not use is an error
            // the user should meet in a second, not once the results are ready to save.
            if !no_persist {
                resolve_db_path(cli.db_path.clone())?;
            }
            let rules_dir = resolve_rules_dir(cli.rules_dir)?;
            // A root scan never picks up the user-writable custom folder on its own: a rule planted
            // there could template root-only facts (sudoers lines, privileged file hashes) into its
            // output. Only a folder named explicitly on the command line is used.
            // Decided by who we run as, not by the flag: `sudo bulwarkctl scan` without
            // `--privileged` is still root, and may still see $HOME's folder.
            let custom = if privileged || engine::is_running_as_root() {
                if cli.no_custom_rules {
                    None
                } else {
                    cli.custom_rules_dir.clone()
                }
            } else {
                custom_rules(cli.custom_rules_dir, cli.no_custom_rules)
            };
            let collectors = all_collectors();
            let profile = scan_profile(needs);
            let scan = engine::run_scan_with_custom(
                rules_dir.source(),
                custom.as_deref(),
                &collectors,
                privileged,
                &profile,
                &|| false,
            );

            // A scan that loaded no rules examined nothing, and "0 findings" from it is not a clean
            // bill of health — it is the absence of an opinion. Reported as success (exit 0, empty
            // findings list) it is indistinguishable from a genuinely healthy host, which is the
            // single most dangerous thing a security scanner can say. Refuse, before persisting:
            // writing that run to the history would also mark every previously-open finding as
            // resolved, because `persist_and_reconcile` closes anything a scan didn't re-observe.
            //
            // The log scan has always had this guard (`logs scan`, below); the config scan did not,
            // so a rules directory that had been emptied, mispackaged, or simply mistyped produced a
            // confident, silent all-clear. Same invariant, same treatment: a failure must be
            // visible, never a silent drop (architecture doc §8).
            if scan.rules_loaded == 0 {
                // Tell "nothing on disk" apart from "nothing for this OS": the fix for one is the
                // path, for the other there is none, and pointing at the path sends people the
                // wrong way.
                let on_disk = engine::load_rules(rules_dir.source()).0.len();
                if on_disk > 0 {
                    anyhow::bail!(
                        "none of the {on_disk} rules in {} apply to this host ({}) — refusing to \
                         report a clean result from a scan that examined nothing. The config \
                         checks cover Linux; `bulwarkctl ai scan` works here",
                        rules_dir.describe(),
                        std::env::consts::OS
                    );
                }
                anyhow::bail!(
                    "scan loaded 0 rules from {} — refusing to report a clean result from a scan \
                     that examined nothing (check the path, or pass --rules-dir)",
                    rules_dir.describe()
                );
            }

            // What you've chosen not to see (whole checks and single findings). The JSON stays raw —
            // remote scanning reads it and must see everything — but the table and the exit code a
            // cron job gates on follow your decisions.
            let ignores = db_path_as_named(cli.db_path.clone())
                .ok()
                .filter(|p| p.exists())
                // Only reachable with --no-persist. Said out loud, or the table quietly grows.
                .filter(|p| match db_refusal(p) {
                    Some(refusal) => {
                        eprintln!("[bulwark] your ignore list was not applied: {refusal}");
                        false
                    }
                    None => true,
                })
                .and_then(|p| Store::open(&p).ok())
                .and_then(|mut st| st.ignores().ok())
                .unwrap_or_default();

            if !no_persist {
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                // Reconciled, matching the GUI's scan_start and the monitoring loop — a
                // manual CLI scan and a background tick finding the same issue must not
                // produce two rows for it. Using plain persist() here was the actual root
                // cause of a real "I see duplicated issues now" bug report: this command
                // kept inserting a fresh row every run against the same shared DB.
                let fresh = store.persist_and_reconcile(&scan)?;
                // Ignored issues and turned-off checks never alert.
                let fresh: Vec<_> = fresh.into_iter().filter(|f| !ignores.covers(f)).collect();
                drop(store);
                if !no_notify && !fresh.is_empty() {
                    notify_local(&db_path, &scan, &fresh);
                }
            }

            let worst = scan
                .findings
                .iter()
                .filter(|f| !ignores.covers(f))
                .map(|f| f.severity)
                .max();
            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                print_scan_table(&scan, &ignores, all, "this computer");
            }

            std::process::exit(exit_code_for(worst));
        }
        Commands::Rules { action } => match action {
            ConfigRulesAction::List => {
                let rules_dir = resolve_rules_dir(cli.rules_dir)?;
                let custom = custom_rules(cli.custom_rules_dir, cli.no_custom_rules);
                let (rules, errors) =
                    engine::load_rule_packs(rules_dir.source(), custom.as_deref());
                for r in &rules {
                    let os_tag = r
                        .rule
                        .os
                        .iter()
                        .map(|os| format!("{os:?}").to_lowercase())
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{:<20} [{:<8}] ({os_tag:<7}) {}{}",
                        r.rule.id,
                        severity_label(r.rule.severity),
                        r.rule.title,
                        if r.custom { "  (custom)" } else { "" }
                    );
                }
                if !errors.is_empty() {
                    eprintln!("\n{} rule(s) failed to load:", errors.len());
                    for e in &errors {
                        eprintln!("  {}: {}", e.path, e.message);
                    }
                    std::process::exit(1);
                }
            }
            ConfigRulesAction::Validate { path } => {
                let custom_dir = cli
                    .custom_rules_dir
                    .clone()
                    .or_else(bulwark_core::paths::custom_rules_dir);
                let outcome = validate_rules(&path, custom_dir.as_deref())?;
                println!("{} rule(s) valid", outcome.valid);
                if !outcome.errors.is_empty() {
                    eprintln!("{} problem(s) found:", outcome.errors.len());
                    for e in &outcome.errors {
                        eprintln!("  {}: {}", term_safe(&e.path), term_safe(&e.message));
                    }
                    std::process::exit(1);
                }
            }
            ConfigRulesAction::Suppress {
                rule_id,
                reason,
                place,
            } => {
                // Reject a suppression for a rule that doesn't exist — otherwise a typo'd ID
                // becomes a suppression that silently matches nothing, which is indistinguishable
                // from a working one until the day the real rule fires anyway and confuses everyone.
                let rules_dir = resolve_rules_dir(cli.rules_dir)?;
                let custom = custom_rules(cli.custom_rules_dir, cli.no_custom_rules);
                let (rules, _) = engine::load_rule_packs(rules_dir.source(), custom.as_deref());
                if !rules.iter().any(|r| r.rule.id == rule_id) {
                    anyhow::bail!(
                        "no rule '{rule_id}' in the loaded pack — check the id with: bulwarkctl rules list"
                    );
                }
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                if let Some(place) = place {
                    let location = place_to_ignore(&mut store, &rule_id, &place)?;
                    let i = store.ignore_finding(&rule_id, &location, &reason, &current_actor())?;
                    println!("ignoring {} at {} — {}", i.rule_id, i.location, i.reason);
                    println!("(the rule still reports every other place; lift it with: bulwarkctl rules unsuppress {rule_id} --place '{}' --reason ...)", i.location);
                    return Ok(());
                }
                let s = store.suppress_rule(&rule_id, &reason, &current_actor())?;
                println!("suppressed {} — {}", s.rule_id, s.reason);
                println!("(the rule still runs every scan; lift it with: bulwarkctl rules unsuppress {rule_id} --reason ...)");
            }
            ConfigRulesAction::Unsuppress {
                rule_id,
                reason,
                place,
            } => {
                let db_path = resolve_db_path(cli.db_path)?;
                let mut store = Store::open(&db_path)?;
                if let Some(place) = place {
                    let place = place_to_unignore(&mut store, &rule_id, &place)?;
                    store.unignore_finding(&rule_id, &place, &reason, &current_actor())?;
                    println!("no longer ignoring {rule_id} at {place}");
                    return Ok(());
                }
                store.unsuppress_rule(&rule_id, &reason, &current_actor())?;
                println!("unsuppressed {rule_id} — it will count against you again");
            }
            ConfigRulesAction::Suppressions { audit, rule_id } => {
                let db_path = resolve_db_path(cli.db_path)?;
                if !db_path.exists() {
                    println!("no suppressions — nothing recorded yet");
                    return Ok(());
                }
                let mut store = Store::open(&db_path)?;
                if audit {
                    let log = store.suppression_audit_log(rule_id.as_deref(), 500)?;
                    if log.is_empty() {
                        println!("no suppression history recorded");
                    }
                    for e in &log {
                        println!(
                            "{}  {:<12} {:<18} {}{} — {}",
                            e.at.format("%Y-%m-%d %H:%M"),
                            e.action.as_str(),
                            e.rule_id,
                            e.location
                                .as_deref()
                                .map(|l| format!("at {l} "))
                                .unwrap_or_default(),
                            e.actor,
                            e.reason
                        );
                    }
                } else {
                    let active = store.list_suppressions()?;
                    let places = store.list_finding_ignores()?;
                    if active.is_empty() && places.is_empty() {
                        println!("no active suppressions");
                    }
                    for i in &places {
                        println!(
                            "{:<18} at {} — by {} on {} — {}",
                            i.rule_id,
                            i.location,
                            i.created_by,
                            i.created_at.format("%Y-%m-%d"),
                            i.reason
                        );
                    }
                    for s in &active {
                        println!(
                            "{:<18} by {} on {} — {}",
                            s.rule_id,
                            s.created_by,
                            s.created_at.format("%Y-%m-%d"),
                            s.reason
                        );
                    }
                }
            }
        },
        Commands::History { limit } => {
            let db_path = resolve_db_path(cli.db_path)?;
            if !db_path.exists() {
                println!("no scans recorded yet at {}", db_path.display());
                return Ok(());
            }
            let mut store = Store::open(&db_path)?;
            let total = store.count_scan_runs()?;
            let runs = store.list_scan_runs(i64::from(limit))?;
            print!("{}", term::for_locale(&history_table(&runs, total)));
        }
        Commands::Fim { action } => match action {
            FimAction::Baseline { privileged } => {
                if privileged && !engine::is_running_as_root() {
                    anyhow::bail!(
                        "--privileged requires root — re-run as: sudo bulwarkctl fim baseline --privileged"
                    );
                }
                let mut paths: Vec<&str> = FIM_UNPRIVILEGED_WATCHED_PATHS.to_vec();
                if privileged {
                    paths.extend_from_slice(FIM_PRIVILEGED_WATCHED_PATHS);
                }
                let n = fim_establish_baseline(&paths)?;
                println!(
                    "baseline recorded for {n} file(s) at {}",
                    fim_baseline_path().display()
                );
                if !privileged {
                    println!(
                        "note: root-only files ({}) were not included — re-run with sudo and --privileged to cover them too",
                        FIM_PRIVILEGED_WATCHED_PATHS.join(", ")
                    );
                }
            }
        },
        Commands::Logs { action } => run_logs(action, cli.db_path)?,
        Commands::Ai { action } => {
            note_unused_rule_options(
                "ai",
                cli.rules_dir.is_some() || cli.custom_rules_dir.is_some() || cli.no_custom_rules,
            );
            run_ai(action, cli.db_path)?
        }
        Commands::Hosts { action } => {
            let db = resolve_db_path(cli.db_path)?;
            let code = hosts::run(action, &db, cli.rules_dir)?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Notify { action } => {
            let db = resolve_db_path(cli.db_path)?;
            let code = notify::run(action, &db)?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Agent { action } => {
            note_unused_rule_options(
                "agent",
                cli.rules_dir.is_some() || cli.custom_rules_dir.is_some() || cli.no_custom_rules,
            );
            let code = agent::run(action, &resolve_home()?)?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Ssh { action } => run_ssh(action)?,
        Commands::Fix { action } => {
            let code = fix::run(action)?;
            if code != 0 {
                std::process::exit(code);
            }
        }
    }

    Ok(())
}

/// Resolves the user's home directory for AI-artifact discovery.
fn resolve_home() -> anyhow::Result<PathBuf> {
    let home = bulwark_core::paths::home_var().context("HOME not set")?;
    Ok(PathBuf::from(home))
}

/// How a scan's result is printed: the raw `ScanRun` for scripts, or the human report.
#[derive(Clone, Copy)]
enum ScanOutput {
    Json,
    Report { all: bool },
}

/// Drive a remote scan over SSH: run it, print it, persist it to an isolated per-host history DB,
/// and return the worst severity so `main` can pick the process exit code. Kept separate from the
/// local scan path because the persistence target differs — a remote host's findings must never
/// land in this machine's single-host database, where reconciliation would resolve local findings
/// whose rules the remote scan happened to run (the `findings` table has no host column by design).
fn run_ssh_scan(
    target: remote::RemoteTarget,
    privileged: bool,
    needs: &[String],
    output: ScanOutput,
    no_persist: bool,
    rules_dir: Option<PathBuf>,
    db_path: Option<PathBuf>,
) -> anyhow::Result<Option<Severity>> {
    let json = matches!(output, ScanOutput::Json);
    let rules_dir = resolve_rules_dir(rules_dir)?;
    let local_binary = std::env::current_exe().context("cannot locate this bulwarkctl binary")?;

    let spec = target.spec.clone();
    if !json {
        eprintln!("Scanning {spec} over SSH…");
    }
    let ssh_line = target.ssh_command_line();
    let result = remote::run_remote_scan(&target, privileged, needs, &local_binary, &rules_dir)
        .map_err(|e| match e.downcast_ref::<remote::RemoteError>() {
            // A classified failure gets its plain-language next step, not just ssh's words.
            Some(re) => anyhow::anyhow!("{re}\n{}", re.kind.hint(&ssh_line)),
            None => e,
        })?;
    let scan = result.scan;

    // Same invariant as the local path: a scan that loaded no rules examined nothing, and its empty
    // findings list is the absence of an opinion, not a clean bill of health. Refuse before persisting.
    if scan.rules_loaded == 0 {
        anyhow::bail!(
            "remote scan of {spec} loaded 0 rules — refusing to report a clean result from a scan \
             that examined nothing (is the rule pack present on the remote?)"
        );
    }

    // Same invariant as `hosts scan`: a scan that ran no check is the absence of an opinion, never
    // a clean result — whether or not it is saved.
    if scan.rules_evaluated.is_empty() {
        anyhow::bail!(
            "no check could run on {spec} ({} loaded, none applied) — refusing to report a clean \
             result from a scan that examined nothing",
            scan.rules_loaded
        );
    }

    let mut ignores = bulwark_core::Ignores::default();
    if !no_persist {
        let (db_path, registered) = remote_db_path(&resolve_db_path(db_path)?, &spec)?;
        // An address that now answers as a different machine must not resolve the registered
        // machine's issues: the results are shown, but not saved into its history.
        let mismatch = registered
            .as_ref()
            .and_then(|h| bulwark_core::fleet::identity_mismatch(h, &scan.host_fingerprint))
            .zip(registered.as_ref());
        if let Some(((expected, actual), h)) = mismatch {
            eprintln!(
                "warning: {spec} is registered as {}, which answers as \"{expected}\", but this \
                 scan answered as \"{actual}\" — showing the results without saving them into that \
                 machine's history. Check the address; if the machine was rebuilt, accept its new \
                 identity under Remote.",
                h.name
            );
        } else {
            // `Store::open` creates the folder, and locks down one it creates.
            let mut store = Store::open(&db_path)?;
            store.persist_and_reconcile(&scan)?;
            ignores = store.ignores()?;
            if !json {
                eprintln!("History for {spec}: {}", db_path.display());
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&scan)?);
    } else {
        match &result.engine {
            remote::RemoteEngine::Installed { path, version } => {
                eprintln!("Ran the remote's installed bulwark {version} ({path}).");
            }
            remote::RemoteEngine::Pushed { arch, .. } => {
                eprintln!("Pushed this bulwarkctl ({arch}) to a temp dir and cleaned it up.");
            }
        }
        let all = matches!(output, ScanOutput::Report { all: true });
        print_scan_table(&scan, &ignores, all, &spec);
    }
    Ok(scan
        .findings
        .iter()
        .filter(|f| !ignores.covers(f))
        .map(|f| f.severity)
        .max())
}

/// Alert on issues a local scan newly opened, if the user set up alerts and included this computer.
/// Best-effort: a delivery problem is printed and recorded, never fatal to the scan.
fn notify_local(db: &Path, scan: &bulwark_core::ScanRun, fresh: &[bulwark_core::Finding]) {
    let Ok(mut store) = Store::open(db) else {
        return;
    };
    let Ok(cfg) = bulwark_core::notify_config::load(&mut store) else {
        return;
    };
    if !cfg.any_channel_enabled() || !cfg.include_this_computer {
        return;
    }
    let host = bulwark_core::fleet::hostname_of_fingerprint(&scan.host_fingerprint);
    let name = if host.is_empty() {
        "This computer".to_string()
    } else {
        host
    };
    let briefs: Vec<(Severity, String)> = fresh
        .iter()
        .map(|f| (f.severity, f.title.clone()))
        .collect();
    if let Some(alert) = bulwark_core::fleet::new_issues_alert(&name, &briefs) {
        for r in notify::deliver(db, &[alert]) {
            if let Some(e) = r.error {
                eprintln!("warning: couldn't send the {} alert: {e}", r.channel);
            }
        }
    }
}

/// Isolated per-remote-host history database, so each scanned host reconciles against its own prior
/// findings and this machine's dashboard stays pristine. A machine registered with `hosts add`
/// keeps its history under its stable id, so an ad-hoc `scan --ssh` of the same address lands in
/// the same history the scheduler and the GUI read; anything else gets a slug of the address.
fn remote_db_path(
    main_db: &Path,
    spec: &str,
) -> anyhow::Result<(PathBuf, Option<bulwark_core::fleet::RemoteHost>)> {
    if main_db.exists() {
        if let Some(h) = Store::open(main_db)?.find_remote_host(spec)? {
            return Ok((
                bulwark_core::paths::remote_host_db_path(main_db, &h.id),
                Some(h),
            ));
        }
    }
    Ok((
        bulwark_core::paths::adhoc_remote_db_path(main_db, spec),
        None,
    ))
}

/// Handles the `ssh` subcommand group. Calls the linked `bulwark-core` remediation directly —
/// the CLI is just a front-door over the same in-process function the GUI uses.
fn run_ssh(action: SshAction) -> anyhow::Result<()> {
    use bulwark_core::{protect_unencrypted_keys, KeyProtectionOutcome};
    match action {
        SshAction::Protect { stdin, json } => {
            let passphrase = if stdin {
                use std::io::BufRead;
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line.trim_end_matches(['\n', '\r']).to_string()
            } else {
                // No-echo prompt, entered twice so a typo doesn't silently lock keys with the
                // wrong passphrase.
                let p1 =
                    rpassword::prompt_password("New passphrase for all unencrypted SSH keys: ")?;
                let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
                if p1 != p2 {
                    anyhow::bail!("passphrases did not match");
                }
                p1
            };
            if passphrase.is_empty() {
                anyhow::bail!(
                    "empty passphrase — an empty passphrase would leave the keys unprotected"
                );
            }

            let home = bulwark_core::paths::home_var().context("HOME not set")?;
            let backup_dir = PathBuf::from(home).join(".local/share/bulwark/ssh-key-backups");
            let report = protect_unencrypted_keys(&passphrase, &backup_dir)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            if report.results.is_empty() {
                println!("No SSH private keys found in ~/.ssh.");
                return Ok(());
            }
            for r in &report.results {
                let status = match &r.outcome {
                    KeyProtectionOutcome::Protected => "protected".to_string(),
                    KeyProtectionOutcome::AlreadyEncrypted => "already encrypted".to_string(),
                    KeyProtectionOutcome::Undetermined => "skipped (status unreadable)".to_string(),
                    KeyProtectionOutcome::Failed { reason } => format!("FAILED: {reason}"),
                };
                println!("  {status:<28}  {}", r.path);
            }
            println!(
                "\n{} protected, {} already encrypted, {} undetermined, {} failed.",
                report.protected, report.already_encrypted, report.undetermined, report.failed
            );
            if report.protected > 0 {
                println!("Backups of the originals: {}", backup_dir.display());
                println!(
                    "Tip: 'ssh-add <key>' loads a key into your agent once per session so you \
                     don't retype the passphrase."
                );
            }
        }
    }
    Ok(())
}

/// The command line. The three rule-pack options are global, so clap lists them under every
/// subcommand, including `ai` and `agent`, which have no rule pack: their checks are built into
/// the program. They are hidden from the help of those two (a hidden copy defined on the
/// subcommand takes the place of the one clap would otherwise pass down), and the arms below say
/// so if one is given anyway.
fn parse_cli() -> Cli {
    use clap::{CommandFactory, FromArgMatches};
    let mut cmd = Cli::command();
    let hidden: Vec<clap::Arg> = cmd
        .get_arguments()
        .filter(|a| RULE_PACK_OPTIONS.contains(&a.get_id().as_str()))
        .map(|a| a.clone().hide(true))
        .collect();
    for sub in ["ai", "agent"] {
        cmd = cmd.mut_subcommand(sub, |c| c.args(hidden.clone()));
    }
    let matches = cmd.get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

const RULE_PACK_OPTIONS: &[&str] = &["rules_dir", "custom_rules_dir", "no_custom_rules"];

/// Says so when a rule-pack option was given to a command that has no rule pack.
fn note_unused_rule_options(command: &str, given: bool) {
    if given {
        eprintln!(
            "note: --rules-dir, --custom-rules-dir and --no-custom-rules have no effect on \
             `{command}`: its checks are built in"
        );
    }
}

/// A path the user typed, made absolute: `~` and `~/x` are the home folder (a shell does not
/// expand `--exclude=~/x`), and a relative path is taken from the current directory.
fn user_path(path: &Path, home: &Path) -> PathBuf {
    let expanded = match path.strip_prefix("~") {
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    };
    std::path::absolute(&expanded).unwrap_or(expanded)
}

/// The folders named with `flag`, each resolved and checked to exist. A folder that is not there
/// is an error, as a missing `--rules-dir` is: scanning nothing and reporting "no problems" for a
/// mistyped path is the one answer that must not be given.
fn existing_folders(flag: &str, paths: &[PathBuf], home: &Path) -> anyhow::Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|p| {
            let full = user_path(p, home);
            match std::fs::canonicalize(&full) {
                Ok(real) if real.is_dir() => Ok(real),
                Ok(_) => anyhow::bail!(
                    "{flag} {}: not a folder",
                    line_safe(&full.display().to_string())
                ),
                Err(e) => anyhow::bail!("{flag} {}: {e}", line_safe(&full.display().to_string())),
            }
        })
        .collect()
}

/// A file name or message from the scanned machine, safe to print on one line: control
/// characters, line breaks included, are replaced, so a name cannot move the cursor, ring the
/// bell or start a line of its own.
fn line_safe(text: &str) -> String {
    term_safe(text)
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Handles the `ai` subcommand group. Like `scan`, the `scan` path exits with a
/// severity-derived code so cron/CI can gate on it identically.
fn run_ai(action: AiAction, db_path: Option<PathBuf>) -> anyhow::Result<()> {
    use bulwark_core::ai_scan::redact::{redact_with, RedactOptions};
    use bulwark_core::{run_ai_scan, AiScanOptions};

    match action {
        AiAction::Scan {
            json,
            all,
            no_persist,
            roots,
            excludes,
            targets,
        } => {
            let home = resolve_home()?;
            let targets = existing_folders("--target", &targets, &home)?;
            let roots = existing_folders("--root", &roots, &home)?;
            let excludes: Vec<PathBuf> = excludes.iter().map(|p| user_path(p, &home)).collect();
            // Only a whole-machine scan is saved: the store keeps the latest run as the picture of
            // the machine, and a run of one folder is not that. Where it will be saved is decided
            // before the scan, so a database this run may not use is an error met at once.
            let save_to = if no_persist || !targets.is_empty() {
                None
            } else {
                Some(resolve_db_path(db_path)?)
            };
            let opts = AiScanOptions {
                home: home.clone(),
                configured_roots: roots,
                excluded_roots: excludes,
                explicit_targets: targets,
                max_workspaces: bulwark_core::ai_scan::DEFAULT_MAX_WORKSPACES,
            };
            let report = run_ai_scan(&opts, |_| {});

            // The report first. Saving it is second, and a failure to save is a warning: it used
            // to come first, so a read-only home turned a critical finding (exit 2) into a bare
            // "Permission denied" and exit 1.
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let opts = report::ReportOptions::for_stdout(all, "");
                print!("{}", report::render_ai(&report, home.to_str(), &opts));
            }
            for note in &report.notes {
                eprintln!("note: {}", line_safe(note));
            }
            if let Some(db) = save_to {
                let saved = Store::open(&db).and_then(|mut store| store.persist_ai_scan(&report));
                if let Err(e) = saved {
                    eprintln!(
                        "warning: this result was not saved — {} could not be written ({e:#})",
                        db.display()
                    );
                }
            }
            std::process::exit(exit_code_for(report.worst_severity()));
        }
        AiAction::Redact {
            apply,
            include_active,
            targets,
        } => {
            let home = resolve_home()?;
            let opts = AiScanOptions {
                explicit_targets: existing_folders("--target", &targets, &home)?,
                ..AiScanOptions::for_home(home)
            };
            let report = run_ai_scan(&opts, |_| {});
            let files = report.redactable_files();
            // Files that hold a key and are not rewritten: a project's own files, a `.env`, a
            // file reached through a link. Said, so "nothing to redact" is not read as "no keys".
            let left_alone = report
                .findings
                .iter()
                .filter(|f| f.rule_id == "BLWK-AI-001" && !f.redactable)
                .map(|f| f.file.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let say_left_alone = || {
                if left_alone > 0 {
                    println!(
                        "{left_alone} other file(s) hold a secret that redact does not rewrite \
                         (a project's own files, or files reached through a link) — \
                         `bulwarkctl ai scan` lists them; remove those by hand and rotate the keys."
                    );
                }
            };
            if files.is_empty() {
                println!(
                    "No redactable secrets found across {} artifact(s).",
                    report.artifacts_scanned
                );
                say_left_alone();
                return Ok(());
            }

            let backup_dir = resolve_db_path(None)?
                .parent()
                .map(|p| p.join("redaction-backups"))
                .unwrap_or_else(|| PathBuf::from("redaction-backups"));
            let outcome = redact_with(
                &files,
                RedactOptions {
                    apply,
                    include_active,
                },
                &backup_dir,
            );
            print_redaction_report(&outcome, apply, &backup_dir);
            say_left_alone();
            // A file that was meant to be cleaned and still holds its key is not a success.
            if apply && outcome.unfinished() {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn print_redaction_report(report: &bulwark_core::RedactionReport, apply: bool, backup_dir: &Path) {
    use bulwark_core::ai_scan::redact::IN_USE;
    if report.dry_run {
        println!("Dry run — nothing was changed. Re-run with --apply to redact.\n");
    }
    // Every name here comes from the scanned machine: printed on one line, with nothing that a
    // terminal would act on.
    for entry in &report.entries {
        let verb = if entry.applied {
            "redacted"
        } else {
            "would redact"
        };
        println!(
            "{} {} secret(s) in {}",
            verb,
            entry.secrets_redacted,
            line_safe(&entry.path)
        );
        if let Some(backup) = &entry.backup_path {
            println!("  backup: {}", line_safe(backup));
        }
    }
    for e in &report.errors {
        println!("⚠ {}", line_safe(e));
    }
    let verb = if apply { "Redacted" } else { "Found" };
    println!(
        "\n{} {} secret(s) across {} file(s).",
        verb,
        report.total_secrets,
        report.entries.len()
    );
    if apply && report.unfinished() {
        println!("Not every file was cleaned: a secret is still in each file marked ⚠ above.");
        if report.errors.iter().any(|e| e.contains(IN_USE)) {
            println!(
                "A file changed in the last 30 seconds is left alone. Run this again when the \
                 session has ended, or add --include-active to rewrite it now."
            );
        }
    }
    if report.entries.iter().any(|e| e.backup_path.is_some()) {
        println!(
            "\nThe backups are the original files, secrets included. They are kept in\n  {}\n\
             (readable only by you) until you delete that folder. Delete it once you have checked \
             the result — and rotate the keys either way: removing a key from a file does not \
             un-leak it.",
            line_safe(&backup_dir.display().to_string())
        );
    }
}

/// Handles the `logs` subcommand group. Kept as its own function so `main`'s top-level match
/// stays readable; the `scan` path calls `std::process::exit` with a severity-derived code just
/// like `Commands::Scan`, so scripts and cron can gate on it identically.
fn run_logs(action: LogsAction, db_path: Option<PathBuf>) -> anyhow::Result<()> {
    match action {
        LogsAction::Scan {
            json,
            all,
            no_persist,
            boot: _,
            since,
            from_file,
            decoders_dir,
            log_rules_dir,
        } => {
            let decoders_dir = resolve_pack(
                decoders_dir,
                "BULWARK_DECODERS_DIR",
                "decoders",
                "--decoders-dir",
                embedded::EMBEDDED_DECODERS,
            )?;
            let rules_dir = resolve_pack(
                log_rules_dir,
                "BULWARK_LOG_RULES_DIR",
                "log-rules",
                "--log-rules-dir",
                embedded::EMBEDDED_LOG_RULES,
            )?;

            let mut source: Box<dyn LogSource> = match from_file {
                Some(path) => {
                    // Refuses a folder and a pipe up front: reading either never ended.
                    let file = bulwark_core::open_log_file(&path)?;
                    // syslog headers carry no year. Use the file's last-modified time as the
                    // reference so a rotated log from last year is dated correctly (and a Dec/Jan
                    // boundary is handled per-line by the source), falling back to now for a file
                    // whose mtime can't be read.
                    let reference = file
                        .metadata()
                        .and_then(|m| m.modified())
                        .map(chrono::DateTime::<chrono::Utc>::from)
                        .unwrap_or_else(|_| chrono::Utc::now());
                    Box::new(SyslogLinesSource::new(BufReader::new(file), reference))
                }
                None => {
                    let range = match since {
                        Some(spec) => JournalRange::Since(spec),
                        None => JournalRange::CurrentBoot,
                    };
                    Box::new(JournaldSource::batch(range)?)
                }
            };

            let scan = run_log_scan(decoders_dir.source(), rules_dir.source(), source.as_mut());

            if !no_persist {
                let db_path = resolve_db_path(db_path)?;
                let mut store = Store::open(&db_path)?;
                store.persist_log_scan(&scan)?;
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                let opts = report::ReportOptions::for_stdout(all, "");
                print!("{}", report::render_logs(&scan, &opts));
            }
            // A scan that loaded no decoders or no rules never actually analyzed anything — exit
            // with an error so a script gating on the exit code can't mistake it for a clean run
            // (the finding-severity exit code below would otherwise report success).
            if scan.decoders_loaded == 0 || scan.rules_loaded == 0 {
                eprintln!("error: log scan could not run — no decoders and/or rules were loaded");
                std::process::exit(2);
            }
            // Same for input that held nothing usable — nothing read at all, or nothing of a kind
            // Bulwark understands: "no findings" from it is not a clean log. With `--json` the
            // reason goes to stderr, where a script that only checks the exit code still finds it.
            if let Some(why) = report::nothing_analyzed_reason(&scan) {
                if json {
                    eprintln!("error: {why}");
                }
                std::process::exit(2);
            }
            std::process::exit(exit_code_for(scan.worst_severity()));
        }
        LogsAction::Rules { action } => match action {
            RulesAction::List => {
                let dir = resolve_pack(
                    None,
                    "BULWARK_LOG_RULES_DIR",
                    "log-rules",
                    "--log-rules-dir",
                    embedded::EMBEDDED_LOG_RULES,
                )?;
                let (rules, errors) = load_log_rules(dir.source());
                for r in &rules {
                    let corr = if r.rule.correlate.is_some() {
                        " [correlated]"
                    } else {
                        ""
                    };
                    println!(
                        "{:<24} [{:<8}] {}{corr}",
                        r.rule.id,
                        severity_label(r.rule.severity),
                        r.rule.title
                    );
                }
                report_load_errors(&errors)?;
            }
            RulesAction::Validate { path } => {
                let (rules, mut errors) = load_log_rules(&path);
                nothing_to_validate(&path, rules.is_empty() && errors.is_empty())?;
                // Cross-check that every rule's `decoder:` names a real decoder — the log analog
                // of the config path's "unknown collector" validate-time guard. A typo there
                // would load cleanly but then silently never match an event.
                if let Ok(decoders_dir) = resolve_pack(
                    None,
                    "BULWARK_DECODERS_DIR",
                    "decoders",
                    "--decoders-dir",
                    embedded::EMBEDDED_DECODERS,
                ) {
                    let (decoders, _) = load_decoders(decoders_dir.source());
                    let ids: std::collections::HashSet<&str> =
                        decoders.iter().map(|d| d.id.as_str()).collect();
                    for r in &rules {
                        if let Some(dec) = &r.rule.decoder {
                            if !ids.contains(dec.as_str()) {
                                errors.push(bulwark_core::models::RuleLoadError {
                                    path: r.rule.id.clone(),
                                    message: format!("unknown decoder '{dec}'"),
                                });
                            }
                        }
                    }
                }
                println!(
                    "{} log rule(s) valid",
                    rules.len().saturating_sub(errors.len())
                );
                report_load_errors(&errors)?;
            }
        },
        LogsAction::Decoders { action } => match action {
            RulesAction::List => {
                let dir = resolve_pack(
                    None,
                    "BULWARK_DECODERS_DIR",
                    "decoders",
                    "--decoders-dir",
                    embedded::EMBEDDED_DECODERS,
                )?;
                let (decoders, errors) = load_decoders(dir.source());
                for d in &decoders {
                    let prog = d.program.as_deref().unwrap_or("(any)");
                    println!("{:<16} program={prog}", d.id);
                }
                report_load_errors(&errors)?;
            }
            RulesAction::Validate { path } => {
                let (decoders, errors) = load_decoders(&path);
                nothing_to_validate(&path, decoders.is_empty() && errors.is_empty())?;
                println!("{} decoder(s) valid", decoders.len());
                report_load_errors(&errors)?;
            }
        },
    }
    Ok(())
}

fn report_load_errors(errors: &[bulwark_core::models::RuleLoadError]) -> anyhow::Result<()> {
    if !errors.is_empty() {
        eprintln!("{} item(s) failed to load:", errors.len());
        for e in errors {
            eprintln!("  {}: {}", e.path, e.message);
        }
        std::process::exit(1);
    }
    Ok(())
}

/// The location to store for `--place <given>`: the place a finding is really at when the text
/// means exactly one, else the text as typed — with a warning naming the places that exist,
/// because an ignore nothing matches is otherwise indistinguishable from one that works.
pub(crate) fn place_to_ignore(
    store: &mut Store,
    rule_id: &str,
    given: &str,
) -> anyhow::Result<String> {
    if store.count_scan_runs()? == 0 {
        eprintln!(
            "note: no scan has been saved here yet, so '{}' could not be checked against a real \
             finding. After a scan, `bulwarkctl scan --all` lists each place on a line starting \
             with `·`.",
            term_safe(given)
        );
        return Ok(given.to_string());
    }
    let open = store.open_findings()?;
    let of_rule: Vec<&bulwark_core::Finding> =
        open.iter().filter(|f| f.rule_id == rule_id).collect();
    let home = bulwark_core::paths::home_var().ok();
    Ok(match place::match_place(given, &of_rule, home.as_deref()) {
        place::PlaceMatch::Exact(location) => location,
        place::PlaceMatch::Understood(location) => {
            println!(
                "(no finding is at '{}'; taking it to mean the place '{}')",
                term_safe(given),
                term_safe(&location)
            );
            location
        }
        place::PlaceMatch::NotFound { existing } => {
            eprintln!("{}", place::not_found_warning(rule_id, given, &existing));
            given.to_string()
        }
    })
}

/// The stored location to lift for `--place <given>`: the ignore itself, or the one ignore the
/// text clearly means. Refuses, listing what is ignored, when it means none.
pub(crate) fn place_to_unignore(
    store: &mut Store,
    rule_id: &str,
    given: &str,
) -> anyhow::Result<String> {
    let ignored: Vec<String> = store
        .list_finding_ignores()?
        .into_iter()
        .filter(|i| i.rule_id == rule_id)
        .map(|i| i.location)
        .collect();
    let home = bulwark_core::paths::home_var().ok();
    match place::match_ignored(given, &ignored, home.as_deref()) {
        Some(location) => Ok(location),
        None if ignored.is_empty() => {
            anyhow::bail!("{rule_id} has no single place ignored, so there is nothing to lift")
        }
        None => anyhow::bail!(
            "{rule_id} is not ignored at '{}'. It is ignored at: {}",
            term_safe(given),
            ignored
                .iter()
                .map(|l| format!("'{}'", term_safe(l)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The error for a `validate` that had nothing to look at: a path that isn't there, or one with
/// no YAML file in it. "0 valid" with exit code 0 is what a typo in the path used to produce.
fn nothing_to_validate(path: &Path, loaded_nothing: bool) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!(
            "{} does not exist, so nothing was validated",
            path.display()
        );
    }
    if loaded_nothing {
        anyhow::bail!(
            "no rule files (.yaml or .yml) found in {}, so nothing was validated",
            path.display()
        );
    }
    Ok(())
}

/// What `rules validate` found.
struct Validation {
    valid: usize,
    errors: Vec<bulwark_core::models::RuleLoadError>,
}

/// Checks a rule file or folder the way loading would, plus what only shows at scan time.
///
/// Three things used to pass that are not valid. A path that isn't there, or a folder without a
/// single rule file, printed "0 rule(s) valid" and exited 0 — a typo read as a clean result. And
/// a custom rule with a reserved id was reported valid, although a scan refuses to load it.
fn validate_rules(path: &Path, custom_dir: Option<&Path>) -> anyhow::Result<Validation> {
    let (rules, mut errors) = engine::load_rules(path);
    nothing_to_validate(path, rules.is_empty() && errors.is_empty())?;
    let mut invalid: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Schema/condition validity alone isn't enough: a `collector:` field that doesn't match any
    // registered collector name loads without error but then never matches a fact row at scan
    // time, so the rule silently never fires — forever, with nothing in `collector_errors` or
    // `rule_load_errors` to catch it. Cross-checking against the real collector registry here is
    // what turns that into a validate-time failure instead.
    let collectors = all_collectors();
    let mut known: Vec<&str> = collectors.iter().map(|c| c.name()).collect();
    known.sort_unstable();
    for r in &rules {
        if !known.contains(&r.rule.collector.as_str()) {
            invalid.insert(r.rule.id.clone());
            errors.push(bulwark_core::models::RuleLoadError {
                path: r.rule.id.clone(),
                message: format!(
                    "unknown collector '{}' — not one of: {}",
                    r.rule.collector,
                    known.join(", ")
                ),
            });
        }
    }

    // The id rules for your own checks, exactly as `engine::load_rule_packs` applies them: the
    // BLWK- prefix is reserved, and so is every id a built-in check uses. They apply to your own
    // rules folder, and to any other folder that is mostly rules of your own — but not to a copy
    // of the built-in pack itself, which is all BLWK- ids and is what CI validates.
    let reserved = |id: &str| id.to_ascii_uppercase().starts_with("BLWK-");
    let own_rules = rules.iter().filter(|r| !reserved(&r.rule.id)).count();
    let in_custom_dir = custom_dir.is_some_and(|dir| {
        let resolve = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        resolve(path).starts_with(resolve(dir))
    });
    if in_custom_dir || own_rules * 2 >= rules.len().max(1) {
        let builtin: std::collections::HashSet<String> =
            engine::load_rules(bulwark_core::PackSource::Embedded(embedded::EMBEDDED_RULES))
                .0
                .into_iter()
                .map(|r| r.rule.id)
                .collect();
        for r in &rules {
            let message = if reserved(&r.rule.id) {
                "custom rule ids can't start with BLWK- (reserved for Bulwark's own checks), so a \
                 scan would refuse this rule — use your own prefix, e.g. MY-001"
                    .to_string()
            } else if builtin.contains(&r.rule.id) {
                format!(
                    "'{}' is already a built-in check's id, so a scan would refuse this rule",
                    r.rule.id
                )
            } else {
                continue;
            };
            invalid.insert(r.rule.id.clone());
            errors.push(bulwark_core::models::RuleLoadError {
                path: r.rule.id.clone(),
                message,
            });
        }
    }

    let valid = rules
        .iter()
        .filter(|r| !invalid.contains(&r.rule.id))
        .count();
    Ok(Validation { valid, errors })
}

/// `bulwarkctl history`: the count, then the newest runs, one per line.
fn history_table(runs: &[bulwark_core::ScanRunSummary], total: i64) -> String {
    use std::fmt::Write as _;
    let mut out = format!("{total} scan run(s) recorded\n");
    if runs.is_empty() {
        return out;
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {:<17} {:<12} {:<6} FINDINGS LEFT OPEN",
        "WHEN", "CHECKS RAN", "ADMIN"
    );
    for r in runs {
        let when = r
            .started_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M");
        // A run saved before the set of checks that ran was kept has no number to show; "0 of 99"
        // would say nothing ran.
        let checks = if r.rules_evaluated == 0 {
            format!("? of {}", r.rules_loaded)
        } else {
            format!("{} of {}", r.rules_evaluated, r.rules_loaded)
        };
        let admin = if r.privileged_collectors_skipped.is_empty() {
            "yes"
        } else {
            "no"
        };
        let findings = match &r.severity_counts {
            Some(c) if c.total() == 0 => "none".to_string(),
            Some(c) => {
                let parts: Vec<String> = [
                    (c.critical, "critical"),
                    (c.high, "high"),
                    (c.medium, "medium"),
                    (c.low, "low"),
                    (c.info, "info"),
                ]
                .iter()
                .filter(|(n, _)| *n > 0)
                .map(|(n, word)| format!("{n} {word}"))
                .collect();
                format!("{:<4} {}", c.total(), parts.join(" · "))
            }
            // Saved before the split by severity was kept: the total is known, the split is not.
            None => format!(
                "{:<4} (severity not recorded for this run)",
                r.total_findings
            ),
        };
        let _ = writeln!(out, "  {when:<17} {checks:<12} {admin:<6} {findings}");
    }
    if (runs.len() as i64) < total {
        let _ = writeln!(
            out,
            "\nShowing the newest {} of {total}. `bulwarkctl history --limit N` shows more.",
            runs.len()
        );
    }
    let _ = writeln!(
        out,
        "\nADMIN is whether the run included the checks that need root (sudo bulwarkctl scan \
         --privileged). `bulwarkctl scan` shows the findings themselves."
    );
    out
}

fn print_scan_table(
    scan: &bulwark_core::ScanRun,
    ignores: &bulwark_core::Ignores,
    all: bool,
    target: &str,
) {
    let opts = report::ReportOptions::for_stdout(all, target);
    print!("{}", report::render(scan, ignores, &opts));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_needs_flag_keeps_the_detected_roles() {
        assert_eq!(scan_profile(vec![]).needs, Profile::current_host().needs);
        // Every host is at least a desktop or a server, so the default is never empty.
        assert!(!scan_profile(vec![]).needs.is_empty());
    }

    #[test]
    fn explicit_needs_replace_the_detected_roles() {
        let profile = scan_profile(vec!["developer".to_string()]);
        let host = Profile::current_host();
        let mut expected = vec!["developer".to_string()];
        // Explicit needs replace roles, not environment facts. WSL must remain
        // tagged so manual scans and background scans apply the same skip rules.
        if host.needs.iter().any(|need| need == "wsl") {
            expected.push("wsl".to_string());
        }
        assert_eq!(profile.needs, expected);
        assert_eq!(profile.os, host.os);
    }
}

//! Remote machines monitored over SSH: the data model, validation, scheduling and health rules.
//!
//! **No networking happens here.** `bulwark-core` has a hard no-network invariant (architecture doc
//! §10), so the SSH transport itself lives in the CLI front-door (`bulwarkctl/src/remote.rs`) and
//! the GUI reaches it by running that CLI. What lives here is everything both front-doors must agree
//! on and that can be decided without touching a socket: what a valid target looks like, when a
//! machine is next due, how a failure is classified and explained, and what "healthy" means.
//!
//! Two invariants carry over from the local scanner and are not negotiable:
//!
//! * **A machine we could not reach is never "clean".** Health is derived from the *last attempt*,
//!   not from the last stored findings: a host whose newest scan failed shows as unreachable (or
//!   stale), never as the all-clear its old empty findings list would suggest.
//! * **A failure is always explained.** Every [`RemoteErrorKind`] carries a plain-language title and
//!   a concrete next step (usually a command to copy), because "ssh exited 255" is not something a
//!   user can act on.

use crate::models::Severity;
use crate::store::Store;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Shortest and longest scan interval a machine may be given, in minutes. The floor stops a
/// misconfiguration from hammering a machine over SSH; the ceiling is one week.
pub const MIN_INTERVAL_MINUTES: u32 = 5;
pub const MAX_INTERVAL_MINUTES: u32 = 7 * 24 * 60;
/// Default interval for a newly added machine. Longer than the local loop's 15 minutes because a
/// remote scan costs an SSH session (and, when Bulwark is not installed there, a binary upload).
pub const DEFAULT_INTERVAL_MINUTES: u32 = 60;
/// A failing machine is retried less often, doubling per consecutive failure, up to this cap — so
/// a laptop that is simply switched off doesn't produce a connection attempt every few minutes.
pub const MAX_BACKOFF_MINUTES: u32 = 6 * 60;
/// Consecutive failures before a machine counts as "unreachable" rather than as a blip, and before
/// the GUI raises a desktop notification about it. One failed attempt is usually Wi-Fi.
pub const UNREACHABLE_AFTER_FAILURES: u32 = 3;

/// Why a remote scan (or connection check) failed. Serialized in snake_case, and stored that way in
/// `remote_hosts.last_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteErrorKind {
    /// The address, name, port or key file failed validation before anything ran.
    InvalidTarget,
    /// No `ssh` client on this machine.
    SshMissing,
    /// The host name doesn't resolve.
    Unresolvable,
    /// Refused, no route, network down — the machine isn't answering.
    Unreachable,
    /// The connection or the scan took longer than its deadline.
    Timeout,
    /// The machine's host key isn't trusted yet (first connection).
    HostKeyUnknown,
    /// The machine presented a *different* host key from the one on record. Possibly a reinstall,
    /// possibly interception — never auto-resolved.
    HostKeyChanged,
    /// The machine refused our keys (or would need a password/passphrase prompt).
    AuthFailed,
    /// Bulwark isn't installed there and this build can't run on the machine's CPU.
    ArchUnsupported,
    /// Bulwark isn't installed there and this build can't copy itself (e.g. inside a Flatpak).
    EngineMissing,
    /// Root checks were requested but `sudo` there needs a password.
    SudoRequiresPassword,
    /// The remote engine answered with something this version can't read (version skew).
    IncompatibleEngine,
    /// The remote scan loaded zero rules — it examined nothing, so it proves nothing.
    NoRules,
    /// The address now answers as a different machine (its hostname changed).
    IdentityChanged,
    /// The machine's operating system isn't one Bulwark can scan yet (e.g. a Windows SSH shell).
    UnsupportedOs,
    /// The scan ran, but none of Bulwark's checks apply to or could run on this system yet.
    NothingAssessed,
    /// The scan ran, but this computer couldn't save its results (the machine's history database).
    LocalStorage,
    /// Anything else; the raw message is kept alongside.
    Other,
}

impl RemoteErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTarget => "invalid_target",
            Self::SshMissing => "ssh_missing",
            Self::Unresolvable => "unresolvable",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::HostKeyUnknown => "host_key_unknown",
            Self::HostKeyChanged => "host_key_changed",
            Self::AuthFailed => "auth_failed",
            Self::ArchUnsupported => "arch_unsupported",
            Self::EngineMissing => "engine_missing",
            Self::SudoRequiresPassword => "sudo_requires_password",
            Self::IncompatibleEngine => "incompatible_engine",
            Self::NoRules => "no_rules",
            Self::IdentityChanged => "identity_changed",
            Self::UnsupportedOs => "unsupported_os",
            Self::NothingAssessed => "nothing_assessed",
            Self::LocalStorage => "local_storage",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }

    /// True for failures that mean "the machine isn't answering right now" — the ones that are
    /// expected to clear by themselves and that a backoff is for. Everything else needs a person.
    pub fn is_connectivity(self) -> bool {
        matches!(self, Self::Unresolvable | Self::Unreachable | Self::Timeout)
    }

    /// True when the machine works but Bulwark has nothing for it *yet* — not a fault anyone can fix
    /// today, so it is shown neutrally, checked rarely, and never alerted on. Support for more
    /// systems is added gradually; a machine in this state starts scanning as soon as it lands.
    pub fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedOs | Self::NothingAssessed)
    }

    /// True for failures that may indicate an attack rather than a misconfiguration. The GUI
    /// notifies on these immediately instead of waiting for repeated failures.
    pub fn is_security_relevant(self) -> bool {
        matches!(self, Self::HostKeyChanged | Self::IdentityChanged)
    }

    /// One short sentence a person can read in a status pill or notification.
    pub fn title(self) -> &'static str {
        match self {
            Self::InvalidTarget => "The machine's address isn't valid",
            Self::SshMissing => "No SSH client is installed on this computer",
            Self::Unresolvable => "The machine's name can't be found",
            Self::Unreachable => "The machine isn't answering",
            Self::Timeout => "The machine took too long to respond",
            Self::HostKeyUnknown => "This machine hasn't been trusted yet",
            Self::HostKeyChanged => "The machine's identity key has changed",
            Self::AuthFailed => "The machine didn't accept your SSH key",
            Self::ArchUnsupported => "Bulwark can't run on this machine's processor",
            Self::EngineMissing => "Bulwark needs to be installed on this machine",
            Self::SudoRequiresPassword => "Root checks need passwordless sudo",
            Self::IncompatibleEngine => "The machine runs an incompatible Bulwark version",
            Self::NoRules => "The machine's scan didn't load any checks",
            Self::IdentityChanged => "This address now belongs to a different machine",
            Self::UnsupportedOs => "Bulwark can't scan this operating system yet",
            Self::NothingAssessed => "No checks for this system yet",
            Self::LocalStorage => "Couldn't save this machine's results",
            Self::Other => "The scan failed",
        }
    }

    /// What to do about it, with the exact command where there is one. `ssh` is the command the
    /// user would type to reach this machine (see [`ssh_command_line`]).
    pub fn hint(self, ssh: &str) -> String {
        match self {
            Self::InvalidTarget => {
                "Use user@host, a plain host name, or a Host alias from ~/.ssh/config.".into()
            }
            Self::SshMissing => {
                "Install the OpenSSH client (sudo apt install openssh-client, or sudo dnf install \
                 openssh-clients)."
                    .into()
            }
            Self::Unresolvable => format!(
                "Check the spelling, or use the machine's IP address. `{ssh}` should connect from \
                 a terminal."
            ),
            Self::Unreachable => format!(
                "Make sure the machine is on and reachable from this network, and that SSH is \
                 running on it. Bulwark will keep retrying, less often, until it answers. Test with \
                 `{ssh}`."
            ),
            Self::Timeout => format!(
                "The network may be slow or a firewall may be dropping the connection. Test with \
                 `{ssh}`."
            ),
            Self::HostKeyUnknown => format!(
                "Compare the machine's host key fingerprint and approve it (Remote → Check \
                 connection, or `bulwarkctl hosts trust`), or connect once from a terminal with \
                 `{ssh}` and answer yes."
            ),
            Self::HostKeyChanged => format!(
                "This happens when a machine is reinstalled — or when someone is intercepting the \
                 connection. Scans are refused until you confirm the new key with whoever manages \
                 the machine. Once confirmed, replace the stored key (Remote → Check connection, \
                 or `bulwarkctl hosts trust <name> --fingerprint <new> --replace`). If the old key \
                 is in your own ~/.ssh/known_hosts, also remove it there (`ssh-keygen -R <host>`), \
                 or test with `{ssh}`."
            ),
            Self::AuthFailed => format!(
                "Bulwark signs in without prompting, so it needs key access. Easiest: let Bulwark \
                 install its own restricted key — sign in once with your password (Remote → Set \
                 up key access, or `bulwarkctl hosts setup-key <name> --password-stdin`); the \
                 password is never stored. Or make `{ssh}` work without a prompt: load your key \
                 with `ssh-add`, or copy it over with `ssh-copy-id`."
            ),
            Self::ArchUnsupported => {
                "Install Bulwark on that machine (see bulwark's download page) and scan again — an \
                 installed copy always runs natively."
                    .into()
            }
            Self::EngineMissing => {
                "Bulwark can't copy itself there (it only copies itself from Linux to Linux \
                 machines with the same processor). Install Bulwark on that machine — bulwarkctl on \
                 Linux or macOS, Bulwark for Windows on Windows — then scan again; Check \
                 connection shows the install command."
                    .into()
            }
            Self::SudoRequiresPassword => {
                "Root checks run unattended, so sudo there must not ask for a password. With \
                 Bulwark installed on the machine, allow just the scanner: run `sudo visudo -f \
                 /etc/sudoers.d/bulwark` there and add `<user> ALL=(root) NOPASSWD: \
                 /usr/bin/bulwarkctl scan --json --no-persist --privileged` (exactly that command — \
                 never a wildcard). Or turn root checks off for this machine."
                    .into()
            }
            Self::IncompatibleEngine => {
                "Update Bulwark on that machine to the same version as this one, or uninstall it \
                 there so Bulwark copies itself for each scan."
                    .into()
            }
            Self::NoRules => {
                "The rule pack on that machine is missing or empty. Reinstall Bulwark there."
                    .into()
            }
            Self::IdentityChanged => {
                "Its history was kept and nothing was merged. If the machine was renamed or \
                 rebuilt on purpose, accept its new identity (Remote → Accept new identity, or \
                 `bulwarkctl hosts set <name> --accept-identity`); otherwise check where this \
                 address points."
                    .into()
            }
            Self::UnsupportedOs => {
                "Remote scans cover Linux (including WSL), macOS, and Windows with Bulwark \
                 installed on it. This machine's shell answered in a way Bulwark doesn't recognise \
                 — on Windows, check that PowerShell is available to the SSH account. Bulwark \
                 checks back once a day."
                    .into()
            }
            Self::NothingAssessed => {
                "The connection works and the scan ran, but none of Bulwark's checks apply to this \
                 system yet, so there's nothing to report — which is not the same as clean. \
                 Bulwark checks back once a day and will start reporting when checks for it land."
                    .into()
            }
            Self::LocalStorage => {
                "The machine answered and the scan ran; the problem is on this computer, which \
                 couldn't write the machine's history (its database under Bulwark's data folder). \
                 Check free disk space and that nothing else holds the file open — the next scan \
                 tries again."
                    .into()
            }
            Self::Other => format!("Try `{ssh}` from a terminal to see the full error."),
        }
    }
}

impl std::fmt::Display for RemoteErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify an `ssh` failure from its stderr. Only meaningful when ssh itself failed (it exits 255
/// for its own errors); returns `None` when nothing recognizable is present.
pub fn classify_ssh_stderr(stderr: &str) -> Option<RemoteErrorKind> {
    let e = stderr.to_lowercase();
    // Order matters: the "changed" banner also contains "host key verification failed".
    if e.contains("remote host identification has changed")
        || e.contains("host key for") && e.contains("has changed")
    {
        return Some(RemoteErrorKind::HostKeyChanged);
    }
    if e.contains("host key verification failed")
        || e.contains("no ") && e.contains("host key is known")
        || e.contains("host key is not known")
    {
        return Some(RemoteErrorKind::HostKeyUnknown);
    }
    if e.contains("could not resolve hostname")
        || e.contains("name or service not known")
        || e.contains("temporary failure in name resolution")
        || e.contains("nodename nor servname")
    {
        return Some(RemoteErrorKind::Unresolvable);
    }
    if e.contains("connection timed out")
        || e.contains("operation timed out")
        || e.contains("timed out during banner exchange")
    {
        return Some(RemoteErrorKind::Timeout);
    }
    if e.contains("connection refused")
        || e.contains("no route to host")
        || e.contains("network is unreachable")
        || e.contains("connection closed by")
        || e.contains("connection reset")
    {
        return Some(RemoteErrorKind::Unreachable);
    }
    if e.contains("permission denied")
        || e.contains("too many authentication failures")
        || e.contains("no more authentication methods")
    {
        return Some(RemoteErrorKind::AuthFailed);
    }
    None
}

/// What the user would type to reach the machine — used in hints, so every suggested command
/// actually targets the same port and key Bulwark uses.
pub fn ssh_command_line(
    spec: &str,
    port: Option<u16>,
    identity: Option<&str>,
    jump: Option<&str>,
) -> String {
    let mut s = String::from("ssh");
    if let Some(j) = jump {
        s.push_str(&format!(" -J {j}"));
    }
    if let Some(p) = port {
        s.push_str(&format!(" -p {p}"));
    }
    if let Some(i) = identity {
        s.push_str(&format!(" -i {i}"));
    }
    s.push(' ');
    s.push_str(spec);
    s
}

// ---- validation ---------------------------------------------------------------------------------

/// Validates an SSH target: `host`, `user@host`, an `~/.ssh/config` alias, or an IPv6 literal.
///
/// The one rule that is about security rather than tidiness: **a target may not start with `-`**.
/// It is passed to `ssh` as an argument, and `-oProxyCommand=…` there would run a local command —
/// harmless when typed into a terminal by its owner, not harmless when stored and replayed by a
/// background scheduler. The character set is otherwise conservative: anything a real host name,
/// user name or alias needs, and nothing a shell would treat specially.
pub fn validate_spec(spec: &str) -> Result<(), String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("enter a host name, user@host, or an ~/.ssh/config alias".into());
    }
    if s.len() > 255 {
        return Err("that address is too long".into());
    }
    if s.starts_with('-') {
        return Err("an address can't start with '-'".into());
    }
    if let Some(bad) = s.chars().find(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '[' | ']'))
    }) {
        return Err(format!("'{bad}' isn't allowed in an address"));
    }
    if s.matches('@').count() > 1 {
        return Err("use a single '@' (user@host)".into());
    }
    let host = s.rsplit('@').next().unwrap_or("");
    if host.is_empty() || host.starts_with('-') {
        return Err("the host part is missing".into());
    }
    if s.starts_with('@') {
        return Err("the user part is missing".into());
    }
    Ok(())
}

/// Validates a display name: 1–64 characters, no control characters.
pub fn validate_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("give the machine a name".into());
    }
    if n.chars().count() > 64 {
        return Err("keep the name under 64 characters".into());
    }
    if n.chars().any(char::is_control) {
        return Err("the name contains control characters".into());
    }
    Ok(())
}

/// Validates a private-key path: absolute (or `~/…`), not option-shaped.
pub fn validate_identity(path: &str) -> Result<(), String> {
    let p = path.trim();
    if p.starts_with('-') {
        return Err("a key path can't start with '-'".into());
    }
    // A Windows drive path (`C:\Users\…\key`) is as absolute as `/home/…`: Bulwark's own key lives
    // under %LOCALAPPDATA% there, and rejecting it made key setup impossible on Windows.
    let b = p.as_bytes();
    let windows_drive = b.len() > 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    if !(p.starts_with('/') || p.starts_with("~/") || p.starts_with("~\\") || windows_drive) {
        return Err("use a full path to the private key, e.g. ~/.ssh/id_ed25519".into());
    }
    if p.chars().any(char::is_control) {
        return Err("the key path contains control characters".into());
    }
    Ok(())
}

/// Validates a ProxyJump chain: one or more comma-separated hops, each `[user@]host[:port]`, each
/// held to the same rules as an address (in particular, never option-shaped).
pub fn validate_jump(jump: &str) -> Result<(), String> {
    let j = jump.trim();
    if j.is_empty() {
        return Ok(());
    }
    for hop in j.split(',') {
        validate_spec(hop).map_err(|e| format!("jump host: {e}"))?;
    }
    Ok(())
}

pub fn validate_interval(minutes: u32) -> Result<(), String> {
    if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&minutes) {
        return Err(format!(
            "the interval must be between {MIN_INTERVAL_MINUTES} minutes and one week"
        ));
    }
    Ok(())
}

/// Expands a leading `~/` against `$HOME`, so a key path typed the way people type it works.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = crate::paths::home_var_os() {
            return Path::new(&home).join(rest).display().to_string();
        }
    }
    path.to_string()
}

/// A sensible default display name for a target: the host part of `user@host`.
pub fn default_name_for(spec: &str) -> String {
    spec.trim()
        .rsplit('@')
        .next()
        .unwrap_or(spec)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string()
}

// ---- the model ----------------------------------------------------------------------------------

/// A registered remote machine and the outcome of its last scan attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteHost {
    pub id: String,
    pub name: String,
    pub spec: String,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    /// ProxyJump chain to reach the machine through, e.g. `me@bastion`.
    pub jump_host: Option<String>,
    /// Run the root-only checks too, via `sudo -n` on the machine.
    pub privileged: bool,
    /// Included in scheduled scans. A paused machine keeps its history and can still be scanned on
    /// demand.
    pub enabled: bool,
    pub interval_minutes: u32,
    pub created_at: DateTime<Utc>,
    /// The machine's hostname, learned on the first successful scan. See the migration.
    pub expected_hostname: Option<String>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    /// `None` = never attempted; `Some(Ok)` = last attempt succeeded.
    pub last_status: Option<LastStatus>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    /// How the last scan obtained its engine, e.g. "installed /usr/bin/bulwarkctl (0.11.1)".
    pub engine: Option<String>,
    /// Short OS key for the app's icon (`ubuntu`, `macos`, `wsl`, `windows`, …) and its readable
    /// name, as last seen by a successful connection.
    pub os_kind: Option<String>,
    pub os_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "kind")]
pub enum LastStatus {
    Ok,
    Failed(RemoteErrorKind),
}

impl LastStatus {
    pub fn to_db(self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::Failed(k) => k.as_str().into(),
        }
    }
    pub fn from_db(s: &str) -> Self {
        if s == "ok" {
            Self::Ok
        } else {
            Self::Failed(RemoteErrorKind::parse(s).unwrap_or(RemoteErrorKind::Other))
        }
    }
}

/// Input for registering a machine. Validated by [`NewRemoteHost::validate`] (and again by the
/// store, so no caller can skip it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRemoteHost {
    pub name: Option<String>,
    pub spec: String,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    #[serde(default)]
    pub jump_host: Option<String>,
    #[serde(default)]
    pub privileged: bool,
    pub interval_minutes: Option<u32>,
}

impl NewRemoteHost {
    pub fn validate(&self) -> Result<(), String> {
        validate_spec(&self.spec)?;
        if let Some(n) = &self.name {
            validate_name(n)?;
        }
        if let Some(i) = &self.identity_file {
            validate_identity(i)?;
        }
        if let Some(j) = &self.jump_host {
            validate_jump(j)?;
        }
        if self.port == Some(0) {
            return Err("port 0 isn't valid".into());
        }
        if let Some(m) = self.interval_minutes {
            validate_interval(m)?;
        }
        Ok(())
    }
}

/// A partial update. `None` leaves a field alone; for the optional fields, `Some(None)` clears. In
/// JSON: an absent field keeps, an explicit `null` clears.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteHostPatch {
    pub name: Option<String>,
    pub spec: Option<String>,
    #[serde(default, deserialize_with = "present_or_null")]
    pub port: Option<Option<u16>>,
    #[serde(default, deserialize_with = "present_or_null")]
    pub identity_file: Option<Option<String>>,
    #[serde(default, deserialize_with = "present_or_null")]
    pub jump_host: Option<Option<String>>,
    pub privileged: Option<bool>,
    pub enabled: Option<bool>,
    pub interval_minutes: Option<u32>,
    /// Forget the pinned hostname so the next successful scan re-learns it ("Accept new identity").
    #[serde(default)]
    pub reset_identity: bool,
}

/// Deserializes a present field (including `null`) as `Some(..)`; `#[serde(default)]` makes an
/// absent one `None`. That is what lets a patch say "clear the port" as distinct from "leave it".
fn present_or_null<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

impl RemoteHostPatch {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(s) = &self.spec {
            validate_spec(s)?;
        }
        if let Some(n) = &self.name {
            validate_name(n)?;
        }
        if let Some(Some(i)) = &self.identity_file {
            validate_identity(i)?;
        }
        if let Some(Some(j)) = &self.jump_host {
            validate_jump(j)?;
        }
        if self.port == Some(Some(0)) {
            return Err("port 0 isn't valid".into());
        }
        if let Some(m) = self.interval_minutes {
            validate_interval(m)?;
        }
        Ok(())
    }
}

/// The result of one scan attempt, as recorded against the machine.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Success {
        hostname: String,
        engine: String,
    },
    Failure {
        kind: RemoteErrorKind,
        message: String,
    },
}

// ---- scheduling ---------------------------------------------------------------------------------

impl RemoteHost {
    /// The interval actually in force: the configured one, doubled per consecutive *connectivity*
    /// failure (up to [`MAX_BACKOFF_MINUTES`], never below the configured interval). A failure that
    /// needs a person — a refused key, a changed host key — is not backed off: it won't fix itself,
    /// and retrying at the normal pace costs one cheap rejected handshake.
    pub fn effective_interval(&self) -> Duration {
        let base = self.interval_minutes.max(MIN_INTERVAL_MINUTES) as i64;
        if matches!(self.last_status, Some(LastStatus::Failed(k)) if k.is_unsupported()) {
            return Duration::minutes(base.max(24 * 60));
        }
        let backing_off = matches!(
            self.last_status,
            Some(LastStatus::Failed(k)) if k.is_connectivity()
        );
        if !backing_off || self.consecutive_failures == 0 {
            return Duration::minutes(base);
        }
        let factor = 1i64 << self.consecutive_failures.min(6);
        let cap = (MAX_BACKOFF_MINUTES as i64).max(base);
        Duration::minutes((base * factor).min(cap))
    }

    /// When the next scheduled scan is due; `None` when paused. A never-attempted machine is due
    /// immediately.
    pub fn next_due_at(&self) -> Option<DateTime<Utc>> {
        if !self.enabled {
            return None;
        }
        Some(match self.last_attempt_at {
            None => self.created_at,
            Some(t) => t + self.effective_interval(),
        })
    }

    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        self.next_due_at().is_some_and(|t| now >= t)
    }

    /// The last *successful* scan is older than two intervals: whatever its findings say, they are
    /// no longer a current picture of the machine.
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        match self.last_success_at {
            None => false,
            Some(t) => now - t > Duration::minutes(self.interval_minutes as i64 * 2),
        }
    }

    pub fn ssh_command_line(&self) -> String {
        ssh_command_line(
            &self.spec,
            self.port,
            self.identity_file.as_deref(),
            self.jump_host.as_deref(),
        )
    }
}

// ---- health and summaries -----------------------------------------------------------------------

/// Open-finding counts for one machine, from its own database.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Open findings of rules the user accepted the risk of — counted, never hidden.
    pub suppressed: usize,
}

impl FindingCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
    fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// One word for the state of a machine, in priority order: the first that applies wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHealth {
    /// Never scanned yet.
    New,
    /// The last attempt hit something only a person can fix (key refused, host key changed, …).
    NeedsAttention,
    /// Reachable, but Bulwark has no checks for its system yet. Neutral: nothing to fix.
    Unsupported,
    /// Several connectivity failures in a row.
    Unreachable,
    /// The last successful scan is more than two intervals old.
    Stale,
    /// Up to date, with critical or high findings open.
    AtRisk,
    /// Up to date, with only medium/low/info findings open.
    Issues,
    /// Up to date, nothing open.
    Healthy,
}

pub fn health(host: &RemoteHost, counts: &FindingCounts, now: DateTime<Utc>) -> HostHealth {
    match host.last_status {
        None => return HostHealth::New,
        Some(LastStatus::Failed(k)) if k.is_unsupported() => return HostHealth::Unsupported,
        Some(LastStatus::Failed(k)) if !k.is_connectivity() => return HostHealth::NeedsAttention,
        Some(LastStatus::Failed(_)) if host.consecutive_failures >= UNREACHABLE_AFTER_FAILURES => {
            return HostHealth::Unreachable
        }
        _ => {}
    }
    if host.last_success_at.is_none() {
        // Failed, not yet often enough to be "unreachable", and never succeeded: nothing to show.
        return HostHealth::New;
    }
    if host.is_stale(now) {
        return HostHealth::Stale;
    }
    if counts.critical + counts.high > 0 {
        HostHealth::AtRisk
    } else if counts.total() > 0 {
        HostHealth::Issues
    } else {
        HostHealth::Healthy
    }
}

/// Everything a list view needs about one machine, assembled from the registry row plus its own
/// findings database.
#[derive(Debug, Clone, Serialize)]
pub struct RemoteHostView {
    #[serde(flatten)]
    pub host: RemoteHost,
    pub health: HostHealth,
    pub counts: FindingCounts,
    pub next_due_at: Option<DateTime<Utc>>,
    /// Root-only checks the last scan had to skip (non-empty when root checks are off).
    pub privileged_collectors_skipped: Vec<String>,
    /// How many checks the last successful scan actually ran. Shown beside "healthy" so a machine
    /// whose system only a few checks cover doesn't read as thoroughly examined.
    pub checks_run: Option<usize>,
    pub ssh_command: String,
    /// Title and next step for the last failure, if the last attempt failed.
    pub problem: Option<Problem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    pub kind: RemoteErrorKind,
    pub title: String,
    pub hint: String,
    pub detail: Option<String>,
}

impl Problem {
    pub fn new(kind: RemoteErrorKind, ssh: &str, detail: Option<String>) -> Self {
        Problem {
            kind,
            title: kind.title().into(),
            hint: kind.hint(ssh),
            detail,
        }
    }
}

/// What a machine's own database says about it: open-finding counts, the root-only collectors the
/// last scan skipped, and how many checks it ran.
pub struct HostSummary {
    pub counts: FindingCounts,
    pub skipped: Vec<String>,
    pub checks_run: Option<usize>,
}

/// Reads a machine's summary. A missing database (never scanned) yields an empty summary rather
/// than an error.
pub fn read_host_summary(host_db: &Path) -> anyhow::Result<HostSummary> {
    if !host_db.exists() {
        return Ok(HostSummary {
            counts: FindingCounts::default(),
            skipped: Vec::new(),
            checks_run: None,
        });
    }
    let mut store = Store::open(host_db)?;
    let split = store.open_findings_split()?;
    let mut counts = FindingCounts::default();
    for f in &split.active {
        counts.add(f.severity);
    }
    counts.suppressed = split.suppressed.len();
    let skipped = store
        .latest_scan_run_meta()?
        .map(|m| m.privileged_collectors_skipped)
        .unwrap_or_default();
    let checks_run = store.latest_rules_evaluated()?.map(|s| s.len());
    Ok(HostSummary {
        counts,
        skipped,
        checks_run,
    })
}

pub fn build_view(host: RemoteHost, main_db: &Path, now: DateTime<Utc>) -> RemoteHostView {
    let host_db = crate::paths::remote_host_db_path(main_db, &host.id);
    let HostSummary {
        counts,
        skipped,
        checks_run,
    } = read_host_summary(&host_db).unwrap_or(HostSummary {
        counts: FindingCounts::default(),
        skipped: Vec::new(),
        checks_run: None,
    });
    let ssh = host.ssh_command_line();
    let problem = match host.last_status {
        Some(LastStatus::Failed(k)) => Some(Problem::new(k, &ssh, host.last_error.clone())),
        _ => None,
    };
    RemoteHostView {
        health: health(&host, &counts, now),
        next_due_at: host.next_due_at(),
        counts,
        privileged_collectors_skipped: skipped,
        checks_run,
        ssh_command: ssh,
        problem,
        host,
    }
}

/// All registered machines with their summaries, ordered by name.
pub fn list_views(main_db: &Path) -> anyhow::Result<Vec<RemoteHostView>> {
    let mut store = Store::open(main_db)?;
    let now = Utc::now();
    Ok(store
        .list_remote_hosts()?
        .into_iter()
        .map(|h| build_view(h, main_db, now))
        .collect())
}

/// The hostname this machine was pinned to and the one a scan answered with, when they differ — the
/// "this address now belongs to a different machine" guard. Shared by every path that saves a scan
/// into a registered machine's history, so they can't disagree about what counts as a change.
pub fn identity_mismatch(host: &RemoteHost, scan_fingerprint: &str) -> Option<(String, String)> {
    let actual = hostname_of_fingerprint(scan_fingerprint);
    let expected = host.expected_hostname.as_deref()?;
    (!actual.is_empty() && expected != actual).then(|| (expected.to_string(), actual))
}

/// The hostname part of a [`crate::ScanRun::host_fingerprint`] (`hostname/kernel`). The kernel half
/// changes on every update, so identity is pinned on the hostname alone.
pub fn hostname_of_fingerprint(fp: &str) -> String {
    fp.split('/').next().unwrap_or("").trim().to_string()
}

// ---- alerts -------------------------------------------------------------------------------------

/// Something about a machine worth interrupting a person for. Derived here, once, so the desktop
/// notification, the Telegram message and the e-mail all agree on *when* to speak up — and so none
/// of them can drift into alerting on every failed attempt of a laptop that is simply asleep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub machine: String,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// The scan found issues that weren't open before.
    NewIssues,
    /// Several connection failures in a row.
    Unreachable,
    /// Answering again after having been unreachable.
    BackOnline,
    /// Host key or identity changed — possibly an attack. Raised immediately.
    SecurityWarning,
    /// A failure only a person can fix (key refused, sudo, version skew…). Raised once.
    NeedsAttention,
}

/// The alerts one scan attempt produces. `before` is the machine as it was *before* the attempt,
/// `after` as recorded after it; `new_findings` are the issues the scan opened.
pub fn alerts_for_attempt(
    before: &RemoteHost,
    after: &RemoteHost,
    new_findings: &[(Severity, String)],
) -> Vec<Alert> {
    let name = after.name.clone();
    let mut out = Vec::new();
    match after.last_status {
        Some(LastStatus::Ok) => {
            if before.consecutive_failures >= UNREACHABLE_AFTER_FAILURES {
                out.push(Alert {
                    machine: name.clone(),
                    kind: AlertKind::BackOnline,
                    severity: Severity::Info,
                    title: format!("{name} is back online"),
                    body: "Bulwark reached it again and scanned it.".into(),
                });
            }
            if let Some(a) = new_issues_alert(&name, new_findings) {
                out.push(a);
            }
        }
        Some(LastStatus::Failed(kind)) => {
            let changed = before.last_status != Some(LastStatus::Failed(kind));
            let ssh = after.ssh_command_line();
            let body = match &after.last_error {
                Some(e) => format!("{}\n{}", e, kind.hint(&ssh)),
                None => kind.hint(&ssh),
            };
            if kind.is_unsupported() {
                // Nothing anyone can act on today — shown in the app, not pushed to a phone.
            } else if kind.is_security_relevant() {
                if changed {
                    out.push(Alert {
                        machine: name.clone(),
                        kind: AlertKind::SecurityWarning,
                        severity: Severity::Critical,
                        title: format!("{name}: {}", kind.title()),
                        body,
                    });
                }
            } else if kind.is_connectivity() {
                if after.consecutive_failures == UNREACHABLE_AFTER_FAILURES {
                    out.push(Alert {
                        machine: name.clone(),
                        kind: AlertKind::Unreachable,
                        severity: Severity::Medium,
                        title: format!("{name} is unreachable"),
                        body,
                    });
                }
            } else if changed {
                out.push(Alert {
                    machine: name.clone(),
                    kind: AlertKind::NeedsAttention,
                    severity: Severity::Medium,
                    title: format!("{name}: {}", kind.title()),
                    body,
                });
            }
        }
        None => {}
    }
    out
}

/// "N new issues", worst first — shared by remote machines and this computer's own monitoring.
pub fn new_issues_alert(machine: &str, new_findings: &[(Severity, String)]) -> Option<Alert> {
    if new_findings.is_empty() {
        return None;
    }
    let worst = new_findings
        .iter()
        .map(|(s, _)| *s)
        .max()
        .unwrap_or(Severity::Info);
    let mut sorted: Vec<&(Severity, String)> = new_findings.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut body: Vec<String> = sorted
        .iter()
        .take(5)
        .map(|(s, t)| format!("[{}] {t}", severity_word(*s)))
        .collect();
    if sorted.len() > 5 {
        body.push(format!("…and {} more", sorted.len() - 5));
    }
    let n = new_findings.len();
    Some(Alert {
        machine: machine.to_string(),
        kind: AlertKind::NewIssues,
        severity: worst,
        title: format!("{machine}: {n} new issue{}", if n == 1 { "" } else { "s" }),
        body: body.join("\n"),
    })
}

pub fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> RemoteHost {
        RemoteHost {
            id: "id".into(),
            name: "web-1".into(),
            spec: "deploy@web-1".into(),
            port: None,
            identity_file: None,
            jump_host: None,
            privileged: false,
            enabled: true,
            interval_minutes: 60,
            created_at: Utc::now() - Duration::days(1),
            expected_hostname: None,
            last_attempt_at: None,
            last_success_at: None,
            last_status: None,
            last_error: None,
            consecutive_failures: 0,
            engine: None,
            os_kind: None,
            os_name: None,
        }
    }

    #[test]
    fn option_shaped_targets_are_refused() {
        // The security-relevant case: an argument ssh would parse as an option.
        assert!(validate_spec("-oProxyCommand=touch /tmp/pwned").is_err());
        assert!(validate_spec("-p22").is_err());
        assert!(validate_spec("user@-oProxyCommand=x").is_err());
        // Shell metacharacters never reach a shell, but have no place in an address either.
        assert!(validate_spec("host;rm -rf /").is_err());
        assert!(validate_spec("host$(id)").is_err());
        assert!(validate_spec("a b").is_err());
        assert!(validate_spec("").is_err());
        assert!(validate_spec("@host").is_err());
        assert!(validate_spec("a@b@c").is_err());
    }

    #[test]
    fn ordinary_targets_are_accepted() {
        for ok in [
            "web-1",
            "deploy@web-1.example.com",
            "root@10.0.0.5",
            "my_alias",
            "user@::1",
            "user@[fe80::1]",
        ] {
            assert!(validate_spec(ok).is_ok(), "{ok} should be valid");
        }
    }

    #[test]
    fn identity_paths_must_be_absolute_and_not_option_shaped() {
        assert!(validate_identity("~/.ssh/id_ed25519").is_ok());
        assert!(validate_identity("/home/u/.ssh/k").is_ok());
        assert!(validate_identity("-oProxyCommand=x").is_err());
        assert!(validate_identity("id_rsa").is_err());
        // Windows: drive paths and ~\ are full paths; a bare drive or relative path is not.
        assert!(
            validate_identity(r"C:\Users\u\AppData\Local\bulwark\keys\bulwark_ed25519").is_ok()
        );
        assert!(validate_identity("D:/keys/k").is_ok());
        assert!(validate_identity(r"~\.ssh\id_ed25519").is_ok());
        assert!(validate_identity("C:").is_err());
        assert!(validate_identity(r"keys\k").is_err());
    }

    #[test]
    fn a_patch_tells_absent_from_null() {
        let p: RemoteHostPatch = serde_json::from_str(r#"{"port":null,"name":"x"}"#).unwrap();
        assert_eq!(p.port, Some(None), "explicit null clears");
        assert_eq!(p.identity_file, None, "absent keeps");
        let p: RemoteHostPatch = serde_json::from_str(r#"{"port":2222}"#).unwrap();
        assert_eq!(p.port, Some(Some(2222)));
    }

    #[test]
    fn jump_chains_are_validated_hop_by_hop() {
        assert!(validate_jump("me@bastion").is_ok());
        assert!(validate_jump("me@bastion:2222,ops@inner").is_ok());
        assert!(validate_jump("me@bastion,-oProxyCommand=x").is_err());
        assert!(validate_jump("").is_ok());
    }

    #[test]
    fn classifies_the_ssh_errors_people_actually_hit() {
        use RemoteErrorKind::*;
        let cases = [
            ("ssh: Could not resolve hostname nope: Name or service not known", Unresolvable),
            ("ssh: connect to host 10.0.0.9 port 22: Connection refused", Unreachable),
            ("ssh: connect to host 10.0.0.9 port 22: No route to host", Unreachable),
            ("ssh: connect to host 10.0.0.9 port 22: Connection timed out", Timeout),
            ("deploy@web: Permission denied (publickey).", AuthFailed),
            (
                "No ED25519 host key is known for web and you have requested strict checking.\r\nHost key verification failed.",
                HostKeyUnknown,
            ),
            (
                "@@@@@@@@\r\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\nHost key verification failed.",
                HostKeyChanged,
            ),
        ];
        for (stderr, want) in cases {
            assert_eq!(classify_ssh_stderr(stderr), Some(want), "{stderr}");
        }
        assert_eq!(classify_ssh_stderr("something else entirely"), None);
    }

    #[test]
    fn a_new_machine_is_due_at_once_and_a_paused_one_never() {
        let mut h = host();
        assert!(h.is_due(Utc::now()));
        h.enabled = false;
        assert!(h.next_due_at().is_none());
        assert!(!h.is_due(Utc::now()));
    }

    #[test]
    fn connectivity_failures_back_off_but_never_past_the_cap() {
        let mut h = host();
        h.last_attempt_at = Some(Utc::now());
        h.last_status = Some(LastStatus::Failed(RemoteErrorKind::Unreachable));
        h.consecutive_failures = 1;
        assert_eq!(h.effective_interval(), Duration::minutes(120));
        h.consecutive_failures = 10;
        assert_eq!(h.effective_interval(), Duration::minutes(360));
        // An interval already above the cap is never shortened by "backing off".
        h.interval_minutes = 1440;
        assert_eq!(h.effective_interval(), Duration::minutes(1440));
    }

    #[test]
    fn failures_that_need_a_person_are_not_backed_off() {
        let mut h = host();
        h.last_status = Some(LastStatus::Failed(RemoteErrorKind::AuthFailed));
        h.consecutive_failures = 5;
        assert_eq!(h.effective_interval(), Duration::minutes(60));
    }

    #[test]
    fn an_unreachable_machine_is_never_reported_healthy() {
        // The invariant: old, empty findings must not read as a clean bill of health once the
        // machine stops answering.
        let now = Utc::now();
        let mut h = host();
        h.last_success_at = Some(now - Duration::minutes(10));
        h.last_attempt_at = Some(now);
        h.last_status = Some(LastStatus::Failed(RemoteErrorKind::Unreachable));
        h.consecutive_failures = UNREACHABLE_AFTER_FAILURES;
        let empty = FindingCounts::default();
        assert_eq!(health(&h, &empty, now), HostHealth::Unreachable);

        h.last_status = Some(LastStatus::Failed(RemoteErrorKind::HostKeyChanged));
        assert_eq!(health(&h, &empty, now), HostHealth::NeedsAttention);

        // Recovered and fresh: now the counts speak.
        h.last_status = Some(LastStatus::Ok);
        h.consecutive_failures = 0;
        assert_eq!(health(&h, &empty, now), HostHealth::Healthy);
        let risky = FindingCounts {
            high: 1,
            ..Default::default()
        };
        assert_eq!(health(&h, &risky, now), HostHealth::AtRisk);

        // Old success, nothing since: stale, whatever the counts say.
        h.last_success_at = Some(now - Duration::hours(5));
        assert_eq!(health(&h, &empty, now), HostHealth::Stale);
    }

    #[test]
    fn an_unsupported_system_is_neutral_rare_and_silent() {
        let mut h = host();
        h.last_attempt_at = Some(Utc::now());
        h.last_success_at = None;
        let before = h.clone();
        h.last_status = Some(LastStatus::Failed(RemoteErrorKind::UnsupportedOs));
        h.consecutive_failures = 5;
        assert_eq!(
            health(&h, &FindingCounts::default(), Utc::now()),
            HostHealth::Unsupported
        );
        assert_eq!(h.effective_interval(), Duration::minutes(24 * 60));
        assert!(alerts_for_attempt(&before, &h, &[]).is_empty());
        assert_eq!(
            RemoteErrorKind::parse("nothing_assessed"),
            Some(RemoteErrorKind::NothingAssessed)
        );
    }

    #[test]
    fn last_status_round_trips_through_its_db_form() {
        for s in [
            LastStatus::Ok,
            LastStatus::Failed(RemoteErrorKind::HostKeyChanged),
            LastStatus::Failed(RemoteErrorKind::SudoRequiresPassword),
        ] {
            assert_eq!(LastStatus::from_db(&s.to_db()), s);
        }
    }

    #[test]
    fn hostname_pin_ignores_the_kernel_half() {
        assert_eq!(hostname_of_fingerprint("web-1/6.8.0-45-generic"), "web-1");
        assert_eq!(hostname_of_fingerprint(""), "");
    }

    fn attempt(before: &RemoteHost, status: LastStatus, failures: u32) -> RemoteHost {
        let mut a = before.clone();
        a.last_status = Some(status);
        a.consecutive_failures = failures;
        a
    }

    #[test]
    fn an_asleep_laptop_alerts_once_not_on_every_attempt() {
        let down = LastStatus::Failed(RemoteErrorKind::Unreachable);
        let mut h = host();
        let mut alerts = Vec::new();
        for n in 1..=6 {
            let after = attempt(&h, down, n);
            alerts.extend(alerts_for_attempt(&h, &after, &[]));
            h = after;
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Unreachable);

        let back = attempt(&h, LastStatus::Ok, 0);
        let a = alerts_for_attempt(&h, &back, &[]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, AlertKind::BackOnline);
    }

    #[test]
    fn a_changed_host_key_alerts_immediately_and_only_once() {
        let k = LastStatus::Failed(RemoteErrorKind::HostKeyChanged);
        let h = host();
        let first = attempt(&h, k, 1);
        let a = alerts_for_attempt(&h, &first, &[]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, AlertKind::SecurityWarning);
        assert_eq!(a[0].severity, Severity::Critical);
        let second = attempt(&first, k, 2);
        assert!(alerts_for_attempt(&first, &second, &[]).is_empty());
    }

    #[test]
    fn new_issues_lead_with_the_worst() {
        let h = host();
        let after = attempt(&h, LastStatus::Ok, 0);
        let a = alerts_for_attempt(
            &h,
            &after,
            &[
                (Severity::Low, "low thing".into()),
                (Severity::High, "high thing".into()),
            ],
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::High);
        assert_eq!(a[0].title, "web-1: 2 new issues");
        assert!(a[0].body.starts_with("[High] high thing"));
    }
}

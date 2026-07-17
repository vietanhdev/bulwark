//! Harden `/etc/ssh/sshd_config` — the highest-risk autofix, so the most conservative.
//!
//! Only the directives Bulwark's own SSH rules flag are managed, and each is written **only when the
//! effective config is actually insecure** (e.g. `PasswordAuthentication` is set/defaults to `yes`).
//! The change is applied by inserting a single sentinel-delimited block at the very TOP of the main
//! config:
//!
//! ```text
//! # BEGIN bulwark-hardening (managed) …
//! PasswordAuthentication no
//! # END bulwark-hardening
//! ```
//!
//! Top placement is what makes this correct under OpenSSH's *first-value-wins* semantics: sshd takes
//! the first value it obtains for a keyword, and `Include` directives are expanded inline where they
//! appear. Putting our block above everything — including the `Include /etc/ssh/sshd_config.d/*.conf`
//! line Ubuntu/Debian ship at the top — guarantees our value is the one that takes effect, without
//! having to hunt through drop-in files. The block is idempotent: a prior block is stripped and
//! rebuilt, never stacked.
//!
//! Safety rails:
//!   * **Dry-run by default** — nothing is written unless `apply` is true.
//!   * **Backup first** — the original is copied (0600) before any rewrite, and restored if a
//!     post-write `sshd -t` validation fails, so a syntactically broken config is never left behind.
//!   * **Lockout directives are opt-in.** `PasswordAuthentication` and `PermitRootLogin` can lock an
//!     operator out of a box reached only by password; they are flagged `lockout_risk` and excluded
//!     unless the caller explicitly asks to include them.

use crate::collectors::sshd::{parse_sshd_config_with, resolve_include_glob};
use crate::models::Fact;
use serde::Serialize;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const MAIN_CONFIG: &str = "/etc/ssh/sshd_config";
const BEGIN_MARKER: &str = "# BEGIN bulwark-hardening";
const END_MARKER: &str = "# END bulwark-hardening";

/// One managed directive. `desired` is the value written when the current effective value is
/// insecure (as judged by [`is_insecure`], which mirrors the corresponding `BLWK-SSH-*` rule).
struct Directive {
    keyword: &'static str,
    field: &'static str,
    desired: &'static str,
    lockout_risk: bool,
    why: &'static str,
}

const DIRECTIVES: &[Directive] = &[
    Directive {
        keyword: "PasswordAuthentication",
        field: "password_authentication",
        desired: "no",
        lockout_risk: true,
        why: "password logins are brute-forceable; prefer keys (BLWK-SSH-001)",
    },
    Directive {
        keyword: "PermitRootLogin",
        field: "permit_root_login",
        desired: "no",
        lockout_risk: true,
        why: "direct root login removes the audit trail of who acted (BLWK-SSH-002)",
    },
    Directive {
        keyword: "PermitEmptyPasswords",
        field: "permit_empty_passwords",
        desired: "no",
        lockout_risk: false,
        why: "empty-password accounts are trivially accessible (BLWK-SSH-003)",
    },
    Directive {
        keyword: "X11Forwarding",
        field: "x11_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "X11 forwarding exposes the client's display to the server (BLWK-SSH-004)",
    },
    Directive {
        keyword: "AllowTcpForwarding",
        field: "allow_tcp_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "TCP forwarding can turn the host into a network pivot (BLWK-SSH-005)",
    },
    Directive {
        keyword: "PermitUserEnvironment",
        field: "permit_user_environment",
        desired: "no",
        lockout_risk: false,
        why: "user-set environment can bypass restrictions (BLWK-SSH-006)",
    },
    Directive {
        keyword: "PermitTunnel",
        field: "permit_tunnel",
        desired: "no",
        lockout_risk: false,
        why: "tun-device tunneling extends the client onto the host's network (BLWK-SSH-007)",
    },
    Directive {
        keyword: "StrictModes",
        field: "strict_modes",
        desired: "yes",
        lockout_risk: false,
        why: "StrictModes rejects world-writable key files (BLWK-SSH-008)",
    },
    Directive {
        keyword: "GatewayPorts",
        field: "gateway_ports",
        desired: "no",
        lockout_risk: false,
        why: "GatewayPorts exposes forwarded ports to the whole network (BLWK-SSH-009)",
    },
    Directive {
        keyword: "AllowAgentForwarding",
        field: "allow_agent_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "agent forwarding lets a compromised host use your keys (BLWK-SSH-010)",
    },
    Directive {
        keyword: "MaxAuthTries",
        field: "max_auth_tries",
        desired: "4",
        lockout_risk: false,
        why: "fewer auth attempts per connection slows brute forcing (BLWK-SSH-011)",
    },
];

/// Whether the current effective value of `field` is insecure — kept in lockstep with the
/// `BLWK-SSH-*` rule conditions so a fix only fires where the scanner would flag.
fn is_insecure(field: &str, value: &Value) -> bool {
    match field {
        "max_auth_tries" => value.as_i64().map(|n| n > 6).unwrap_or(false),
        "strict_modes" => value.as_str() == Some("no"),
        // Every other managed directive is insecure exactly when it is "yes".
        _ => value.as_str() == Some("yes"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SshdChangeStatus {
    /// Would be set (dry run) from the current value to the desired value.
    WouldSet,
    /// Was set.
    Set,
    /// Insecure and fixable, but skipped because it is a lockout risk and the caller didn't opt in.
    SkippedLockout,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshdChange {
    pub keyword: String,
    pub current: String,
    pub desired: String,
    pub lockout_risk: bool,
    pub why: String,
    pub status: SshdChangeStatus,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SshdHardeningReport {
    pub config_path: String,
    pub changes: Vec<SshdChange>,
    pub applied: bool,
    pub backup_path: Option<String>,
    /// Set when `sshd -t` was available and run; `Some(true)` means the new config validated.
    pub validated: Option<bool>,
    /// Non-fatal note surfaced to the user (e.g. "sshd -t not found, skipped validation").
    pub note: Option<String>,
}

impl SshdHardeningReport {
    pub fn pending_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c.status, SshdChangeStatus::Set | SshdChangeStatus::WouldSet))
            .count()
    }
}

/// Remove any previously-inserted bulwark block from the config text, returning the cleaned text.
/// Idempotency depends on this: each run rebuilds the block from scratch rather than stacking.
fn strip_managed_block(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(BEGIN_MARKER) {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed.starts_with(END_MARKER) {
                in_block = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Decide which directives need changing, given the effective (parsed) config and whether the caller
/// opted into the lockout-risky ones.
fn plan(effective: &Fact, include_lockout: bool) -> Vec<SshdChange> {
    let mut changes = Vec::new();
    for d in DIRECTIVES {
        let current = effective.get(d.field).cloned().unwrap_or(Value::Null);
        if !is_insecure(d.field, &current) {
            continue;
        }
        let current_str = match &current {
            Value::String(s) => s.clone(),
            Value::Null => "(default)".to_string(),
            other => other.to_string(),
        };
        let status = if d.lockout_risk && !include_lockout {
            SshdChangeStatus::SkippedLockout
        } else {
            SshdChangeStatus::WouldSet
        };
        changes.push(SshdChange {
            keyword: d.keyword.to_string(),
            current: current_str,
            desired: d.desired.to_string(),
            lockout_risk: d.lockout_risk,
            why: d.why.to_string(),
            status,
        });
    }
    changes
}

/// Render the sentinel-delimited block for the directives that will actually be written.
fn render_block(changes: &[SshdChange]) -> String {
    let mut block = String::new();
    block.push_str(BEGIN_MARKER);
    block.push_str(" (managed) — remove this block and restore the backup to undo\n");
    for c in changes {
        if matches!(c.status, SshdChangeStatus::WouldSet | SshdChangeStatus::Set) {
            block.push_str(&format!("{} {}\n", c.keyword, c.desired));
        }
    }
    block.push_str(END_MARKER);
    block.push('\n');
    block
}

/// Public entry point. `config_path` defaults to `/etc/ssh/sshd_config` when `None`. `backup_dir` is
/// where the pre-change copy is written. With `apply = false` this only previews.
pub fn harden_sshd_config(
    config_path: Option<&Path>,
    backup_dir: &Path,
    apply: bool,
    include_lockout: bool,
) -> anyhow::Result<SshdHardeningReport> {
    let path = config_path.unwrap_or_else(|| Path::new(MAIN_CONFIG));
    // Only `sshd -t`-validate the real system config. That path is edited as root (the CLI gates
    // `fix sshd --apply` on it), where sshd can read the root-only host keys and the check is
    // meaningful. An explicit `--config` path is for testing or a non-default file and is often
    // edited unprivileged — and `sshd -t` run as non-root FALSE-fails because it can't read
    // `/etc/ssh/ssh_host_*_key`, which would wrongly revert a perfectly good change.
    let validate = config_path.is_none();
    harden_with(
        path,
        backup_dir,
        apply,
        include_lockout,
        validate,
        &resolve_include_glob,
    )
}

/// Testable core: takes the include resolver as a parameter so unit tests can feed drop-ins without
/// touching `/etc/ssh`. `validate` runs the `sshd -t` post-write check (only meaningful for the real
/// root-owned config); tests pass `false` so the result never depends on whether sshd is installed.
fn harden_with(
    path: &Path,
    backup_dir: &Path,
    apply: bool,
    include_lockout: bool,
    validate: bool,
    resolve: &dyn Fn(&str) -> Vec<String>,
) -> anyhow::Result<SshdHardeningReport> {
    let mut report = SshdHardeningReport {
        config_path: path.display().to_string(),
        ..Default::default()
    };
    if !path.exists() {
        anyhow::bail!("{} does not exist — is OpenSSH installed?", path.display());
    }
    let original = std::fs::read_to_string(path)?;
    let cleaned = strip_managed_block(&original);
    // Parse the effective config *without* our old block, so re-running sees the real underlying
    // values, not the ones a previous run wrote.
    let effective = parse_sshd_config_with(&cleaned, resolve);

    let mut changes = plan(&effective, include_lockout);
    let to_write = changes
        .iter()
        .filter(|c| matches!(c.status, SshdChangeStatus::WouldSet))
        .count();

    if !apply || to_write == 0 {
        report.changes = changes;
        return Ok(report);
    }

    // Build the new config: managed block on top, cleaned original below.
    let block = render_block(&changes);
    let new_content = format!("{block}\n{cleaned}");

    // Back up the original (0600) before writing.
    std::fs::create_dir_all(backup_dir)?;
    let backup_path = backup_dir.join(format!(
        "sshd_config.{}.bak",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sshd_config")
    ));
    std::fs::write(&backup_path, &original)?;
    std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600))?;

    // Preserve the original file's mode across the rewrite.
    let orig_mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
    std::fs::write(path, &new_content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(orig_mode))?;

    // Validate with `sshd -t` when asked (real system config only) and available; roll back on
    // failure so we never leave a config that would stop sshd from starting.
    match validate.then(|| validate_sshd(path)).flatten() {
        Some(true) => report.validated = Some(true),
        Some(false) => {
            // Restore and report a failure rather than a false success.
            std::fs::write(path, &original)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(orig_mode))?;
            anyhow::bail!(
                "the hardened config failed `sshd -t` validation — reverted {} from the backup, no \
                 changes were kept",
                path.display()
            );
        }
        None => {
            report.validated = None;
            if validate {
                report.note = Some(
                    "sshd not found on PATH — wrote the change without `sshd -t` validation; run \
                     `sshd -t` yourself before restarting sshd"
                        .to_string(),
                );
            }
        }
    }

    for c in changes.iter_mut() {
        if matches!(c.status, SshdChangeStatus::WouldSet) {
            c.status = SshdChangeStatus::Set;
        }
    }
    report.changes = changes;
    report.applied = true;
    report.backup_path = Some(backup_path.display().to_string());
    Ok(report)
}

/// Run `sshd -t -f <path>` if an `sshd` binary is on PATH. `Some(ok)` when it ran, `None` when no
/// sshd binary exists (common in containers and this dev environment).
fn validate_sshd(path: &Path) -> Option<bool> {
    // `sshd` usually lives in /usr/sbin, which isn't always on a login PATH; try both.
    for cand in ["sshd", "/usr/sbin/sshd", "/sbin/sshd"] {
        if let Ok(out) = std::process::Command::new(cand)
            .arg("-t")
            .arg("-f")
            .arg(path)
            .output()
        {
            return Some(out.status.success());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_includes(_: &str) -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn strip_block_is_idempotent() {
        let text =
            format!("{BEGIN_MARKER} (managed)\nPasswordAuthentication no\n{END_MARKER}\nPort 22\n");
        let cleaned = strip_managed_block(&text);
        assert!(!cleaned.contains("bulwark-hardening"));
        assert!(cleaned.contains("Port 22"));
    }

    #[test]
    fn plan_flags_insecure_defaults_and_skips_lockout_by_default() {
        // A stock config relying on defaults: password auth defaults to yes (insecure), tcp
        // forwarding yes, etc.
        let effective = parse_sshd_config_with("Port 22\n", &no_includes);
        let changes = plan(&effective, false);
        let by = |kw: &str| changes.iter().find(|c| c.keyword == kw).cloned();

        // PasswordAuthentication is insecure-by-default AND a lockout risk → skipped without opt-in.
        let pw = by("PasswordAuthentication").expect("password auth planned");
        assert_eq!(pw.status, SshdChangeStatus::SkippedLockout);

        // AllowTcpForwarding defaults to yes and is not a lockout risk → would set.
        let tcp = by("AllowTcpForwarding").expect("tcp forwarding planned");
        assert_eq!(tcp.status, SshdChangeStatus::WouldSet);
        assert_eq!(tcp.desired, "no");
    }

    #[test]
    fn lockout_directives_included_when_opted_in() {
        let effective = parse_sshd_config_with("PasswordAuthentication yes\n", &no_includes);
        let changes = plan(&effective, true);
        let pw = changes
            .iter()
            .find(|c| c.keyword == "PasswordAuthentication")
            .unwrap();
        assert_eq!(pw.status, SshdChangeStatus::WouldSet);
    }

    #[test]
    fn a_hardened_config_needs_no_changes() {
        let text = "PasswordAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\n\
                    X11Forwarding no\nAllowTcpForwarding no\nPermitUserEnvironment no\n\
                    PermitTunnel no\nStrictModes yes\nGatewayPorts no\nAllowAgentForwarding no\n\
                    MaxAuthTries 4\n";
        let effective = parse_sshd_config_with(text, &no_includes);
        let changes = plan(&effective, true);
        assert!(
            changes.is_empty(),
            "a fully-hardened config should plan no changes, got: {changes:?}"
        );
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        std::fs::write(&cfg, "AllowTcpForwarding yes\n").unwrap();
        let before = std::fs::read_to_string(&cfg).unwrap();

        let report = harden_with(
            &cfg,
            &dir.path().join("bak"),
            false,
            false,
            false,
            &no_includes,
        )
        .unwrap();
        assert!(report.pending_count() >= 1);
        assert!(!report.applied);
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            before,
            "dry run must not write"
        );
    }

    #[test]
    fn apply_inserts_block_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        std::fs::write(&cfg, "AllowTcpForwarding yes\nX11Forwarding yes\nPort 22\n").unwrap();

        let r1 = harden_with(&cfg, &bak, true, false, false, &no_includes).unwrap();
        assert!(r1.applied);
        assert!(r1.backup_path.is_some());
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            after.starts_with(BEGIN_MARKER),
            "block goes on top:\n{after}"
        );
        assert!(after.contains("AllowTcpForwarding no"));
        assert!(after.contains("X11Forwarding no"));
        assert!(
            after.contains("Port 22"),
            "original directives are preserved"
        );

        // Re-running sees the underlying (still-insecure) originals below the block, rebuilds the
        // single block, and does not stack a second one.
        let r2 = harden_with(&cfg, &bak, true, false, false, &no_includes).unwrap();
        assert!(r2.applied);
        let after2 = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(
            after2.matches(BEGIN_MARKER).count(),
            1,
            "must not stack blocks:\n{after2}"
        );
    }

    #[test]
    fn backup_matches_the_original_before_change() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        let original = "AllowTcpForwarding yes\nPort 2222\n";
        std::fs::write(&cfg, original).unwrap();
        let report = harden_with(&cfg, &bak, true, false, false, &no_includes).unwrap();
        let backup = std::fs::read_to_string(report.backup_path.unwrap()).unwrap();
        assert_eq!(backup, original, "backup is the pre-change file, verbatim");
    }
}

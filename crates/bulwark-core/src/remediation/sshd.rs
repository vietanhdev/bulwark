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
//! having to hunt through drop-in files. The one thing it does not beat is a `Match all` block,
//! whose values sshd copies over the global ones; a directive set there is reported, not "fixed".
//!
//! Running it again is safe:
//!   * The plan is made against what sshd obeys **now**, managed block included. Once a run has
//!     applied, the next one finds nothing to do and writes nothing — no rewrite, no new backup.
//!   * There is only ever one block. When a later run does have something to add, the block is
//!     rebuilt with **everything it already held** plus the new lines, so a plain run never removes
//!     what an earlier `--include-auth` run set.
//!
//! Safety rails:
//!   * **Dry-run by default** — nothing is written unless `apply` is true.
//!   * **Backup first** — the file is copied (0600) under a new timestamped name before every
//!     rewrite, so the copy from before the first run is never overwritten, and it is restored if a
//!     post-write `sshd -t` validation fails, so a syntactically broken config is never left behind.
//!   * **Lockout directives are opt-in.** `PasswordAuthentication` and `PermitRootLogin` can lock an
//!     operator out of a box reached only by password; they are flagged `lockout_risk` and excluded
//!     unless the caller explicitly asks to include them.

#[cfg(test)]
use crate::collectors::sshd::ConfigFile;
use crate::collectors::sshd::{
    parse_sshd_config_with, resolve_include_glob, split_keyword, IncludeResolver,
};
use crate::models::Fact;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

const BEGIN_MARKER: &str = "# BEGIN bulwark-hardening";
const END_MARKER: &str = "# END bulwark-hardening";

/// One managed directive. `desired` is the value written when the current effective value is
/// insecure (as judged by [`is_insecure`], which mirrors the corresponding `BLWK-SSH-*` rule).
struct Directive {
    keyword: &'static str,
    field: &'static str,
    /// The `BLWK-SSH-*` rule this directive clears. Named explicitly rather than parsed out of
    /// `why`, so `remediation::FIX_CAPABILITIES` can be checked against this table by a test.
    /// Read only by that test — the hardener itself works off `field`.
    #[cfg_attr(not(test), allow(dead_code))]
    rule_id: &'static str,
    desired: &'static str,
    lockout_risk: bool,
    why: &'static str,
}

const DIRECTIVES: &[Directive] = &[
    Directive {
        keyword: "PasswordAuthentication",
        rule_id: "BLWK-SSH-001",
        field: "password_authentication",
        desired: "no",
        lockout_risk: true,
        why: "password logins are brute-forceable; prefer keys (BLWK-SSH-001)",
    },
    Directive {
        keyword: "PermitRootLogin",
        rule_id: "BLWK-SSH-002",
        field: "permit_root_login",
        desired: "no",
        lockout_risk: true,
        why: "direct root login removes the audit trail of who acted (BLWK-SSH-002)",
    },
    Directive {
        keyword: "PermitEmptyPasswords",
        rule_id: "BLWK-SSH-003",
        field: "permit_empty_passwords",
        desired: "no",
        lockout_risk: false,
        why: "empty-password accounts are trivially accessible (BLWK-SSH-003)",
    },
    Directive {
        keyword: "X11Forwarding",
        rule_id: "BLWK-SSH-004",
        field: "x11_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "X11 forwarding exposes the client's display to the server (BLWK-SSH-004)",
    },
    Directive {
        keyword: "AllowTcpForwarding",
        rule_id: "BLWK-SSH-005",
        field: "allow_tcp_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "TCP forwarding can turn the host into a network pivot (BLWK-SSH-005)",
    },
    Directive {
        keyword: "PermitUserEnvironment",
        rule_id: "BLWK-SSH-006",
        field: "permit_user_environment",
        desired: "no",
        lockout_risk: false,
        why: "user-set environment can bypass restrictions (BLWK-SSH-006)",
    },
    Directive {
        keyword: "PermitTunnel",
        rule_id: "BLWK-SSH-007",
        field: "permit_tunnel",
        desired: "no",
        lockout_risk: false,
        why: "tun-device tunneling extends the client onto the host's network (BLWK-SSH-007)",
    },
    Directive {
        keyword: "StrictModes",
        rule_id: "BLWK-SSH-008",
        field: "strict_modes",
        desired: "yes",
        lockout_risk: false,
        why: "StrictModes rejects world-writable key files (BLWK-SSH-008)",
    },
    Directive {
        keyword: "GatewayPorts",
        rule_id: "BLWK-SSH-009",
        field: "gateway_ports",
        desired: "no",
        lockout_risk: false,
        why: "GatewayPorts exposes forwarded ports to the whole network (BLWK-SSH-009)",
    },
    Directive {
        keyword: "AllowAgentForwarding",
        rule_id: "BLWK-SSH-010",
        field: "allow_agent_forwarding",
        desired: "no",
        lockout_risk: false,
        why: "agent forwarding lets a compromised host use your keys (BLWK-SSH-010)",
    },
    Directive {
        keyword: "MaxAuthTries",
        rule_id: "BLWK-SSH-011",
        field: "max_auth_tries",
        desired: "4",
        lockout_risk: false,
        why: "fewer auth attempts per connection slows brute forcing (BLWK-SSH-011)",
    },
];

/// The rule ids this hardener can clear — the set `remediation::FIX_CAPABILITIES` must mirror.
#[cfg(test)]
pub(crate) fn managed_rule_ids() -> Vec<&'static str> {
    DIRECTIVES.iter().map(|d| d.rule_id).collect()
}

/// The directive table's own view of whether a rule's fix risks locking the operator out.
#[cfg(test)]
pub(crate) fn directive_lockout_risk(rule_id: &str) -> Option<bool> {
    DIRECTIVES
        .iter()
        .find(|d| d.rule_id == rule_id)
        .map(|d| d.lockout_risk)
}

/// Whether the current effective value of `field` is insecure — kept in lockstep with the
/// `BLWK-SSH-*` rule conditions so a fix only fires where the scanner would flag
/// (`is_insecure_agrees_with_the_shipped_rules` compares the two against the real rule files).
fn is_insecure(field: &str, value: &Value) -> bool {
    let text = value.as_str();
    match field {
        "max_auth_tries" => value.as_i64().map(|n| n > 6).unwrap_or(false),
        "strict_modes" => text == Some("no"),
        // These three take more than yes/no, and every value but `no` leaves some of the feature
        // on. See the comments in the rule files for what each value allows.
        "allow_tcp_forwarding" => matches!(text, Some("yes" | "all" | "local" | "remote")),
        "permit_tunnel" => matches!(text, Some("yes" | "point-to-point" | "ethernet")),
        "gateway_ports" => matches!(text, Some("yes" | "clientspecified")),
        // Every other managed directive is insecure exactly when it is "yes".
        _ => text == Some("yes"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SshdChangeStatus {
    /// Would be set (dry run) from the current value to the desired value.
    WouldSet,
    /// Was set.
    Set,
    /// Insecure and fixable, but skipped because it is a lockout risk and the caller didn't opt in.
    SkippedLockout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshdChange {
    pub keyword: String,
    pub current: String,
    pub desired: String,
    pub lockout_risk: bool,
    pub why: String,
    pub status: SshdChangeStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshdHardeningReport {
    pub config_path: String,
    pub changes: Vec<SshdChange>,
    pub applied: bool,
    /// The copy of the file as it was before this run changed it. `None` when nothing was written.
    pub backup_path: Option<String>,
    /// Set when `sshd -t` was available and run; `Some(true)` means the new config validated.
    pub validated: Option<bool>,
    /// Non-fatal note surfaced to the user (e.g. "sshd -t not found, skipped validation").
    pub note: Option<String>,
    /// True when the settings cannot be written safely on this system, so `--apply` refuses and
    /// `note` says what to put where by hand. See [`harden_sshd_config`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub by_hand: bool,
}

impl SshdHardeningReport {
    pub fn pending_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c.status, SshdChangeStatus::Set | SshdChangeStatus::WouldSet))
            .count()
    }
}

/// A config file split into the managed block a previous run wrote and everything else.
struct SplitConfig {
    /// The lines between the markers, without the markers. Empty when there is no block.
    block_lines: Vec<String>,
    /// The file without the block, byte for byte: deleting the block by hand gives this back.
    rest: Vec<u8>,
}

/// Takes any previously-inserted bulwark block out of the config. The block is rebuilt on every
/// write, never stacked, and what it already holds is carried into the new one.
///
/// Works on bytes, and line by line with the line endings kept, so a file with CRLF endings, no
/// final newline, or a Latin-1 character in a comment is written back exactly as it was.
fn split_managed_block(original: &[u8]) -> anyhow::Result<SplitConfig> {
    let mut split = SplitConfig {
        block_lines: Vec::new(),
        rest: Vec::with_capacity(original.len()),
    };
    let mut in_block = false;
    // The blank line this fixer puts after the block belongs to the block, or each run would add
    // one more.
    let mut after_block = false;
    for line in original.split_inclusive(|b| *b == b'\n') {
        let text = String::from_utf8_lossy(line);
        let trimmed = text.trim();
        if trimmed.starts_with(BEGIN_MARKER) {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed.starts_with(END_MARKER) {
                in_block = false;
                after_block = true;
            } else {
                split.block_lines.push(trimmed.to_string());
            }
            continue;
        }
        if std::mem::take(&mut after_block) && trimmed.is_empty() {
            continue;
        }
        split.rest.extend_from_slice(line);
    }
    if in_block {
        // Taking "the rest of the file" for the block would delete it on the next write.
        anyhow::bail!(
            "found '{BEGIN_MARKER}' with no '{END_MARKER}' line after it — the managed block was \
             edited by hand. Restore the END line (or delete the BEGIN line) and run again; nothing \
             was changed"
        );
    }
    Ok(split)
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

/// The body of the new managed block: every line the old block held, with the values this run
/// sets replaced in place, then the directives that are new.
///
/// Carrying the old lines forward is what makes a later run safe. The block is the only place this
/// fixer writes, so a directive an earlier run put there (`PasswordAuthentication no` from
/// `--include-auth`, say) is by now the secure effective value and no longer in the plan. Building
/// the block from the plan alone dropped it, and a plain `fix all --apply` quietly turned password
/// logins back on.
fn block_body(old_lines: &[String], set: &[&SshdChange]) -> Vec<String> {
    let keyword_of = |line: &str| split_keyword(line).map(|(k, _)| k.to_ascii_lowercase());
    let mut written = std::collections::HashSet::new();
    let mut body = Vec::new();
    for line in old_lines {
        let Some(keyword) = keyword_of(line) else {
            if !line.is_empty() {
                body.push(line.clone()); // a comment someone added: keep it
            }
            continue;
        };
        match set
            .iter()
            .find(|c| c.keyword.to_ascii_lowercase() == keyword)
        {
            // sshd takes the first value, so only the first line for a keyword counts.
            Some(c) if written.insert(keyword) => body.push(format!("{} {}", c.keyword, c.desired)),
            Some(_) => {}
            None => body.push(line.clone()),
        }
    }
    for c in set {
        if written.insert(c.keyword.to_ascii_lowercase()) {
            body.push(format!("{} {}", c.keyword, c.desired));
        }
    }
    body
}

/// The whole new file: the managed block on top, one blank line, then the rest untouched.
fn render_config(body: &[String], rest: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push_str(" (managed) — remove this block and restore the backup to undo\n");
    for line in body {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(END_MARKER);
    out.push_str("\n\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(rest);
    bytes
}

/// Copies the file as it is now into `backup_dir` under a name no earlier backup has, so the copy
/// of the file from before the first run is never replaced by a copy of an already-changed one.
fn write_backup(backup_dir: &Path, path: &Path, original: &[u8]) -> anyhow::Result<PathBuf> {
    use std::io::Write;
    std::fs::create_dir_all(backup_dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "sshd_config".to_string());
    for _ in 0..100 {
        // To the millisecond, so that two runs in one second get different names and the names
        // still sort oldest first.
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
        let backup_path = backup_dir.join(format!("{name}.{stamp}.bak"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup_path)
        {
            Ok(mut file) => {
                // The config may hold nothing secret, but its backup need not be world-readable.
                crate::platform::set_file_mode(&backup_path, 0o600)?;
                file.write_all(original)?;
                return Ok(backup_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!(
        "could not find a free backup name in {}",
        backup_dir.display()
    )
}

/// Adds the way out to an error caused by a config file this run may not read: the preview
/// commands run as an ordinary user, and a cloud image's drop-in is mode 600.
fn with_sudo_hint(e: anyhow::Error) -> anyhow::Error {
    let denied = e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    });
    if denied {
        anyhow::anyhow!(
            "{e} — the sshd settings in force cannot be worked out without it; run this with sudo"
        )
    } else {
        e
    }
}

/// Public entry point. `config_path` defaults to `/etc/ssh/sshd_config` when `None`. `backup_dir` is
/// where the pre-change copy is written. With `apply = false` this only previews.
///
/// On a system that keeps the vendor's file in `/usr/etc` and has no `/etc/ssh/sshd_config`
/// (openSUSE Tumbleweed, Leap 16) the plan is made against the file sshd really reads, but nothing
/// is written: the vendor file is replaced by the next package update, and creating
/// `/etc/ssh/sshd_config` would make sshd read that file *instead*, dropping every setting and
/// `Include` the vendor file has (measured with `sshd -T`). The report then says which lines to put
/// in a drop-in, and `apply` is refused.
pub fn harden_sshd_config(
    config_path: Option<&Path>,
    backup_dir: &Path,
    apply: bool,
    include_lockout: bool,
) -> anyhow::Result<SshdHardeningReport> {
    if config_path.is_none() && crate::etc::SSHD_CONFIG.vendor_in_use() {
        return plan_for_vendor_config(
            Path::new(crate::etc::SSHD_CONFIG.vendor),
            backup_dir,
            apply,
            include_lockout,
            &resolve_include_glob,
        );
    }
    let path = config_path.unwrap_or_else(|| Path::new(crate::etc::SSHD_CONFIG.etc));
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

/// The plan for a system whose sshd reads the vendor's file; see [`harden_sshd_config`].
fn plan_for_vendor_config(
    vendor: &Path,
    backup_dir: &Path,
    apply: bool,
    include_lockout: bool,
    resolve: &IncludeResolver,
) -> anyhow::Result<SshdHardeningReport> {
    let mut report = harden_with(vendor, backup_dir, false, include_lockout, false, resolve)?;
    let lines: Vec<String> = report
        .changes
        .iter()
        .filter(|c| c.status == SshdChangeStatus::WouldSet)
        .map(|c| format!("{} {}", c.keyword, c.desired))
        .collect();
    if lines.is_empty() {
        return Ok(report);
    }
    let message = vendor_config_message(vendor, &lines);
    if apply {
        anyhow::bail!(message);
    }
    report.by_hand = true;
    report.note = Some(match report.note.take() {
        Some(earlier) => format!("{earlier}. {message}"),
        None => message,
    });
    Ok(report)
}

/// What to do by hand on a system whose sshd reads the vendor's file.
fn vendor_config_message(vendor: &Path, lines: &[String]) -> String {
    format!(
        "this system has no {etc}, so sshd reads the vendor's file {vendor}. Bulwark does not edit \
         that file (the next package update replaces it) and does not create {etc} (sshd would \
         then read that file instead and lose every setting the vendor file makes). Put these \
         lines in a new file {dir}/00-hardening.conf, which sshd reads before the vendor's \
         settings: {lines}. Then check with 'sudo sshd -t' and reload sshd",
        etc = crate::etc::SSHD_CONFIG.etc,
        vendor = vendor.display(),
        dir = crate::etc::SSHD_DROP_IN_DIR,
        lines = lines.join("; ")
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
    resolve: &IncludeResolver,
) -> anyhow::Result<SshdHardeningReport> {
    let mut report = SshdHardeningReport {
        config_path: path.display().to_string(),
        ..Default::default()
    };
    if !path.exists() {
        anyhow::bail!("{} does not exist — is OpenSSH installed?", path.display());
    }
    let original = std::fs::read(path).map_err(|e| {
        let message = format!("could not read {}: {e}", path.display());
        with_sudo_hint(anyhow::Error::new(e).context(message))
    })?;
    // What sshd obeys right now, the managed block included. Planning against the file with the
    // block taken out reported "would set … (was yes)" for ever after a successful run.
    //
    // A drop-in that cannot be read stops the fix: the plan would be made against a guess.
    let origin = path.display().to_string();
    let effective = parse_sshd_config_with(&String::from_utf8_lossy(&original), &origin, resolve)
        .map_err(with_sudo_hint)?;
    let mut changes = plan(&effective, include_lockout);

    let split = split_managed_block(&original)?;
    let wanted = |changes: &[SshdChange]| -> Vec<SshdChange> {
        changes
            .iter()
            .filter(|c| c.status == SshdChangeStatus::WouldSet)
            .cloned()
            .collect()
    };
    let render = |changes: &[SshdChange]| {
        let set = wanted(changes);
        let body = block_body(&split.block_lines, &set.iter().collect::<Vec<_>>());
        render_config(&body, &split.rest)
    };

    // Check the result before promising it. The block wins over everything below it except a
    // `Match all` block, whose values sshd copies over the global ones; a directive set there is
    // not something a line at the top of the file can change.
    let mut new_content = render(&changes);
    let after = parse_sshd_config_with(&String::from_utf8_lossy(&new_content), &origin, resolve)?;
    let out_of_reach: Vec<String> = DIRECTIVES
        .iter()
        .filter(|d| {
            after.get(d.field).is_some_and(|v| is_insecure(d.field, v))
                && changes
                    .iter()
                    .any(|c| c.keyword == d.keyword && c.status == SshdChangeStatus::WouldSet)
        })
        .map(|d| d.keyword.to_string())
        .collect();
    if !out_of_reach.is_empty() {
        let message = format!(
            "{} cannot be fixed from the top of the file: a `Match all` block sets it, and sshd \
             lets that override everything before it. Change it inside that block by hand",
            out_of_reach.join(", ")
        );
        changes.retain(|c| !out_of_reach.contains(&c.keyword));
        if changes.is_empty() {
            // Nothing else to report, and "already hardened" would be false.
            anyhow::bail!(message);
        }
        report.note = Some(message);
        new_content = render(&changes);
    }

    let to_write = wanted(&changes).len();
    // Nothing to set, or (the block having moved or been edited) nothing would actually change:
    // leave the file and the backups alone.
    if !apply || to_write == 0 || new_content == original {
        report.changes = changes;
        return Ok(report);
    }

    // Back up the file as it is (0600) before writing.
    let backup_path = write_backup(backup_dir, path, &original)?;
    // So the file-integrity baseline can follow this edit, and only this edit (see
    // `update_baseline_after_fix`).
    let hash_before = super::hash_before_fix(path);

    // Preserve the original file's mode across the rewrite.
    let orig_mode = crate::platform::file_mode(&std::fs::metadata(path)?)
        .ok_or_else(|| anyhow::anyhow!("file modes are not supported on this platform"))?
        & 0o7777;
    std::fs::write(path, &new_content)?;
    crate::platform::set_file_mode(path, orig_mode)?;

    // Validate with `sshd -t` when asked (real system config only) and available; roll back on
    // failure so we never leave a config that would stop sshd from starting.
    match validate.then(|| validate_sshd(path)).flatten() {
        Some(true) => report.validated = Some(true),
        Some(false) => {
            // Restore and report a failure rather than a false success.
            std::fs::write(path, &original)?;
            crate::platform::set_file_mode(path, orig_mode)?;
            anyhow::bail!(
                "the hardened config failed `sshd -t` validation — reverted {} from the backup, no \
                 changes were kept",
                path.display()
            );
        }
        None => {
            report.validated = None;
            if validate {
                let no_sshd = "sshd not found on PATH — wrote the change without `sshd -t` \
                               validation; run `sshd -t` yourself before restarting sshd";
                report.note = Some(match report.note.take() {
                    Some(earlier) => format!("{earlier}. {no_sshd}"),
                    None => no_sshd.to_string(),
                });
            }
        }
    }

    if let Some(update) = super::update_baseline_after_fix(path, hash_before.as_deref()) {
        let said = update.message();
        report.note = Some(match report.note.take() {
            Some(earlier) => format!("{earlier}. {said}"),
            None => said,
        });
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
        if let Ok(out) = crate::sandbox::quiet_command(cand)
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

    fn no_includes(_: &str) -> anyhow::Result<Vec<ConfigFile>> {
        Ok(Vec::new())
    }

    fn effective_of(text: &str) -> Fact {
        parse_sshd_config_with(text, "sshd_config", &no_includes).unwrap()
    }

    /// One run against a config in a temp folder, with no drop-ins and no `sshd -t`.
    fn run(cfg: &Path, bak: &Path, apply: bool, include_lockout: bool) -> SshdHardeningReport {
        harden_with(cfg, bak, apply, include_lockout, false, &no_includes).unwrap()
    }

    fn backups_in(bak: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(bak) {
            Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        files
    }

    #[test]
    fn splitting_out_the_block_leaves_the_rest_byte_for_byte() {
        let text = format!(
            "{BEGIN_MARKER} (managed)\nPasswordAuthentication no\n{END_MARKER}\n\n\nPort 22\r\n# caf\u{e9}"
        );
        let split = split_managed_block(text.as_bytes()).unwrap();
        assert_eq!(split.block_lines, ["PasswordAuthentication no"]);
        assert_eq!(
            String::from_utf8(split.rest).unwrap(),
            "\nPort 22\r\n# caf\u{e9}",
            "only the block and the one blank line the fixer adds after it are taken out"
        );

        let untouched = b"Port 22\n\n# no block here";
        let split = split_managed_block(untouched).unwrap();
        assert!(split.block_lines.is_empty());
        assert_eq!(split.rest, untouched);
    }

    #[test]
    fn a_block_with_no_end_marker_is_refused_not_treated_as_the_rest_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let text =
            format!("{BEGIN_MARKER} (managed)\nX11Forwarding no\nPort 2222\nX11Forwarding yes\n");
        std::fs::write(&cfg, &text).unwrap();
        let err = harden_with(
            &cfg,
            &dir.path().join("bak"),
            true,
            false,
            false,
            &no_includes,
        )
        .unwrap_err();
        assert!(err.to_string().contains("END"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            text,
            "nothing written"
        );
    }

    #[test]
    fn plan_flags_insecure_defaults_and_skips_lockout_by_default() {
        // A stock config relying on defaults: password auth defaults to yes (insecure), tcp
        // forwarding yes, etc.
        let changes = plan(&effective_of("Port 22\n"), false);
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
        let changes = plan(&effective_of("PasswordAuthentication yes\n"), true);
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
        let changes = plan(&effective_of(text), true);
        assert!(
            changes.is_empty(),
            "a fully-hardened config should plan no changes, got: {changes:?}"
        );
    }

    #[test]
    fn the_values_that_keep_part_of_a_feature_on_are_planned() {
        // `sshd -T` prints `yes` for `AllowTcpForwarding all`; the others are narrower than `yes`
        // but still on. Each used to be left alone because only the word "yes" counted.
        for (text, keyword) in [
            ("AllowTcpForwarding all\n", "AllowTcpForwarding"),
            ("AllowTcpForwarding local\n", "AllowTcpForwarding"),
            ("AllowTcpForwarding remote\n", "AllowTcpForwarding"),
            ("PermitTunnel point-to-point\n", "PermitTunnel"),
            ("PermitTunnel ethernet\n", "PermitTunnel"),
            ("GatewayPorts clientspecified\n", "GatewayPorts"),
        ] {
            let changes = plan(&effective_of(text), false);
            assert!(
                changes
                    .iter()
                    .any(|c| c.keyword == keyword && c.desired == "no"),
                "{text:?} should be planned"
            );
        }
        // Benign values of the multi-valued directives are left alone.
        let changes = plan(
            &effective_of(
                "PermitRootLogin prohibit-password\nPermitRootLogin forced-commands-only\n\
                 AllowTcpForwarding no\nPermitTunnel no\nGatewayPorts no\nMaxAuthTries 6\n\
                 AllowAgentForwarding no\nPasswordAuthentication no\n",
            ),
            true,
        );
        assert!(changes.is_empty(), "{changes:?}");
    }

    /// `is_insecure` restates the rule conditions in Rust, so the two can drift. Evaluate the real
    /// rule files against every value sshd accepts for each managed directive and require the same
    /// answer.
    #[test]
    fn is_insecure_agrees_with_the_shipped_rules() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/ssh-remote-access");
        let values: &[Value] = &[
            "yes".into(),
            "no".into(),
            "all".into(),
            "local".into(),
            "remote".into(),
            "point-to-point".into(),
            "ethernet".into(),
            "clientspecified".into(),
            "prohibit-password".into(),
            "without-password".into(),
            "forced-commands-only".into(),
            "lang,lc_*".into(),
            1.into(),
            4.into(),
            6.into(),
            7.into(),
            10.into(),
        ];
        for d in DIRECTIVES {
            let text = std::fs::read_to_string(rules_dir.join(format!("{}.yaml", d.rule_id)))
                .unwrap_or_else(|e| panic!("{}: {e}", d.rule_id));
            let rule: crate::models::Rule = crate::yaml::from_str(&text).unwrap();
            let condition = crate::condition::Condition::parse(&rule.condition).unwrap();
            for value in values {
                // A number is only ever the value of MaxAuthTries, and the other way round.
                if value.is_number() != (d.field == "max_auth_tries") {
                    continue;
                }
                let fact: Fact = [(d.field.to_string(), value.clone())].into_iter().collect();
                assert_eq!(
                    condition.eval(&fact).unwrap(),
                    is_insecure(d.field, value),
                    "{} and is_insecure disagree on {} = {value}",
                    d.rule_id,
                    d.keyword
                );
            }
            // And the value the fixer writes must be one the rule accepts.
            let desired: Value = match d.desired.parse::<i64>() {
                Ok(n) => n.into(),
                Err(_) => d.desired.into(),
            };
            let fact: Fact = [(d.field.to_string(), desired)].into_iter().collect();
            assert!(!condition.eval(&fact).unwrap(), "{} desired", d.rule_id);
        }
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        std::fs::write(&cfg, "AllowTcpForwarding yes\n").unwrap();
        let before = std::fs::read_to_string(&cfg).unwrap();

        let report = run(&cfg, &bak, false, false);
        assert!(report.pending_count() >= 1);
        assert!(!report.applied);
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            before,
            "dry run must not write"
        );
        assert!(!bak.exists(), "a dry run must not write a backup");
    }

    #[cfg(unix)]
    #[test]
    fn apply_inserts_the_block_and_a_second_run_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        let original = "AllowTcpForwarding yes\nX11Forwarding yes\nPort 22\n";
        std::fs::write(&cfg, original).unwrap();

        let r1 = run(&cfg, &bak, true, false);
        assert!(r1.applied);
        let after = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            after.starts_with(BEGIN_MARKER),
            "block goes on top:\n{after}"
        );
        assert!(after.contains("AllowTcpForwarding no"));
        assert!(after.contains("X11Forwarding no"));
        assert!(after.ends_with(original), "the original is kept below");
        assert_eq!(backups_in(&bak).len(), 1);

        // The fix took, so there is nothing left to plan: no "would set … (was yes)" for ever, no
        // rewrite, and above all no second backup taken of the already-changed file.
        for _ in 0..3 {
            let again = run(&cfg, &bak, true, false);
            assert!(!again.applied);
            assert_eq!(again.pending_count(), 0, "{:?}", again.changes);
            assert!(again.backup_path.is_none());
        }
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), after);
        assert_eq!(backups_in(&bak).len(), 1);
        let preview = run(&cfg, &bak, false, true);
        assert!(
            preview
                .changes
                .iter()
                .all(|c| c.status != SshdChangeStatus::WouldSet || c.lockout_risk),
            "only the opt-in directives are still open: {:?}",
            preview.changes
        );
    }

    #[cfg(unix)]
    #[test]
    fn backup_matches_the_original_before_change() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        let original = "AllowTcpForwarding yes\nPort 2222\n";
        std::fs::write(&cfg, original).unwrap();
        let report = run(&cfg, &bak, true, false);
        let backup = std::fs::read_to_string(report.backup_path.unwrap()).unwrap();
        assert_eq!(backup, original, "backup is the pre-change file, verbatim");
    }

    /// The backup of the untouched file used to have a fixed name, so the second applying run
    /// replaced it with a copy of the already-modified config.
    #[cfg(unix)]
    #[test]
    fn a_later_run_never_overwrites_the_backup_of_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        let original = "PasswordAuthentication yes\nX11Forwarding yes\n";
        std::fs::write(&cfg, original).unwrap();

        let first = run(&cfg, &bak, true, false);
        let after_first = std::fs::read_to_string(&cfg).unwrap();
        // Straight away, inside the same second: a different name all the same.
        let second = run(&cfg, &bak, true, true);
        assert!(first.applied && second.applied);

        let first_backup = first.backup_path.unwrap();
        let second_backup = second.backup_path.unwrap();
        assert_ne!(first_backup, second_backup);
        assert_eq!(std::fs::read_to_string(&first_backup).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(&second_backup).unwrap(),
            after_first
        );
        // Sorted by name, the oldest backup — the untouched file — comes first.
        let listed = backups_in(&bak);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].display().to_string(), first_backup);
    }

    /// `fix sshd --apply --include-auth`, then a plain `fix all --apply`: password logins must stay
    /// off. The second run used to rebuild the block from its own plan, which leaves the lockout
    /// directives out, and so turned them back on.
    #[cfg(unix)]
    #[test]
    fn a_later_safe_run_keeps_what_include_auth_set() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        std::fs::write(&cfg, "PasswordAuthentication yes\nPermitRootLogin yes\n").unwrap();

        assert!(run(&cfg, &bak, true, true).applied);
        let hardened = std::fs::read_to_string(&cfg).unwrap();

        // Nothing new to fix: the plain run leaves the file exactly as it is.
        let plain = run(&cfg, &bak, true, false);
        assert!(!plain.applied);
        assert!(plain.changes.is_empty(), "{:?}", plain.changes);
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), hardened);

        // Something new to fix (a line added below since): the block is rewritten, and still
        // holds the two auth directives.
        std::fs::write(&cfg, format!("{hardened}X11Forwarding yes\n")).unwrap();
        let plain = run(&cfg, &bak, true, false);
        assert!(plain.applied);
        let text = std::fs::read_to_string(&cfg).unwrap();
        let fact = effective_of(&text);
        assert_eq!(fact["password_authentication"], "no");
        assert_eq!(fact["permit_root_login"], "no");
        assert_eq!(fact["x11_forwarding"], "no");
        assert_eq!(text.matches(BEGIN_MARKER).count(), 1, "one block:\n{text}");
        assert_eq!(text.matches("PasswordAuthentication no").count(), 1);
    }

    /// Every rewrite used to add one more blank line under the block.
    #[cfg(unix)]
    #[test]
    fn rewrites_do_not_add_blank_lines_and_removing_the_block_restores_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        let original = "# site config\nX11Forwarding yes\nPasswordAuthentication yes\n";
        std::fs::write(&cfg, original).unwrap();

        run(&cfg, &bak, true, false);
        run(&cfg, &bak, true, true);
        // A third rewrite, forced by a new insecure line at the end.
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str("GatewayPorts yes\n");
        std::fs::write(&cfg, &text).unwrap();
        assert!(run(&cfg, &bak, true, false).applied);

        let text = std::fs::read_to_string(&cfg).unwrap();
        let below = text.split_once(END_MARKER).unwrap().1;
        assert_eq!(
            below,
            format!("\n\n{original}GatewayPorts yes\n"),
            "exactly one blank line between the block and the file"
        );
        let split = split_managed_block(text.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(split.rest).unwrap(),
            format!("{original}GatewayPorts yes\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn bytes_and_line_endings_outside_the_block_are_written_back_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");
        // Latin-1 in a comment, CRLF endings, no final newline.
        let original: &[u8] = b"# caf\xe9\r\nX11Forwarding yes\r\nPort 22";
        std::fs::write(&cfg, original).unwrap();

        let report = run(&cfg, &bak, true, false);
        assert!(report.applied, "a non-UTF-8 byte must not stop the fix");
        let written = std::fs::read(&cfg).unwrap();
        assert!(written.ends_with(original));
        assert_eq!(
            std::fs::read(report.backup_path.unwrap()).unwrap(),
            original
        );
        assert_eq!(
            effective_of(&String::from_utf8_lossy(&written))["x11_forwarding"],
            "no"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_hand_edited_block_is_corrected_in_place_and_its_other_lines_kept() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let text = format!(
            "{BEGIN_MARKER} (managed)\n# kept: see ticket 42\nx11forwarding yes\n\
             PasswordAuthentication no\n{END_MARKER}\n\nPort 22\n"
        );
        std::fs::write(&cfg, text).unwrap();
        assert!(run(&cfg, &dir.path().join("bak"), true, false).applied);
        let text = std::fs::read_to_string(&cfg).unwrap();
        let block = text.split_once(END_MARKER).unwrap().0;
        assert!(block.contains("# kept: see ticket 42"), "{block}");
        assert!(block.contains("X11Forwarding no"), "{block}");
        assert!(!block.contains("x11forwarding yes"), "{block}");
        assert!(block.contains("PasswordAuthentication no"), "{block}");
    }

    /// A `Match all` block overrides whatever comes before it, the managed block included. Writing
    /// the directive at the top anyway and reporting "set" would be a fix that fixed nothing.
    #[cfg(unix)]
    #[test]
    fn a_directive_set_in_match_all_is_reported_as_out_of_reach() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        let bak = dir.path().join("bak");

        // Only that one is insecure: an error, never "already hardened".
        let only = "PasswordAuthentication no\nPermitRootLogin no\nAllowTcpForwarding no\n\
                    AllowAgentForwarding no\nMatch all\nX11Forwarding yes\n";
        std::fs::write(&cfg, only).unwrap();
        let err = harden_with(&cfg, &bak, true, false, false, &no_includes).unwrap_err();
        assert!(err.to_string().contains("X11Forwarding"), "{err}");
        assert!(err.to_string().contains("Match all"), "{err}");
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), only);

        // With something else to fix: that is fixed, and the note names the one that is not.
        let mixed = "PasswordAuthentication no\nPermitRootLogin no\nAllowTcpForwarding yes\n\
                     AllowAgentForwarding no\nMatch all\nX11Forwarding yes\n";
        std::fs::write(&cfg, mixed).unwrap();
        let report = run(&cfg, &bak, true, false);
        assert!(report.applied);
        assert!(report.note.as_deref().unwrap().contains("X11Forwarding"));
        assert_eq!(report.changes.len(), 1, "{:?}", report.changes);
        assert_eq!(report.changes[0].keyword, "AllowTcpForwarding");
        let text = std::fs::read_to_string(&cfg).unwrap();
        let block = text.split_once(END_MARKER).unwrap().0;
        assert!(
            !block.contains("X11Forwarding"),
            "no useless line:\n{block}"
        );
    }

    #[test]
    fn an_include_that_cannot_be_read_stops_the_fix_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        std::fs::write(&cfg, "Include sshd_config.d/*.conf\nX11Forwarding yes\n").unwrap();
        let denied = |_: &str| -> anyhow::Result<Vec<ConfigFile>> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        };
        let err =
            harden_with(&cfg, &dir.path().join("bak"), false, false, false, &denied).unwrap_err();
        assert!(err.to_string().contains("sudo"), "{err}");
    }

    /// With no `/etc/ssh/sshd_config`, creating one would make sshd read it instead of the vendor
    /// file, and editing the vendor file is undone by the next update: the plan is shown, nothing
    /// is written, and the note says which drop-in to create.
    #[test]
    fn the_vendor_file_is_planned_against_but_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = dir.path().join("sshd_config");
        let text = "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding yes\n";
        std::fs::write(&vendor, text).unwrap();
        let bak = dir.path().join("bak");

        let preview = plan_for_vendor_config(&vendor, &bak, false, false, &no_includes).unwrap();
        assert!(preview.by_hand);
        assert!(!preview.applied);
        assert!(preview
            .changes
            .iter()
            .any(|c| c.keyword == "X11Forwarding" && c.status == SshdChangeStatus::WouldSet));
        let note = preview.note.unwrap();
        assert!(
            note.contains("/etc/ssh/sshd_config.d/00-hardening.conf"),
            "{note}"
        );
        assert!(note.contains("X11Forwarding no"), "{note}");
        assert!(
            !note.contains("PasswordAuthentication no"),
            "a lockout directive is not listed without --include-auth: {note}"
        );

        let err = plan_for_vendor_config(&vendor, &bak, true, false, &no_includes).unwrap_err();
        assert!(err.to_string().contains("00-hardening.conf"), "{err}");
        assert_eq!(std::fs::read_to_string(&vendor).unwrap(), text);
        assert!(
            !bak.exists(),
            "no backup either: nothing was going to be written"
        );

        // A hardened vendor configuration has nothing to say and nothing to refuse.
        std::fs::write(
            &vendor,
            "PermitRootLogin no\nPasswordAuthentication no\nAllowTcpForwarding no\n\
             AllowAgentForwarding no\n",
        )
        .unwrap();
        let quiet = plan_for_vendor_config(&vendor, &bak, true, false, &no_includes).unwrap();
        assert!(quiet.changes.is_empty() && !quiet.by_hand);
    }

    #[cfg(unix)]
    #[test]
    fn a_drop_in_does_not_beat_the_block() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        std::fs::write(&cfg, "Include sshd_config.d/*.conf\nX11Forwarding no\n").unwrap();
        let drop_in = |_: &str| {
            Ok(crate::collectors::sshd::tests::included(&[
                "X11Forwarding yes\n",
            ]))
        };
        let bak = dir.path().join("bak");
        let report = harden_with(&cfg, &bak, true, false, false, &drop_in).unwrap();
        assert!(report.applied);
        let text = std::fs::read_to_string(&cfg).unwrap();
        let fact = parse_sshd_config_with(&text, "sshd_config", &drop_in).unwrap();
        assert_eq!(fact["x11_forwarding"], "no");
        // And it stays fixed without another write.
        let again = harden_with(&cfg, &bak, true, false, false, &drop_in).unwrap();
        assert!(!again.applied);
        assert_eq!(again.pending_count(), 0);
    }
}

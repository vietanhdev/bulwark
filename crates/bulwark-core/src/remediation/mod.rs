//! Autofixes — the "apply the suggested fix, safely" half of the tool.
//!
//! A scan tells you *what* is wrong and, in each finding's `fix` field, *how* to fix it by hand.
//! This module turns the safe, mechanical subset of those fixes into one-command remediations, each
//! sharing the same discipline the existing `ssh_keys` passphrase fix and `ai_scan` redaction
//! already follow:
//!
//!   * **Dry-run by default.** Every entry point previews; nothing is written without an explicit
//!     `apply` flag.
//!   * **Reversible.** Permission changes record the prior mode; the sshd rewrite keeps a backup and
//!     validates with `sshd -t` before keeping the change.
//!   * **Never widens access, never guesses, never follows a symlink.**
//!   * **Fails loud.** A fix that can't be applied is reported as failed, never silently skipped.
//!
//! It stays inside `bulwark-core`'s no-network / no-UI contract: pure filesystem operations on the
//! local host, no telemetry. Remote application is simply running the CLI's `fix` over SSH, exactly
//! like a remote scan.

pub mod banner;
pub mod login_defs;
pub mod permissions;
pub mod sshd;
pub mod sysctl;

pub use banner::{write_banners, BannerOutcome, BannerReport, BannerResult, DEFAULT_BANNER};
pub use login_defs::{harden_login_defs, LoginDefsChange, LoginDefsChangeStatus, LoginDefsReport};
pub use permissions::{
    etc_permission_targets, ssh_permission_targets, tighten_permissions, PermOutcome, PermReport,
    PermResult, PermTarget,
};
pub use sshd::{harden_sshd_config, SshdChange, SshdChangeStatus, SshdHardeningReport};
pub use sysctl::{harden_sysctl, SysctlChange, SysctlChangeStatus, SysctlHardeningReport};

use serde::{Deserialize, Serialize};

/// Which fixer can address a finding. Deliberately a closed set: these are the only three
/// remediations that exist, and nothing may claim a rule is fixable without one of them behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixKind {
    /// `~/.ssh` permission tightening — user-scoped, needs no privilege.
    SshPerms,
    /// Sensitive `/etc` file permission tightening — needs root to apply.
    EtcPerms,
    /// `/etc/ssh/sshd_config` hardening — needs root to apply.
    Sshd,
    /// Kernel network knobs, persisted to `/etc/sysctl.d/` — needs root to apply.
    Sysctl,
    /// Legal warning banners in `/etc/issue` and `/etc/issue.net` — needs root to apply.
    Banner,
    /// Password-aging policy in `/etc/login.defs` — needs root to apply.
    LoginDefs,
}

/// One rule an autofix can actually clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixCapability {
    pub rule_id: &'static str,
    pub kind: FixKind,
    /// True for the two sshd directives that can lock an operator out of a password-only host
    /// (`PasswordAuthentication no`, `PermitRootLogin no`). These are opt-in per-issue and are
    /// **never** part of the "fix everything safe" set — see [`safe_fix_capabilities`].
    pub lockout_risk: bool,
    /// Whether applying needs root (and therefore, in the GUI, a `pkexec` prompt).
    pub needs_root: bool,
}

/// The complete rule → fixer map. This is the single source of truth for "does a Fix button exist
/// for this finding?", shared by the CLI and the GUI so neither can drift into offering a fix that
/// no fixer implements.
///
/// It is deliberately sparse. Most of the rule pack (kernel/sysctl hardening, service posture,
/// account policy, rootkit indicators) has no mechanical, reversible, safe remediation, and the
/// project would rather show no button than a button that lies. Coverage grows only when a real
/// fixer lands in this module.
///
/// The sshd entries mirror `sshd::DIRECTIVES` one-for-one; `sshd_capabilities_match_directives`
/// asserts that, so adding a directive without a rule id (or vice versa) is a failing test.
pub const FIX_CAPABILITIES: &[FixCapability] = &[
    // Sensitive /etc file modes — both filesystem-permission rules read the same watched set that
    // `etc_permission_targets` pins.
    FixCapability {
        rule_id: "BLWK-FS-001",
        kind: FixKind::EtcPerms,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-FS-002",
        kind: FixKind::EtcPerms,
        lockout_risk: false,
        needs_root: true,
    },
    // sshd_config directives.
    FixCapability {
        rule_id: "BLWK-SSH-001",
        kind: FixKind::Sshd,
        lockout_risk: true,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-002",
        kind: FixKind::Sshd,
        lockout_risk: true,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-003",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-004",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-005",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-006",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-007",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-008",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-009",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-010",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-SSH-011",
        kind: FixKind::Sshd,
        lockout_risk: false,
        needs_root: true,
    },
    // Kernel network knobs. Not lockout-risky: neither knob can cut an existing session.
    // `send_redirects=0` only stops this host *emitting* ICMP redirects, which a non-router has no
    // reason to do (and the rule is already gated to the server profile); `log_martians=1` only
    // adds kernel log lines. Both are therefore in the bulk set. The one caveat worth knowing is
    // that on a host deliberately acting as a router, send_redirects=0 is a behaviour change — the
    // rule's own `fix` text says as much, and the preview names every interface it touches.
    FixCapability {
        rule_id: "BLWK-KERNEL-016",
        kind: FixKind::Sysctl,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-KERNEL-017",
        kind: FixKind::Sysctl,
        lockout_risk: false,
        needs_root: true,
    },
    // Login banners. Text in two files that nothing parses for behaviour — the safest change in
    // the whole set, and it refuses to overwrite a banner a human already wrote. In the bulk set.
    FixCapability {
        rule_id: "BLWK-BANN-001",
        kind: FixKind::Banner,
        lockout_risk: false,
        needs_root: true,
    },
    // Password-aging policy. In the bulk set: neither directive can lock anyone out of a current
    // session or invalidate an existing password. PASS_MAX_DAYS/PASS_MIN_DAYS apply to accounts
    // created or whose aging is next recalculated — `login.defs` is read at account-management
    // time, not at login, so no one is denied access by this edit.
    FixCapability {
        rule_id: "BLWK-ACCT-002",
        kind: FixKind::LoginDefs,
        lockout_risk: false,
        needs_root: true,
    },
    FixCapability {
        rule_id: "BLWK-ACCT-003",
        kind: FixKind::LoginDefs,
        lockout_risk: false,
        needs_root: true,
    },
];

/// Every rule id served by one fixer. Derived from [`FIX_CAPABILITIES`] so callers that need to
/// drive a whole fixer ("fix every sysctl rule") can't hand it a stale hardcoded list.
pub fn rules_for_kind(kind: FixKind) -> Vec<&'static str> {
    FIX_CAPABILITIES
        .iter()
        .filter(|c| c.kind == kind)
        .map(|c| c.rule_id)
        .collect()
}

/// Look up the fixer for a rule id, if one exists.
pub fn fix_capability(rule_id: &str) -> Option<&'static FixCapability> {
    FIX_CAPABILITIES.iter().find(|c| c.rule_id == rule_id)
}

/// The capabilities a bulk "fix everything safe" action is allowed to touch: everything except the
/// lockout-risky sshd auth directives. Locking an operator out of a host they reach only by
/// password is the one failure mode a one-click bulk fix must never be able to cause, so those two
/// stay per-issue and opt-in — mirroring the CLI's `fix all` vs `fix sshd --include-auth` split.
pub fn safe_fix_capabilities() -> impl Iterator<Item = &'static FixCapability> {
    FIX_CAPABILITIES.iter().filter(|c| !c.lockout_risk)
}

/// The result of running more than one fixer in a single pass — what `bulwarkctl fix all --json`
/// prints and what the GUI's "Fix All" deserializes. Each part is `None` when that fixer didn't run
/// (not applicable, or not selected); `sshd_error` carries the reason the sshd pass was skipped so
/// a failure is never silently absent from the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CombinedFixReport {
    pub ssh_perms: Option<PermReport>,
    pub etc_perms: Option<PermReport>,
    pub sshd: Option<SshdHardeningReport>,
    pub sysctl: Option<SysctlHardeningReport>,
    pub banner: Option<BannerReport>,
    pub login_defs: Option<LoginDefsReport>,
    pub sshd_error: Option<String>,
    /// Reasons a fixer was skipped, one per fixer that couldn't run. Never a silent drop.
    #[serde(default)]
    pub errors: Vec<String>,
    /// False for a preview (dry run), true when the changes were actually written.
    pub applied: bool,
}

impl CombinedFixReport {
    /// Total number of changes made (or, in a preview, that would be made) across every part.
    pub fn changes(&self) -> usize {
        self.ssh_perms.as_ref().map_or(0, |r| r.changes())
            + self.etc_perms.as_ref().map_or(0, |r| r.changes())
            + self.sshd.as_ref().map_or(0, |r| r.pending_count())
            + self.sysctl.as_ref().map_or(0, |r| r.pending_count())
            + self.banner.as_ref().map_or(0, |r| r.pending_count())
            + self.login_defs.as_ref().map_or(0, |r| r.pending_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bulk path must never be able to lock a user out of their own machine. This is the
    /// single most consequential invariant in this module: `PasswordAuthentication no` and
    /// `PermitRootLogin no` on a host reached only by password make it unreachable, and there is
    /// no undo from the other end of a severed SSH session.
    #[test]
    fn safe_set_excludes_the_lockout_risky_auth_directives() {
        let safe: Vec<&str> = safe_fix_capabilities().map(|c| c.rule_id).collect();
        assert!(
            !safe.contains(&"BLWK-SSH-001"),
            "PasswordAuthentication must not be in the bulk fix set"
        );
        assert!(
            !safe.contains(&"BLWK-SSH-002"),
            "PermitRootLogin must not be in the bulk fix set"
        );
        assert!(safe
            .iter()
            .all(|id| !fix_capability(id).unwrap().lockout_risk));
        // …and the safe set is not vacuously empty, which would satisfy the above trivially.
        assert!(safe.contains(&"BLWK-SSH-004"));
        assert!(safe.contains(&"BLWK-FS-002"));
    }

    /// Every advertised capability must name a rule that exists in the shipped pack, and every
    /// sshd directive the fixer manages must have a capability — otherwise the GUI either offers a
    /// Fix button for a rule that can never fire, or silently withholds one that would work.
    /// Every fixer's own managed-rule list must match what the capability map advertises for it.
    /// Generalised over all four rule-keyed fixers so adding a directive to any of them without a
    /// capability (or vice versa) is a failing test, not a Fix button that silently never appears.
    #[test]
    fn every_fixer_agrees_with_the_capability_map() {
        for (kind, managed) in [
            (FixKind::Sshd, sshd::managed_rule_ids()),
            (FixKind::Sysctl, sysctl::managed_rule_ids()),
            (FixKind::Banner, banner::managed_rule_ids()),
            (FixKind::LoginDefs, login_defs::managed_rule_ids()),
        ] {
            let advertised: Vec<&str> = FIX_CAPABILITIES
                .iter()
                .filter(|c| c.kind == kind)
                .map(|c| c.rule_id)
                .collect();
            assert!(!managed.is_empty(), "{kind:?} manages no rules");
            for id in &managed {
                assert!(
                    advertised.contains(id),
                    "{id} is fixed by {kind:?} but has no FixCapability"
                );
            }
            for id in &advertised {
                assert!(
                    managed.contains(id),
                    "{id} advertises a {kind:?} fix no directive implements"
                );
            }
        }
    }

    /// BLWK-LOG-002 (logs not forwarded off-box) is deliberately NOT fixable: it needs a remote
    /// log server address that cannot be inferred, and guessing one would write a broken rsyslog
    /// config. Pinned as a test so a future "let's cover everything" pass has to argue with it.
    #[test]
    fn log_forwarding_is_deliberately_not_fixable() {
        assert!(
            fix_capability("BLWK-LOG-002").is_none(),
            "BLWK-LOG-002 needs a destination that cannot be inferred — it must stay unfixable"
        );
    }

    #[test]
    fn sshd_capabilities_match_directives() {
        let managed = sshd::managed_rule_ids();
        let advertised: Vec<&str> = FIX_CAPABILITIES
            .iter()
            .filter(|c| c.kind == FixKind::Sshd)
            .map(|c| c.rule_id)
            .collect();
        for id in &managed {
            assert!(
                advertised.contains(id),
                "{id} is fixed by the sshd hardener but has no FixCapability"
            );
        }
        for id in &advertised {
            assert!(
                managed.contains(id),
                "{id} advertises an sshd fix no directive implements"
            );
        }
    }

    /// `lockout_risk` here must agree with `lockout_risk` in the directive table — the two are
    /// written independently, and a disagreement would put an auth directive into the bulk set.
    #[test]
    fn lockout_flags_agree_with_the_directive_table() {
        for c in FIX_CAPABILITIES.iter().filter(|c| c.kind == FixKind::Sshd) {
            assert_eq!(
                Some(c.lockout_risk),
                sshd::directive_lockout_risk(c.rule_id),
                "{} disagrees with the directive table on lockout risk",
                c.rule_id
            );
        }
    }

    #[test]
    fn unknown_rules_have_no_fix() {
        assert!(fix_capability("BLWK-KERNEL-001").is_none());
        assert!(fix_capability("BLWK-AI-001").is_none());
        assert!(
            fix_capability("BLWK-SSH-012").is_none(),
            "key passphrases are `ssh protect`, not a fixer here"
        );
        assert!(fix_capability("BLWK-SSH-004").is_some());
    }
}

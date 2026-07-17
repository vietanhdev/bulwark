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

pub mod permissions;
pub mod sshd;

pub use permissions::{
    etc_permission_targets, ssh_permission_targets, tighten_permissions, PermOutcome, PermReport,
    PermResult, PermTarget,
};
pub use sshd::{harden_sshd_config, SshdChange, SshdChangeStatus, SshdHardeningReport};

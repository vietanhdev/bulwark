//! End-to-end coverage of the autofixes through the crate's *public* API — the same surface the
//! CLI and GUI call. The unit tests inside `remediation/` prove each helper in isolation; these
//! prove the full "detect → fix → resolved" loop: a fix, applied, actually leaves the host in a
//! state where the very issue it targeted no longer holds.

use bulwark_core::{harden_sshd_config, ssh_permission_targets, tighten_permissions};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// Loose `~/.ssh` → after applying the fix, a re-scan finds nothing left to tighten. That "second
/// pass is clean" is the machine-checkable definition of the issue being resolved, not merely acted
/// on.
#[test]
fn ssh_permission_fix_resolves_every_loose_file() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();

    // A representative spread of the things a real ~/.ssh holds, all deliberately too open.
    fs::write(
        ssh.join("id_ed25519"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(ssh.join("id_ed25519.pub"), "ssh-ed25519 AAAA").unwrap();
    fs::write(ssh.join("authorized_keys"), "ssh-ed25519 AAAA").unwrap();
    fs::write(ssh.join("config"), "Host *\n").unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(ssh.join("id_ed25519"), fs::Permissions::from_mode(0o666)).unwrap();
    fs::set_permissions(
        ssh.join("authorized_keys"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(ssh.join("config"), fs::Permissions::from_mode(0o644)).unwrap();

    // Detect: a dry run must see multiple problems.
    let targets = ssh_permission_targets(&ssh);
    let preview = tighten_permissions(&targets, false);
    assert!(
        preview.would_tighten >= 4,
        "expected several loose files, saw {}",
        preview.would_tighten
    );

    // Fix.
    let applied = tighten_permissions(&targets, true);
    assert!(applied.tightened >= 4);
    assert_eq!(applied.failed, 0);
    assert_eq!(mode(&ssh), 0o700);
    assert_eq!(mode(&ssh.join("id_ed25519")), 0o600);

    // Resolved: a fresh scan of the same tree now finds nothing to change, and the public key that
    // was already fine is untouched.
    let after = tighten_permissions(&ssh_permission_targets(&ssh), false);
    assert_eq!(after.would_tighten, 0, "the issue must be fully resolved");
    assert_eq!(mode(&ssh.join("id_ed25519.pub")), 0o644);
}

/// An insecure sshd_config → after hardening, the values sshd will actually obey (the managed block
/// sits on top, and OpenSSH takes the first value it sees) are all the secure ones. We assert the
/// block is present, contains each fixed directive at its secure value, and precedes the original
/// insecure lines it overrides.
#[test]
fn sshd_hardening_resolves_the_flagged_directives() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("sshd_config");
    let bak = dir.path().join("backups");
    let insecure = "PasswordAuthentication yes\nPermitRootLogin yes\nX11Forwarding yes\n\
                    AllowTcpForwarding yes\nAllowAgentForwarding yes\nMaxAuthTries 10\nPort 22\n";
    fs::write(&cfg, insecure).unwrap();

    // Include the lockout-risky directives so we exercise the full set in one pass.
    let report = harden_sshd_config(Some(&cfg), &bak, true, true).unwrap();
    assert!(report.applied);
    assert!(report.pending_count() >= 6);

    let hardened = fs::read_to_string(&cfg).unwrap();
    let block_end = hardened.find("# END bulwark-hardening").unwrap();
    let block = &hardened[..block_end];

    // Every flagged directive is now pinned to its secure value, at the top of the file.
    for secure in [
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "X11Forwarding no",
        "AllowTcpForwarding no",
        "AllowAgentForwarding no",
        "MaxAuthTries 4",
    ] {
        assert!(
            block.contains(secure),
            "block must set `{secure}`:\n{block}"
        );
        // The winning (managed) line must come before the original insecure line it overrides.
        let managed_at = hardened.find(secure).unwrap();
        let directive = secure.split(' ').next().unwrap();
        if let Some(orig_at) = hardened.rfind(&format!("{directive} ")) {
            if orig_at != managed_at {
                assert!(
                    managed_at < orig_at,
                    "the secure `{secure}` must win by appearing first"
                );
            }
        }
    }

    // The original file was backed up verbatim, so the change is reversible.
    let backup = fs::read_to_string(report.backup_path.unwrap()).unwrap();
    assert_eq!(backup, insecure);
}

/// A config that is already hardened must not be "fixed" again — no block written, nothing pending.
/// This is the guard against a fix that fires on a healthy host.
#[test]
fn sshd_hardening_is_a_noop_on_a_secure_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("sshd_config");
    let secure = "PasswordAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\n\
                  X11Forwarding no\nAllowTcpForwarding no\nPermitUserEnvironment no\n\
                  PermitTunnel no\nStrictModes yes\nGatewayPorts no\nAllowAgentForwarding no\n\
                  MaxAuthTries 4\n";
    fs::write(&cfg, secure).unwrap();

    let report = harden_sshd_config(Some(&cfg), &dir.path().join("bak"), true, true).unwrap();
    assert!(!report.applied, "a secure config needs no change");
    assert_eq!(report.pending_count(), 0);
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        secure,
        "the file must be byte-for-byte untouched"
    );
}

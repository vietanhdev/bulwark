//! Drives the real `bulwarkctl fix` binary end-to-end against throwaway files, the same way a user
//! would run it. The remediation *logic* is unit-tested in `bulwark-core`; this proves the CLI
//! wiring — argument parsing, the dry-run/apply split, the root gate's `--config` exemption, and the
//! human-readable output — actually hangs together.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("bulwarkctl");
    p
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// Run `bulwarkctl fix …` with HOME pointed at `home` so writes stay contained.
fn run_fix(home: &Path, args: &[&str]) -> (String, bool) {
    let out = Command::new(bin())
        .arg("fix")
        .args(args)
        .env("HOME", home)
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        out.status.success(),
    )
}

#[test]
fn ssh_perms_preview_then_apply() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    let key = ssh.join("id_ed25519");
    fs::write(
        &key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    // Preview must change nothing.
    let (out, ok) = run_fix(home.path(), &["ssh-perms"]);
    assert!(ok, "preview should succeed:\n{out}");
    assert!(out.contains("would chmod"), "preview output:\n{out}");
    assert_eq!(mode_of(&key), 0o644, "preview must not change the key");

    // Apply tightens.
    let (out, ok) = run_fix(home.path(), &["ssh-perms", "--apply"]);
    assert!(ok, "apply should succeed:\n{out}");
    assert_eq!(mode_of(&key), 0o600, "key tightened to 600");
    assert_eq!(mode_of(&ssh), 0o700, ".ssh tightened to 700");

    // Idempotent.
    let (out, _) = run_fix(home.path(), &["ssh-perms", "--apply"]);
    assert!(out.contains("already correct"), "second apply:\n{out}");
}

#[test]
fn sshd_hardening_via_config_flag_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("sshd_config");
    fs::write(&cfg, "X11Forwarding yes\nAllowTcpForwarding yes\nPort 22\n").unwrap();

    // The --config path exempts the root gate, so --apply works unprivileged here.
    let (out, ok) = run_fix(
        home.path(),
        &["sshd", "--apply", "--config", cfg.to_str().unwrap()],
    );
    assert!(ok, "sshd apply should succeed:\n{out}");
    let after = fs::read_to_string(&cfg).unwrap();
    assert!(
        after.starts_with("# BEGIN bulwark-hardening"),
        "block on top:\n{after}"
    );
    assert!(after.contains("X11Forwarding no"));
    assert!(after.contains("Port 22"), "original preserved");

    // Re-apply must not stack a second managed block.
    let (_out, ok) = run_fix(
        home.path(),
        &["sshd", "--apply", "--config", cfg.to_str().unwrap()],
    );
    assert!(ok);
    let after2 = fs::read_to_string(&cfg).unwrap();
    assert_eq!(after2.matches("# BEGIN bulwark-hardening").count(), 1);
}

#[test]
fn sshd_lockout_directives_are_opt_in() {
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("sshd_config");
    fs::write(&cfg, "PasswordAuthentication yes\nX11Forwarding yes\n").unwrap();

    // Without --include-auth, PasswordAuthentication must NOT be written into the file.
    run_fix(
        home.path(),
        &["sshd", "--apply", "--config", cfg.to_str().unwrap()],
    );
    let safe = fs::read_to_string(&cfg).unwrap();
    let block = safe.split("# END bulwark-hardening").next().unwrap();
    assert!(
        !block.contains("PasswordAuthentication no"),
        "auth directive must be skipped by default; block:\n{block}"
    );
    assert!(block.contains("X11Forwarding no"));

    // With --include-auth it is written.
    run_fix(
        home.path(),
        &[
            "sshd",
            "--apply",
            "--include-auth",
            "--config",
            cfg.to_str().unwrap(),
        ],
    );
    let full = fs::read_to_string(&cfg).unwrap();
    let block2 = full.split("# END bulwark-hardening").next().unwrap();
    assert!(
        block2.contains("PasswordAuthentication no"),
        "auth directive written with --include-auth; block:\n{block2}"
    );
}

#[test]
fn etc_perms_apply_without_root_is_refused() {
    let home = tempfile::tempdir().unwrap();
    // Not root in CI, so --apply must refuse rather than silently fail on root-owned files.
    let (out, ok) = run_fix(home.path(), &["etc-perms", "--apply"]);
    assert!(!ok, "should exit non-zero:\n{out}");
    assert!(out.contains("root"), "should explain it needs root:\n{out}");
}

#[test]
fn fix_all_applies_user_scoped_and_skips_root_gracefully() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    let key = ssh.join("id_ed25519");
    fs::write(
        &key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    // `fix all --apply`, unprivileged: the ~/.ssh fix (user-scoped) runs; the /etc and sshd fixes
    // need root, so they must be *skipped with an explanation*, never silently attempted-and-failed.
    let (out, ok) = run_fix(home.path(), &["all", "--apply"]);
    assert!(
        ok,
        "fix all should succeed even when root fixes are skipped:\n{out}"
    );
    assert_eq!(
        mode_of(&key),
        0o600,
        "the user-scoped ssh fix must have applied"
    );
    assert!(out.contains("[ssh-perms]"));
    assert!(
        out.contains("needs root") || out.contains("[etc-perms]"),
        "root-scoped fixes must be acknowledged:\n{out}"
    );
    // It must be explicit about what it deliberately did not touch.
    assert!(
        out.contains("lockout") || out.contains("Not included"),
        "should name the excluded lockout-risky fixes:\n{out}"
    );
}

#[test]
fn fix_list_runs_and_previews() {
    let home = tempfile::tempdir().unwrap();
    let (out, ok) = run_fix(home.path(), &["list"]);
    assert!(ok, "list should succeed:\n{out}");
    assert!(out.contains("fix ssh-perms"));
    assert!(out.contains("fix etc-perms"));
    assert!(
        out.contains("ssh protect"),
        "should mention the passphrase fix too"
    );
}

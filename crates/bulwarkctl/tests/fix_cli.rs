//! Drives the real `bulwarkctl fix` binary end-to-end against throwaway files, the same way a user
//! would run it. The remediation *logic* is unit-tested in `bulwark-core`; this proves the CLI
//! wiring — argument parsing, the dry-run/apply split, the root gate's `--config` exemption, and the
//! human-readable output — actually hangs together.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    // Cargo's own path to the binary. Guessing it from the test executable's folder broke when
    // Cargo moved test executables under target/<profile>/build/.
    PathBuf::from(env!("CARGO_BIN_EXE_bulwarkctl"))
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// Whether the test process is running as root (effective uid 0). Read from `/proc/self/status`
/// rather than via libc, to avoid a dev-dependency just for this. Linux-only, which these tests are.
/// The CI distro matrix runs inside root containers, where the "needs root" guard legitimately does
/// not trip — so root-gated refusal assertions must be skipped there.
fn running_as_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                // "Uid:\t<real>\t<effective>\t<saved>\t<fs>" — the effective uid is field 2.
                .and_then(|l| l.split_whitespace().nth(2).map(|u| u == "0"))
        })
        .unwrap_or(false)
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

/// The tester's sequence: copy the config, apply twice, compare the backup with the copy. The
/// second run used to overwrite the one backup with the already-changed file, add a blank line,
/// and keep announcing the same "would set … (was yes)" lines for ever.
#[test]
fn sshd_hardening_applied_twice_keeps_the_original_backup_and_then_has_nothing_to_do() {
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("sshd_config");
    let original = "\n# site config\nX11Forwarding yes\nAllowTcpForwarding yes\nPort 22\n";
    fs::write(&cfg, original).unwrap();
    let args = ["sshd", "--apply", "--config", cfg.to_str().unwrap()];

    let (out, ok) = run_fix(home.path(), &args);
    assert!(ok && out.contains("Applied."), "first apply:\n{out}");
    let after_first = fs::read_to_string(&cfg).unwrap();

    for _ in 0..3 {
        let (out, ok) = run_fix(home.path(), &args);
        assert!(ok, "{out}");
        assert!(!out.contains("Applied."), "nothing left to apply:\n{out}");
        assert!(
            !out.contains("X11Forwarding") && !out.contains("AllowTcpForwarding"),
            "still planning a fix that is done:\n{out}"
        );
    }
    assert_eq!(
        fs::read_to_string(&cfg).unwrap(),
        after_first,
        "a run with nothing to do must not rewrite the file"
    );

    let backups: Vec<PathBuf> =
        fs::read_dir(home.path().join(".local/share/bulwark/sshd-config-backups"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
    assert_eq!(
        backups.len(),
        1,
        "one applied change, one backup: {backups:?}"
    );
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), original);

    // The preview and `fix sshd` agree that the safe set is done.
    let (out, _) = run_fix(home.path(), &["sshd", "--config", cfg.to_str().unwrap()]);
    assert!(!out.contains("would set: X11Forwarding"), "preview:\n{out}");
    assert!(
        !out.contains("would set: AllowTcpForwarding"),
        "preview:\n{out}"
    );
}

/// `fix sshd --apply --include-auth`, then a plain `fix sshd --apply` (what `fix all --apply` runs):
/// the second must not take `PasswordAuthentication no` back out of the managed block.
#[test]
fn a_plain_sshd_fix_after_include_auth_keeps_password_logins_off() {
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join("sshd_config");
    fs::write(&cfg, "PasswordAuthentication yes\nPermitRootLogin yes\n").unwrap();
    let path = cfg.to_str().unwrap();

    let (out, ok) = run_fix(
        home.path(),
        &["sshd", "--apply", "--include-auth", "--config", path],
    );
    assert!(ok, "{out}");
    // A new insecure line appears below afterwards, so the plain run has something to write.
    let mut text = fs::read_to_string(&cfg).unwrap();
    text.push_str("X11Forwarding yes\n");
    fs::write(&cfg, text).unwrap();

    let (out, ok) = run_fix(home.path(), &["sshd", "--apply", "--config", path]);
    assert!(ok && out.contains("set: X11Forwarding no"), "{out}");
    let text = fs::read_to_string(&cfg).unwrap();
    let block = text.split("# END bulwark-hardening").next().unwrap();
    for kept in [
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "X11Forwarding no",
    ] {
        assert!(
            block.contains(kept),
            "`{kept}` must be in the block:\n{block}"
        );
    }
    assert_eq!(text.matches("# BEGIN bulwark-hardening").count(), 1);
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
    // The refusal only fires when we're actually unprivileged. CI's distro matrix runs in root
    // containers, where the command is legitimately allowed to proceed — nothing to assert there.
    if running_as_root() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    // Unprivileged: --apply must refuse rather than silently fail on root-owned files.
    let (out, ok) = run_fix(home.path(), &["etc-perms", "--apply"]);
    assert!(!ok, "should exit non-zero:\n{out}");
    assert!(out.contains("root"), "should explain it needs root:\n{out}");
}

#[test]
fn fix_all_applies_user_scoped_and_skips_root_gracefully() {
    // As root, `fix all --apply` is the real thing: it would change /etc on whatever machine runs
    // the tests. The root path is exercised in a throw-away container instead.
    if running_as_root() {
        return;
    }
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

/// The tester's cases: `known_hosts` at 660 became 644 (everyone gained read) and a key at 440
/// became 600. A fix removes access; it never adds any, and a second run changes nothing.
#[test]
fn ssh_perms_never_adds_a_permission_bit() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o770)).unwrap();
    let known_hosts = ssh.join("known_hosts");
    fs::write(&known_hosts, "h ssh-ed25519 AAAA\n").unwrap();
    fs::set_permissions(&known_hosts, fs::Permissions::from_mode(0o660)).unwrap();
    let key = ssh.join("k");
    fs::write(
        &key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o440)).unwrap();

    let (out, ok) = run_fix(home.path(), &["ssh-perms"]);
    assert!(ok, "{out}");
    assert!(
        out.contains("660 → 640"),
        "the preview shows the real new mode:\n{out}"
    );

    let (out, ok) = run_fix(home.path(), &["ssh-perms", "--apply"]);
    assert!(ok, "{out}");
    assert_eq!(
        mode_of(&known_hosts),
        0o640,
        "world must not gain read:\n{out}"
    );
    assert_eq!(
        mode_of(&key),
        0o400,
        "the owner must not gain write:\n{out}"
    );
    assert_eq!(mode_of(&ssh), 0o700);

    let (out, ok) = run_fix(home.path(), &["ssh-perms", "--apply"]);
    assert!(
        ok && out.contains("Nothing to do"),
        "a second run changes nothing:\n{out}"
    );
    assert_eq!(mode_of(&known_hosts), 0o640);
    assert_eq!(mode_of(&key), 0o400);
}

/// `fix all` applied the banner and password-age fixers although its help listed neither. Its
/// JSON form (what the desktop app reads) carries neither report now, and lists them instead.
#[test]
fn fix_all_leaves_wording_and_policy_changes_to_be_run_by_name() {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["fix", "all", "--root-only", "--json"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert!(report["banner"].is_null(), "{report}");
    assert!(report["login_defs"].is_null(), "{report}");
    assert!(report["not_included"].is_array(), "{report}");
    assert!(
        !report["etc_perms"].is_null(),
        "the permission part still runs: {report}"
    );
    assert_eq!(report["applied"], false);

    let (out, ok) = run_fix(home.path(), &["all"]);
    assert!(ok, "{out}");
    assert!(
        !out.contains("[banner]") && !out.contains("[login.defs]"),
        "{out}"
    );
    assert!(out.contains("[sysctl]") || out.contains("sysctl"), "{out}");
}

/// `fix login-defs` answered "already within thresholds" for a file with aging disabled (`-1`)
/// and for one with no such lines, while the scan reported both as "no limit".
#[test]
fn login_defs_fixes_disabled_and_missing_password_aging() {
    let home = tempfile::tempdir().unwrap();
    for content in ["PASS_MAX_DAYS -1\nPASS_MIN_DAYS -1\n", "UMASK 022\n"] {
        let cfg = home.path().join("login.defs");
        fs::write(&cfg, content).unwrap();
        let cfg_arg = cfg.to_str().unwrap();
        let (out, ok) = run_fix(home.path(), &["login-defs", "--config", cfg_arg]);
        assert!(ok, "{out}");
        assert!(!out.contains("already within"), "{out}");
        assert!(out.contains("no limit"), "{out}");
        assert_eq!(
            fs::read_to_string(&cfg).unwrap(),
            content,
            "a preview writes nothing"
        );

        let (out, ok) = run_fix(home.path(), &["login-defs", "--config", cfg_arg, "--apply"]);
        assert!(ok, "{out}");
        let text = fs::read_to_string(&cfg).unwrap();
        assert!(
            text.contains("PASS_MAX_DAYS 90") && text.contains("PASS_MIN_DAYS 1"),
            "{text}"
        );

        let (out, ok) = run_fix(home.path(), &["login-defs", "--config", cfg_arg, "--apply"]);
        assert!(ok && out.contains("Nothing to do"), "{out}");
        assert_eq!(
            fs::read_to_string(&cfg).unwrap(),
            text,
            "a second run changes nothing"
        );
    }
}

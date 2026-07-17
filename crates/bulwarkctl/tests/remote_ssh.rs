//! End-to-end coverage of `bulwarkctl scan --ssh` without a real remote host.
//!
//! There is no SSH daemon in CI, so we can't scan a genuine second machine. What we *can* verify —
//! and what actually broke in past shell-out bugs — is the orchestration: the exact `ssh`/`scp`
//! command lines, the "prefer installed else push" branch, parsing the ScanRun back out of the
//! remote stdout (including the fact that a successful scan exits non-zero on findings), and always
//! cleaning up a pushed temp dir. We do that by putting a **mock `ssh` and `scp`** on `PATH` that
//! records every invocation and replays a canned ScanRun for the `scan --json` call, then driving
//! the real compiled binary against it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    // The integration-test binary lives at target/<profile>/deps/…; the CLI is two levels up.
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    p.pop(); // profile dir
    p.push("bulwarkctl");
    p
}

fn fixture_json() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/remote_scanrun.json");
    fs::read_to_string(p).unwrap()
}

/// Write a mock `ssh` (and matching `scp`) into `dir`. The mock records each call to `log_path` and,
/// for the recognized remote commands, replays canned output. `installed` decides whether
/// `command -v` reports a bulwark on the remote (the "installed" branch) or nothing (the "push"
/// branch).
fn write_mocks(dir: &Path, log_path: &Path, fixture_path: &Path, installed: bool) {
    let installed_line = if installed {
        "echo /usr/bin/bulwarkctl; exit 0"
    } else {
        "exit 1" // command -v found nothing
    };
    // The remote command is the LAST argument ssh receives. We branch on its content.
    let ssh = format!(
        r#"#!/bin/sh
echo "ssh $*" >> "{log}"
for a in "$@"; do cmd="$a"; done
case "$cmd" in
  *"command -v"*) {installed_line} ;;
  *"uname -m"*) uname -m ;;
  *"mktemp"*) echo /tmp/bulwark.MOCK01 ;;
  *"chmod"*) exit 0 ;;
  *"rm -rf"*) exit 0 ;;
  *"scan --json"*)
    cat "{fixture}"
    # A real successful scan exits non-zero when it finds issues; mimic that to prove the
    # caller keys success off "did stdout parse", not off the exit code.
    exit 1 ;;
  *) exit 0 ;;
esac
"#,
        log = log_path.display(),
        fixture = fixture_path.display(),
    );
    let scp = format!(
        r#"#!/bin/sh
echo "scp $*" >> "{log}"
exit 0
"#,
        log = log_path.display()
    );
    let ssh_path = dir.join("ssh");
    let scp_path = dir.join("scp");
    fs::write(&ssh_path, ssh).unwrap();
    fs::write(&scp_path, scp).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&ssh_path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&scp_path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Run `bulwarkctl scan --ssh …` with the mock ssh/scp on PATH. Returns (stdout, stderr, ssh/scp log).
fn run_remote(installed: bool, extra_args: &[&str]) -> (String, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let bindir = tmp.path().join("mockbin");
    fs::create_dir_all(&bindir).unwrap();
    let log = tmp.path().join("calls.log");
    fs::write(&log, "").unwrap();
    // Copy the fixture next to the mocks so the mock's absolute path is stable.
    let fixture = tmp.path().join("scanrun.json");
    fs::write(&fixture, fixture_json()).unwrap();
    write_mocks(&bindir, &log, &fixture, installed);

    let path = format!(
        "{}:{}",
        bindir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // Give the binary a real rules dir (used only on the push path for --rules-dir; harmless here).
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let mut args = vec![
        "scan",
        "--ssh",
        "testhost",
        "--no-persist",
        "--rules-dir",
        rules.to_str().unwrap(),
    ];
    args.extend_from_slice(extra_args);

    let out = Command::new(bin())
        .args(&args)
        .env("PATH", path)
        .env("HOME", tmp.path()) // keep any stray writes inside the temp dir
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        fs::read_to_string(&log).unwrap(),
    )
}

#[test]
fn installed_remote_is_invoked_in_place() {
    let (stdout, stderr, log) = run_remote(true, &["--json"]);
    // The canned ScanRun round-tripped: its distinctive host fingerprint shows up in our output.
    assert!(
        stdout.contains("remote-test-host/9.9.9"),
        "expected the remote host fingerprint in stdout, got:\n{stdout}\n---stderr---\n{stderr}"
    );
    // It used the installed binary, so it must NOT have pushed anything.
    assert!(
        !log.contains("scp "),
        "installed path must not scp a binary; log:\n{log}"
    );
    assert!(
        log.contains("command -v"),
        "must probe for an installed binary"
    );
    assert!(log.contains("scan --json"), "must run the remote scan");
}

#[test]
fn missing_remote_binary_triggers_push_and_cleanup() {
    let (stdout, stderr, log) = run_remote(false, &["--json"]);
    assert!(
        stdout.contains("remote-test-host/9.9.9"),
        "expected the remote scan result, got stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Push path: it must scp the binary and the rule pack, then rm the temp dir it made.
    assert!(log.contains("scp "), "push path must scp; log:\n{log}");
    assert!(log.contains("uname -m"), "push path must check arch first");
    assert!(
        log.contains("rm -rf") && log.contains("/tmp/bulwark.MOCK01"),
        "push path must clean up its temp dir; log:\n{log}"
    );
}

#[test]
fn non_zero_scan_exit_is_not_treated_as_failure() {
    // The mock's `scan --json` exits 1 (findings present). The command must still succeed at the
    // orchestration level because stdout parsed — that's the whole point of the parse-first logic.
    let (stdout, _stderr, _log) = run_remote(true, &["--json"]);
    assert!(stdout.contains("\"rules_loaded\""));
}

/// Run `scan --ssh` against a fully custom `ssh` mock script body. Returns (success, stdout, stderr).
fn run_with_ssh_script(ssh_body: &str, extra_args: &[&str]) -> (bool, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let bindir = tmp.path().join("mockbin");
    fs::create_dir_all(&bindir).unwrap();
    let ssh_path = bindir.join("ssh");
    let scp_path = bindir.join("scp");
    fs::write(&ssh_path, format!("#!/bin/sh\n{ssh_body}\n")).unwrap();
    fs::write(&scp_path, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&ssh_path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&scp_path, fs::Permissions::from_mode(0o755)).unwrap();

    let path = format!(
        "{}:{}",
        bindir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let mut args = vec![
        "scan",
        "--ssh",
        "testhost",
        "--no-persist",
        "--rules-dir",
        rules.to_str().unwrap(),
    ];
    args.extend_from_slice(extra_args);
    let out = Command::new(bin())
        .args(&args)
        .env("PATH", path)
        .env("HOME", tmp.path())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_connection_failure_is_reported_not_papered_over() {
    // ssh can't authenticate: it prints the classic diagnostic to stderr and exits 255. This must
    // surface as a connection error, and must NOT be mistaken for "no binary installed → push".
    let (ok, _out, err) =
        run_with_ssh_script("echo 'Permission denied (publickey).' 1>&2; exit 255", &[]);
    assert!(!ok, "a dead connection must be a failure");
    assert!(
        err.contains("could not connect") || err.contains("Permission denied"),
        "expected a connection error, got:\n{err}"
    );
}

#[test]
fn an_arch_mismatch_refuses_to_push() {
    // No installed binary (command -v exits 1 cleanly), and the remote reports a foreign arch — the
    // pushed binary could never run there, so we must refuse rather than copy a broken binary over.
    let ssh = r#"for a in "$@"; do cmd="$a"; done
case "$cmd" in
  *"command -v"*) exit 1 ;;
  *"uname -m"*) echo sparc64 ;;
  *) exit 0 ;;
esac"#;
    let (ok, _out, err) = run_with_ssh_script(ssh, &[]);
    assert!(!ok, "an arch mismatch must abort");
    assert!(
        err.contains("sparc64") && err.to_lowercase().contains("install bulwark"),
        "expected an arch-mismatch refusal that suggests installing on the remote, got:\n{err}"
    );
}

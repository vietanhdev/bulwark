//! End-to-end fixture tests: build a container with a real, known-bad-or-good sshd_config/
//! cron entry/systemd unit, mount the real `bulwarkctl` binary and rule pack into it, run a real
//! `bulwarkctl scan --json`, and check the actual findings against `expected-findings.json`
//! (rule IDs that MUST appear) and an optional `forbidden-findings.json` (rule IDs that must
//! NOT appear) checked in alongside each fixture's Dockerfile. This is the layer collector
//! unit tests (fixture strings parsed in isolation) don't cover: proving the full pipeline —
//! real file on a real filesystem -> collector reads it -> rule evaluates -> finding appears
//! in the CLI's actual JSON output — genuinely works, not just that each piece works alone.
//!
//! Deliberately a subset check, not exact-set equality: a bare `ubuntu:24.04` container has
//! its own baseline of unrelated findings (no ClamAV, no rsyslog, no FIM baseline, default
//! login.defs policy, ...) that have nothing to do with what a given fixture is testing —
//! and kernel/sysctl rules specifically read the *host's* live sysctl values, since sysctls
//! aren't containerized/namespaced by default, so they vary by whatever machine runs this
//! suite. Asserting the full findings set exactly would make every fixture fail the moment an
//! unrelated rule is added to the pack, or simply be run on a different host.
//!
//! `#[ignore]`d so plain `cargo test --workspace` (what every contributor runs, Docker or not)
//! stays fast and Docker-independent; CI runs these explicitly in their own job
//! (`cargo test -p bulwarkctl --test e2e -- --ignored`), gated on changes to `rules/` or
//! `crates/bulwark-core/src/collectors/` — see .github/workflows/ci.yml.
//!
//! Deliberately shells out to the `docker` CLI directly (`std::process::Command`) rather than
//! pulling in the `testcontainers` crate: this workspace has no async runtime anywhere else,
//! and `docker build`/`run`/`exec`/`rm` are a stable, well-documented interface that doesn't
//! need a new dependency to get right.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should resolve")
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Kills and removes the fixture container on drop, including on a failed/panicking
/// assertion — a fixture container left running after a failed test run is exactly the kind
/// of manual-cleanup foot-gun containers-over-runner-mutation was chosen to avoid (see
/// docs/guide/architecture.md's testing notes).
struct Container {
    name: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

fn run_fixture(scenario: &str) -> BTreeSet<String> {
    let root = workspace_root();
    let fixture_dir = root.join("tests/e2e/fixtures").join(scenario);
    assert!(
        fixture_dir.is_dir(),
        "no fixture directory at {}",
        fixture_dir.display()
    );

    let image_tag = format!("bulwark-e2e-{scenario}");
    let build = Command::new("docker")
        .args(["build", "-t", &image_tag])
        .arg(&fixture_dir)
        .output()
        .expect("failed to invoke `docker build` — is Docker installed and running?");
    assert!(
        build.status.success(),
        "docker build failed for scenario '{scenario}':\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let container_name = format!("bulwark-e2e-{scenario}-{}", std::process::id());
    let bulwark_bin = env!("CARGO_BIN_EXE_bulwarkctl");
    let rules_dir = root.join("rules");

    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            "-v",
            &format!("{bulwark_bin}:/usr/local/bin/bulwarkctl:ro"),
            "-v",
            &format!("{}:/rules:ro", rules_dir.display()),
            &image_tag,
            "sleep",
            "300",
        ])
        .output()
        .expect("failed to invoke `docker run`");
    assert!(
        run.status.success(),
        "docker run failed for scenario '{scenario}':\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let _container = Container {
        name: container_name.clone(),
    };

    let exec = Command::new("docker")
        .args([
            "exec",
            &container_name,
            "bulwarkctl",
            "scan",
            "--json",
            "--no-persist",
            "--rules-dir",
            "/rules",
        ])
        .output()
        .expect("failed to invoke `docker exec`");
    // `bulwarkctl scan` exits 1/2 when findings exist — that's expected for the weak-config
    // fixtures, not a real failure, so don't assert on exit status; the JSON body is the
    // actual assertion surface below.
    let scan: serde_json::Value = serde_json::from_slice(&exec.stdout).unwrap_or_else(|e| {
        panic!(
            "scenario '{scenario}': `bulwarkctl scan --json` produced invalid JSON: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&exec.stdout),
            String::from_utf8_lossy(&exec.stderr)
        )
    });

    scan["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("scenario '{scenario}': scan JSON had no 'findings' array"))
        .iter()
        .map(|f| {
            f["rule_id"]
                .as_str()
                .unwrap_or_else(|| panic!("scenario '{scenario}': a finding had no rule_id"))
                .to_string()
        })
        .collect()
}

fn read_rule_id_set(scenario: &str, filename: &str) -> BTreeSet<String> {
    let path = workspace_root()
        .join("tests/e2e/fixtures")
        .join(scenario)
        .join(filename);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return BTreeSet::new(), // forbidden-findings.json is optional per fixture
    };
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("scenario '{scenario}': invalid {filename}: {e}"))
}

macro_rules! e2e_scenario {
    ($test_name:ident, $scenario:literal) => {
        #[test]
        #[ignore = "needs Docker; run via `cargo test -p bulwarkctl --test e2e -- --ignored`"]
        fn $test_name() {
            if !docker_available() {
                eprintln!(
                    "skipping '{}': Docker is not available in this environment",
                    $scenario
                );
                return;
            }
            let actual = run_fixture($scenario);
            let expected = read_rule_id_set($scenario, "expected-findings.json");
            let forbidden = read_rule_id_set($scenario, "forbidden-findings.json");

            let missing: Vec<_> = expected.difference(&actual).collect();
            assert!(
                missing.is_empty(),
                "scenario '{}': expected finding(s) {:?} did not appear — actual findings: {:?}",
                $scenario,
                missing,
                actual
            );

            let unexpected: Vec<_> = forbidden.intersection(&actual).collect();
            assert!(
                unexpected.is_empty(),
                "scenario '{}': forbidden finding(s) {:?} appeared — actual findings: {:?}",
                $scenario,
                unexpected,
                actual
            );
        }
    };
}

e2e_scenario!(ssh_weak_config_is_detected, "ssh-weak");
e2e_scenario!(ssh_hardened_config_produces_no_findings, "ssh-hardened");
e2e_scenario!(
    cron_downloader_pipe_to_shell_is_detected,
    "cron-curl-pipe-sh"
);
e2e_scenario!(
    systemd_tunnel_persistence_is_detected,
    "systemd-tunnel-persistence"
);

// ---- agentless remote monitoring over a real sshd ---------------------------------------------

/// Runs this build's `bulwarkctl` against an isolated database and returns (exit code, stdout).
fn ctl(db: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_bulwarkctl"))
        .args(args)
        .env("BULWARK_DB_PATH", db)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bulwarkctl");
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}):\n{s}"))
}

/// The whole remote-monitoring path against a real OpenSSH server, the way a user meets it:
/// first contact refuses an unverified host key and offers its fingerprint; trusting a *wrong*
/// fingerprint writes nothing; trusting the right one lets a password-only account be switched to
/// Bulwark's restricted key (password used once, via stdin); the scan copies the engine over, finds
/// the server's real misconfiguration, and cleans up; and a machine that goes away is reported as
/// unreachable, never as clean. Each of these was first verified by hand and broke in at least one
/// way no mock reproduced (an agent full of keys tripping MaxAuthTries, for one).
#[test]
#[ignore = "needs Docker; run via `cargo test -p bulwarkctl --test e2e -- --ignored`"]
fn remote_monitoring_over_real_ssh() {
    if !docker_available() {
        eprintln!("skipping remote monitoring e2e: Docker is not available");
        return;
    }
    let root = workspace_root();
    let image = "bulwark-e2e-remote-sshd";
    let build = Command::new("docker")
        .args(["build", "-q", "-t", image])
        .arg(root.join("tests/e2e/remote-sshd"))
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("authorized");
    std::fs::create_dir_all(&keys).unwrap();
    // No key is authorized up front: the account is password-only, the case setup-key exists for.
    std::fs::write(keys.join("deploy"), "").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(keys.join("deploy"), std::fs::Permissions::from_mode(0o644)).unwrap();

    let name = format!("bulwark-e2e-remote-{}", std::process::id());
    let _guard = Container { name: name.clone() };
    let run = Command::new("docker")
        .args(["run", "-d", "--name", &name, "-p", "127.0.0.1::22", "-v"])
        .arg(format!("{}:/authorized_keys:ro", keys.display()))
        .arg(image)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let port_out = Command::new("docker")
        .args(["port", &name, "22"])
        .output()
        .unwrap();
    let mapped = String::from_utf8_lossy(&port_out.stdout);
    let port: String = mapped
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .unwrap()
        .trim()
        .to_string();
    for _ in 0..50 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let db = tmp.path().join("state/bulwark.db");
    let (code, _) = ctl(
        &db,
        &[
            "hosts",
            "add",
            "deploy@127.0.0.1",
            "--port",
            &port,
            "--name",
            "web-1",
        ],
        None,
    );
    assert_eq!(code, 0);

    // 1. First contact: refused, with the fingerprint offered for comparison.
    let (_, out) = ctl(&db, &["hosts", "test", "web-1", "--json"], None);
    let report = json(&out);
    assert_eq!(report["ok"], false);
    assert_eq!(report["steps"][1]["problem"]["kind"], "host_key_unknown");
    let offered = report["host_keys"][0]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let real = Command::new("docker")
        .args(["exec", &name, "sh", "-c"])
        .arg(format!(
            "ssh-keygen -lf /etc/ssh/ssh_host_{}_key.pub",
            report["host_keys"][0]["key_type"]
                .as_str()
                .unwrap()
                .to_lowercase()
        ))
        .output()
        .unwrap();
    let real_fp = String::from_utf8_lossy(&real.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    assert_eq!(
        offered, real_fp,
        "the offered fingerprint must be the machine's own"
    );

    // 2. A wrong fingerprint trusts nothing.
    let (code, _) = ctl(
        &db,
        &[
            "hosts",
            "trust",
            "web-1",
            "--fingerprint",
            "SHA256:not-the-key",
            "--json",
        ],
        None,
    );
    assert_ne!(code, 0);
    assert!(!db.with_file_name("known_hosts").exists());

    // 3. The right one does — into Bulwark's own known_hosts.
    let (code, _) = ctl(
        &db,
        &[
            "hosts",
            "trust",
            "web-1",
            "--fingerprint",
            &offered,
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0);
    let (_, out) = ctl(&db, &["hosts", "test", "web-1", "--json"], None);
    assert_eq!(json(&out)["steps"][1]["problem"]["kind"], "auth_failed");

    // 4. Password once → dedicated restricted key; a wrong password changes nothing.
    let (code, _) = ctl(
        &db,
        &["hosts", "setup-key", "web-1", "--password-stdin", "--json"],
        Some("wrong-password\n"),
    );
    assert_ne!(code, 0);
    let (code, out) = ctl(
        &db,
        &["hosts", "setup-key", "web-1", "--password-stdin", "--json"],
        Some("bulwark-e2e-only\n"),
    );
    assert_eq!(code, 0, "{out}");
    assert!(json(&out)["public_key"]
        .as_str()
        .unwrap()
        .starts_with("restrict ssh-ed25519 "));
    let (_, out) = ctl(&db, &["hosts", "test", "web-1", "--json"], None);
    let report = json(&out);
    assert_eq!(report["ok"], true, "{out}");
    assert!(report["advice"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == "key" && a["level"] == "good"));

    // 5. Scan: engine copied in, real finding found, nothing left behind.
    let (_, out) = ctl(
        &db,
        &["hosts", "scan", "web-1", "--json", "--no-notify"],
        None,
    );
    let results = json(&out);
    assert_eq!(results[0]["ok"], true, "{out}");
    let (_, out) = ctl(&db, &["hosts", "show", "web-1", "--json"], None);
    let ids: BTreeSet<String> = json(&out)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains("BLWK-SSH-001"),
        "password auth is on in the image: {ids:?}"
    );
    let leftovers = Command::new("docker")
        .args([
            "exec",
            &name,
            "sh",
            "-c",
            "ls /tmp | grep -c bulwark || true",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&leftovers.stdout).trim(), "0");

    // 6. Gone: reported as a failure, never as a clean scan.
    let _ = Command::new("docker")
        .args(["stop", "-t", "1", &name])
        .output();
    let (code, out) = ctl(
        &db,
        &["hosts", "scan", "web-1", "--json", "--no-notify"],
        None,
    );
    assert_eq!(code, 3);
    let r = json(&out);
    assert_eq!(r[0]["ok"], false);
    let kind = r[0]["machine"]["problem"]["kind"].as_str().unwrap();
    assert!(matches!(kind, "unreachable" | "timeout"), "{kind}");
}

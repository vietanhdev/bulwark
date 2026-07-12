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

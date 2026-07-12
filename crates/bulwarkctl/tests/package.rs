//! Built-package tests: install the real `.deb` into a clean Ubuntu container and prove the
//! *installed* artifact works — the binary runs, and the decoders/rule packs it ships actually
//! resolve from their installed `/usr/share/bulwark/...` locations (not a dev-mode workspace
//! walk). This is the layer the e2e tests don't cover: they mount a freshly-built binary and the
//! source rule tree, so they'd pass even if the packaging dropped an asset. A packaging
//! regression — the exact class of bug where `cargo generate-rpm`'s asset list drifted out of
//! sync with the `.deb` and shipped a CLI that failed on every run — only shows up when you
//! install what was actually packaged.
//!
//! Requires a pre-built `.deb` at `target/debian/*.deb` (build it with `cargo deb -p bulwarkctl`
//! after a release build). Skips cleanly when Docker or the `.deb` is absent, so plain
//! `cargo test --workspace` stays green everywhere. `#[ignore]`d for the same reason as the e2e
//! suite — CI runs it explicitly after building the package.

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

/// The newest `.deb` cargo-deb produced, if any. Named like `bulwarkctl_0.2.0-1_amd64.deb`.
fn find_deb() -> Option<PathBuf> {
    let dir = workspace_root().join("target/debian");
    let mut debs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("deb"))
        .collect();
    debs.sort();
    debs.pop()
}

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

/// Runs `sh -c <script>` inside the container, returning (success, stdout, stderr).
fn exec(name: &str, script: &str) -> (bool, String, String) {
    let out = Command::new("docker")
        .args(["exec", name, "sh", "-c", script])
        .output()
        .expect("docker exec failed to launch");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "needs Docker + a built .deb; run via `cargo deb -p bulwarkctl` then `cargo test -p bulwarkctl --test package -- --ignored`"]
fn installed_deb_runs_config_and_log_scans() {
    if !docker_available() {
        eprintln!("skipping: Docker is not available in this environment");
        return;
    }
    let Some(deb) = find_deb() else {
        eprintln!(
            "skipping: no .deb found under target/debian — run `cargo deb -p bulwarkctl` first"
        );
        return;
    };

    let name = format!("bulwark-pkg-{}", std::process::id());
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-v",
            &format!("{}:/pkg.deb:ro", deb.display()),
            "ubuntu:24.04",
            "sleep",
            "600",
        ])
        .output()
        .expect("docker run failed to launch");
    assert!(
        run.status.success(),
        "docker run failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let _cleanup = Container { name: name.clone() };

    // Install the package exactly as a user would — apt resolves the `$auto` deps.
    let (ok, _out, err) = exec(
        &name,
        "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq /pkg.deb",
    );
    assert!(ok, "installing the .deb failed:\n{err}");

    // 1) The binary runs and reports the current version. Read the expected value from
    //    `CARGO_PKG_VERSION` rather than hardcoding it: a literal here drifts every release (it
    //    was pinned at "0.2.0" through the 0.2.1 bump, silently failing this ignored test), and
    //    the whole point of the check is that the *packaged* binary matches the *source* version.
    let expected = env!("CARGO_PKG_VERSION");
    let (ok, ver, err) = exec(&name, "bulwarkctl --version");
    assert!(ok, "`bulwarkctl --version` failed:\n{err}");
    assert!(
        ver.contains(expected),
        "expected version {expected}, got: {ver:?}"
    );

    // 2) The packaged asset trees actually shipped to their installed locations.
    let (ok, _o, err) = exec(
        &name,
        "test -f /usr/share/bulwark/decoders/sshd.yaml && \
         ls /usr/share/bulwark/log-rules/ssh-remote-access/*.yaml >/dev/null && \
         ls /usr/share/bulwark/rules/ssh-remote-access/*.yaml >/dev/null",
    );
    assert!(
        ok,
        "packaged decoders/log-rules/rules missing from /usr/share/bulwark:\n{err}"
    );

    // 3) The log pipeline works end-to-end from the *installed* paths (no --*-dir flags, so this
    //    exercises the `/usr/share/bulwark/{decoders,log-rules}` fallback resolution): a
    //    brute-force burst must raise BLWK-LOG-SSH-001.
    let make_log = "for i in 0 1 2 3 4 5 6 7; do \
        printf 'Jul 12 09:15:0%d h sshd[1]: Failed password for root from 203.0.113.7 port 4%d ssh2\\n' \"$i\" \"$i\"; \
        done > /tmp/auth.log";
    let (ok, findings, err) = exec(
        &name,
        &format!("{make_log}; bulwarkctl logs scan --from-file /tmp/auth.log --no-persist --json"),
    );
    assert!(ok || !findings.is_empty(), "`logs scan` failed:\n{err}");
    let parsed: serde_json::Value =
        serde_json::from_str(&findings).expect("logs scan should emit valid JSON");
    let ids: Vec<&str> = parsed["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    assert!(
        ids.contains(&"BLWK-LOG-SSH-001"),
        "installed package's log pipeline did not detect the brute-force; findings: {ids:?}"
    );

    // 4) The config scanner also runs from the installed rule pack.
    let (_ok, config_json, err) = exec(&name, "bulwarkctl scan --no-persist --json");
    assert!(
        !config_json.is_empty(),
        "`bulwarkctl scan --json` produced no output:\n{err}"
    );
    serde_json::from_str::<serde_json::Value>(&config_json)
        .expect("config scan should emit valid JSON from the installed rule pack");
}

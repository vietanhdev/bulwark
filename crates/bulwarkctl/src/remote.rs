//! Remote scanning over SSH — `bulwarkctl scan --ssh user@host`.
//!
//! This lives in the CLI front-door, **not** in `bulwark-core`: the core library has a hard
//! no-network-calls invariant (architecture doc §10, the "fully local, no telemetry" claim depends
//! on it), so anything that reaches across the network belongs here. The engine itself is never
//! aware a scan happened on another machine; we simply run the *same* `bulwarkctl scan --json` over
//! there and deserialize its stdout back into a [`ScanRun`] — exactly the round-trip the GUI already
//! relies on for its `pkexec` privileged path (see `models::ScanRun`'s doc comment).
//!
//! Transport is the **system `ssh`/`scp`**, shelled out to rather than a bundled SSH library. That
//! is deliberate: it reuses the operator's existing `~/.ssh/config`, agent, `known_hosts`, jump
//! hosts, and multiplexing for free, and it keeps a security tool from reimplementing SSH auth. The
//! host spec is always passed as its own argv element to `ssh`, never interpolated into a shell
//! string, so there is no command-injection surface through the target.
//!
//! Bootstrap model ("prefer installed, else push"):
//!   1. `command -v bulwarkctl || command -v bulwark` on the remote — if a binary is installed, run
//!      it in place (it resolves its own `/usr/share/bulwark/rules`).
//!   2. Otherwise verify the remote CPU arch matches ours (`uname -m`), `scp` this binary and the
//!      local rule pack into a fresh `mktemp -d`, run from there with an explicit `--rules-dir`, and
//!      `rm -rf` the temp dir afterwards.

use anyhow::{Context, Result};
use bulwark_core::ScanRun;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Everything needed to reach one remote host. `spec` is the raw `user@host` (or a `Host` alias
/// from `~/.ssh/config`) — it is handed to `ssh` verbatim as a single argument.
pub struct RemoteTarget {
    pub spec: String,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    /// Extra `-o Key=Value` options, passed straight through to both `ssh` and `scp`.
    pub ssh_opts: Vec<String>,
}

impl RemoteTarget {
    /// Base `ssh` argv (options only, no target, no remote command). `-o BatchMode` is *not* forced:
    /// a first-time password or key-passphrase prompt should still reach the operator's terminal.
    fn ssh_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(id) = &self.identity {
            a.push("-i".into());
            a.push(id.display().to_string());
        }
        for o in &self.ssh_opts {
            a.push("-o".into());
            a.push(o.clone());
        }
        a
    }

    /// Base `scp` argv. Same options as `ssh` except the port flag is capital `-P` (an scp quirk),
    /// and `-r` for the recursive rule-pack copy.
    fn scp_args(&self) -> Vec<String> {
        let mut a = vec!["-r".to_string()];
        if let Some(p) = self.port {
            a.push("-P".into());
            a.push(p.to_string());
        }
        if let Some(id) = &self.identity {
            a.push("-i".into());
            a.push(id.display().to_string());
        }
        for o in &self.ssh_opts {
            a.push("-o".into());
            a.push(o.clone());
        }
        a
    }

    /// Run one command on the remote and return its captured [`std::process::Output`]. The remote
    /// command is a single shell string executed by the login shell over there.
    fn run(&self, remote_cmd: &str) -> Result<std::process::Output> {
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args());
        cmd.arg(&self.spec);
        cmd.arg(remote_cmd);
        cmd.output()
            .with_context(|| format!("failed to spawn ssh to {}", self.spec))
    }
}

/// Single-quote a string for safe inclusion in a remote `/bin/sh` command line. Values that reach
/// the remote shell (profile `needs` tags, temp paths) go through here so a stray space or shell
/// metacharacter can never break out of its argument.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Map Rust's `std::env::consts::ARCH` onto the `uname -m` string a Linux host reports, so a pushed
/// binary is only ever run where it can actually execute. Returns the set of `uname -m` values that
/// are compatible with the locally-built binary.
fn compatible_uname_m() -> &'static [&'static str] {
    match std::env::consts::ARCH {
        "x86_64" => &["x86_64", "amd64"],
        "aarch64" => &["aarch64", "arm64"],
        "arm" => &["armv7l", "armv6l", "arm"],
        "x86" => &["i686", "i386", "x86"],
        _ => &[],
    }
}

/// Outcome metadata worth surfacing to the caller alongside the [`ScanRun`]: how the remote engine
/// was obtained, so the user knows whether a binary was copied onto their host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEngine {
    /// An already-installed `bulwarkctl`/`bulwark` was invoked in place.
    Installed(String),
    /// This binary + rule pack were pushed to the given temp dir and removed afterwards.
    Pushed { remote_dir: String, arch: String },
}

/// Result of a remote scan: the deserialized run plus how we ran it.
pub struct RemoteScan {
    pub scan: ScanRun,
    pub engine: RemoteEngine,
}

/// Run a scan on `target` and bring the results home. `local_binary` is the path to *this*
/// `bulwarkctl` (used only if a push is needed); `rules_dir` is the local rule pack to push.
pub fn run_remote_scan(
    target: &RemoteTarget,
    privileged: bool,
    needs: &[String],
    local_binary: &Path,
    rules_dir: &Path,
) -> Result<RemoteScan> {
    // 1. Prefer an installed binary. `command -v` prints the resolved path and exits 0 when found.
    let engine = match detect_installed(target)? {
        Some(path) => RemoteEngine::Installed(path),
        None => push_binary(target, local_binary, rules_dir)?,
    };

    // 2. Build and run the remote scan. `--no-persist` because history for the remote host is kept
    //    locally in an isolated per-host DB (see `main.rs`), never written on the remote itself.
    let run_result = run_scan_cmd(target, &engine, privileged, needs);

    // 3. Always clean up a pushed temp dir, even if the scan itself failed — we never want to leave
    //    a copied binary behind. Cleanup errors are reported but don't mask the scan's own result.
    if let RemoteEngine::Pushed { remote_dir, .. } = &engine {
        if let Err(e) = cleanup(target, remote_dir) {
            eprintln!("warning: failed to remove remote temp dir {remote_dir}: {e}");
        }
    }

    let scan = run_result?;
    Ok(RemoteScan { scan, engine })
}

/// `command -v bulwarkctl || command -v bulwark` — returns the first installed path, if any.
fn detect_installed(target: &RemoteTarget) -> Result<Option<String>> {
    let out = target.run("command -v bulwarkctl 2>/dev/null || command -v bulwark 2>/dev/null")?;
    // A non-zero exit here just means "neither found" (the `||` chain fails) — not an ssh error.
    // Distinguish a genuine connection failure by looking for the classic ssh diagnostics.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let path = stdout.lines().next().unwrap_or("").trim().to_string();
    if !path.is_empty() {
        return Ok(Some(path));
    }
    // Nothing installed. Confirm we could actually reach the host before deciding to push, so a
    // dead connection surfaces as a connection error rather than a confusing "arch mismatch".
    if !out.status.success() && looks_like_ssh_failure(&out) {
        anyhow::bail!(
            "could not connect to {} over ssh:\n{}",
            target.spec,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(None)
}

/// Heuristic: did ssh itself fail to connect/authenticate, as opposed to the remote command exiting
/// non-zero? ssh reports connection/auth trouble with recognizable phrases on stderr.
fn looks_like_ssh_failure(out: &std::process::Output) -> bool {
    let e = String::from_utf8_lossy(&out.stderr).to_lowercase();
    e.contains("permission denied")
        || e.contains("connection refused")
        || e.contains("could not resolve")
        || e.contains("connection timed out")
        || e.contains("no route to host")
        || e.contains("host key verification failed")
        || e.contains("operation timed out")
}

/// Verify arch compatibility, create a remote temp dir, and `scp` the binary + rule pack into it.
fn push_binary(
    target: &RemoteTarget,
    local_binary: &Path,
    rules_dir: &Path,
) -> Result<RemoteEngine> {
    // Arch gate: a locally-built x86_64 binary must never be dropped onto an aarch64 box and run.
    let arch_out = target.run("uname -m")?;
    if !arch_out.status.success() {
        anyhow::bail!(
            "could not determine remote architecture (uname -m) on {}:\n{}",
            target.spec,
            String::from_utf8_lossy(&arch_out.stderr).trim()
        );
    }
    let remote_arch = String::from_utf8_lossy(&arch_out.stdout).trim().to_string();
    let compat = compatible_uname_m();
    if !compat.contains(&remote_arch.as_str()) {
        anyhow::bail!(
            "remote {} is {remote_arch}, but this bulwarkctl was built for {} — install bulwark on \
             the remote host (any matching package) and re-run, or run from a {remote_arch} machine",
            target.spec,
            std::env::consts::ARCH
        );
    }

    if !local_binary.exists() {
        anyhow::bail!(
            "cannot locate the local bulwarkctl binary to push (looked at {}) — install bulwark on \
             the remote host instead",
            local_binary.display()
        );
    }
    if !rules_dir.is_dir() {
        anyhow::bail!("local rules dir {} not found to push", rules_dir.display());
    }

    // `mktemp -d` gives a private (0700) dir with an unpredictable name — no symlink/pre-created
    // path races, and nothing to collide with a concurrent run.
    let mk = target.run("mktemp -d /tmp/bulwark.XXXXXX")?;
    if !mk.status.success() {
        anyhow::bail!(
            "could not create a temp dir on {}:\n{}",
            target.spec,
            String::from_utf8_lossy(&mk.stderr).trim()
        );
    }
    let remote_dir = String::from_utf8_lossy(&mk.stdout).trim().to_string();
    if remote_dir.is_empty() {
        anyhow::bail!("mktemp on {} returned an empty path", target.spec);
    }

    // scp the binary, then the rule pack.
    scp_to(target, local_binary, &format!("{remote_dir}/bulwarkctl"))?;
    scp_to(target, rules_dir, &format!("{remote_dir}/rules"))?;
    // scp does not preserve the executable bit reliably across all platforms; set it explicitly.
    let chmod = target.run(&format!("chmod 0755 {}/bulwarkctl", sh_quote(&remote_dir)))?;
    if !chmod.status.success() {
        anyhow::bail!(
            "could not chmod the pushed binary on {}:\n{}",
            target.spec,
            String::from_utf8_lossy(&chmod.stderr).trim()
        );
    }

    Ok(RemoteEngine::Pushed {
        remote_dir,
        arch: remote_arch,
    })
}

/// `scp <local> <target>:<remote>` with the target's transport options.
fn scp_to(target: &RemoteTarget, local: &Path, remote: &str) -> Result<()> {
    let mut cmd = Command::new("scp");
    cmd.args(target.scp_args());
    cmd.arg(local);
    cmd.arg(format!("{}:{remote}", target.spec));
    let out = cmd
        .output()
        .with_context(|| format!("failed to spawn scp to {}", target.spec))?;
    if !out.status.success() {
        anyhow::bail!(
            "scp of {} to {} failed:\n{}",
            local.display(),
            target.spec,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Build the remote `scan --json` command, run it, and deserialize stdout into a [`ScanRun`].
fn run_scan_cmd(
    target: &RemoteTarget,
    engine: &RemoteEngine,
    privileged: bool,
    needs: &[String],
) -> Result<ScanRun> {
    let (bin, rules_flag) = match engine {
        RemoteEngine::Installed(path) => (sh_quote(path), String::new()),
        RemoteEngine::Pushed { remote_dir, .. } => (
            format!("{}/bulwarkctl", sh_quote(remote_dir)),
            format!(" --rules-dir {}/rules", sh_quote(remote_dir)),
        ),
    };

    let mut remote_cmd = String::new();
    if privileged {
        // Non-interactive sudo: a remote privileged scan needs root, but we are capturing stdout
        // (the JSON), so we can't hand sudo a TTY to prompt on. `-n` fails fast with a clear message
        // if passwordless sudo isn't configured, rather than hanging.
        remote_cmd.push_str("sudo -n ");
    }
    remote_cmd.push_str(&bin);
    remote_cmd.push_str(" scan --json --no-persist");
    remote_cmd.push_str(&rules_flag);
    if privileged {
        remote_cmd.push_str(" --privileged");
    }
    if !needs.is_empty() {
        let joined = needs
            .iter()
            .map(|n| sh_quote(n))
            .collect::<Vec<_>>()
            .join(",");
        remote_cmd.push_str(&format!(" --needs {joined}"));
    }

    let out = target.run(&remote_cmd)?;

    // The scan process deliberately exits 1/2 when it finds medium/critical issues (severity → exit
    // code, so cron can gate on it). A non-zero status is therefore *expected* on a successful run.
    // The reliable success signal is whether stdout deserializes into a ScanRun — parse first, and
    // only fall back to exit code + stderr for the error message when it doesn't.
    let stdout = String::from_utf8_lossy(&out.stdout);
    match serde_json::from_str::<ScanRun>(stdout.trim()) {
        Ok(scan) => Ok(scan),
        Err(parse_err) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if privileged && stderr.contains("sudo") {
                anyhow::bail!(
                    "remote privileged scan needs passwordless sudo on {} (sudo -n failed):\n{}",
                    target.spec,
                    stderr.trim()
                );
            }
            anyhow::bail!(
                "remote scan on {} did not return a parseable result (exit {:?}).\nstderr:\n{}\n\
                 (parse error: {parse_err})",
                target.spec,
                out.status.code(),
                stderr.trim()
            );
        }
    }
}

/// `rm -rf` the pushed temp dir. The path came from our own `mktemp` (always under `/tmp/bulwark.`),
/// so this can only ever remove a directory we created.
fn cleanup(target: &RemoteTarget, remote_dir: &str) -> Result<()> {
    // Belt-and-braces: refuse to rm anything that isn't the shape we created, in case `remote_dir`
    // was somehow corrupted — never send `rm -rf` at a short or unexpected path.
    if !remote_dir.starts_with("/tmp/bulwark.") || remote_dir.len() < "/tmp/bulwark.".len() + 3 {
        anyhow::bail!("refusing to clean up unexpected remote path {remote_dir}");
    }
    let out = target.run(&format!("rm -rf {}", sh_quote(remote_dir)))?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("simple"), "'simple'");
        assert_eq!(sh_quote("a b"), "'a b'");
        // A quote in the value must not let anything escape the quoting.
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(sh_quote("; rm -rf /"), "'; rm -rf /'");
    }

    #[test]
    fn arch_map_covers_common_hosts() {
        // Whatever this test binary was built as, its own uname-m string must be considered
        // compatible — otherwise a same-arch push would be wrongly refused.
        let compat = compatible_uname_m();
        // At least one mapping exists for the tier-1 targets.
        assert!(!compatible_uname_m().is_empty() || std::env::consts::ARCH == "unknown");
        // amd64/arm64 aliases (what some BSD-ish or container unames report) are accepted.
        if std::env::consts::ARCH == "x86_64" {
            assert!(compat.contains(&"amd64"));
        }
    }

    #[test]
    fn ssh_and_scp_args_translate_port_flag() {
        let t = RemoteTarget {
            spec: "user@host".into(),
            port: Some(2222),
            identity: Some(PathBuf::from("/k")),
            ssh_opts: vec!["StrictHostKeyChecking=accept-new".into()],
        };
        let ssh = t.ssh_args();
        assert!(ssh.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(ssh.windows(2).any(|w| w == ["-i", "/k"]));
        let scp = t.scp_args();
        // scp uses capital -P for the port.
        assert!(scp.windows(2).any(|w| w == ["-P", "2222"]));
        assert!(scp.contains(&"-r".to_string()));
    }

    #[test]
    fn cleanup_refuses_unexpected_paths() {
        let t = RemoteTarget {
            spec: "user@host".into(),
            port: None,
            identity: None,
            ssh_opts: vec![],
        };
        // These never even attempt an ssh call — the guard rejects them first.
        assert!(cleanup(&t, "/").is_err());
        assert!(cleanup(&t, "/tmp").is_err());
        assert!(cleanup(&t, "/home/user").is_err());
        assert!(cleanup(&t, "/tmp/bulwark.").is_err());
    }
}

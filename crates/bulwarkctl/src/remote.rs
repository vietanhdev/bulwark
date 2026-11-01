//! Remote scanning over SSH — `bulwarkctl scan --ssh user@host` and the `hosts` commands.
//!
//! This lives in the CLI front-door, **not** in `bulwark-core`: the core library has a hard
//! no-network-calls invariant (architecture doc §10, the "fully local, no telemetry" claim depends
//! on it), so anything that reaches across the network belongs here. The engine itself is never
//! aware a scan happened on another machine; we simply run the *same* `bulwarkctl scan --json` over
//! there and deserialize its stdout back into a [`ScanRun`] — exactly the round-trip the GUI already
//! relies on for its `pkexec` privileged path (see `models::ScanRun`'s doc comment). The data model,
//! validation, error classification and scheduling rules shared with the GUI are in
//! `bulwark_core::fleet`; this module is only the transport.
//!
//! Transport is the **system `ssh`/`scp`**, shelled out to rather than a bundled SSH library. That
//! is deliberate: it reuses the operator's existing `~/.ssh/config`, agent, `known_hosts`, jump
//! hosts, and multiplexing for free, and it keeps a security tool from reimplementing SSH auth. The
//! host spec is always passed as its own argv element, after `--`, and validated so it can never be
//! read as an option.
//!
//! Two modes:
//!   * **interactive** (`scan --ssh` from a terminal): ssh may prompt for a passphrase or a first
//!     host-key confirmation on the user's TTY, exactly as plain `ssh` would.
//!   * **unattended** (`hosts scan`, the GUI's scheduler): `BatchMode=yes` so nothing can ever block
//!     on a prompt nobody will answer, `StrictHostKeyChecking=yes` so an unknown or changed host key
//!     is refused rather than silently accepted, connect/keep-alive timeouts, and a hard deadline on
//!     every command. Host keys the user approved inside Bulwark (`hosts trust`) live in Bulwark's
//!     own `known_hosts`, consulted *in addition to* the user's — Bulwark never edits `~/.ssh`.
//!
//! Bootstrap model ("prefer installed, else push"):
//!   1. One probe round-trip reports whether `bulwarkctl`/`bulwark` is installed (and its version),
//!      the CPU arch, the OS, and — when root checks were asked for — whether `sudo -n` works.
//!   2. If installed, run it in place (it resolves its own `/usr/share/bulwark/rules`).
//!   3. Otherwise verify the arch matches ours, `scp` this binary and the local rule pack into a
//!      fresh `mktemp -d`, run from there with an explicit `--rules-dir`, and `rm -rf` it afterwards.

use anyhow::{Context, Result};
use bulwark_core::fleet::{self, RemoteErrorKind};
use bulwark_core::ScanRun;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// Deadline for a quick command (probe, mktemp, chmod, cleanup, keyscan).
const QUICK_TIMEOUT: Duration = Duration::from_secs(45);
/// Deadline for copying the binary and rule pack over a slow link.
const COPY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Deadline for the scan itself. A normal scan takes seconds; this only bounds a hung one.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// A classified failure. Carried inside `anyhow::Error` so callers that care (the `hosts`
/// commands) can recover the kind with [`kind_of`], and callers that don't just print it.
#[derive(Debug)]
pub struct RemoteError {
    pub kind: RemoteErrorKind,
    pub message: String,
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.title(), self.message)
    }
}

impl std::error::Error for RemoteError {}

fn fail<T>(kind: RemoteErrorKind, message: impl Into<String>) -> Result<T> {
    Err(RemoteError {
        kind,
        message: message.into(),
    }
    .into())
}

/// The classified kind of an error from this module; [`RemoteErrorKind::Other`] for anything else.
pub fn kind_of(err: &anyhow::Error) -> RemoteErrorKind {
    err.downcast_ref::<RemoteError>()
        .map(|e| e.kind)
        .unwrap_or(RemoteErrorKind::Other)
}

/// The raw message of an error from this module, without the kind's title prefix.
pub fn message_of(err: &anyhow::Error) -> String {
    err.downcast_ref::<RemoteError>()
        .map(|e| e.message.clone())
        .unwrap_or_else(|| format!("{err:#}"))
}

/// Everything needed to reach one remote host. `spec` is the raw `user@host` (or a `Host` alias
/// from `~/.ssh/config`) — it is handed to `ssh` verbatim as a single argument.
pub struct RemoteTarget {
    pub spec: String,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    /// Extra `-o Key=Value` options, passed straight through to both `ssh` and `scp`. Only the
    /// interactive `scan --ssh` path accepts these; registered machines never carry any (see the
    /// `remote_hosts` migration for why).
    pub ssh_opts: Vec<String>,
    /// ProxyJump chain (`-J`).
    pub jump: Option<String>,
    /// Never prompt; refuse unknown host keys; time out. See the module docs.
    pub unattended: bool,
    /// Bulwark's own known_hosts file, consulted in addition to the user's.
    pub known_hosts: Option<PathBuf>,
}

impl RemoteTarget {
    pub fn interactive(
        spec: String,
        port: Option<u16>,
        identity: Option<PathBuf>,
        ssh_opts: Vec<String>,
    ) -> Self {
        RemoteTarget {
            spec,
            port,
            identity,
            ssh_opts,
            jump: None,
            unattended: false,
            known_hosts: None,
        }
    }

    /// The unattended target for a registered machine.
    pub fn for_host(host: &fleet::RemoteHost, known_hosts: &Path) -> Self {
        RemoteTarget {
            spec: host.spec.clone(),
            port: host.port,
            identity: host
                .identity_file
                .as_deref()
                .map(|p| PathBuf::from(fleet::expand_tilde(p))),
            ssh_opts: Vec::new(),
            jump: host.jump_host.clone(),
            unattended: true,
            known_hosts: Some(known_hosts.to_path_buf()),
        }
    }

    fn validate(&self) -> Result<()> {
        if let Err(e) = fleet::validate_spec(&self.spec) {
            return fail(RemoteErrorKind::InvalidTarget, e);
        }
        if let Some(id) = &self.identity {
            if id.as_os_str().to_string_lossy().starts_with('-') {
                return fail(
                    RemoteErrorKind::InvalidTarget,
                    "key path can't start with '-'",
                );
            }
        }
        if let Some(j) = &self.jump {
            if let Err(e) = fleet::validate_jump(j) {
                return fail(RemoteErrorKind::InvalidTarget, e);
            }
        }
        Ok(())
    }

    pub fn ssh_command_line(&self) -> String {
        fleet::ssh_command_line(
            &self.spec,
            self.port,
            self.identity
                .as_deref()
                .map(|p| p.to_str().unwrap_or_default()),
            self.jump.as_deref(),
        )
    }

    /// `-o` options shared by `ssh`, `scp` (and, where meaningful, `ssh-keyscan`).
    fn common_opts(&self) -> Vec<String> {
        let mut a = Vec::new();
        if let Some(j) = &self.jump {
            a.push("-J".into());
            a.push(j.clone());
        }
        if let Some(id) = &self.identity {
            a.push("-i".into());
            a.push(id.display().to_string());
            // Offer *only* this key. Without it ssh tries every key in the agent first, and a
            // server's MaxAuthTries (default 6) cuts the connection with "Too many authentication
            // failures" before the named key is ever offered — found by testing against a real
            // sshd with a populated agent, which no mock reproduces.
            a.push("-o".into());
            a.push("IdentitiesOnly=yes".into());
        }
        if self.unattended {
            for o in [
                "BatchMode=yes",
                "StrictHostKeyChecking=yes",
                "ConnectTimeout=15",
                "ServerAliveInterval=15",
                "ServerAliveCountMax=3",
            ] {
                a.push("-o".into());
                a.push(o.into());
            }
        }
        if let Some(kh) = self.known_hosts.as_deref().filter(|p| p.exists()) {
            // GlobalKnownHostsFile, not UserKnownHostsFile: overriding the latter would replace a
            // custom UserKnownHostsFile the user set in ~/.ssh/config. The system defaults are
            // restated so they keep working. Quoted, so a path with spaces stays one entry.
            a.push("-o".into());
            a.push(format!(
                "GlobalKnownHostsFile=\"/etc/ssh/ssh_known_hosts\" \"/etc/ssh/ssh_known_hosts2\" \"{}\"",
                kh.display()
            ));
        }
        for o in &self.ssh_opts {
            a.push("-o".into());
            a.push(o.clone());
        }
        a
    }

    /// Base `ssh` argv (options only, no target, no remote command).
    fn ssh_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        a.extend(self.common_opts());
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
        a.extend(self.common_opts());
        a
    }

    /// Run one command on the remote and return its captured output. The remote command is a
    /// single shell string executed by the login shell over there. An ssh-level failure (exit 255)
    /// is classified and returned as an error; the remote command's own exit status is the
    /// caller's to interpret.
    fn run(&self, remote_cmd: &str, timeout: Duration) -> Result<Output> {
        self.validate()?;
        let mut cmd = bulwark_core::sandbox::host_command("ssh");
        cmd.args(self.ssh_args());
        cmd.arg("--").arg(&self.spec).arg(remote_cmd);
        let out = run_captured(cmd, timeout, "ssh", &self.spec, self.unattended)?;
        check_ssh_failure(&out, &self.spec)?;
        Ok(out)
    }
}

/// Spawn, capture stdout/stderr, and enforce a deadline. A missing program becomes
/// [`RemoteErrorKind::SshMissing`]; a blown deadline kills the child and becomes `Timeout`.
fn run_captured(
    mut cmd: Command,
    timeout: Duration,
    program: &str,
    spec: &str,
    unattended: bool,
) -> Result<Output> {
    // Unattended runs get no stdin at all, so nothing can wait on it. Interactive runs inherit the
    // terminal so a passphrase prompt (which ssh reads from /dev/tty anyway) behaves normally.
    cmd.stdin(if unattended {
        Stdio::null()
    } else {
        Stdio::inherit()
    });
    // Windows' bundled OpenSSH hangs whenever one of its standard streams is a pipe or the NUL
    // device (verified on Windows 11): a refused port with stderr on a pipe, and an authenticated
    // session with stdout on a pipe, both run until killed — while the same commands with every
    // stream on a plain file finish in two seconds. Every remote check from Windows would then
    // time out and be misreported as "took too long". So on Windows all three streams are files in
    // a private temporary folder, read back once the process has exited; elsewhere they are pipes.
    #[cfg(windows)]
    let err_file = {
        /// Removes the stderr file's folder however this function returns.
        struct TempDir(PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = TempDir(private_temp_dir()?);
        let path = dir.0.join("stderr.txt");
        cmd.stderr(Stdio::from(std::fs::File::create(&path)?));
        let out_path = dir.0.join("stdout.txt");
        cmd.stdout(Stdio::from(std::fs::File::create(&out_path)?));
        if unattended {
            let empty = dir.0.join("stdin.txt");
            std::fs::File::create(&empty)?;
            cmd.stdin(Stdio::from(std::fs::File::open(&empty)?));
        }
        (dir, path, out_path)
    };
    #[cfg(not(windows))]
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return fail(
                RemoteErrorKind::SshMissing,
                format!("`{program}` was not found on this computer"),
            )
        }
        Err(e) => return Err(e).with_context(|| format!("failed to start {program} for {spec}")),
    };
    let Some(out) = crate::proc::wait_with_deadline(&mut child, timeout)? else {
        return fail(
            RemoteErrorKind::Timeout,
            format!(
                "{program} to {spec} did not finish within {}s",
                timeout.as_secs()
            ),
        );
    };
    // On Windows the streams went to files (see above); read them now that ssh has exited.
    #[cfg(windows)]
    let out = Output {
        status: out.status,
        stdout: std::fs::read(&err_file.2).unwrap_or_default(),
        stderr: std::fs::read(&err_file.1).unwrap_or_default(),
    };
    Ok(out)
}

/// ssh exits 255 for its own failures (connect, auth, host key) and otherwise passes through the
/// remote command's status. Classify the former.
fn check_ssh_failure(out: &Output, spec: &str) -> Result<()> {
    if out.status.code() != Some(255) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let msg = last_meaningful_lines(&stderr);
    match fleet::classify_ssh_stderr(&stderr) {
        Some(kind) => fail(kind, msg),
        None => fail(
            RemoteErrorKind::Other,
            format!("ssh to {spec} failed: {msg}"),
        ),
    }
}

/// The useful tail of an ssh stderr — the `@@@@` banner and blank lines dropped, at most 3 lines.
fn last_meaningful_lines(s: &str) -> String {
    let lines: Vec<&str> = s
        .lines()
        .map(str::trim)
        // `@@@` is the host-key-changed banner; `**` is the post-quantum key-exchange warning
        // older servers (Windows OpenSSH) trigger on every connection. Neither is the error.
        .filter(|l| !l.is_empty() && !l.starts_with("@@@") && !l.starts_with("**"))
        .collect();
    let n = lines.len();
    lines[n.saturating_sub(3)..].join(" ")
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

// ---- probe --------------------------------------------------------------------------------------

/// What one round-trip learned about the remote machine.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Probe {
    /// Path of an installed Bulwark CLI, if one answered `--version` as bulwarkctl.
    pub bin: Option<String>,
    pub version: Option<String>,
    pub arch: String,
    pub os_id: String,
    pub os_like: String,
    pub os_pretty: String,
    /// Only checked when root checks were asked for.
    pub sudo_ok: Option<bool>,
    /// sudo there grants *everything* without a password, not just the scanner.
    pub sudo_blanket: bool,
    /// The account we signed in as.
    pub user: String,
    /// `uname -s` / `uname -r`, and the macOS version when there is one.
    pub kernel: String,
    pub release: String,
    pub mac_version: String,
}

impl Probe {
    /// A short key for the OS icon and a readable name: `("ubuntu", "Ubuntu 24.04.1 LTS")`,
    /// `("macos", "macOS 15.6")`, `("wsl", "Ubuntu 24.04 (WSL)")`, …
    pub fn os(&self) -> (String, String) {
        if self.is_windows() {
            let name = if self.os_pretty.is_empty() {
                "Windows".to_string()
            } else {
                self.os_pretty.clone()
            };
            return ("windows".into(), name);
        }
        if self.kernel.eq_ignore_ascii_case("darwin") {
            let name = if self.mac_version.is_empty() {
                "macOS".to_string()
            } else {
                format!("macOS {}", self.mac_version)
            };
            return ("macos".into(), name);
        }
        let pretty = if self.os_pretty.is_empty() {
            "Linux".to_string()
        } else {
            self.os_pretty.clone()
        };
        if self.release.to_ascii_lowercase().contains("microsoft") {
            return ("wsl".into(), format!("{pretty} (WSL)"));
        }
        let known = [
            "ubuntu",
            "debian",
            "fedora",
            "arch",
            "alpine",
            "rhel",
            "centos",
            "rocky",
            "almalinux",
            "opensuse",
            "opensuse-leap",
            "opensuse-tumbleweed",
            "linuxmint",
            "pop",
            "raspbian",
            "manjaro",
            "nixos",
            "amzn",
        ];
        let id = self.os_id.to_ascii_lowercase();
        let kind = if known.contains(&id.as_str()) {
            id
        } else {
            "linux".to_string()
        };
        (kind, pretty)
    }

    /// A copy-pasteable install command for the remote's distribution, when we know one.
    pub fn install_hint(&self) -> String {
        if self.is_windows() {
            return "Install Bulwark for Windows on the machine (https://bulwark.nrl.ai/download — the \
                    desktop app includes the scanner), or put bulwarkctl.exe on its PATH"
                .into();
        }
        let ids = format!("{} {}", self.os_id, self.os_like);
        if ids.contains("ubuntu") {
            "sudo add-apt-repository ppa:vietanhng/bulwark && sudo apt install bulwarkctl".into()
        } else if self.os_id == "arch" || ids.contains("arch") {
            "Install `bulwarkctl` from the AUR (e.g. `yay -S bulwarkctl`)".into()
        } else {
            "Download the bulwarkctl .deb, .rpm or tarball from \
             https://github.com/vietanhdev/bulwark/releases"
                .into()
        }
    }
}

/// The probe script, run under `sh` so it behaves the same whatever the login shell is (fish,
/// zsh, …). Prints `key=value` lines and a sentinel, always exits 0.
///
/// A non-interactive SSH session gets a minimal `PATH` (on macOS, just the system directories), so
/// an installed Bulwark in Homebrew's prefix, `~/.local/bin` or `~/.cargo/bin` is invisible to
/// `command -v`; those common locations are checked explicitly before concluding none is installed.
/// The exact arguments a privileged scan of an installed engine runs as root, and therefore the
/// only ones a scoped sudoers rule should allow. Kept in one place so the suggested rule, the probe
/// that checks it and the command that uses it can't drift apart.
pub const SCOPED_SUDO_ARGS: &str = "scan --json --no-persist --privileged";

fn probe_script(check_sudo: bool) -> String {
    let mut s = String::from(
        "B=$(command -v bulwarkctl 2>/dev/null || command -v bulwark 2>/dev/null); \
         if [ -z \"$B\" ]; then for d in /usr/local/bin /opt/homebrew/bin \"$HOME/.local/bin\" \"$HOME/.cargo/bin\"; do \
         if [ -x \"$d/bulwarkctl\" ]; then B=\"$d/bulwarkctl\"; break; fi; done; fi; \
         if [ -z \"$B\" ] && [ -x /Applications/Bulwark.app/Contents/MacOS/bulwark ]; then \
         B=/Applications/Bulwark.app/Contents/MacOS/bulwark; fi; \
         echo \"bin=$B\"; \
         if [ -n \"$B\" ]; then echo \"ver=$(\"$B\" --version 2>/dev/null | head -n1)\"; fi; \
         echo \"arch=$(uname -m)\"; echo \"user=$(id -un 2>/dev/null)\"; \
         echo \"kernel=$(uname -s)\"; echo \"release=$(uname -r)\"; \
         echo \"mac_version=$(sw_vers -productVersion 2>/dev/null)\"; \
         if [ -r /etc/os-release ]; then . /etc/os-release; \
         echo \"os_id=$ID\"; echo \"os_like=$ID_LIKE\"; echo \"os_pretty=$PRETTY_NAME\"; fi; ",
    );
    if check_sudo {
        // `sudo -n -l <bin> scan` succeeds for a sudoers rule scoped to just the scanner (the one
        // we recommend); `sudo -n true` covers blanket NOPASSWD.
        s.push_str(
            "if [ -n \"$B\" ] && sudo -n -l \"$B\" scan --json --no-persist --privileged >/dev/null 2>&1; then echo sudo=ok; \
             elif sudo -n true >/dev/null 2>&1; then echo sudo=ok; else echo sudo=no; fi; \
             if sudo -n -l 2>/dev/null | grep -q 'NOPASSWD: *ALL *$'; then echo sudo_blanket=yes; fi; ",
        );
    }
    s.push_str("echo probe=done");
    format!("sh -c {}", sh_quote(&s))
}

fn parse_probe(stdout: &str) -> Option<Probe> {
    let mut p = Probe::default();
    let mut done = false;
    for line in stdout.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim() {
            "bin" if !v.is_empty() => p.bin = Some(v),
            "ver" if !v.is_empty() => p.version = Some(v),
            "arch" => p.arch = v,
            "os_id" => p.os_id = v,
            "os_like" => p.os_like = v,
            "os_pretty" => p.os_pretty = v,
            "sudo" => p.sudo_ok = Some(v == "ok"),
            "sudo_blanket" => p.sudo_blanket = v == "yes",
            "user" => p.user = v,
            "kernel" => p.kernel = v,
            "release" => p.release = v,
            "mac_version" => p.mac_version = v,
            "probe" => done = v == "done",
            _ => {}
        }
    }
    // Anything claiming to be our CLI must say so: a different program that happens to be called
    // `bulwark` is not an engine we can drive.
    match &p.version {
        Some(v) if v.starts_with("bulwarkctl") => {
            p.version = v.split_whitespace().nth(1).map(str::to_string);
        }
        _ => {
            p.bin = None;
            p.version = None;
        }
    }
    done.then_some(p)
}

/// Connect and learn about the machine. This is also the connection check: every connect, auth
/// and host-key failure surfaces here, classified.
pub fn probe(target: &RemoteTarget, check_sudo: bool) -> Result<Probe> {
    let out = target.run(&probe_script(check_sudo), QUICK_TIMEOUT)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match parse_probe(&stdout) {
        Some(p) => Ok(p),
        None if looks_like_windows_shell(&stdout, &String::from_utf8_lossy(&out.stderr)) => {
            windows_probe(target)
        }
        None => fail(
            RemoteErrorKind::Other,
            format!(
                "the machine's shell didn't run the connection check as expected: {}",
                last_meaningful_lines(&String::from_utf8_lossy(&out.stderr))
            ),
        ),
    }
}

/// The connection check for a machine whose SSH server is Windows' own (its shell is cmd or
/// PowerShell, so the `sh` probe can't run). Looks for an installed Bulwark — on `PATH`, or where the
/// Windows installer puts it (per-user `%LOCALAPPDATA%\bulwark`, per-machine `Program Files\bulwark`)
/// — and reports the same `key=value` lines as the Unix probe, so the rest of the flow is shared.
const WINDOWS_PROBE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$c = @()
foreach ($n in 'bulwarkctl.exe', 'bulwark.exe') { $g = Get-Command $n | Select-Object -First 1; if ($g) { $c += $g.Source } }
$c += "$env:LOCALAPPDATA\bulwark\bulwark.exe", "$env:ProgramFiles\bulwark\bulwark.exe", "$env:LOCALAPPDATA\Programs\bulwark\bulwark.exe"
$bin = ''; $ver = ''
foreach ($p in $c) { if ($p -and (Test-Path -LiteralPath $p)) { $v = (& $p --version 2>$null | Select-Object -First 1); if ("$v" -like 'bulwarkctl *') { $bin = $p; $ver = "$v"; break } } }
"bin=$bin"; "ver=$ver"
"arch=$env:PROCESSOR_ARCHITECTURE"
"user=$env:USERNAME"
"kernel=Windows"
$os = Get-CimInstance Win32_OperatingSystem
"os_id=windows"
"os_pretty=$(("$($os.Caption)" -replace '^Microsoft ', '').Trim())"
"release=$($os.Version)"
"probe=done"
"#;

fn windows_probe(target: &RemoteTarget) -> Result<Probe> {
    let out = target.run(&powershell_command(WINDOWS_PROBE), QUICK_TIMEOUT)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    match parse_probe(&stdout) {
        Some(mut p) => {
            // PROCESSOR_ARCHITECTURE says AMD64 / ARM64; the rest of Bulwark speaks uname -m.
            p.arch = match p.arch.to_ascii_uppercase().as_str() {
                "AMD64" | "X64" => "x86_64".into(),
                "ARM64" => "aarch64".into(),
                _ => p.arch.to_ascii_lowercase(),
            };
            if p.os_pretty.is_empty() {
                p.os_pretty = "Windows".into();
            }
            Ok(p)
        }
        None => fail(
            RemoteErrorKind::UnsupportedOs,
            format!(
                "{} answers with a Windows shell, but PowerShell didn't run the connection check: {}",
                target.spec,
                last_meaningful_lines(&String::from_utf8_lossy(&out.stderr))
            ),
        ),
    }
}

impl Probe {
    /// The machine's SSH shell is Windows' (cmd or PowerShell), not a Unix one.
    pub fn is_windows(&self) -> bool {
        self.kernel.eq_ignore_ascii_case("windows")
    }
}

/// A command line that runs `script` in Windows PowerShell whichever shell the SSH server starts
/// (cmd or PowerShell): `-EncodedCommand` takes base64 of the UTF-16LE text, so nothing in the
/// script needs quoting for either shell. A native program the script starts writes straight to the
/// session's stdout, so JSON comes back byte-for-byte.
fn powershell_command(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!(
        "powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        base64_encode(&utf16)
    )
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// PowerShell single-quoted string: the only escape is a doubled `'`.
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A Windows OpenSSH server runs the command through cmd or PowerShell, which reject the probe's
/// `sh -c …` with one of these. Recognised so the user is told "Windows isn't supported yet, use its
/// WSL" instead of a raw cmd error.
fn looks_like_windows_shell(stdout: &str, stderr: &str) -> bool {
    let all = format!("{stdout}\n{stderr}").to_lowercase();
    all.contains("is not recognized as an internal or external command")
        || all.contains("is not recognized as the name of a cmdlet")
        || all.contains("the system cannot find the path specified")
}

// ---- scanning -----------------------------------------------------------------------------------

/// Outcome metadata worth surfacing to the caller alongside the [`ScanRun`]: how the remote engine
/// was obtained, so the user knows whether a binary was copied onto their host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEngine {
    /// An already-installed `bulwarkctl`/`bulwark` was invoked in place.
    Installed { path: String, version: String },
    /// This binary + rule pack were pushed to the given temp dir and removed afterwards.
    Pushed { remote_dir: String, arch: String },
}

impl RemoteEngine {
    pub fn describe(&self) -> String {
        match self {
            Self::Installed { path, version } => format!("installed {path} ({version})"),
            Self::Pushed { arch, .. } => {
                format!(
                    "copied for the scan and removed ({arch}, {})",
                    env!("CARGO_PKG_VERSION")
                )
            }
        }
    }
}

/// Result of a remote scan: the deserialized run plus how we ran it, and what the probe saw.
pub struct RemoteScan {
    pub scan: ScanRun,
    pub engine: RemoteEngine,
    pub probe: Probe,
}

/// Why this computer can't copy its own scanner to the machine `probe` describes, if it can't.
/// The copy is a Linux executable for this computer's processor, so it only helps a Linux machine
/// with a matching CPU: a Windows or macOS build copied over fails with "Exec format error" after
/// the upload, and a Linux build can't run on a Mac at all.
pub fn push_blocker(probe: &Probe) -> Option<(RemoteErrorKind, String)> {
    if probe.is_windows() {
        return Some((
            RemoteErrorKind::EngineMissing,
            "Not installed — install Bulwark for Windows on the machine; Bulwark doesn't copy \
             itself to Windows"
                .into(),
        ));
    }
    if !cfg!(target_os = "linux") {
        return Some((
            RemoteErrorKind::EngineMissing,
            format!(
                "Not installed, and this computer's copy is a {} build that can't run there — \
                 install Bulwark on the machine",
                os_label(std::env::consts::OS)
            ),
        ));
    }
    if bulwark_core::sandbox::detect() == bulwark_core::sandbox::Sandbox::Flatpak {
        return Some((
            RemoteErrorKind::EngineMissing,
            "Not installed, and this sandboxed build can't copy itself there".into(),
        ));
    }
    // An empty kernel name is an older or unusual probe answer, not evidence of another OS.
    let kernel = probe.kernel.trim();
    if !kernel.is_empty() && !kernel.eq_ignore_ascii_case("linux") {
        return Some((
            RemoteErrorKind::EngineMissing,
            format!(
                "Not installed, and this computer's Linux copy can't run on {} — install Bulwark \
                 on the machine",
                os_label(&kernel.to_ascii_lowercase())
            ),
        ));
    }
    if !compatible_uname_m().contains(&probe.arch.as_str()) {
        return Some((
            RemoteErrorKind::ArchUnsupported,
            format!(
                "Not installed, and this computer's copy ({}) can't run on {}",
                std::env::consts::ARCH,
                probe.arch
            ),
        ));
    }
    None
}

fn os_label(os: &str) -> &str {
    match os {
        "windows" => "Windows",
        "macos" | "darwin" => "macOS",
        "linux" => "Linux",
        other => other,
    }
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
    // 1. One round-trip: reachability, installed engine, arch, sudo.
    let probe = probe(target, privileged)?;
    if privileged && probe.sudo_ok == Some(false) {
        return fail(
            RemoteErrorKind::SudoRequiresPassword,
            format!("`sudo -n` on {} needs a password", target.spec),
        );
    }

    // 2. Prefer an installed engine; otherwise push this one.
    let engine = match (&probe.bin, &probe.version) {
        (Some(path), Some(version)) => RemoteEngine::Installed {
            path: path.clone(),
            version: version.clone(),
        },
        _ => push_binary(target, &probe, local_binary, rules_dir)?,
    };

    // 3. Run the scan. `--no-persist` because history for the remote host is kept locally in an
    //    isolated per-host DB (see `hosts.rs`), never written on the remote itself.
    let run_result = run_scan_cmd(
        target,
        &engine,
        privileged && !probe.is_windows(),
        needs,
        probe.is_windows(),
    );

    // 4. Always clean up a pushed temp dir, even if the scan itself failed — we never want to leave
    //    a copied binary behind. Cleanup errors are reported but don't mask the scan's own result.
    if let RemoteEngine::Pushed { remote_dir, .. } = &engine {
        if let Err(e) = cleanup(target, remote_dir) {
            eprintln!("warning: failed to remove remote temp dir {remote_dir}: {e:#}");
        }
    }

    let scan = run_result?;
    Ok(RemoteScan {
        scan,
        engine,
        probe,
    })
}

/// Verify arch compatibility, create a remote temp dir, and `scp` the binary + rule pack into it.
fn push_binary(
    target: &RemoteTarget,
    probe: &Probe,
    local_binary: &Path,
    rules_dir: &Path,
) -> Result<RemoteEngine> {
    // Gate before any upload: a binary that can't execute there must never be copied and run.
    if let Some((kind, why)) = push_blocker(probe) {
        return fail(kind, format!("{}: {why}", target.spec));
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
    let mk = target.run("mktemp -d /tmp/bulwark.XXXXXX", QUICK_TIMEOUT)?;
    if !mk.status.success() {
        anyhow::bail!(
            "could not create a temp dir on {}: {}",
            target.spec,
            String::from_utf8_lossy(&mk.stderr).trim()
        );
    }
    let remote_dir = String::from_utf8_lossy(&mk.stdout).trim().to_string();
    if remote_dir.is_empty() {
        anyhow::bail!("mktemp on {} returned an empty path", target.spec);
    }

    let copy = (|| -> Result<()> {
        scp_to(target, local_binary, &format!("{remote_dir}/bulwarkctl"))?;
        scp_to(target, rules_dir, &format!("{remote_dir}/rules"))?;
        // scp does not preserve the executable bit reliably across all platforms; set it explicitly.
        let chmod = target.run(
            &format!("chmod 0755 {}/bulwarkctl", sh_quote(&remote_dir)),
            QUICK_TIMEOUT,
        )?;
        if !chmod.status.success() {
            anyhow::bail!(
                "could not chmod the pushed binary on {}: {}",
                target.spec,
                String::from_utf8_lossy(&chmod.stderr).trim()
            );
        }
        Ok(())
    })();
    if let Err(e) = copy {
        // The temp dir exists but the scan will never run — remove it now.
        let _ = cleanup(target, &remote_dir);
        return Err(e);
    }

    Ok(RemoteEngine::Pushed {
        remote_dir,
        arch: probe.arch.clone(),
    })
}

/// `scp <local> <target>:<remote>` with the target's transport options.
fn scp_to(target: &RemoteTarget, local: &Path, remote: &str) -> Result<()> {
    let mut cmd = bulwark_core::sandbox::host_command("scp");
    cmd.args(target.scp_args());
    cmd.arg("--");
    cmd.arg(local);
    cmd.arg(format!("{}:{remote}", target.spec));
    let out = run_captured(cmd, COPY_TIMEOUT, "scp", &target.spec, target.unattended)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if let Some(kind) = fleet::classify_ssh_stderr(&stderr) {
            return fail(kind, last_meaningful_lines(&stderr));
        }
        anyhow::bail!(
            "copying {} to {} failed: {}",
            local.display(),
            target.spec,
            stderr.trim()
        );
    }
    Ok(())
}

/// The remote `scan --json` command line for an engine.
fn scan_command(engine: &RemoteEngine, privileged: bool, needs: &[String]) -> String {
    let (bin, rules_flag) = match engine {
        RemoteEngine::Installed { path, .. } => (sh_quote(path), String::new()),
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
    remote_cmd
}

/// Build the remote `scan --json` command, run it, and deserialize stdout into a [`ScanRun`].
/// The same scan on a Windows machine: its installed Bulwark run through PowerShell. There is no
/// `sudo` there, so root checks never apply; Windows settings that need administrator rights are
/// read as "unknown" and never fire.
fn windows_scan_command(engine: &RemoteEngine, needs: &[String]) -> Option<String> {
    let RemoteEngine::Installed { path, .. } = engine else {
        return None;
    };
    let mut script = format!("& {} scan --json --no-persist", ps_quote(path));
    if !needs.is_empty() {
        script.push_str(&format!(" --needs {}", ps_quote(&needs.join(","))));
    }
    script.push_str("\nexit $LASTEXITCODE");
    Some(powershell_command(&script))
}

fn run_scan_cmd(
    target: &RemoteTarget,
    engine: &RemoteEngine,
    privileged: bool,
    needs: &[String],
    windows: bool,
) -> Result<ScanRun> {
    let command = if windows {
        windows_scan_command(engine, needs).ok_or_else(|| {
            anyhow::anyhow!("a Windows machine is only scanned with its own Bulwark")
        })?
    } else {
        scan_command(engine, privileged, needs)
    };
    let out = target.run(&command, SCAN_TIMEOUT)?;

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
                return fail(
                    RemoteErrorKind::SudoRequiresPassword,
                    format!("sudo -n failed on {}: {}", target.spec, stderr.trim()),
                );
            }
            if stderr.contains("loaded 0 rules") || stderr.contains("couldn't find a 'rules'") {
                return fail(RemoteErrorKind::NoRules, last_meaningful_lines(&stderr));
            }
            if let RemoteEngine::Installed { version, .. } = engine {
                if version != env!("CARGO_PKG_VERSION") {
                    return fail(
                        RemoteErrorKind::IncompatibleEngine,
                        format!(
                            "{} has bulwarkctl {version}, this is {}; its output couldn't be read \
                             ({parse_err})",
                            target.spec,
                            env!("CARGO_PKG_VERSION")
                        ),
                    );
                }
            }
            fail(
                RemoteErrorKind::Other,
                format!(
                    "remote scan on {} did not return a readable result (exit {:?}): {} \
                     (parse error: {parse_err})",
                    target.spec,
                    out.status.code(),
                    last_meaningful_lines(&stderr)
                ),
            )
        }
    }
}

/// `rm -rf` the pushed temp dir. The path came from our own `mktemp` (always under `/tmp/bulwark.`),
/// so this can only ever remove a directory we created.
fn cleanup(target: &RemoteTarget, remote_dir: &str) -> Result<()> {
    // Belt-and-braces: refuse to rm anything that isn't the shape we created, in case `remote_dir`
    // was somehow corrupted — never send `rm -rf` at a short or unexpected path.
    if !is_our_temp_dir(remote_dir) {
        anyhow::bail!("refusing to clean up unexpected remote path {remote_dir}");
    }
    let out = target.run(&format!("rm -rf {}", sh_quote(remote_dir)), QUICK_TIMEOUT)?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn is_our_temp_dir(p: &str) -> bool {
    let Some(suffix) = p.strip_prefix("/tmp/bulwark.") else {
        return false;
    };
    suffix.len() >= 3 && suffix.chars().all(|c| c.is_ascii_alphanumeric())
}

// ---- host keys ----------------------------------------------------------------------------------

/// What `ssh -G` resolved the target to, after `~/.ssh/config`.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedConfig {
    pub user: String,
    pub hostname: String,
    pub port: u16,
    /// Reached through a ProxyJump/ProxyCommand: `ssh-keyscan` can't see the host key directly.
    pub proxied: bool,
    pub host_key_alias: Option<String>,
}

/// `ssh -G` prints the effective configuration without connecting.
pub fn resolve_config(target: &RemoteTarget) -> Result<ResolvedConfig> {
    target.validate()?;
    let mut cmd = bulwark_core::sandbox::host_command("ssh");
    cmd.arg("-G")
        .args(target.ssh_args())
        .arg("--")
        .arg(&target.spec);
    let out = run_captured(cmd, QUICK_TIMEOUT, "ssh", &target.spec, true)?;
    if !out.status.success() {
        return fail(
            RemoteErrorKind::InvalidTarget,
            format!(
                "ssh couldn't read the settings for {}: {}",
                target.spec,
                last_meaningful_lines(&String::from_utf8_lossy(&out.stderr))
            ),
        );
    }
    Ok(parse_ssh_g(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_ssh_g(s: &str) -> ResolvedConfig {
    let mut r = ResolvedConfig {
        user: String::new(),
        hostname: String::new(),
        port: 22,
        proxied: false,
        host_key_alias: None,
    };
    for line in s.lines() {
        let Some((k, v)) = line.split_once(' ') else {
            continue;
        };
        let v = v.trim();
        let set = !v.is_empty() && v != "none";
        match k {
            "user" => r.user = v.into(),
            "hostname" => r.hostname = v.into(),
            "port" => r.port = v.parse().unwrap_or(22),
            "proxyjump" | "proxycommand" if set => r.proxied = true,
            "hostkeyalias" if set => r.host_key_alias = Some(v.into()),
            _ => {}
        }
    }
    r
}

/// One host key the machine offered.
#[derive(Debug, Clone, Serialize)]
pub struct HostKey {
    /// e.g. "ED25519".
    pub key_type: String,
    /// e.g. "SHA256:…", exactly as `ssh` and `ssh-keygen -l` print it.
    pub fingerprint: String,
    /// The known_hosts line to write if the user approves it.
    #[serde(skip)]
    pub line: String,
}

/// Learn the host key the machine presents to *this* ssh configuration, without signing in.
///
/// Rather than `ssh-keyscan` (which connects directly and so can't follow a ProxyJump, a
/// ProxyCommand alias or a HostKeyAlias), this runs ssh itself with an empty, throw-away
/// known_hosts and `StrictHostKeyChecking=accept-new`: ssh records the key it negotiated — under
/// exactly the name it will later look it up by — and then stops, because **every authentication
/// method is switched off**. No credential, not even a public key, is offered to a machine whose
/// identity hasn't been confirmed yet. The throw-away file is deleted; nothing is trusted until the
/// user compares the fingerprint and calls [`trust`].
pub fn fetch_host_keys(target: &RemoteTarget) -> Result<Vec<HostKey>> {
    target.validate()?;
    let dir = private_temp_dir()?;
    let kh = dir.join("known_hosts");
    std::fs::write(&kh, "")?;
    let result = (|| {
        let mut cmd = bulwark_core::sandbox::host_command("ssh");
        // The first occurrence of an option wins in ssh, so these come before anything else.
        for o in [
            "StrictHostKeyChecking=accept-new".to_string(),
            format!("UserKnownHostsFile=\"{}\"", kh.display()),
            "GlobalKnownHostsFile=/dev/null".into(),
            "HashKnownHosts=no".into(),
            "UpdateHostKeys=no".into(),
            "BatchMode=yes".into(),
            "PubkeyAuthentication=no".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "GSSAPIAuthentication=no".into(),
            "HostbasedAuthentication=no".into(),
            "ConnectTimeout=15".into(),
        ] {
            cmd.arg("-o").arg(o);
        }
        if let Some(j) = &target.jump {
            cmd.arg("-J").arg(j);
        }
        if let Some(p) = target.port {
            cmd.arg("-p").arg(p.to_string());
        }
        cmd.arg("--").arg(&target.spec).arg("true");
        let out = run_captured(cmd, QUICK_TIMEOUT, "ssh", &target.spec, true)?;
        let recorded = std::fs::read_to_string(&kh).unwrap_or_default();
        let mut keys = Vec::new();
        for line in recorded
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some((fp, ty)) = fingerprint_of(line)? {
                keys.push(HostKey {
                    key_type: ty,
                    fingerprint: fp,
                    line: line.to_string(),
                });
            }
        }
        if keys.is_empty() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let kind = fleet::classify_ssh_stderr(&stderr)
                .filter(|k| k.is_connectivity())
                .unwrap_or(RemoteErrorKind::Unreachable);
            let mut msg = format!(
                "couldn't read {}'s host key: {}",
                target.spec,
                last_meaningful_lines(&stderr)
            );
            if target.jump.is_some() {
                msg.push_str(
                    " (the jump host itself must already be trusted and accept your key — test \
                     it with plain `ssh`)",
                );
            }
            return fail(kind, msg);
        }
        Ok(keys)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// A fresh 0700 directory under the system temp dir, for files that must not be world-readable.
fn private_temp_dir() -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("bulwark-{}-{nanos}", std::process::id()));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// `ssh-keygen -lf -` on one known_hosts line → (fingerprint, key type).
fn fingerprint_of(line: &str) -> Result<Option<(String, String)>> {
    let mut cmd = bulwark_core::sandbox::host_command("ssh-keygen");
    cmd.args(["-l", "-f", "-"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return fail(RemoteErrorKind::SshMissing, "`ssh-keygen` was not found")
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(line.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let out = child.wait_with_output()?;
    Ok(parse_keygen_l(&String::from_utf8_lossy(&out.stdout)))
}

/// `256 SHA256:abc… host (ED25519)` → ("SHA256:abc…", "ED25519").
fn parse_keygen_l(s: &str) -> Option<(String, String)> {
    let line = s.lines().next()?;
    let fp = line.split_whitespace().nth(1)?.to_string();
    let ty = line
        .rsplit_once('(')
        .and_then(|(_, t)| t.strip_suffix(')'))
        .unwrap_or("")
        .to_string();
    fp.starts_with("SHA256:").then_some((fp, ty))
}

/// Re-fetch the machine's key and append it to Bulwark's known_hosts if its fingerprint is the one
/// the user confirmed. The fetch is repeated (rather than trusting whatever was shown earlier) so
/// the key written is the one the user compared, from a connection made now; if the machine no
/// longer presents a key with that fingerprint, nothing is written.
///
/// `replace` first drops every key Bulwark itself stored for this host — the recovery path after
/// the user confirmed a machine was reinstalled. It only ever edits Bulwark's own file; a stale key
/// in `~/.ssh/known_hosts` is left for the user (ssh accepts a match in either file).
pub fn trust(
    target: &RemoteTarget,
    known_hosts: &Path,
    fingerprint: &str,
    replace: bool,
) -> Result<HostKey> {
    let keys = fetch_host_keys(target)?;
    let Some(key) = keys
        .into_iter()
        .find(|k| k.fingerprint == fingerprint.trim())
    else {
        return fail(
            RemoteErrorKind::Other,
            format!(
                "{} doesn't present a key with fingerprint {fingerprint}, so nothing was trusted. \
                 Check that the whole fingerprint was copied; if it was, the key you are being \
                 shown is not the machine's",
                target.spec
            ),
        );
    };
    if replace {
        let name = key
            .line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        remove_known_host(known_hosts, &name)?;
    }
    append_known_host(known_hosts, &key.line)?;
    Ok(key)
}

/// Drop every line for `name` from Bulwark's known_hosts.
fn remove_known_host(path: &Path, name: &str) -> Result<()> {
    let Ok(existing) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let kept: String = existing
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(name))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(path, kept)?;
    Ok(())
}

// ---- dedicated key ------------------------------------------------------------------------------

/// Environment variable that switches this binary into `SSH_ASKPASS` mode. Its value is the path
/// of a 0600 file holding the one-time password. See [`install_key`] and `main`.
pub const ASKPASS_ENV: &str = "BULWARK_ASKPASS_SECRET_FILE";

/// Answer an ssh askpass prompt: the password for a password prompt, "no" to anything else (a
/// host-key yes/no question must never be answered with a password — and is refused anyway by
/// `StrictHostKeyChecking=yes`).
pub fn askpass_main(secret_file: &str) -> i32 {
    let prompt = std::env::args().nth(1).unwrap_or_default().to_lowercase();
    if prompt.contains("yes/no") || prompt.contains("fingerprint") {
        println!("no");
        return 0;
    }
    match std::fs::read_to_string(secret_file) {
        Ok(p) => {
            println!("{}", p.trim_end_matches(['\n', '\r']));
            0
        }
        Err(_) => 1,
    }
}

/// Bulwark's dedicated monitoring key (ed25519), created on first use. Returns the public key line,
/// prefixed with `restrict`, ready for authorized_keys.
pub fn ensure_dedicated_key(key_path: &Path) -> Result<String> {
    if !key_path.exists() {
        if let Some(dir) = key_path.parent() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
        }
        let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
        let comment = format!("bulwark-monitoring@{}", host.trim());
        let out = bulwark_core::sandbox::host_command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f"])
            .arg(key_path)
            .stdin(Stdio::null())
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => anyhow::bail!(
                "ssh-keygen failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return fail(RemoteErrorKind::SshMissing, "`ssh-keygen` was not found")
            }
            Err(e) => return Err(e.into()),
        }
    }
    let pub_path = key_path.with_extension("pub");
    let pubkey = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("reading {}", pub_path.display()))?;
    // `restrict` turns off port/agent/X11 forwarding and PTY allocation for this key — a scan needs
    // none of them, so a leaked monitoring key can't be used as a tunnel or an interactive login.
    Ok(format!("restrict {}", pubkey.trim()))
}

/// The jump hop for a password sign-in. `-J` starts the hop as a child ssh that inherits this
/// process's askpass environment, so a password prompt from the *jump host* would be answered with
/// the *target's* one-time password. A `ProxyCommand` ssh in `BatchMode` never asks for a password
/// at all — the jump host must accept the user's key — so the password only ever reaches the
/// target. One hop only (a chain would reintroduce the inherited prompt), and Unix only, where the
/// command is run by `sh` and the spec can be quoted; the spec itself is validated not to be
/// option-shaped and is passed after `--`.
fn password_safe_proxy(jump: &str) -> Result<String> {
    if jump.contains(',') {
        anyhow::bail!(
            "signing in with a password through a chain of jump hosts isn't supported — set up key \
             access to the machine with your own key instead, or use a single jump host"
        );
    }
    if cfg!(windows) {
        anyhow::bail!(
            "signing in with a password through a jump host isn't supported on Windows yet — set up \
             key access to the machine with your own key instead"
        );
    }
    bulwark_core::fleet::validate_jump(jump).map_err(|e| anyhow::anyhow!(e))?;
    // ssh:// accepts the same [user@]host[:port] a -J hop does.
    Ok(format!(
        "ProxyCommand=ssh -o BatchMode=yes -o ConnectTimeout=15 -W %h:%p -- {}",
        sh_quote(&format!("ssh://{}", jump.trim()))
    ))
}

/// Append `authorized_line` to `~/.ssh/authorized_keys` on the machine, signing in once with a
/// password (or, with `password: None`, however ssh normally would — a terminal prompt, the agent).
/// Idempotent. The password is handed to ssh through a 0600 temp file read by this binary in
/// askpass mode, deleted immediately afterwards, and never stored or logged.
pub fn install_key(
    target: &RemoteTarget,
    authorized_line: &str,
    password: Option<&str>,
) -> Result<()> {
    target.validate()?;
    let script = format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
         (grep -qxF {line} ~/.ssh/authorized_keys || printf '%s\\n' {line} >> ~/.ssh/authorized_keys)",
        line = sh_quote(authorized_line)
    );
    let mut cmd = bulwark_core::sandbox::host_command("ssh");
    let mut args: Vec<String> = Vec::new();
    if let Some(j) = &target.jump {
        if password.is_some() {
            args.extend(["-o".to_string(), password_safe_proxy(j)?]);
        } else {
            args.extend(["-J".to_string(), j.clone()]);
        }
    }
    if let Some(p) = target.port {
        args.extend(["-p".to_string(), p.to_string()]);
    }
    let mut opts = vec![
        "StrictHostKeyChecking=yes".to_string(),
        "ConnectTimeout=15".into(),
        "NumberOfPasswordPrompts=1".into(),
    ];
    if let Some(kh) = target.known_hosts.as_deref().filter(|p| p.exists()) {
        opts.push(format!(
            "GlobalKnownHostsFile=\"/etc/ssh/ssh_known_hosts\" \"/etc/ssh/ssh_known_hosts2\" \"{}\"",
            kh.display()
        ));
    }
    let mut secret_dir = None;
    if let Some(pw) = password {
        opts.push("PreferredAuthentications=keyboard-interactive,password".into());
        opts.push("PubkeyAuthentication=no".into());
        let dir = private_temp_dir()?;
        let f = dir.join("pw");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&f)?.write_all(pw.as_bytes())?;
        let exe = std::env::current_exe().context("locating this binary for SSH_ASKPASS")?;
        cmd.env("SSH_ASKPASS", exe)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env(ASKPASS_ENV, &f);
        if std::env::var_os("DISPLAY").is_none() {
            // OpenSSH before 8.4 ignores SSH_ASKPASS_REQUIRE and only uses askpass with a DISPLAY.
            cmd.env("DISPLAY", ":0");
        }
        secret_dir = Some(dir);
    }
    for o in opts {
        args.push("-o".into());
        args.push(o);
    }
    cmd.args(&args).arg("--").arg(&target.spec).arg(script);
    let interactive = password.is_none() && !target.unattended;
    let res = run_captured(
        cmd,
        Duration::from_secs(90),
        "ssh",
        &target.spec,
        !interactive,
    );
    if let Some(d) = secret_dir {
        let _ = std::fs::remove_dir_all(d);
    }
    let out = res?;
    check_ssh_failure(&out, &target.spec)?;
    if !out.status.success()
        && looks_like_windows_shell(
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        )
    {
        // Windows' OpenSSH keeps keys elsewhere (administrators use one shared, ACL-locked file),
        // and writing that file is not something to do blind. Say exactly what to add, and where.
        anyhow::bail!(
            "{} is a Windows machine, where Bulwark doesn't install keys itself yet. Add this line \
             there yourself — for an administrator account to \
             C:\\ProgramData\\ssh\\administrators_authorized_keys, otherwise to \
             %USERPROFILE%\\.ssh\\authorized_keys:\n  {authorized_line}\nthen run `bulwarkctl hosts \
             set <name> --identity <this computer's Bulwark key>` (shown by `bulwarkctl hosts show`).",
            target.spec
        );
    }
    if !out.status.success() {
        anyhow::bail!(
            "couldn't add the key on {}: {}",
            target.spec,
            last_meaningful_lines(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn append_known_host(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line.trim()) {
        return Ok(());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    f.write_all(line.trim().as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(unattended: bool) -> RemoteTarget {
        RemoteTarget {
            spec: "user@host".into(),
            port: Some(2222),
            identity: Some(PathBuf::from("/k")),
            ssh_opts: vec![],
            jump: None,
            unattended,
            known_hosts: None,
        }
    }

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
        let compat = compatible_uname_m();
        assert!(!compat.is_empty() || std::env::consts::ARCH == "unknown");
        if std::env::consts::ARCH == "x86_64" {
            assert!(compat.contains(&"amd64"));
        }
    }

    #[test]
    fn ssh_and_scp_args_translate_port_flag() {
        let mut t = target(false);
        t.ssh_opts = vec!["StrictHostKeyChecking=accept-new".into()];
        let ssh = t.ssh_args();
        assert!(ssh.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(ssh.windows(2).any(|w| w == ["-i", "/k"]));
        assert!(ssh.windows(2).any(|w| w == ["-o", "IdentitiesOnly=yes"]));
        let scp = t.scp_args();
        // scp uses capital -P for the port.
        assert!(scp.windows(2).any(|w| w == ["-P", "2222"]));
        assert!(scp.contains(&"-r".to_string()));
    }

    /// The unattended contract: never prompt, never silently accept a host key, never hang.
    #[test]
    fn unattended_runs_can_never_prompt_or_accept_unknown_keys() {
        let a = target(true).ssh_args();
        for o in [
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "ConnectTimeout=15",
        ] {
            assert!(a.windows(2).any(|w| w == ["-o", o]), "missing {o}");
        }
        let interactive = target(false).ssh_args();
        assert!(!interactive.iter().any(|x| x == "BatchMode=yes"));
    }

    #[test]
    fn bulwark_known_hosts_is_added_not_substituted() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        let mut t = target(true);
        t.known_hosts = Some(kh.clone());
        // Not added while the file doesn't exist.
        assert!(!t
            .ssh_args()
            .iter()
            .any(|a| a.starts_with("GlobalKnownHostsFile")));
        std::fs::write(&kh, "").unwrap();
        let opt = t
            .ssh_args()
            .into_iter()
            .find(|a| a.starts_with("GlobalKnownHostsFile"))
            .unwrap();
        assert!(opt.contains("/etc/ssh/ssh_known_hosts"));
        assert!(opt.contains(&kh.display().to_string()));
        assert!(!t
            .ssh_args()
            .iter()
            .any(|a| a.starts_with("UserKnownHostsFile")));
    }

    #[test]
    fn option_shaped_targets_are_refused_before_ssh_runs() {
        let mut t = target(true);
        t.spec = "-oProxyCommand=touch /tmp/bulwark-pwned".into();
        let err = t.run("true", QUICK_TIMEOUT).unwrap_err();
        assert_eq!(kind_of(&err), RemoteErrorKind::InvalidTarget);
        assert!(!Path::new("/tmp/bulwark-pwned").exists());
    }

    #[test]
    fn cleanup_refuses_unexpected_paths() {
        let t = target(true);
        // These never even attempt an ssh call — the guard rejects them first.
        for p in [
            "/",
            "/tmp",
            "/home/user",
            "/tmp/bulwark.",
            "/tmp/bulwark.ab/../..",
            "/tmp/bulwark.a b",
        ] {
            assert!(cleanup(&t, p).is_err(), "{p}");
        }
        assert!(is_our_temp_dir("/tmp/bulwark.Ab12Cd"));
    }

    #[test]
    fn probe_output_is_parsed_and_impostors_are_ignored() {
        let out = "bin=/usr/bin/bulwarkctl\nver=bulwarkctl 0.11.1\narch=x86_64\nos_id=ubuntu\n\
                   os_like=debian\nos_pretty=Ubuntu 24.04 LTS\nsudo=no\nprobe=done\n";
        let p = parse_probe(out).unwrap();
        assert_eq!(p.bin.as_deref(), Some("/usr/bin/bulwarkctl"));
        assert_eq!(p.version.as_deref(), Some("0.11.1"));
        assert_eq!(p.arch, "x86_64");
        assert_eq!(p.sudo_ok, Some(false));
        assert!(p.install_hint().contains("ppa:vietanhng/bulwark"));

        // Some other program called `bulwark` is not our engine.
        let other = "bin=/usr/local/bin/bulwark\nver=Bulwark game 2.0\narch=x86_64\nprobe=done\n";
        let p = parse_probe(other).unwrap();
        assert!(p.bin.is_none() && p.version.is_none());

        // No sentinel: the shell didn't run the script.
        assert!(parse_probe("bin=\narch=x86_64\n").is_none());
    }

    #[test]
    fn the_os_is_named_for_the_icon() {
        let mut p = Probe {
            os_id: "ubuntu".into(),
            os_pretty: "Ubuntu 24.04.1 LTS".into(),
            kernel: "Linux".into(),
            release: "6.8.0-45-generic".into(),
            ..Default::default()
        };
        assert_eq!(p.os(), ("ubuntu".into(), "Ubuntu 24.04.1 LTS".into()));
        p.release = "6.6.87.2-microsoft-standard-WSL2".into();
        assert_eq!(p.os(), ("wsl".into(), "Ubuntu 24.04.1 LTS (WSL)".into()));
        let mac = Probe {
            kernel: "Darwin".into(),
            mac_version: "15.6".into(),
            ..Default::default()
        };
        assert_eq!(mac.os(), ("macos".into(), "macOS 15.6".into()));
        let other = Probe {
            os_id: "gentoo".into(),
            os_pretty: "Gentoo Linux".into(),
            kernel: "Linux".into(),
            ..Default::default()
        };
        assert_eq!(other.os().0, "linux");
    }

    #[test]
    fn a_root_scan_runs_exactly_the_scoped_sudo_command() {
        // The suggested sudoers rule allows exactly SCOPED_SUDO_ARGS; the command must match it
        // byte for byte, and the probe must ask sudo about the same arguments.
        let engine = RemoteEngine::Installed {
            path: "/usr/bin/bulwarkctl".into(),
            version: "0.12.0".into(),
        };
        assert_eq!(
            scan_command(&engine, true, &[]),
            format!("sudo -n '/usr/bin/bulwarkctl' {SCOPED_SUDO_ARGS}")
        );
        assert!(probe_script(true).contains(&format!("sudo -n -l \"$B\" {SCOPED_SUDO_ARGS}")));
    }

    #[test]
    fn a_password_sign_in_never_lets_the_jump_host_prompt() {
        if cfg!(windows) {
            assert!(password_safe_proxy("me@bastion").is_err());
            return;
        }
        let p = password_safe_proxy("me@bastion.example.com:2222").unwrap();
        assert!(p.starts_with("ProxyCommand=ssh -o BatchMode=yes"), "{p}");
        assert!(p.ends_with("-- 'ssh://me@bastion.example.com:2222'"), "{p}");
        // A chain, or anything option- or shell-shaped, is refused rather than quoted around.
        assert!(password_safe_proxy("a@b,c@d").is_err());
        assert!(password_safe_proxy("-oProxyCommand=x").is_err());
        let q = password_safe_proxy("me@host'; touch /tmp/x; '").unwrap_or_default();
        assert!(q.is_empty() || q.contains("'\\''"), "{q}");
    }

    #[test]
    fn the_scanner_is_only_copied_where_it_can_run() {
        let here = std::env::consts::ARCH.to_string();
        let linux = Probe {
            kernel: "Linux".into(),
            arch: here.clone(),
            ..Default::default()
        };
        let mac = Probe {
            kernel: "Darwin".into(),
            arch: here.clone(),
            ..Default::default()
        };
        if cfg!(target_os = "linux") {
            // Same OS and CPU: copying works (outside a Flatpak, which tests never run in).
            assert!(push_blocker(&linux).is_none());
            // A Linux build never goes to a Mac, even with a matching CPU.
            let (kind, why) = push_blocker(&mac).unwrap();
            assert_eq!(kind, RemoteErrorKind::EngineMissing);
            assert!(why.contains("macOS"), "{why}");
            // A different CPU is the processor problem, not the install one.
            let other = Probe {
                kernel: "Linux".into(),
                arch: "riscv64".into(),
                ..Default::default()
            };
            assert_eq!(
                push_blocker(&other).unwrap().0,
                RemoteErrorKind::ArchUnsupported
            );
        } else {
            // A Windows or macOS build can't run on a Linux machine at all.
            assert_eq!(
                push_blocker(&linux).unwrap().0,
                RemoteErrorKind::EngineMissing
            );
        }
    }

    #[test]
    fn windows_commands_are_encoded_and_quoted_safely() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // -EncodedCommand is base64 of UTF-16LE; decode it back to prove the round trip.
        let cmd = powershell_command("echo 'hé'");
        let b64 = cmd.rsplit(' ').next().unwrap();
        let decode = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                _ => 63,
            }
        };
        let mut bytes = Vec::new();
        for chunk in b64.as_bytes().chunks(4) {
            let n = chunk
                .iter()
                .take_while(|c| **c != b'=')
                .fold(0u32, |n, c| n << 6 | decode(*c));
            let pad = chunk.iter().filter(|c| **c == b'=').count();
            let n = n << (6 * pad);
            let full = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            bytes.extend_from_slice(&full[..3 - pad]);
        }
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "echo 'hé'");
        assert!(cmd.starts_with("powershell -NoLogo -NoProfile -NonInteractive"));

        // An install path with a quote in it stays one argument.
        let engine = RemoteEngine::Installed {
            path: r"C:\Users\o'neil\AppData\Local\bulwark\bulwark.exe".into(),
            version: "0.11.1".into(),
        };
        let script = windows_scan_command(&engine, &["server".into()]).unwrap();
        assert!(script.starts_with("powershell "));
        assert_eq!(ps_quote("o'neil"), "'o''neil'");
        // Never a copied engine on Windows.
        let pushed = RemoteEngine::Pushed {
            remote_dir: "/tmp/bulwark.x".into(),
            arch: "x86_64".into(),
        };
        assert!(windows_scan_command(&pushed, &[]).is_none());
    }

    #[test]
    fn a_windows_probe_reads_as_windows() {
        let out = "bin=C:\\Users\\a\\AppData\\Local\\bulwark\\bulwark.exe\nver=bulwarkctl 0.11.1\n\
                   arch=AMD64\nuser=a\nkernel=Windows\nos_id=windows\nos_pretty=Windows 11 Pro\n\
                   release=10.0.26100\nprobe=done\n";
        let p = parse_probe(out).unwrap();
        assert!(p.is_windows());
        assert_eq!(p.version.as_deref(), Some("0.11.1"));
        assert_eq!(p.os(), ("windows".into(), "Windows 11 Pro".into()));
        assert!(p.install_hint().contains("Windows"));
        // Bulwark never copies itself to Windows, whatever this computer runs.
        assert_eq!(push_blocker(&p).unwrap().0, RemoteErrorKind::EngineMissing);
    }

    #[test]
    fn a_windows_shell_is_recognised_and_noise_is_dropped() {
        assert!(looks_like_windows_shell(
            "",
            "'sh' is not recognized as an internal or external command,"
        ));
        assert!(looks_like_windows_shell(
            "",
            "The system cannot find the path specified."
        ));
        assert!(!looks_like_windows_shell(
            "",
            "Permission denied (publickey)."
        ));
        assert_eq!(
            last_meaningful_lines("** WARNING: connection is not using a post-quantum key exchange\n** The server may need to be upgraded.\nPermission denied (publickey)."),
            "Permission denied (publickey)."
        );
    }

    #[test]
    fn the_probe_looks_beyond_a_minimal_path() {
        let script = probe_script(false);
        for dir in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            ".local/bin",
            ".cargo/bin",
        ] {
            assert!(script.contains(dir), "probe should look in {dir}");
        }
        // And it actually runs under a POSIX sh with nothing installed.
        let inner = script.trim_start_matches("sh -c ");
        let inner = &inner[1..inner.len() - 1];
        let out = Command::new("sh")
            .arg("-c")
            .arg(inner.replace("'\\''", "'"))
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        let p = parse_probe(&String::from_utf8_lossy(&out.stdout)).expect("sentinel");
        assert!(!p.arch.is_empty());
    }

    #[test]
    fn scan_command_quotes_every_remote_value() {
        let pushed = RemoteEngine::Pushed {
            remote_dir: "/tmp/bulwark.abc123".into(),
            arch: "x86_64".into(),
        };
        let cmd = scan_command(&pushed, true, &["server".into(), "x'y".into()]);
        assert!(
            cmd.starts_with("sudo -n '/tmp/bulwark.abc123'/bulwarkctl scan --json --no-persist")
        );
        assert!(cmd.contains("--rules-dir '/tmp/bulwark.abc123'/rules"));
        assert!(cmd.contains("--needs 'server','x'\\''y'"));
    }

    #[test]
    fn ssh_g_output_is_parsed() {
        let g = "user deploy\nhostname 10.0.0.5\nport 2222\nproxyjump bastion\n";
        let c = parse_ssh_g(g);
        assert_eq!(
            (c.user.as_str(), c.hostname.as_str(), c.port),
            ("deploy", "10.0.0.5", 2222)
        );
        assert!(c.proxied);
        let plain = parse_ssh_g("user u\nhostname h\nport 22\nproxycommand none\n");
        assert!(!plain.proxied);
    }

    #[test]
    fn keygen_fingerprint_line_is_parsed() {
        assert_eq!(
            parse_keygen_l("256 SHA256:AbCdEf0123 [h]:2222 (ED25519)\n"),
            Some(("SHA256:AbCdEf0123".into(), "ED25519".into()))
        );
        assert_eq!(parse_keygen_l("garbage"), None);
    }

    #[test]
    fn known_hosts_append_is_idempotent_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("sub/known_hosts");
        append_known_host(&kh, "h ssh-ed25519 AAAA").unwrap();
        append_known_host(&kh, "h ssh-ed25519 AAAA").unwrap();
        append_known_host(&kh, "h2 ssh-ed25519 BBBB").unwrap();
        let s = std::fs::read_to_string(&kh).unwrap();
        assert_eq!(s, "h ssh-ed25519 AAAA\nh2 ssh-ed25519 BBBB\n");
        remove_known_host(&kh, "h").unwrap();
        assert_eq!(
            std::fs::read_to_string(&kh).unwrap(),
            "h2 ssh-ed25519 BBBB\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&kh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn a_hung_command_is_killed_at_its_deadline() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = std::time::Instant::now();
        let err = run_captured(cmd, Duration::from_millis(300), "sleep", "x", true).unwrap_err();
        assert_eq!(kind_of(&err), RemoteErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

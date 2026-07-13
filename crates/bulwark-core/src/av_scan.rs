//! Real on-demand antivirus scanning — distinct from the `clamav_status` collector (which
//! only checks whether ClamAV is installed and how fresh its signatures are). This actually
//! invokes `clamscan` and reports what it finds. Deliberately *not* modeled as a `Collector`:
//! every other collector is a fast, sub-second fact read evaluated against declarative rules,
//! and a real filesystem scan is a fundamentally different kind of operation — slow, explicit,
//! user-initiated — that would break the "under 10 seconds" scan experience if bundled into
//! the regular rule-engine pass. This is why the project's own non-goals say "shell out to
//! ClamAV, don't reimplement AV": that's exactly what this module does, nothing more.

use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThreatDetection {
    pub path: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClamavVersionInfo {
    pub engine_version: String,
    pub database_version: String,
    pub database_date: String,
}

/// Parses `clamscan -V`'s single-line output — `ClamAV <engine>/<db-version>/<db-build-date>`
/// (e.g. `ClamAV 1.5.3/28055/Thu Jul  9 13:25:20 2026`, verified against a real install on
/// this project's own dev machine before writing this parser). One command gives the engine
/// version, the signature database version, *and* its build date together — a real "is this
/// actually current" answer, not just a file-modification-time guess the way the
/// `clamav_status` collector's `db_age_days` is (that one exists for fast, no-subprocess rule
/// evaluation; this is for the richer on-demand display the Antivirus page wants).
pub fn parse_version_output(output: &str) -> Option<ClamavVersionInfo> {
    let rest = output.trim().strip_prefix("ClamAV ")?;
    let mut parts = rest.splitn(3, '/');
    let engine_version = parts.next()?.trim().to_string();
    let database_version = parts.next()?.trim().to_string();
    let database_date = parts.next()?.trim().to_string();
    if engine_version.is_empty() || database_version.is_empty() || database_date.is_empty() {
        return None;
    }
    Some(ClamavVersionInfo {
        engine_version,
        database_version,
        database_date,
    })
}

/// `None` covers both "clamscan isn't installed" and "installed but produced output this
/// parser doesn't recognize" — the caller already has a separate, cheaper
/// `clamav_status`-collector-driven "is it installed at all" signal, so this doesn't need to
/// distinguish those two cases itself.
pub fn get_version_info() -> Option<ClamavVersionInfo> {
    let output = Command::new("clamscan").arg("-V").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_version_output(&String::from_utf8_lossy(&output.stdout))
}

/// The right install command for *this* host, not a one-size-fits-all `apt install` that's
/// simply wrong on non-Debian distros. Reads `ID`/`ID_LIKE` from `/etc/os-release` — the
/// standard, portable way to identify a Linux distro family (systemd's own spec, present on
/// every systemd-based distro and most others besides).
pub fn install_command_for_os_release(os_release_text: &str) -> &'static str {
    let mut id = "";
    let mut id_like = "";
    for line in os_release_text.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = v.trim_matches('"');
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            id_like = v.trim_matches('"');
        }
    }
    let family = format!("{id} {id_like}").to_ascii_lowercase();

    if family.contains("debian") || family.contains("ubuntu") {
        "sudo apt install clamav"
    } else if family.contains("fedora") || family.contains("rhel") || family.contains("centos") {
        "sudo dnf install clamav clamav-update"
    } else if family.contains("arch") {
        "sudo pacman -S clamav"
    } else if family.contains("suse") {
        "sudo zypper install clamav"
    } else if family.contains("alpine") {
        "sudo apk add clamav"
    } else {
        "See https://docs.clamav.net/manual/Installing.html for your distro"
    }
}

pub fn detect_install_command() -> &'static str {
    std::fs::read_to_string("/etc/os-release")
        .map(|text| install_command_for_os_release(&text))
        .unwrap_or("See https://docs.clamav.net/manual/Installing.html for your distro")
}

/// One parsed line of `clamscan`'s real-time, per-file output — the streaming counterpart to
/// [`parse_clamscan_output`]'s batch `--infected` parsing. Used to drive live scan progress
/// (GUI: "N files scanned, currently: <path>") rather than only reporting a result once the
/// whole scan finishes minutes later.
#[derive(Debug, Clone, PartialEq)]
pub enum ClamscanLine {
    Clean(String),
    Infected(ThreatDetection),
    /// A file `clamscan` couldn't scan (permission denied, unsupported archive, ...) — still
    /// progress (the file was reached), just not a clean/infected verdict.
    Error(String),
}

/// Parses one line of `clamscan`'s default (non-`--infected`) per-file output:
/// `<path>: OK`, `<path>: <Signature> FOUND`, or `<path>: <reason> ERROR`. Lines that match
/// none of these (blank lines, the trailing summary block if present) return `None` rather
/// than erroring — a scan that silently drops progress updates on an unrecognized line is
/// worse than one that's merely permissive about what it doesn't understand.
pub fn parse_clamscan_line(line: &str) -> Option<ClamscanLine> {
    let line = line.trim();
    // Unlike the FOUND/ERROR cases, a clean line has nothing between the path and the
    // verdict (`<path>: OK`, not `<path>: <reason> OK`) — the separator is part of the
    // suffix to strip, not just the verdict word, or the path would keep a trailing colon.
    if let Some(rest) = line.strip_suffix(": OK") {
        return Some(ClamscanLine::Clean(rest.to_string()));
    }
    if let Some(rest) = line.strip_suffix(" FOUND") {
        let (path, signature) = rest.rsplit_once(": ")?;
        return Some(ClamscanLine::Infected(ThreatDetection {
            path: path.to_string(),
            signature: signature.to_string(),
        }));
    }
    if let Some(rest) = line.strip_suffix(" ERROR") {
        return Some(ClamscanLine::Error(rest.to_string()));
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct AvScanResult {
    pub scanned_paths: Vec<String>,
    pub files_scanned: Option<u64>,
    pub threats: Vec<ThreatDetection>,
    pub clamscan_available: bool,
    /// True when the user stopped the scan before it finished. The counts and threat list are
    /// then *partial*, and a caller must say so rather than rendering "no threats found" — a
    /// scan that was cut short has proved nothing about the files it never reached.
    #[serde(default)]
    pub cancelled: bool,
    /// Set when `clamscan` exited with an error status (exit code 2) — a missing/unloadable virus
    /// database (a fresh install before `freshclam` ran), an unreadable path, resource exhaustion.
    /// The scan did NOT actually inspect the files, so an empty `threats` here is meaningless: a
    /// caller must render this as "scan failed", never as "no threats found". Same discipline as
    /// `cancelled`.
    #[serde(default)]
    pub scan_error: Option<String>,
}

/// Parses `clamscan --infected --no-summary` output. Each detection line looks like
/// `/path/to/file: Signature.Name FOUND`; everything else (directory notices, warnings) is
/// ignored rather than erroring the whole scan over one unparseable line — a scan that
/// silently drops findings on a parse quirk is worse than one that's merely permissive.
pub fn parse_clamscan_output(stdout: &str) -> Vec<ThreatDetection> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_suffix(" FOUND")?;
            let (path, signature) = rest.rsplit_once(": ")?;
            Some(ThreatDetection {
                path: path.to_string(),
                signature: signature.to_string(),
            })
        })
        .collect()
}

/// Bounded, fast-ish default scan targets rather than the whole filesystem (or even the
/// whole home directory, which can hold many GB of unrelated project data) — the places
/// malware actually lands: browser downloads and the world-writable temp directories every
/// local user and process can drop a file into.
pub fn default_scan_targets(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Downloads"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect()
}

/// Default folders for *real-time* protection to watch — deliberately narrower than
/// [`default_scan_targets`]: `/tmp` and `/var/tmp` see constant churn from every application
/// on the system, which would make a continuous on-write watcher fire near-permanently. The
/// user-facing folders malware actually lands in (browser downloads, files dragged to the
/// desktop) are the ones worth watching live; the noisier system temp dirs stay covered by
/// the on-demand scan instead.
pub fn default_realtime_watch_targets(home: &Path) -> Vec<PathBuf> {
    vec![home.join("Downloads"), home.join("Desktop")]
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

fn is_clamscan_available() -> bool {
    Command::new("clamscan")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn scan(paths: &[PathBuf]) -> anyhow::Result<AvScanResult> {
    let available = is_clamscan_available();

    if !available || paths.is_empty() {
        return Ok(AvScanResult {
            scanned_paths: paths.iter().map(|p| p.display().to_string()).collect(),
            files_scanned: None,
            threats: Vec::new(),
            clamscan_available: available,
            cancelled: false,
            scan_error: None,
        });
    }

    let output = Command::new("clamscan")
        .arg("--recursive")
        .arg("--infected")
        .arg("--no-summary")
        // `--` ends option parsing: the scan targets come from the UI (user-chosen files and
        // folders), and without this a path like `--copy=/somewhere` or one that merely starts
        // with `-` would be swallowed by clamscan as a flag instead of scanned as a path.
        .arg("--")
        .args(paths)
        .output()?;

    // clamscan's exit codes are meaningful: 0 = clean, 1 = infections found (a normal result), and
    // 2 = a scan error (no virus DB, unreadable path, resource exhaustion). Treating 2 as "clean"
    // — which ignoring the status does — is a false all-clear: an install whose database never
    // loaded emits zero FOUND lines and exits 2, and the user would be told the host is clean when
    // nothing was actually inspected.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let threats = parse_clamscan_output(&stdout);
    let scan_error = match output.status.code() {
        Some(0) | Some(1) => None,
        Some(code) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.lines().next().unwrap_or("").trim();
            Some(if detail.is_empty() {
                format!("clamscan exited with status {code}")
            } else {
                format!("clamscan error (status {code}): {detail}")
            })
        }
        None => Some("clamscan was terminated by a signal".to_string()),
    };

    Ok(AvScanResult {
        scanned_paths: paths.iter().map(|p| p.display().to_string()).collect(),
        files_scanned: None,
        threats,
        clamscan_available: true,
        cancelled: false,
        scan_error,
    })
}

/// Same underlying scan as [`scan`], but drives `on_line` with every per-file result as
/// `clamscan` produces it instead of buffering the whole run and returning once at the end —
/// what actually backs the GUI's live "N files scanned, currently: <path>" progress. Doesn't
/// pass `--infected` (unlike `scan`): that flag suppresses the "OK" lines entirely, which
/// would mean clean files (the overwhelming majority of any real scan) produce zero progress
/// signal at all.
pub fn scan_streaming(
    paths: &[PathBuf],
    on_line: impl FnMut(&ClamscanLine),
) -> anyhow::Result<AvScanResult> {
    scan_streaming_cancellable(paths, on_line, &|| false)
}

/// [`scan_streaming`] plus the ability to stop. `should_cancel` is polled after every line
/// `clamscan` emits; when it returns true the child process is **killed**, not merely abandoned.
/// That distinction is the whole point: a ClamAV sweep of a large tree runs for minutes, and
/// simply dropping our end of the pipe would leave it churning the disk in the background long
/// after the user pressed Stop.
///
/// A cancelled run reports `cancelled: true` and its partial counts. Callers must not present it
/// as a clean bill of health — "we stopped early and found nothing yet" is not "there is nothing".
pub fn scan_streaming_cancellable(
    paths: &[PathBuf],
    mut on_line: impl FnMut(&ClamscanLine),
    should_cancel: &dyn Fn() -> bool,
) -> anyhow::Result<AvScanResult> {
    let available = is_clamscan_available();

    if !available || paths.is_empty() {
        return Ok(AvScanResult {
            scanned_paths: paths.iter().map(|p| p.display().to_string()).collect(),
            files_scanned: None,
            threats: Vec::new(),
            clamscan_available: available,
            cancelled: false,
            scan_error: None,
        });
    }

    let mut child = Command::new("clamscan")
        .arg("--recursive")
        .arg("--no-summary")
        // `--` ends option parsing. This is the path the GUI's "scan this folder" command drives
        // with webview-supplied paths, so without it an entry like `--remove` or `--move=/dir`
        // (or `-d attacker.db`) would be honored as a destructive clamscan flag, not a scan target.
        .arg("--")
        .args(paths)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("clamscan produced no stdout pipe"))?;

    let mut files_scanned: u64 = 0;
    let mut threats = Vec::new();
    let mut unscanned = 0u64;
    let mut cancelled = false;
    for line in BufReader::new(stdout).lines() {
        if should_cancel() {
            cancelled = true;
            let _ = child.kill();
            break;
        }
        let line = line?;
        let Some(parsed) = parse_clamscan_line(&line) else {
            continue;
        };
        match &parsed {
            ClamscanLine::Clean(_) => files_scanned += 1,
            // An ERROR line means clamscan *reached* the file but could not scan it (permission
            // denied, an encrypted/oversized archive). It is NOT a clean verdict, so it must not be
            // folded into files_scanned as if it were — malware inside a password-protected archive
            // is exactly this case. Counted separately and surfaced.
            ClamscanLine::Error(_) => unscanned += 1,
            ClamscanLine::Infected(t) => {
                files_scanned += 1;
                threats.push(t.clone());
            }
        }
        on_line(&parsed);
    }
    // Reap the child and inspect its exit status. clamscan: 0 = clean, 1 = infections found (a
    // normal, already-consumed result), 2 = scan error (no/broken virus DB, unreadable path). A 2
    // means the files weren't really inspected, so — like `cancelled` — the caller must not present
    // an empty threat list as a clean bill of health. A cancelled run is expected to be killed, so
    // its status isn't treated as an error.
    let status = child.wait();
    let scan_error = if cancelled {
        None
    } else {
        match status.ok().and_then(|s| s.code()) {
            Some(0) | Some(1) => {
                if unscanned > 0 {
                    Some(format!("{unscanned} file(s) could not be scanned"))
                } else {
                    None
                }
            }
            Some(code) => Some(format!("clamscan exited with error status {code}")),
            None => Some("clamscan was terminated by a signal".to_string()),
        }
    };

    Ok(AvScanResult {
        scanned_paths: paths.iter().map(|p| p.display().to_string()).collect(),
        files_scanned: Some(files_scanned),
        threats,
        clamscan_available: true,
        cancelled,
        scan_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_detection_line() {
        // The name a current ClamAV reports for the canonical 68-byte EICAR file, matched by
        // the hash signature in main.hdb.
        let output = "/tmp/eicar.com: Eicar-Test-Signature FOUND\n";
        let threats = parse_clamscan_output(output);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].path, "/tmp/eicar.com");
        assert_eq!(threats[0].signature, "Eicar-Test-Signature");
    }

    #[test]
    fn parses_the_bytecode_engines_eicar_variant() {
        // EICAR padded with trailing whitespace (still a valid test file, up to 128 bytes)
        // misses the exact-hash signature and is caught by the bytecode engine instead, which
        // reports a *different* name. Both are real detections and both must parse.
        let output = "/tmp/eicar-padded.com: Eicar-Signature FOUND\n";
        let threats = parse_clamscan_output(output);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].signature, "Eicar-Signature");
    }

    #[test]
    fn ignores_non_detection_lines() {
        let output = "/tmp/clean.txt: OK\n\
             ----------- SCAN SUMMARY -----------\n\
             Scanned files: 42\n";
        assert!(parse_clamscan_output(output).is_empty());
    }

    #[test]
    fn handles_paths_containing_colons() {
        // A filename with its own ": " substring shouldn't split at the wrong point —
        // rsplit_once anchors from the right, so the FOUND-adjacent separator wins.
        let output = "/tmp/notes: draft.txt: Unix.Trojan.Mirai-1 FOUND\n";
        let threats = parse_clamscan_output(output);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].path, "/tmp/notes: draft.txt");
        assert_eq!(threats[0].signature, "Unix.Trojan.Mirai-1");
    }

    #[test]
    fn default_targets_only_include_existing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("Downloads")).unwrap();
        let targets = default_scan_targets(tmp.path());
        assert!(targets.contains(&tmp.path().join("Downloads")));
        // /tmp and /var/tmp existing on the actual host they don't control from this test —
        // just confirm the one we created shows up and nothing crashes on a fixture home dir.
    }

    #[test]
    fn default_realtime_watch_targets_only_include_existing_paths() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("Downloads")).unwrap();
        // Desktop deliberately left uncreated — must be skipped, not produce a nonexistent
        // watch target that would fail when handed to `notify::Watcher::watch`.
        let targets = default_realtime_watch_targets(tmp.path());
        assert_eq!(targets, vec![tmp.path().join("Downloads")]);
    }

    #[test]
    fn parses_a_clean_line() {
        assert_eq!(
            parse_clamscan_line("/tmp/notes.txt: OK"),
            Some(ClamscanLine::Clean("/tmp/notes.txt".to_string()))
        );
    }

    #[test]
    fn parses_an_infected_line() {
        assert_eq!(
            parse_clamscan_line("/tmp/eicar.com: Eicar-Signature FOUND"),
            Some(ClamscanLine::Infected(ThreatDetection {
                path: "/tmp/eicar.com".to_string(),
                signature: "Eicar-Signature".to_string(),
            }))
        );
    }

    #[test]
    fn parses_an_error_line() {
        assert_eq!(
            parse_clamscan_line("/root/private: Permission denied ERROR"),
            Some(ClamscanLine::Error(
                "/root/private: Permission denied".to_string()
            ))
        );
    }

    #[test]
    fn unrecognized_lines_are_ignored_not_erroring() {
        assert_eq!(parse_clamscan_line(""), None);
        assert_eq!(
            parse_clamscan_line("----------- SCAN SUMMARY -----------"),
            None
        );
        assert_eq!(parse_clamscan_line("Scanned files: 42"), None);
    }

    #[test]
    fn scan_streaming_reports_clamscan_unavailable_without_invoking_on_line() {
        // A binary named "clamscan" almost certainly isn't on PATH inside a test sandbox in
        // a way that would make this test flaky either way — either it's genuinely absent
        // (available=false, the common case) or present, in which case an empty paths list
        // still short-circuits before spawning. Either way `on_line` must never fire here.
        let mut calls = 0;
        let result = scan_streaming(&[], |_| calls += 1).unwrap();
        assert_eq!(calls, 0);
        assert_eq!(result.threats.len(), 0);
    }

    #[test]
    fn parses_a_real_clamscan_version_line() {
        // Verified against a real `clamscan -V` invocation on this project's own dev
        // machine before writing this parser.
        let info = parse_version_output("ClamAV 1.5.3/28055/Thu Jul  9 13:25:20 2026\n").unwrap();
        assert_eq!(info.engine_version, "1.5.3");
        assert_eq!(info.database_version, "28055");
        assert_eq!(info.database_date, "Thu Jul  9 13:25:20 2026");
    }

    #[test]
    fn unparseable_version_output_is_none_not_a_panic() {
        assert!(parse_version_output("").is_none());
        assert!(parse_version_output("not clamav output at all").is_none());
    }

    #[test]
    fn picks_apt_for_a_real_ubuntu_os_release() {
        // The actual content of this project's own dev machine's /etc/os-release.
        let text = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(
            install_command_for_os_release(text),
            "sudo apt install clamav"
        );
    }

    #[test]
    fn picks_the_right_package_manager_per_distro_family() {
        assert_eq!(
            install_command_for_os_release("ID=fedora\n"),
            "sudo dnf install clamav clamav-update"
        );
        assert_eq!(
            install_command_for_os_release("ID=arch\n"),
            "sudo pacman -S clamav"
        );
        assert_eq!(
            install_command_for_os_release("ID=opensuse-tumbleweed\nID_LIKE=suse\n"),
            "sudo zypper install clamav"
        );
        assert_eq!(
            install_command_for_os_release("ID=alpine\n"),
            "sudo apk add clamav"
        );
    }

    #[test]
    fn unknown_distro_falls_back_to_the_docs_link_not_a_wrong_command() {
        let hint = install_command_for_os_release("ID=some-unknown-distro\n");
        assert!(
            hint.contains("docs.clamav.net"),
            "must not guess a specific package manager"
        );
    }
}

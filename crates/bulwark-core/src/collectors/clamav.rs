use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;
use std::time::SystemTime;

pub struct ClamavStatusCollector;

/// Whether ClamAV's `clamscan` is installed, as a three-state answer: `Some(true)` present,
/// `Some(false)` provably absent, `None` undetermined.
///
/// The old logic was `Command::new("clamscan").output().map(success).unwrap_or(false)` — the exact
/// "command failure becomes a confident negative" bug. It reported "ClamAV is not installed"
/// (BLWK-AV-001) when clamscan was merely under a non-PATH prefix, or installed-but-broken (a
/// non-zero `--version` after a bad upgrade), or unspawnable under resource pressure. So: check the
/// known absolute locations first (a present binary is provable regardless of PATH or exit code),
/// and only conclude "absent" when the OS says ENOENT. Anything else is left undetermined, so
/// BLWK-AV-001 abstains (MissingField → collector_error) rather than crying wolf.
fn detect_installed() -> Option<bool> {
    const KNOWN_PATHS: &[&str] = &[
        "/usr/bin/clamscan",
        "/usr/local/bin/clamscan",
        "/bin/clamscan",
        "/opt/homebrew/bin/clamscan",
        "/snap/bin/clamscan",
    ];
    // In a Flatpak these paths are the *runtime's*, not the host's, so a hit would say
    // nothing about the machine being audited and a miss would say nothing either. The
    // question is only ever answerable by asking the host.
    let via_host = crate::sandbox::detect() == crate::sandbox::Sandbox::Flatpak;
    if !via_host && KNOWN_PATHS.iter().any(|p| Path::new(p).exists()) {
        return Some(true);
    }
    match crate::sandbox::host_command("clamscan")
        .arg("--version")
        .output()
    {
        Ok(o) if o.status.success() => Some(true),
        // Through flatpak-spawn the process we launch is always present, so a missing host
        // binary can never surface as ErrorKind::NotFound — it comes back as a non-zero exit
        // with the portal's own message. Without this arm the provable negative degrades to
        // "undetermined", BLWK-AV-001 abstains with MissingField, and the scan reports a
        // collector error instead of the plain truth that ClamAV is not installed.
        Ok(o) if via_host && host_reported_missing(&o.stderr) => Some(false),
        // Present but `--version` failed (broken install) — can't conclude "not installed".
        Ok(_) => None,
        // The OS looked and there is no such binary: a provable negative.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        // EACCES, EMFILE, ENOMEM, … — we couldn't determine anything.
        Err(_) => None,
    }
}

/// Whether `flatpak-spawn`'s stderr says the host has no such binary, as opposed to some
/// other failure (portal denied, host busy, permission error) which proves nothing.
///
/// Matching on message text is unpleasant, but the exit status is 1 for every failure mode,
/// so it is the only signal available. Both fragments must be present, and anything
/// unrecognised stays undetermined — the collector invariant is that "couldn't look" must
/// never become a confident negative.
fn host_reported_missing(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("Failed to execute child process") && text.contains("No such file or directory")
}

/// Rootkit/malware detection in Bulwark is deliberately *not* a reimplemented signature
/// engine (architecture doc §2 non-goals: "shells out to the system's own ClamAV installation
/// ... rather than reimplementing it"). This collector reports whether ClamAV is even
/// installed and how stale its signature database is — the two things that make a
/// present-but-useless install indistinguishable from a real one to a casual glance.
pub fn describe_db_freshness(
    installed: Option<bool>,
    db_mtime: Option<SystemTime>,
    now: SystemTime,
) -> Fact {
    let mut fact = Fact::new();
    // Only record `installed` when we actually determined it. An undetermined result (`None`) is
    // left off, so BLWK-AV-001 raises MissingField instead of falsely reporting "not installed".
    if let Some(installed) = installed {
        fact.insert("installed".to_string(), Value::Bool(installed));
    }
    let age_days = db_mtime
        .and_then(|t| now.duration_since(t).ok())
        .map(|d| (d.as_secs() / 86400) as i64);
    // `db_age_days` is ALWAYS emitted, so BLWK-AV-002 (`db_age_days > 14`) never MissingFields —
    // which it used to do on every scan of a host without ClamAV, producing a recurring
    // collector_error. The value encodes the three real states:
    //   * a signature DB with a real mtime → its actual age;
    //   * ClamAV installed but NO signature DB (never ran freshclam — more dangerous than merely
    //     stale) → a large sentinel, so AV-002 fires and the gap is reported rather than silent;
    //   * not installed, or install state undetermined → 0, so AV-002 stays quiet (BLWK-AV-001
    //     already owns "not installed") and doesn't error.
    const NO_DATABASE_AGE: i64 = 100_000;
    let db_age_days = match age_days {
        Some(days) => days,
        None if installed == Some(true) => NO_DATABASE_AGE,
        None => 0,
    };
    fact.insert("db_age_days".to_string(), Value::from(db_age_days));
    fact
}

impl Collector for ClamavStatusCollector {
    fn name(&self) -> &'static str {
        "clamav_status"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let installed = detect_installed();

        let db_mtime = ["/var/lib/clamav/daily.cvd", "/var/lib/clamav/daily.cld"]
            .iter()
            .find_map(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()));

        Ok(vec![describe_db_freshness(
            installed,
            db_mtime,
            SystemTime::now(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn not_installed_reports_age_zero_so_the_staleness_rule_stays_quiet_and_error_free() {
        // db_age_days is always emitted now (was omitted, which made BLWK-AV-002 MissingField and
        // error every scan on a host without ClamAV). Not-installed → 0, so AV-002 (`> 14`) is
        // quiet; BLWK-AV-001 owns "not installed".
        let fact = describe_db_freshness(Some(false), None, SystemTime::now());
        assert_eq!(fact.get("installed").unwrap(), &Value::Bool(false));
        assert_eq!(fact.get("db_age_days").unwrap(), &Value::from(0));
    }

    #[test]
    fn installed_but_no_signature_database_reports_as_very_stale() {
        // Installed, freshclam never ran (no DB) — more dangerous than merely stale. A large
        // sentinel makes AV-002 fire and report the gap rather than staying silent.
        let fact = describe_db_freshness(Some(true), None, SystemTime::now());
        let age = fact.get("db_age_days").unwrap().as_i64().unwrap();
        assert!(age > 14, "absent DB must read as stale, got {age}");
    }

    #[test]
    fn computes_age_in_days() {
        let now = SystemTime::now();
        let ten_days_ago = now - Duration::from_secs(10 * 86400);
        let fact = describe_db_freshness(Some(true), Some(ten_days_ago), now);
        assert_eq!(fact.get("db_age_days").unwrap(), &Value::from(10));
    }

    #[test]
    fn undetermined_install_state_omits_the_fact_so_the_rule_abstains() {
        // The fix for the command-failure-as-negative bug: when we couldn't determine whether
        // clamscan is installed, `installed` must be absent — never a false `false` that would
        // fire "ClamAV is not installed" on a host where it's merely broken or off-PATH.
        let fact = describe_db_freshness(None, None, SystemTime::now());
        assert!(
            !fact.contains_key("installed"),
            "an undetermined install state must not assert installed=false"
        );
    }
}

#[cfg(test)]
mod host_spawn_tests {
    use super::host_reported_missing;

    /// The exact message `flatpak-spawn --host` produces for a binary the host lacks.
    /// Captured from a real run inside the sandbox, not invented — if the portal ever
    /// rewords it, this test is what notices before users get a collector error instead of
    /// "ClamAV is not installed".
    #[test]
    fn portal_missing_binary_message_is_a_provable_negative() {
        let real = b"Portal call failed: Failed to start command: Failed to execute child \
                     process \xe2\x80\x9cdefinitely-not-a-real-binary\xe2\x80\x9d (No such file \
                     or directory)\n";
        assert!(host_reported_missing(real));
    }

    /// Everything else proves nothing. A denied portal, a busy host or an empty stderr must
    /// stay undetermined: reporting "ClamAV is not installed" because we could not ask is
    /// the confident-negative bug this collector exists to avoid.
    #[test]
    fn other_failures_stay_undetermined() {
        assert!(!host_reported_missing(b""));
        assert!(!host_reported_missing(
            b"Portal call failed: Permission denied"
        ));
        assert!(!host_reported_missing(
            b"Failed to execute child process (Permission denied)"
        ));
        assert!(!host_reported_missing(b"No such file or directory"));
    }
}

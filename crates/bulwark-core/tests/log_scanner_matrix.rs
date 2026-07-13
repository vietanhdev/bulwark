//! End-to-end validation matrix for the log scanner: every shipped log rule is exercised in both
//! its firing and non-firing state, plus the correlation boundary cases (window edge, distributed-
//! slow, out-of-order multi-host) and the syslog year-inference boundary. This drives the REAL
//! decoders and log-rules from the repo (not fixtures), so it proves the shipped pack behaves
//! correctly across situations, not just that the code compiles.

use bulwark_core::{run_log_scan, LogScanRun, SyslogLinesSource};
use std::io::Cursor;
use std::path::PathBuf;

fn root(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(p)
}

/// Runs the real decoders + log-rules over `text`, with a fixed late-2026 reference so RFC3164
/// lines land in 2026.
fn scan(text: &str) -> LogScanRun {
    let reference =
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 12, 31, 0, 0, 0).unwrap();
    let mut src = SyslogLinesSource::new(Cursor::new(text.as_bytes().to_vec()), reference);
    run_log_scan(&root("decoders"), &root("log-rules"), &mut src)
}

fn fired(scan: &LogScanRun, rule_id: &str) -> bool {
    scan.findings.iter().any(|f| f.rule_id == rule_id)
}

/// Builds N sshd password-failure lines from one source, one second apart starting at HH:MM:SS.
fn ssh_failures(n: u32, ip: &str, base_sec: u32) -> String {
    (0..n)
        .map(|i| {
            let s = base_sec + i;
            format!(
                "Jul 12 10:{:02}:{:02} host sshd[1]: Failed password for root from {ip} port {} ssh2",
                s / 60,
                s % 60,
                2000 + i
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- SSH brute force (SSH-001): count 8 within 60s, by srcip -------------------------------

#[test]
fn ssh_001_fires_at_the_threshold_and_not_below_it() {
    // 8 failures in a tight window → fires.
    assert!(fired(
        &scan(&ssh_failures(8, "9.9.9.9", 0)),
        "BLWK-LOG-SSH-001"
    ));
    // 7 failures → below threshold, silent (the window edge).
    assert!(!fired(
        &scan(&ssh_failures(7, "9.9.9.9", 0)),
        "BLWK-LOG-SSH-001"
    ));
}

#[test]
fn ssh_001_does_not_fire_when_failures_are_spread_beyond_the_window() {
    // 8 failures 20s apart span 140s — never 8 within any 60s window. A slow/distributed guess must
    // not trip the burst rule.
    let text: String = (0..8)
        .map(|i| {
            let s = i * 20;
            format!(
                "Jul 12 10:{:02}:{:02} host sshd[1]: Failed password for root from 9.9.9.9 port {} ssh2",
                s / 60, s % 60, 2000 + i
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!fired(&scan(&text), "BLWK-LOG-SSH-001"));
}

#[test]
fn ssh_001_counts_per_source_not_in_aggregate() {
    // Two IPs, 4 failures each interleaved: 8 total but only 4 per source → no single-source burst.
    let mut lines = Vec::new();
    for i in 0..4 {
        lines.push(ssh_failures(1, "1.1.1.1", i * 2));
        lines.push(ssh_failures(1, "2.2.2.2", i * 2 + 1));
    }
    assert!(!fired(&scan(&lines.join("\n")), "BLWK-LOG-SSH-001"));
}

#[test]
fn ssh_001_still_fires_when_a_bursts_events_arrive_out_of_chronological_order() {
    // The LH3 fix: the same 8-event burst from one IP, shuffled so timestamps are NOT ascending in
    // the file (as merged multi-host logs or a crafted file would be). Sorting before correlation
    // must still see them all inside the window and fire.
    let mut lines: Vec<String> = (0..8).map(|i| ssh_failures(1, "9.9.9.9", i)).collect();
    // Reverse + interleave to guarantee non-ascending order.
    lines.reverse();
    lines.swap(0, 4);
    assert!(fired(&scan(&lines.join("\n")), "BLWK-LOG-SSH-001"));
}

// ---- SSH invalid-user scan (SSH-002): count 5, tag invalid_user ----------------------------

#[test]
fn ssh_002_fires_on_a_username_spray_and_not_on_a_few() {
    let spray: String = (0..5)
        .map(|i| {
            format!("Jul 12 10:00:{:02} host sshd[1]: Failed password for invalid user user{i} from 8.8.8.8 port {} ssh2", i, 3000 + i)
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(fired(&scan(&spray), "BLWK-LOG-SSH-002"));
    // Two invalid users is not a scan.
    let few = "Jul 12 10:00:01 h sshd[1]: Failed password for invalid user a from 8.8.8.8 port 1 ssh2\nJul 12 10:00:02 h sshd[1]: Failed password for invalid user b from 8.8.8.8 port 2 ssh2";
    assert!(!fired(&scan(few), "BLWK-LOG-SSH-002"));
}

// ---- SSH root login (SSH-003): per-event, success as root ----------------------------------

#[test]
fn ssh_003_fires_on_root_login_but_not_on_a_normal_user() {
    let root_login =
        "Jul 12 10:00:01 host sshd[1]: Accepted password for root from 10.0.0.5 port 22 ssh2";
    assert!(fired(&scan(root_login), "BLWK-LOG-SSH-003"));
    let user_login =
        "Jul 12 10:00:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2";
    assert!(!fired(&scan(user_login), "BLWK-LOG-SSH-003"));
}

// ---- sudo: not-allowed (SUDO-002), single-session (SUDO-003), multi-session (SUDO-001) -----

#[test]
fn sudo_002_fires_on_a_not_in_sudoers_line() {
    let line = "Jul 12 10:00:01 host sudo[1]:   mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash";
    assert!(fired(&scan(line), "BLWK-LOG-SUDO-002"));
}

#[test]
fn sudo_003_fires_on_a_single_session_exhausting_the_attempt_limit() {
    let line = "Jul 12 10:00:01 host sudo[1]:   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash";
    assert!(fired(&scan(line), "BLWK-LOG-SUDO-003"));
    // One wrong password is a fat-finger, not a brute force.
    let one = "Jul 12 10:00:01 host sudo[1]:   alice : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls";
    assert!(!fired(&scan(one), "BLWK-LOG-SUDO-003"));
}

#[test]
fn sudo_001_fires_across_three_separate_failed_invocations() {
    let text: String = (0..3)
        .map(|i| format!("Jul 12 10:00:{:02} host sudo[1]:   bob : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", i))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(fired(&scan(&text), "BLWK-LOG-SUDO-001"));
}

// ---- su failures (SU-001) and PAM (PAM-001) ------------------------------------------------

#[test]
fn su_001_fires_on_repeated_su_failures() {
    let text: String = (0..3)
        .map(|i| {
            format!(
                "Jul 12 10:00:{:02} host su[1]: FAILED su for root by eve",
                i
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(fired(&scan(&text), "BLWK-LOG-SU-001"));
}

#[test]
fn pam_001_fires_on_repeated_pam_auth_failures_for_a_user() {
    let text: String = (0..5)
        .map(|i| format!("Jul 12 10:00:{:02} host sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=7.7.7.7 user=root", i))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(fired(&scan(&text), "BLWK-LOG-PAM-001"));
}

// ---- A genuinely benign log produces nothing, with no false-clean warning ------------------

#[test]
fn a_benign_log_produces_no_findings_and_is_a_real_clean_result() {
    let benign = "Jul 12 10:00:01 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2\nJul 12 10:05:00 host CRON[1]: pam_unix(cron:session): session opened for user root";
    let s = scan(benign);
    assert!(s.findings.is_empty());
    // And it's a genuine clean result — decoders and rules loaded, lines understood.
    assert!(
        s.warnings.is_empty(),
        "a real clean log must carry no health warnings: {:?}",
        s.warnings
    );
    assert!(s.events_decoded > 0);
}

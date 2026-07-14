//! A scan that loaded no rules must never report a clean result.
//!
//! "0 findings" from a scan that evaluated nothing is not a healthy host — it is the absence of an
//! opinion, and reporting it as success (exit 0, empty findings) is indistinguishable from a genuine
//! all-clear. That is the most dangerous sentence a security scanner can utter, and it shipped: a
//! mistyped `--rules-dir`, an emptied directory, or a mispackaged build produced a confident,
//! silent, green result. Persisting such a run makes it worse, because `persist_and_reconcile`
//! resolves every open finding a scan didn't re-observe — an empty rule pack would quietly wipe the
//! dashboard clean.
//!
//! These drive the real binary (`CARGO_BIN_EXE_*`, no Docker) so they cover the CLI's actual
//! argument handling and exit codes, not just the library beneath it.

use std::process::Command;

fn bulwarkctl() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bulwarkctl"));
    // Never touch the developer's real findings database.
    c.arg("scan").arg("--no-persist").arg("--json");
    c
}

#[test]
fn a_scan_that_loads_no_rules_fails_instead_of_reporting_clean() {
    let empty = tempfile::tempdir().unwrap();

    let out = bulwarkctl()
        .arg("--rules-dir")
        .arg(empty.path())
        .output()
        .expect("binary runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an empty rule pack must not exit 0 — stdout was: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains("0 rules"),
        "the error must say why, got: {stderr}"
    );
}

#[test]
fn a_rules_dir_that_does_not_exist_is_an_error_not_a_fallback() {
    // Silently falling back to the auto-detected pack would scan a *different* rule set than the one
    // asked for, which is its own kind of lie.
    let out = bulwarkctl()
        .arg("--rules-dir")
        .arg("/nonexistent/rules")
        .output()
        .expect("binary runs");

    assert!(!out.status.success(), "a bad --rules-dir must not exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a directory"),
        "expected a path complaint, got: {stderr}"
    );
}

#[test]
fn the_env_var_is_validated_the_same_way_as_the_flag() {
    let out = bulwarkctl()
        .env("BULWARK_RULES_DIR", "/nonexistent/rules")
        .output()
        .expect("binary runs");

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a directory"));
}

/// The guard must not fire on a real rule pack — otherwise it would be a very effective way of
/// making the scanner useless.
#[test]
fn the_real_rule_pack_still_scans() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules");

    let out = bulwarkctl()
        .arg("--rules-dir")
        .arg(rules)
        .output()
        .expect("binary runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("0 rules"),
        "the guard fired on the real pack: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let scan: serde_json::Value = serde_json::from_str(&stdout).expect("scan emits JSON");
    assert!(
        scan["rules_loaded"].as_u64().unwrap() > 0,
        "the real pack must load rules"
    );
}

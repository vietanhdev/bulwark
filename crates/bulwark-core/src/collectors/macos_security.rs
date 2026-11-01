//! macOS security posture: the handful of settings that decide how exposed a Mac is — disk
//! encryption (FileVault), app-signature enforcement (Gatekeeper), System Integrity Protection,
//! the application firewall, automatic security updates, and the guest account.
//!
//! Every value is read with the tool Apple ships for it, unprivileged, and every value carries a
//! `*_known` flag: a command that fails or prints something unrecognised yields "unknown", never
//! "off". A scanner that reads a parse failure as "FileVault is off" would raise a high-severity
//! alarm on a perfectly encrypted machine — the false positive this project keeps refusing.
//!
//! The parsers are pure and unit-tested on every OS against the exact output of a real Mac; only `collect()` needs a Mac.

use super::Collector;
use crate::models::{Fact, OperatingSystem};
use serde_json::Value;
use std::process::Command;

const MACOS_ONLY: &[OperatingSystem] = &[OperatingSystem::Macos];

pub struct MacosSecurityCollector;

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    // Some of these tools (sysadminctl) print their answer on stderr.
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

/// `fdesetup status` → "FileVault is On." / "FileVault is Off."
pub(crate) fn parse_filevault(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    if l.contains("filevault is on") {
        Some(true)
    } else if l.contains("filevault is off") {
        Some(false)
    } else {
        None
    }
}

/// `spctl --status` → "assessments enabled" / "assessments disabled"
pub(crate) fn parse_gatekeeper(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    if l.contains("assessments enabled") {
        Some(true)
    } else if l.contains("assessments disabled") {
        Some(false)
    } else {
        None
    }
}

/// `csrutil status` → "System Integrity Protection status: enabled." (or "disabled.", or a custom
/// configuration, which counts as not fully enabled).
pub(crate) fn parse_sip(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    let status = l.split("status:").nth(1)?.trim();
    if status.starts_with("enabled") {
        // "enabled (custom configuration)" is a partly-disabled SIP.
        Some(!l.contains("custom configuration"))
    } else if status.starts_with("disabled") || status.starts_with("unknown") {
        Some(false)
    } else {
        None
    }
}

/// `socketfilterfw --getglobalstate` → "Firewall is enabled. (State = 1)" / "disabled. (State = 0)"
pub(crate) fn parse_firewall(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    if l.contains("firewall is enabled") || l.contains("state = 1") || l.contains("state = 2") {
        Some(true)
    } else if l.contains("firewall is disabled") || l.contains("state = 0") {
        Some(false)
    } else {
        None
    }
}

/// `defaults read <domain> <key>` → "1"/"0"; a missing key means the macOS default applies (on),
/// so it is reported as unknown rather than as off.
pub(crate) fn parse_default_bool(s: &str) -> Option<bool> {
    match s.trim() {
        "1" | "true" | "YES" => Some(true),
        "0" | "false" | "NO" => Some(false),
        _ => None,
    }
}

fn insert(f: &mut Fact, key: &str, v: Option<bool>) {
    f.insert(format!("{key}_known"), Value::Bool(v.is_some()));
    f.insert(key.to_string(), Value::Bool(v.unwrap_or(false)));
}

impl Collector for MacosSecurityCollector {
    fn name(&self) -> &'static str {
        "macos_security"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        MACOS_ONLY
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut f = Fact::new();
        insert(
            &mut f,
            "filevault_on",
            output("/usr/bin/fdesetup", &["status"]).and_then(|s| parse_filevault(&s)),
        );
        insert(
            &mut f,
            "gatekeeper_on",
            output("/usr/sbin/spctl", &["--status"]).and_then(|s| parse_gatekeeper(&s)),
        );
        insert(
            &mut f,
            "sip_on",
            output("/usr/bin/csrutil", &["status"]).and_then(|s| parse_sip(&s)),
        );
        insert(
            &mut f,
            "firewall_on",
            output(
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                &["--getglobalstate"],
            )
            .and_then(|s| parse_firewall(&s)),
        );
        let su = |key: &str| {
            output(
                "/usr/bin/defaults",
                &["read", "/Library/Preferences/com.apple.SoftwareUpdate", key],
            )
            .and_then(|s| parse_default_bool(&s))
        };
        // Security responses = critical updates + XProtect/MRT data. Either off is a gap.
        let security_updates = match (su("CriticalUpdateInstall"), su("ConfigDataInstall")) {
            (Some(a), Some(b)) => Some(a && b),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        };
        insert(&mut f, "security_updates_on", security_updates);
        insert(
            &mut f,
            "guest_enabled",
            output(
                "/usr/bin/defaults",
                &[
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "GuestEnabled",
                ],
            )
            .and_then(|s| parse_default_bool(&s)),
        );
        Ok(vec![f])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact strings as printed by macOS.
    #[test]
    fn real_macos_output_is_parsed() {
        assert_eq!(parse_filevault("FileVault is On.\n"), Some(true));
        assert_eq!(parse_filevault("FileVault is Off.\n"), Some(false));
        assert_eq!(parse_gatekeeper("assessments enabled\n"), Some(true));
        assert_eq!(parse_gatekeeper("assessments disabled\n"), Some(false));
        assert_eq!(
            parse_sip("System Integrity Protection status: disabled.\n"),
            Some(false)
        );
        assert_eq!(
            parse_sip("System Integrity Protection status: enabled.\n"),
            Some(true)
        );
        assert_eq!(
            parse_sip("System Integrity Protection status: enabled (Custom Configuration).\n"),
            Some(false)
        );
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            parse_firewall("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
        assert_eq!(parse_default_bool("1\n"), Some(true));
        assert_eq!(parse_default_bool("0\n"), Some(false));
    }

    #[test]
    fn anything_unrecognised_is_unknown_not_off() {
        // A missing key, a permission error or a changed message format must never read as "off".
        let missing = "Error: Could not find key 'AutomaticCheckEnabled' in domain 'com.apple.SoftwareUpdate'.";
        assert_eq!(parse_default_bool(missing), None);
        assert_eq!(parse_filevault("fdesetup: command not found"), None);
        assert_eq!(parse_sip(""), None);
        assert_eq!(parse_gatekeeper("spctl: error"), None);
        assert_eq!(parse_firewall(""), None);
    }

    #[test]
    fn only_declares_macos_support() {
        assert_eq!(
            MacosSecurityCollector.supported_os(),
            &[OperatingSystem::Macos]
        );
    }
}

use super::Collector;
use crate::models::Fact;
use serde_json::Value;

pub struct MacStatusCollector;

/// Mandatory-access-control status: which framework is present, and whether it's actually
/// enforcing rather than just installed. Installed-but-permissive is a common gap Lynis
/// flags under its own `tests_mac_frameworks` category (see research report §1).
///
/// The subtlety that made this collector wrong for its first two releases: AppArmor's profile
/// list at `/sys/kernel/security/apparmor/profiles` is mode 0444 but the *kernel* gates reads on
/// `CAP_MAC_ADMIN`, so an unprivileged scan gets EACCES. Treating that error as "AppArmor isn't
/// there" reported "nothing is enforcing" on every stock Ubuntu desktop, which is both false and
/// alarming. So we separate three states rather than two:
///
///   * **enforcing** — we read the profile list and saw an `(enforce)` profile.
///   * **not enforcing** — we could see the whole picture, and nothing is enforcing. This is a
///     real finding, and it is exactly what a host with no MAC framework at all looks like.
///   * **unknown** — a framework is present but its state is behind a privilege wall. Reporting
///     this as "not enforcing" is the failure mode the architecture doc calls out in §8.
///
/// `enforcement_known` is what lets the rule fire on the middle case and stay silent on the last.
pub fn detect_mac_status(
    apparmor_profiles: Option<&str>,
    apparmor_lsm_active: bool,
    selinux_enforce: Option<&str>,
) -> Fact {
    let mut fact = Fact::new();

    // Present if the kernel says so via a world-readable path, even when the profile list itself
    // is unreadable — that's the whole point of consulting the LSM list.
    let apparmor_present = apparmor_lsm_active || apparmor_profiles.is_some();
    let apparmor_enforcing = apparmor_profiles
        .map(|text| text.lines().any(|l| l.trim_end().ends_with("(enforce)")))
        .unwrap_or(false);
    // If AppArmor isn't present at all, "AppArmor is not enforcing" is a sound conclusion, not a
    // guess. It's only unknowable when AppArmor *is* loaded and the profile list is walled off.
    let apparmor_enforcement_known = apparmor_profiles.is_some() || !apparmor_present;

    // SELinux's `enforce` node is genuinely world-readable, so its state is never in doubt: either
    // the file is there and we read it, or SELinux isn't on this host.
    let selinux_present = selinux_enforce.is_some();
    let selinux_enforcing = selinux_enforce.map(|t| t.trim() == "1").unwrap_or(false);

    let any_mac_enforcing = apparmor_enforcing || selinux_enforcing;

    // Finding something enforcing settles the question regardless of what else we couldn't read.
    // Concluding *nothing* is enforcing requires having actually been able to look everywhere.
    let enforcement_known = any_mac_enforcing || apparmor_enforcement_known;

    fact.insert(
        "apparmor_present".to_string(),
        Value::Bool(apparmor_present),
    );
    fact.insert(
        "apparmor_enforcing_any".to_string(),
        Value::Bool(apparmor_enforcing),
    );
    fact.insert("selinux_present".to_string(), Value::Bool(selinux_present));
    fact.insert(
        "selinux_enforcing".to_string(),
        Value::Bool(selinux_enforcing),
    );
    fact.insert(
        "any_mac_enforcing".to_string(),
        Value::Bool(any_mac_enforcing),
    );
    fact.insert(
        "enforcement_known".to_string(),
        Value::Bool(enforcement_known),
    );
    fact
}

/// True when the kernel reports AppArmor as an active LSM. Both paths are world-readable (unlike
/// the profile list), so this works in an unprivileged scan.
fn apparmor_lsm_active() -> bool {
    let in_lsm_list = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|lsms| lsms.trim().split(',').any(|l| l.trim() == "apparmor"))
        .unwrap_or(false);
    let module_enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|v| matches!(v.trim(), "Y" | "1"))
        .unwrap_or(false);
    in_lsm_list || module_enabled
}

impl Collector for MacStatusCollector {
    fn name(&self) -> &'static str {
        "mac_status"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let apparmor = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles").ok();
        let selinux = std::fs::read_to_string("/sys/fs/selinux/enforce").ok();
        Ok(vec![detect_mac_status(
            apparmor.as_deref(),
            apparmor_lsm_active(),
            selinux.as_deref(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_mac_framework_at_all_is_a_known_and_real_finding() {
        // Nothing installed, nothing enforcing, and we are entitled to say so — this host really
        // does lack mandatory access control, and the rule should fire.
        let fact = detect_mac_status(None, false, None);
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(false));
        assert_eq!(fact.get("enforcement_known").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn apparmor_loaded_but_profile_list_unreadable_is_unknown_not_unenforced() {
        // The regression that shipped: an unprivileged scan on stock Ubuntu gets EACCES reading
        // /sys/kernel/security/apparmor/profiles (mode 0444, but the kernel gates it on
        // CAP_MAC_ADMIN). The old code called that "no MAC framework is enforcing" and raised a
        // MEDIUM on a perfectly well-defended laptop.
        let fact = detect_mac_status(None, true, None);
        assert_eq!(
            fact.get("apparmor_present").unwrap(),
            &Value::Bool(true),
            "the LSM list still tells us AppArmor is right there"
        );
        assert_eq!(
            fact.get("enforcement_known").unwrap(),
            &Value::Bool(false),
            "we could not see the profile list, so we must not claim nothing is enforcing"
        );
    }

    #[test]
    fn apparmor_profiles_but_all_complain_mode_is_not_enforcing() {
        let profiles = "/usr/sbin/ntpd (complain)\n/usr/bin/man (complain)\n";
        let fact = detect_mac_status(Some(profiles), true, None);
        assert_eq!(fact.get("apparmor_present").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(false));
        assert_eq!(
            fact.get("enforcement_known").unwrap(),
            &Value::Bool(true),
            "we read the list and it really is all permissive — a true finding"
        );
    }

    #[test]
    fn apparmor_with_an_enforce_profile_counts_as_enforcing() {
        let profiles = "/usr/sbin/ntpd (complain)\n/usr/sbin/sshd (enforce)\n";
        let fact = detect_mac_status(Some(profiles), true, None);
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("enforcement_known").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn selinux_enforce_file_of_one_means_enforcing() {
        let fact = detect_mac_status(None, false, Some("1\n"));
        assert_eq!(fact.get("selinux_enforcing").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("enforcement_known").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn selinux_enforcing_settles_the_question_even_if_apparmor_is_opaque() {
        // Finding *something* enforcing is a positive observation — it doesn't matter that the
        // AppArmor half was unreadable, because the host demonstrably has MAC coverage.
        let fact = detect_mac_status(None, true, Some("1\n"));
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("enforcement_known").unwrap(), &Value::Bool(true));
    }
}

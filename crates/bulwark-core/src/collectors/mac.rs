use super::Collector;
use crate::models::Fact;
use serde_json::Value;

pub struct MacStatusCollector;

/// Mandatory-access-control status: which framework is present, and whether it's actually
/// enforcing rather than just installed. Installed-but-permissive is a common gap Lynis
/// flags under its own `tests_mac_frameworks` category (see research report §1).
pub fn detect_mac_status(apparmor_profiles: Option<&str>, selinux_enforce: Option<&str>) -> Fact {
    let mut fact = Fact::new();

    let apparmor_enabled = apparmor_profiles.is_some();
    let apparmor_enforcing = apparmor_profiles
        .map(|text| text.lines().any(|l| l.trim_end().ends_with("(enforce)")))
        .unwrap_or(false);

    let selinux_enabled = selinux_enforce.is_some();
    let selinux_enforcing = selinux_enforce.map(|t| t.trim() == "1").unwrap_or(false);

    fact.insert(
        "apparmor_present".to_string(),
        Value::Bool(apparmor_enabled),
    );
    fact.insert(
        "apparmor_enforcing_any".to_string(),
        Value::Bool(apparmor_enforcing),
    );
    fact.insert("selinux_present".to_string(), Value::Bool(selinux_enabled));
    fact.insert(
        "selinux_enforcing".to_string(),
        Value::Bool(selinux_enforcing),
    );
    fact.insert(
        "any_mac_enforcing".to_string(),
        Value::Bool(apparmor_enforcing || selinux_enforcing),
    );
    fact
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
            selinux.as_deref(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_present_means_nothing_enforcing() {
        let fact = detect_mac_status(None, None);
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn apparmor_profiles_but_all_complain_mode_is_not_enforcing() {
        let profiles = "/usr/sbin/ntpd (complain)\n/usr/bin/man (complain)\n";
        let fact = detect_mac_status(Some(profiles), None);
        assert_eq!(fact.get("apparmor_present").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn apparmor_with_an_enforce_profile_counts_as_enforcing() {
        let profiles = "/usr/sbin/ntpd (complain)\n/usr/sbin/sshd (enforce)\n";
        let fact = detect_mac_status(Some(profiles), None);
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn selinux_enforce_file_of_one_means_enforcing() {
        let fact = detect_mac_status(None, Some("1\n"));
        assert_eq!(fact.get("selinux_enforcing").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("any_mac_enforcing").unwrap(), &Value::Bool(true));
    }
}

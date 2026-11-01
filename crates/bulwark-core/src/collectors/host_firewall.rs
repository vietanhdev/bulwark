//! Whether the host filters inbound traffic at all. The authoritative answer is the kernel's packet
//! filter, which only root can list, so this collector is privileged. ufw and firewalld both
//! program that filter, so reading it covers them; their own state is reported alongside for the
//! explanation.
//!
//! Three-state: `firewall_known` is true only when the packet filter was actually listed. A scan
//! that couldn't list it never claims the firewall is off.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::process::Command;

pub struct HostFirewallCollector;

/// True if an nftables ruleset filters inbound traffic: some chain hooked on `input` either has a
/// drop policy or contains a drop/reject verdict.
pub fn nft_filters_input(ruleset: &str) -> bool {
    ruleset.split("chain ").skip(1).any(|chain| {
        let body = chain.split("\n\t}").next().unwrap_or(chain);
        body.contains("hook input")
            && (body.contains("policy drop")
                || body.lines().any(|l| {
                    let l = l.trim();
                    l.ends_with(" drop") || l == "drop" || l.contains("reject")
                }))
    })
}

/// True if `iptables -S INPUT` output shows inbound filtering (drop policy, or a DROP/REJECT rule).
pub fn iptables_filters_input(rules: &str) -> bool {
    rules.lines().any(|l| {
        let l = l.trim();
        l == "-P INPUT DROP" || l.contains("-j DROP") || l.contains("-j REJECT")
    })
}

/// `Some(true/false)` from `/etc/ufw/ufw.conf`'s `ENABLED=`; `None` if ufw isn't installed.
pub fn ufw_enabled_from_conf(conf: &str) -> Option<bool> {
    conf.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("ENABLED="))
        .map(|v| {
            v.trim_matches(|c| c == '"' || c == '\'')
                .eq_ignore_ascii_case("yes")
        })
}

/// True when ufw is enabled with a deny/reject default for incoming traffic. Both files are
/// world-readable, so an unprivileged scan can tell — unlike the packet filter itself. Used by the
/// listening-ports collector so a service on 0.0.0.0 behind a default-deny firewall isn't reported
/// as "reachable by anyone on the network". `/etc/default/ufw` ships `DEFAULT_INPUT_POLICY="DROP"`.
pub fn ufw_denies_inbound(ufw_conf: &str, ufw_default: &str) -> bool {
    let policy_denies = ufw_default
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("DEFAULT_INPUT_POLICY="))
        .map(|v| {
            let v = v.trim_matches(|c| c == '"' || c == '\'');
            v.eq_ignore_ascii_case("DROP") || v.eq_ignore_ascii_case("REJECT")
        })
        .unwrap_or(false);
    ufw_enabled_from_conf(ufw_conf) == Some(true) && policy_denies
}

/// [`ufw_denies_inbound`] for this host.
pub fn host_ufw_denies_inbound() -> bool {
    match (
        std::fs::read_to_string("/etc/ufw/ufw.conf"),
        std::fs::read_to_string("/etc/default/ufw"),
    ) {
        (Ok(conf), Ok(default)) => ufw_denies_inbound(&conf, &default),
        _ => false,
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Collector for HostFirewallCollector {
    fn name(&self) -> &'static str {
        "host_firewall"
    }

    fn requires_privilege(&self) -> bool {
        true
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut fact = Fact::new();

        let ufw = std::fs::read_to_string("/etc/ufw/ufw.conf")
            .ok()
            .and_then(|c| ufw_enabled_from_conf(&c));
        if let Some(enabled) = ufw {
            fact.insert("ufw_enabled".into(), Value::Bool(enabled));
        }
        if let Ok(state) = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
        {
            let active = String::from_utf8_lossy(&state.stdout).trim() == "active";
            fact.insert("firewalld_active".into(), Value::Bool(active));
        }

        // The kernel filter is the ground truth; try nftables first, then iptables.
        let filtering = run("nft", &["list", "ruleset"])
            .map(|r| nft_filters_input(&r))
            .or_else(|| run("iptables", &["-S", "INPUT"]).map(|r| iptables_filters_input(&r)));

        fact.insert("firewall_known".into(), Value::Bool(filtering.is_some()));
        fact.insert(
            "firewall_active".into(),
            Value::Bool(filtering.unwrap_or(false) || ufw == Some(true)),
        );
        Ok(vec![fact])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_input_chain_with_drop_policy_counts() {
        let rs = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established accept\n\t}\n}\n";
        assert!(nft_filters_input(rs));
    }

    #[test]
    fn docker_only_ruleset_is_not_inbound_filtering() {
        // Docker installs an accept-policy INPUT chain and its own FORWARD rules — no filtering.
        let rs = "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n";
        assert!(!nft_filters_input(rs));
    }

    #[test]
    fn iptables_rules_are_read() {
        assert!(iptables_filters_input("-P INPUT DROP\n"));
        assert!(iptables_filters_input(
            "-P INPUT ACCEPT\n-A INPUT -p tcp -j REJECT\n"
        ));
        assert!(!iptables_filters_input("-P INPUT ACCEPT\n"));
    }

    #[test]
    fn ufw_default_deny_is_recognised() {
        assert!(ufw_denies_inbound(
            "ENABLED=yes\n",
            "DEFAULT_INPUT_POLICY=\"DROP\"\n"
        ));
        assert!(ufw_denies_inbound(
            "ENABLED=yes\n",
            "DEFAULT_INPUT_POLICY=\"REJECT\"\n"
        ));
        assert!(!ufw_denies_inbound(
            "ENABLED=no\n",
            "DEFAULT_INPUT_POLICY=\"DROP\"\n"
        ));
        assert!(!ufw_denies_inbound(
            "ENABLED=yes\n",
            "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n"
        ));
        assert!(!ufw_denies_inbound("", ""));
    }

    #[test]
    fn ufw_conf_is_parsed() {
        assert_eq!(ufw_enabled_from_conf("ENABLED=yes\n"), Some(true));
        assert_eq!(ufw_enabled_from_conf("# x\nENABLED=no\n"), Some(false));
        assert_eq!(ufw_enabled_from_conf("LOGLEVEL=low\n"), None);
    }
}

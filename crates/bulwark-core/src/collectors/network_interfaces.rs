//! Detects network interfaces running in promiscuous mode — the classic packet-sniffer
//! indicator chkrootkit's own `sniffer` test checks for (`ifpromisc`). A normal desktop/server
//! interface is never promiscuous; enabling it is exactly what lets a packet sniffer capture
//! traffic that isn't addressed to this host.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// `IFF_PROMISC`, from `<linux/if.h>` — the flag bit `/sys/class/net/<iface>/flags` reports.
const IFF_PROMISC: u32 = 0x100;

/// Parses the hex text a real `/sys/class/net/<iface>/flags` file contains (e.g. `"0x1003\n"`
/// — verified against this project's own dev machine, which has 20+ real interfaces, none
/// promiscuous) and checks the `IFF_PROMISC` bit. An unparseable value degrades to "not
/// promiscuous" rather than erroring the whole collector over one odd interface.
pub fn is_promiscuous(flags_text: &str) -> bool {
    let trimmed = flags_text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u32::from_str_radix(trimmed, 16)
        .map(|flags| flags & IFF_PROMISC != 0)
        .unwrap_or(false)
}

pub struct NetworkInterfacesCollector;

impl Collector for NetworkInterfacesCollector {
    fn name(&self) -> &'static str {
        "network_interfaces"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/sys/class/net").is_dir()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        for entry in std::fs::read_dir("/sys/class/net")?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                // Loopback traffic never leaves the host — not a sniffing vector, and some
                // kernels report it with unrelated flag bits that would just be noise here.
                continue;
            }
            let Ok(flags_text) = std::fs::read_to_string(entry.path().join("flags")) else {
                continue;
            };
            let mut fact = Fact::new();
            fact.insert("interface".to_string(), Value::String(name));
            fact.insert(
                "promiscuous".to_string(),
                Value::Bool(is_promiscuous(&flags_text)),
            );
            rows.push(fact);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_observed_flag_values_on_this_machine_are_not_promiscuous() {
        // Actual /sys/class/net/*/flags values read from this dev machine's own interfaces
        // (docker bridges, wifi, tailscale, loopback) — none are promiscuous, and this locks
        // that in as a regression test rather than trusting the bit math by inspection alone.
        for real_flags in ["0x1003\n", "0x1091\n", "0x9\n"] {
            assert!(
                !is_promiscuous(real_flags),
                "{real_flags} should not read as promiscuous"
            );
        }
    }

    #[test]
    fn detects_the_promiscuous_bit_when_set() {
        // 0x1003 (this machine's normal bridge-interface flags) with IFF_PROMISC (0x100)
        // additionally set.
        assert!(is_promiscuous("0x1103\n"));
    }

    #[test]
    fn unparseable_flags_degrade_to_not_promiscuous_rather_than_erroring() {
        assert!(!is_promiscuous("not-hex-at-all"));
        assert!(!is_promiscuous(""));
    }

    #[test]
    fn collects_real_interfaces_from_this_machine_excluding_loopback() {
        let rows = NetworkInterfacesCollector.collect().unwrap();
        assert!(
            !rows.is_empty(),
            "this dev machine has real non-loopback interfaces"
        );
        assert!(
            rows.iter().all(|f| f.get("interface").unwrap() != "lo"),
            "loopback must be excluded"
        );
        assert!(
            rows.iter()
                .all(|f| f.get("promiscuous") == Some(&Value::Bool(false))),
            "no interface on this real machine is actually promiscuous"
        );
    }
}

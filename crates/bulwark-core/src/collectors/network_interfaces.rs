//! Detects network interfaces running in promiscuous mode — the classic packet-sniffer
//! indicator chkrootkit's own `sniffer` test checks for (`ifpromisc`). Enabling it is exactly
//! what lets a packet sniffer capture traffic that isn't addressed to this host.
//!
//! The catch chkrootkit's 1997-era heuristic never had to handle: **bridge ports are always
//! promiscuous, by design**. `br_add_if()` calls `dev_set_promiscuity()` on every interface it
//! enslaves, because forwarding frames not addressed to you is the entire job of a bridge port.
//! Docker attaches a fresh `vethXXXX` to a bridge for every container it starts, so a flag-only
//! check fires HIGH on every container launch on every Docker host, forever. We therefore also
//! report whether the interface is a bridge port, so the rule can exclude the expected case
//! without going blind on a real NIC.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// `IFF_PROMISC`, from `<linux/if.h>` — the flag bit `/sys/class/net/<iface>/flags` reports.
const IFF_PROMISC: u32 = 0x100;

/// True when the interface is enslaved to a bridge. The kernel materializes a `brport/`
/// directory under an interface's sysfs node if and only if it is a bridge port, which makes
/// this a structural test rather than a name test — an attacker who names a tap device `veth0`
/// to hide in the noise gains nothing, because it still has no `brport/`.
fn is_bridge_port(iface_dir: &Path) -> bool {
    iface_dir.join("brport").is_dir()
}

/// Parses the hex text a real `/sys/class/net/<iface>/flags` file contains (e.g. `"0x1003\n"`
/// — verified against this project's own dev machine, which has 20+ real interfaces, none
/// promiscuous) and checks the `IFF_PROMISC` bit. Returns `None` when the value can't be parsed:
/// per the collector invariant, "couldn't read the flags" is undetermined, not a confident "not
/// promiscuous" — the latter would let an interface whose flags we couldn't parse read as clean.
pub fn is_promiscuous(flags_text: &str) -> Option<bool> {
    let trimmed = flags_text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u32::from_str_radix(trimmed, 16)
        .ok()
        .map(|flags| flags & IFF_PROMISC != 0)
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
            // Undetermined if the flags file can't be read or parsed — emit the interface with
            // `promiscuous_known: false` rather than dropping it (a dropped row is never evaluated,
            // so a sniffing interface whose flags we couldn't read would silently vanish) or
            // asserting a confident `promiscuous: false` (which would read as a clean interface).
            let promiscuous = std::fs::read_to_string(entry.path().join("flags"))
                .ok()
                .and_then(|t| is_promiscuous(&t));
            let mut fact = Fact::new();
            fact.insert("interface".to_string(), Value::String(name));
            fact.insert(
                "promiscuous".to_string(),
                Value::Bool(promiscuous.unwrap_or(false)),
            );
            fact.insert(
                "promiscuous_known".to_string(),
                Value::Bool(promiscuous.is_some()),
            );
            fact.insert(
                "bridge_port".to_string(),
                Value::Bool(is_bridge_port(&entry.path())),
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
            assert_eq!(
                is_promiscuous(real_flags),
                Some(false),
                "{real_flags} should read as known-not-promiscuous"
            );
        }
    }

    #[test]
    fn detects_the_promiscuous_bit_when_set() {
        // 0x1003 (this machine's normal bridge-interface flags) with IFF_PROMISC (0x100)
        // additionally set.
        assert_eq!(is_promiscuous("0x1103\n"), Some(true));
    }

    #[test]
    fn unparseable_flags_are_undetermined_not_a_confident_not_promiscuous() {
        // The collector-invariant case: a value we can't parse must come back `None` (undetermined),
        // never `Some(false)` — otherwise an interface we couldn't read would read as clean.
        assert_eq!(is_promiscuous("not-hex-at-all"), None);
        assert_eq!(is_promiscuous(""), None);
    }

    #[test]
    fn bridge_port_is_decided_by_the_kernels_brport_directory_not_the_interface_name() {
        let tmp = tempfile::tempdir().unwrap();

        // A bridge-enslaved interface: the kernel materializes `brport/` under it.
        let enslaved = tmp.path().join("veth6dc1556");
        std::fs::create_dir_all(enslaved.join("brport")).unwrap();
        assert!(is_bridge_port(&enslaved));

        // A tap device an attacker named to *look* like a container veth has no `brport/`,
        // so it stays visible to the rule. This is the whole reason the check is structural.
        let impostor = tmp.path().join("veth0");
        std::fs::create_dir_all(&impostor).unwrap();
        assert!(!is_bridge_port(&impostor));
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
        // Deliberately asserts the *shape* of every row and not the promiscuous values. The
        // previous version of this test asserted no interface here was promiscuous, which was
        // only ever true because no container happened to be running: `docker run` attaches a
        // veth to a bridge, the kernel sets IFF_PROMISC on it, and the suite went red on a
        // machine that was behaving perfectly normally. Live host state is not a fixture.
        for fact in &rows {
            assert!(fact.get("promiscuous").unwrap().is_boolean());
            assert!(fact.get("bridge_port").unwrap().is_boolean());
        }
    }
}

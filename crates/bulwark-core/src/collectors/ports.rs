use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct ListeningPortsCollector;

const TCP_LISTEN_STATE: &str = "0A";

/// True if the local-address hex from `/proc/net/tcp{,6}` is a loopback address — a socket bound
/// only to loopback is reachable only from this host, so it is not the remotely-exploitable
/// exposure the port rules describe. IPv4 is stored little-endian, so 127.0.0.0/8 is "the last
/// octet, i.e. the last two hex chars, is 7F". IPv6 loopback is `::1`.
fn is_loopback(ip_hex: &str) -> bool {
    match ip_hex.len() {
        8 => ip_hex
            .get(6..8)
            .is_some_and(|last| last.eq_ignore_ascii_case("7f")),
        32 => ip_hex.eq_ignore_ascii_case("00000000000000000000000001000000"),
        _ => false,
    }
}

/// A human-readable rendering of the bind address for the finding's explain text. IPv4 is fully
/// decoded (little-endian); IPv6 is labelled at the useful granularity (`::`, `::1`, or `ipv6`)
/// rather than doing the fiddly word-order expansion, since the rules only need to distinguish
/// "all interfaces" from "loopback".
fn decode_addr(ip_hex: &str) -> String {
    match ip_hex.len() {
        8 => {
            let b = |i: usize| u8::from_str_radix(&ip_hex[i..i + 2], 16).unwrap_or(0);
            format!("{}.{}.{}.{}", b(6), b(4), b(2), b(0))
        }
        32 if ip_hex == "00000000000000000000000000000000" => "::".to_string(),
        32 if ip_hex.eq_ignore_ascii_case("00000000000000000000000001000000") => "::1".to_string(),
        32 => "ipv6".to_string(),
        _ => ip_hex.to_string(),
    }
}

/// Parses `/proc/net/tcp`-format text (also valid for `/proc/net/tcp6`) into one fact row
/// per LISTEN-state socket, capturing the bind address so a rule can tell a loopback-only
/// listener (harmless) from one exposed on all interfaces. Doesn't require root, unlike shelling
/// out to `ss -tlnp` for the owning process name — v1 reports the port, not the process.
pub fn parse_proc_net_tcp(text: &str, protocol: &str) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let state = fields[3];
        if state != TCP_LISTEN_STATE {
            continue;
        }
        let Some((ip_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let mut fact = Fact::new();
        fact.insert("port".to_string(), Value::from(port));
        fact.insert("protocol".to_string(), Value::String(protocol.to_string()));
        fact.insert(
            "listen_address".to_string(),
            Value::String(decode_addr(ip_hex)),
        );
        fact.insert(
            "loopback_only".to_string(),
            Value::Bool(is_loopback(ip_hex)),
        );
        rows.push(fact);
    }
    rows
}

impl Collector for ListeningPortsCollector {
    fn name(&self) -> &'static str {
        "listening_ports"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/proc/net/tcp").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        if let Ok(text) = std::fs::read_to_string("/proc/net/tcp") {
            rows.extend(parse_proc_net_tcp(&text, "tcp"));
        }
        if let Ok(text) = std::fs::read_to_string("/proc/net/tcp6") {
            rows.extend(parse_proc_net_tcp(&text, "tcp6"));
        }
        // A service that listens on both IPv4 and IPv6 shows up once in /proc/net/tcp and once in
        // tcp6, which made a port rule fire twice for one service. Collapse rows with the same
        // (port, loopback disposition): it's one exposure, so it should be one finding.
        let mut seen = std::collections::HashSet::new();
        rows.retain(|f| {
            let key = (
                f.get("port").and_then(Value::as_u64),
                f.get("loopback_only").and_then(Value::as_bool),
            );
            seen.insert(key)
        });
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_state_only() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 00000000:1770 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
             1: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1\n";
        let rows = parse_proc_net_tcp(text, "tcp");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("port").unwrap(), &Value::from(0x1770u16));
    }

    #[test]
    fn distinguishes_loopback_from_all_interfaces() {
        // 0.0.0.0:5900 (all interfaces) vs 127.0.0.1:5900 (loopback). The loopback one must NOT be
        // treated as a remote-desktop backdoor — that was the false positive on container-published
        // and SSH-tunnel VNC.
        let text = "sl local rem st ...\n\
             0: 00000000:170C 00000000:0000 0A 0 0 0 0 0 1 1\n\
             1: 0100007F:170C 00000000:0000 0A 0 0 0 0 0 1 1\n";
        let rows = parse_proc_net_tcp(text, "tcp");
        assert_eq!(rows.len(), 2);
        let all = rows
            .iter()
            .find(|r| r.get("loopback_only").unwrap() == &Value::Bool(false))
            .unwrap();
        let lo = rows
            .iter()
            .find(|r| r.get("loopback_only").unwrap() == &Value::Bool(true))
            .unwrap();
        assert_eq!(all.get("listen_address").unwrap(), "0.0.0.0");
        assert_eq!(lo.get("listen_address").unwrap(), "127.0.0.1");
    }

    #[test]
    fn ipv6_loopback_is_recognized() {
        // ::1 (loopback) should be loopback_only; :: (all) should not.
        assert!(is_loopback("00000000000000000000000001000000"));
        assert!(!is_loopback("00000000000000000000000000000000"));
    }
}

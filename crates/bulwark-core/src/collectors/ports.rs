use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct ListeningPortsCollector;

const TCP_LISTEN_STATE: &str = "0A";

/// Parses `/proc/net/tcp`-format text (also valid for `/proc/net/tcp6`) into one fact row
/// per LISTEN-state socket. Doesn't require root, unlike shelling out to `ss -tlnp` for the
/// owning process name — v1 reports the port, not the process (see architecture doc §14 for what's
/// still open).
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
        let Some((_ip_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let mut fact = Fact::new();
        fact.insert("port".to_string(), Value::from(port));
        fact.insert("protocol".to_string(), Value::String(protocol.to_string()));
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
}

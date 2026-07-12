use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct SysctlKernelCollector;

/// The `/proc/sys/...` hardening flags worth a rule, mapped to the flat field name a rule
/// condition reads. Reading `/proc/sys` directly needs no privilege for these specific
/// keys, unlike `sysctl -a`'s occasional permission-gated entries — `net.core.bpf_jit_harden`
/// was deliberately left off this list even though Lynis checks it, because on a stock
/// kernel its `/proc/sys` node is `-rw-------` (root-only); including it here would make
/// every unprivileged rule referencing it fail with "field not found" on most machines,
/// not report a real finding. Sourced from Lynis's `default.prf` (`config-data=sysctl;...`
/// lines), filtered down to the keys that are Linux-specific (Lynis's list also carries
/// FreeBSD/macOS `security.bsd.*` and `net.inet.*` keys, which don't exist on Linux) and
/// world-readable in practice.
const WATCHED: &[(&str, &str)] = &[
    ("/proc/sys/kernel/yama/ptrace_scope", "ptrace_scope"),
    ("/proc/sys/kernel/dmesg_restrict", "dmesg_restrict"),
    ("/proc/sys/kernel/kptr_restrict", "kptr_restrict"),
    ("/proc/sys/net/ipv4/conf/all/rp_filter", "rp_filter"),
    ("/proc/sys/net/ipv4/tcp_syncookies", "tcp_syncookies"),
    ("/proc/sys/kernel/randomize_va_space", "randomize_va_space"),
    ("/proc/sys/kernel/sysrq", "sysrq"),
    (
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "unprivileged_bpf_disabled",
    ),
    (
        "/proc/sys/kernel/perf_event_paranoid",
        "perf_event_paranoid",
    ),
    (
        "/proc/sys/kernel/kexec_load_disabled",
        "kexec_load_disabled",
    ),
    ("/proc/sys/fs/suid_dumpable", "suid_dumpable"),
    ("/proc/sys/fs/protected_hardlinks", "protected_hardlinks"),
    ("/proc/sys/fs/protected_symlinks", "protected_symlinks"),
    ("/proc/sys/fs/protected_fifos", "protected_fifos"),
    ("/proc/sys/fs/protected_regular", "protected_regular"),
    (
        "/proc/sys/net/ipv4/conf/all/accept_redirects",
        "accept_redirects",
    ),
    (
        "/proc/sys/net/ipv4/conf/all/accept_source_route",
        "accept_source_route",
    ),
    (
        "/proc/sys/net/ipv4/conf/all/send_redirects",
        "send_redirects",
    ),
    ("/proc/sys/net/ipv4/conf/all/log_martians", "log_martians"),
];

impl Collector for SysctlKernelCollector {
    fn name(&self) -> &'static str {
        "sysctl_kernel"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/proc/sys/kernel").is_dir()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut fact = Fact::new();
        for (path, field) in WATCHED {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(n) = text.trim().parse::<i64>() {
                    fact.insert(field.to_string(), Value::from(n));
                }
            }
            // A missing/unreadable flag (older kernel, different sysctl layout) is left
            // out of the fact map rather than defaulted — a rule reading it then reports
            // MissingField, which surfaces as a collector-level condition error (§8),
            // not a false "secure" or false "vulnerable" reading.
        }
        Ok(vec![fact])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_applicable_when_proc_sys_kernel_exists() {
        // This test runs on a real Linux CI/dev box, so /proc/sys/kernel genuinely exists —
        // exercising the real path rather than a fixture keeps this collector's one branch honest.
        assert!(SysctlKernelCollector.is_applicable());
    }

    #[test]
    fn collects_the_expanded_hardening_keys_from_a_real_kernel() {
        // Every WATCHED key here is world-readable on a stock Linux kernel (unlike
        // net.core.bpf_jit_harden, deliberately excluded — see the WATCHED doc comment).
        // Reading the real /proc/sys on this CI/dev box is what actually caught, during
        // development, that bpf_jit_harden is root-only and would have broken this contract.
        let rows = SysctlKernelCollector.collect().unwrap();
        let fact = &rows[0];
        for field in [
            "randomize_va_space",
            "sysrq",
            "unprivileged_bpf_disabled",
            "perf_event_paranoid",
            "kexec_load_disabled",
            "suid_dumpable",
            "protected_hardlinks",
            "protected_symlinks",
            "protected_fifos",
            "protected_regular",
            "accept_redirects",
            "accept_source_route",
            "send_redirects",
            "log_martians",
        ] {
            assert!(
                fact.contains_key(field),
                "expected field '{field}' to be collected from a real kernel"
            );
        }
    }
}

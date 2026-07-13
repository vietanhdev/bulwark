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
];

/// How the kernel folds `conf/all/<key>` together with each interface's own `conf/<iface>/<key>`
/// (from `include/linux/inetdevice.h`). Reading `conf/all` alone — which the old collector did for
/// all five of these keys — is *not* the value the kernel enforces, and it was wrong in both
/// directions: it reported `rp_filter` "disabled" on hosts where `max(all=0, iface=1)=1` means it's
/// fully on, and stayed silent on hosts accepting ICMP redirects via `or(all=0, iface=1)`.
#[derive(Clone, Copy)]
enum Fold {
    And,
    Or,
    Max,
    /// `accept_redirects` — the operator flips on whether the interface is forwarding
    /// (`IN_DEV_RX_REDIRECTS`): forwarding hosts AND the values, non-forwarding hosts OR them.
    RxRedirects,
}

/// Whether the *risky* direction for a key is a high value (redirects accepted/sent, source
/// routing on) or a low one (reverse-path filtering / martian logging off). Determines which
/// interface is the "worst" one to report: the one most exposed.
#[derive(Clone, Copy)]
enum Risk {
    High,
    Low,
}

/// The per-interface network keys, with the fold operator and risk direction the kernel uses.
const PER_IFACE: &[(&str, Fold, Risk)] = &[
    ("rp_filter", Fold::Max, Risk::Low),            // IN_DEV_RPFILTER
    ("log_martians", Fold::Or, Risk::Low),          // IN_DEV_LOG_MARTIANS
    ("send_redirects", Fold::Or, Risk::High),       // IN_DEV_TX_REDIRECTS
    ("accept_source_route", Fold::And, Risk::High), // IN_DEV_SOURCE_ROUTE
    ("accept_redirects", Fold::RxRedirects, Risk::High), // IN_DEV_RX_REDIRECTS
];

/// The effective value of a per-interface key on one interface, given `conf/all` and the
/// interface's own value plus whether it forwards.
fn fold_one(fold: Fold, all: i64, iface: i64, iface_forwarding: bool) -> i64 {
    match fold {
        Fold::And => i64::from(all != 0 && iface != 0),
        Fold::Or => i64::from(all != 0 || iface != 0),
        Fold::Max => all.max(iface),
        Fold::RxRedirects => {
            if iface_forwarding {
                i64::from(all != 0 && iface != 0)
            } else {
                i64::from(all != 0 || iface != 0)
            }
        }
    }
}

/// The least-safe effective value across all real interfaces — a security scan should report the
/// most-exposed interface, not an average. For a high-risk key that's the maximum (any interface
/// with it enabled is the exposure); for a low-risk key the minimum (any interface with it
/// disabled is the gap). With no real interfaces to fold against, falls back to `all` rather than
/// inventing a value.
fn effective(fold: Fold, risk: Risk, all: i64, ifaces: &[(i64, bool)]) -> i64 {
    if ifaces.is_empty() {
        return all;
    }
    let folded = ifaces.iter().map(|&(v, fwd)| fold_one(fold, all, v, fwd));
    match risk {
        Risk::High => folded.max().unwrap_or(all),
        Risk::Low => folded.min().unwrap_or(all),
    }
}

fn read_i64(path: &str) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Real interface names under `/proc/sys/net/ipv4/conf`, excluding the `all`/`default` pseudo
/// entries (which are not devices the kernel folds against).
fn real_interfaces() -> Vec<String> {
    std::fs::read_dir("/proc/sys/net/ipv4/conf")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "all" && n != "default")
        .collect()
}

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

        // Kernel lockdown mode gates whether an *unsigned* kexec image can actually be loaded, so
        // the kexec rule needs it to avoid firing where the attack is already impossible. The node
        // renders as `none [integrity] confidentiality` — the bracketed token is the active mode.
        // If it can't be read we record "unknown", NOT "none": claiming lockdown is off because we
        // couldn't look would be the same absence-as-evidence mistake this codebase keeps finding.
        let lockdown = std::fs::read_to_string("/sys/kernel/security/lockdown")
            .ok()
            .and_then(|t| {
                t.split('[')
                    .nth(1)
                    .and_then(|s| s.split(']').next())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".to_string());
        fact.insert("lockdown".to_string(), Value::String(lockdown));

        // sysrq is 0=off, 1=all functions, >1=bitmask. A bitmask that includes the dangerous bits
        // is as bad as full-on, which `sysrq == 1` alone misses. 0x08 = SYSRQ_ENABLE_DUMP (kernel
        // memory dumps), 0x40 = SYSRQ_ENABLE_SIGNAL (SIGKILL any process).
        if let Some(sysrq) = fact.get("sysrq").and_then(Value::as_i64) {
            fact.insert(
                "sysrq_dump_or_signal".to_string(),
                Value::Bool(sysrq != 1 && (sysrq & 0x48) != 0),
            );
        }

        // ptrace_scope is implemented by the Yama LSM. If its node is absent, Yama isn't loaded and
        // ptrace is *entirely* unrestricted — a stronger finding than scope=0, not an unknown. The
        // WATCHED loop above omits the key when its path is missing, which would leave
        // BLWK-KERNEL-001 to abstain on MissingField. So when Yama is provably absent, emit
        // scope=0 explicitly (the worst case it would report anyway) plus a `yama_present` flag.
        let yama_present = Path::new("/proc/sys/kernel/yama/ptrace_scope").exists();
        fact.insert("yama_present".to_string(), Value::Bool(yama_present));
        if !yama_present {
            fact.insert("ptrace_scope".to_string(), Value::from(0));
        }

        // The five per-interface keys: emit the *effective* value the kernel enforces, under the
        // same flat field name the rules already read, so no rule condition changes.
        let interfaces = real_interfaces();
        for (field, fold, risk) in PER_IFACE {
            let Some(all) = read_i64(&format!("/proc/sys/net/ipv4/conf/all/{field}")) else {
                continue; // unreadable → MissingField, same tri-state discipline as above
            };
            let iface_vals: Vec<(i64, bool)> = interfaces
                .iter()
                .filter_map(|i| {
                    let v = read_i64(&format!("/proc/sys/net/ipv4/conf/{i}/{field}"))?;
                    let fwd = read_i64(&format!("/proc/sys/net/ipv4/conf/{i}/forwarding"))
                        .unwrap_or(0)
                        != 0;
                    Some((v, fwd))
                })
                .collect();
            fact.insert(
                field.to_string(),
                Value::from(effective(*fold, *risk, all, &iface_vals)),
            );
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
    fn rp_filter_is_max_folded_so_all0_iface1_reads_as_enabled() {
        // The false positive: all=0 but every interface filters (iface=1). rp_filter is MAX-folded,
        // so the kernel has it fully ON — reading `all` alone would wrongly report it disabled.
        let eff = effective(Fold::Max, Risk::Low, 0, &[(1, false), (1, false)]);
        assert_eq!(eff, 1, "max(0,1)=1 on every interface — filtering is on");
        // And genuinely off everywhere is still caught.
        assert_eq!(effective(Fold::Max, Risk::Low, 0, &[(0, false)]), 0);
    }

    #[test]
    fn send_redirects_is_or_folded_and_any_sending_interface_is_the_exposure() {
        // OR fold, high risk: even if all=0, one interface at 1 means the host sends redirects.
        assert_eq!(
            effective(Fold::Or, Risk::High, 0, &[(0, false), (1, false)]),
            1
        );
        assert_eq!(
            effective(Fold::Or, Risk::High, 0, &[(0, false), (0, false)]),
            0
        );
    }

    #[test]
    fn accept_source_route_is_and_folded_so_all1_iface0_does_not_fire() {
        // AND fold: all=1 (kernel default) but interfaces at 0 means source routing is NOT
        // accepted — reading `all` alone produced a false positive here.
        assert_eq!(
            effective(Fold::And, Risk::High, 1, &[(0, false), (0, false)]),
            0
        );
        assert_eq!(effective(Fold::And, Risk::High, 1, &[(1, false)]), 1);
    }

    #[test]
    fn accept_redirects_fold_depends_on_forwarding() {
        // Non-forwarding host: OR — all=0 + iface=1 accepts redirects (the silent FN on a laptop).
        assert_eq!(
            effective(Fold::RxRedirects, Risk::High, 0, &[(1, false)]),
            1,
            "non-forwarding: or(all=0, iface=1) accepts redirects"
        );
        // Forwarding host (this Docker box): AND — all=0 + iface=1 does NOT accept redirects.
        assert_eq!(
            effective(Fold::RxRedirects, Risk::High, 0, &[(1, true)]),
            0,
            "forwarding: and(all=0, iface=1) ignores redirects"
        );
    }

    #[test]
    fn no_interfaces_falls_back_to_the_all_value() {
        assert_eq!(effective(Fold::Or, Risk::High, 1, &[]), 1);
        assert_eq!(effective(Fold::Max, Risk::Low, 0, &[]), 0);
    }

    #[test]
    fn lockdown_and_yama_and_sysrq_derived_fields_are_present_on_a_real_kernel() {
        let rows = SysctlKernelCollector.collect().unwrap();
        let fact = &rows[0];
        // lockdown is always recorded (as a real mode or "unknown"), so KERNEL-008 can gate on it.
        assert!(fact.get("lockdown").unwrap().is_string());
        // yama_present is always emitted; on this dev kernel Yama is loaded.
        assert!(fact.get("yama_present").unwrap().is_boolean());
        // ptrace_scope must be present either way — read from Yama, or forced to 0 when Yama is
        // absent — so BLWK-KERNEL-001 never silently abstains.
        assert!(fact.contains_key("ptrace_scope"));
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

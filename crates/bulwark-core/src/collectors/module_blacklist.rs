//! Checks whether a curated set of rarely-needed, historically-exploited kernel modules are
//! blocked from auto-loading — matches Lynis's `NETW-3200` (uncommon network protocols) and
//! `USB-1000` (USB storage) suggestions. These protocol families have a documented history of
//! local-privilege-escalation bugs reachable by an unprivileged user simply opening a socket
//! of that family, which triggers on-demand module autoloading — blacklisting is the standard
//! mitigation when the protocol genuinely isn't needed.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// `usb-storage` is watched separately from the network protocols (different threat: physical
/// USB exfiltration/BadUSB, not remote LPE) but checked with the identical mechanism, so one
/// collector covers both rather than two near-identical ones.
const WATCHED_MODULES: &[&str] = &["dccp", "sctp", "rds", "tipc", "usb-storage"];

/// Every directory `modprobe` actually consults, in precedence order (`modprobe.d(5)`). Reading
/// only `/etc/modprobe.d` — as the first version did — reports a distro-shipped blacklist under
/// `/usr/lib/modprobe.d` as missing, a false positive on any system that ships its blocks there.
const MODPROBE_DIRS: &[&str] = &[
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/local/lib/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
];

/// modprobe treats `-` and `_` in a module name as identical (`usb-storage` and `usb_storage` are
/// one module; `lsmod` prints the underscore form, so an admin most often writes that). Comparing
/// the raw strings misses a real blacklist written in the other spelling.
fn norm(module: &str) -> String {
    module.replace('-', "_")
}

/// The kernel autoload aliases a module answers to, read from the running kernel's `modules.alias`
/// (lines of the form `alias <pattern> <module>`). Ubuntu blocks the rare network protocols not
/// with `blacklist` but with `alias net-pf-21 off` (and similar), which stops exactly the autoload
/// path these rules describe — so recognising it is what keeps `rds`/`tipc` from false-positiving
/// on a stock Ubuntu box that has, in fact, already mitigated them.
fn autoload_aliases(module: &str, modules_alias_text: &str) -> Vec<String> {
    let target = norm(module);
    modules_alias_text
        .lines()
        .filter_map(|line| {
            let mut p = line.split_whitespace();
            if p.next() != Some("alias") {
                return None;
            }
            let alias = p.next()?;
            let modname = p.next()?;
            (norm(modname) == target).then(|| alias.to_string())
        })
        .collect()
}

/// Whether the module can be loaded on the running kernel at all — present in `modules.dep` or
/// built in per `modules.builtin`. A module that is neither (e.g. `dccp`, removed from the upstream
/// kernel as of 7.0) cannot be loaded and cannot be exploited, so "not blacklisted" is not a real
/// finding for it — there is nothing to block. Without this guard the rule reports an unfixable
/// finding on every modern kernel.
fn is_loadable(module: &str, modules_dep_text: &str, modules_builtin_text: &str) -> bool {
    let target = norm(module);
    let mentions = |text: &str| {
        text.lines().any(|line| {
            // dep:     kernel/net/dccp/dccp.ko.zst: <deps>
            // builtin: kernel/net/foo/foo.ko
            let path = line.split(':').next().unwrap_or(line);
            path.rsplit('/')
                .next()
                .map(|file| norm(file.split('.').next().unwrap_or("")) == target)
                .unwrap_or(false)
        })
    };
    mentions(modules_dep_text) || mentions(modules_builtin_text)
}

/// True if `module` is blocked from loading by any modprobe.d line — the classic
/// `blacklist <module>`, the stronger `install <module> /bin/true|false` (which also blocks an
/// explicit `modprobe`), or `alias <autoload-alias> off` (Debian/Ubuntu's idiom for the rare
/// network protocols), matched against the module's known autoload `aliases`. Module-name
/// comparisons are `-`/`_`-insensitive.
pub fn is_blacklisted(module: &str, modprobe_d_text: &str, aliases: &[String]) -> bool {
    let m = norm(module);
    modprobe_d_text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("blacklist") => parts.next().map(norm).as_deref() == Some(m.as_str()),
            Some("install") => {
                parts.next().map(norm).as_deref() == Some(m.as_str())
                    && matches!(parts.next(), Some("/bin/true") | Some("/bin/false"))
            }
            // `alias net-pf-21 off` — blocks the autoload path the rule's own explain names.
            Some("alias") => match (parts.next(), parts.next()) {
                (Some(alias), Some("off")) => aliases.iter().any(|a| a == alias),
                _ => false,
            },
            _ => false,
        }
    })
}

pub struct ModuleBlacklistCollector;

impl ModuleBlacklistCollector {
    /// Concatenates every readable file across all modprobe.d directories.
    fn read_modprobe_d() -> String {
        let mut combined = String::new();
        for dir in MODPROBE_DIRS {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(text) = std::fs::read_to_string(entry.path()) {
                        combined.push_str(&text);
                        combined.push('\n');
                    }
                }
            }
        }
        combined
    }
}

impl Collector for ModuleBlacklistCollector {
    fn name(&self) -> &'static str {
        "module_blacklist"
    }

    fn is_applicable(&self) -> bool {
        MODPROBE_DIRS.iter().any(|d| Path::new(d).is_dir())
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let combined = Self::read_modprobe_d();

        // The running kernel's module metadata, for the alias and loadability checks.
        let kver = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let moddir = format!("/lib/modules/{kver}");
        let modules_alias =
            std::fs::read_to_string(format!("{moddir}/modules.alias")).unwrap_or_default();
        let modules_dep =
            std::fs::read_to_string(format!("{moddir}/modules.dep")).unwrap_or_default();
        let modules_builtin =
            std::fs::read_to_string(format!("{moddir}/modules.builtin")).unwrap_or_default();
        // If we couldn't read the kernel's module index at all, we must not claim a module is
        // unloadable — that would silently suppress a genuine finding (the mirror of the
        // absence-as-evidence bug). Only decide loadability when we actually have the data.
        let have_metadata = !modules_dep.is_empty() || !modules_builtin.is_empty();

        Ok(WATCHED_MODULES
            .iter()
            .map(|module| {
                let aliases = autoload_aliases(module, &modules_alias);
                let mut fact = Fact::new();
                fact.insert("module".to_string(), Value::String(module.to_string()));
                fact.insert(
                    "blacklisted".to_string(),
                    Value::Bool(is_blacklisted(module, &combined, &aliases)),
                );
                fact.insert(
                    "loadable".to_string(),
                    Value::Bool(if have_metadata {
                        is_loadable(module, &modules_dep, &modules_builtin)
                    } else {
                        true // unknown → keep the rule live rather than silently suppressing it
                    }),
                );
                fact
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_bare_blacklist_entry() {
        let text = "blacklist dccp\n";
        assert!(is_blacklisted("dccp", text, &[]));
        assert!(!is_blacklisted("sctp", text, &[]));
    }

    #[test]
    fn detects_an_install_bin_true_entry() {
        let text = "install usb-storage /bin/true\n";
        assert!(is_blacklisted("usb-storage", text, &[]));
    }

    #[test]
    fn dash_and_underscore_spellings_are_equivalent() {
        // `lsmod` prints usb_storage; an admin who blacklists what they see must be detected.
        assert!(is_blacklisted(
            "usb-storage",
            "blacklist usb_storage\n",
            &[]
        ));
        assert!(is_blacklisted(
            "usb_storage",
            "blacklist usb-storage\n",
            &[]
        ));
    }

    #[test]
    fn recognises_the_alias_off_idiom_ubuntu_ships() {
        // /etc/modprobe.d/blacklist-rare-network.conf blocks rds via `alias net-pf-21 off`, which
        // is exactly as effective as `blacklist rds` for the autoload attack the rule describes.
        let aliases = vec!["net-pf-21".to_string()];
        assert!(is_blacklisted("rds", "alias net-pf-21 off\n", &aliases));
        // ...but an `alias ... off` for a DIFFERENT protocol must not count for this module.
        assert!(!is_blacklisted("rds", "alias net-pf-12 off\n", &aliases));
    }

    #[test]
    fn autoload_aliases_are_extracted_for_the_right_module() {
        let modules_alias = "alias net-pf-21 rds\nalias net-pf-12 tipc\nalias net-pf-33 dccp\n";
        assert_eq!(autoload_aliases("rds", modules_alias), vec!["net-pf-21"]);
        assert_eq!(autoload_aliases("tipc", modules_alias), vec!["net-pf-12"]);
        assert!(autoload_aliases("sctp", modules_alias).is_empty());
    }

    #[test]
    fn a_module_absent_from_the_kernel_is_not_loadable() {
        // dccp was removed upstream; on such a kernel it appears in neither index, so there is
        // nothing to blacklist and the rule must not report it.
        let dep =
            "kernel/net/sctp/sctp.ko.zst: kernel/net/foo.ko.zst\nkernel/net/rds/rds.ko.zst:\n";
        let builtin = "kernel/net/ipv4/tcp.ko\n";
        assert!(!is_loadable("dccp", dep, builtin));
        assert!(is_loadable("sctp", dep, builtin));
        assert!(is_loadable("rds", dep, builtin));
    }

    #[test]
    fn ignores_comments_and_unrelated_lines() {
        let text = "# blacklist dccp\nblacklist unrelated-module\ninstall dccp /sbin/modprobe --ignore-install dccp\n";
        assert!(!is_blacklisted("dccp", text, &[]));
    }

    #[test]
    fn collector_emits_both_blacklisted_and_loadable_for_every_watched_module() {
        // No longer asserts "none are blacklisted" — that assertion only ever passed because the
        // old collector couldn't see Ubuntu's `alias net-pf-21 off`. It now checks the shape the
        // rules depend on: each watched module has both a `blacklisted` and a `loadable` boolean.
        let rows = ModuleBlacklistCollector.collect().unwrap();
        assert_eq!(rows.len(), WATCHED_MODULES.len());
        for row in &rows {
            assert!(row.get("blacklisted").unwrap().is_boolean());
            assert!(row.get("loadable").unwrap().is_boolean());
        }
    }
}

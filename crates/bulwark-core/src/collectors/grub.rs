//! Checks whether the GRUB boot loader has a password set — matches Lynis's `BOOT-5122`
//! suggestion. Without one, anyone with physical or console access can edit boot parameters
//! at the GRUB menu (e.g. append `init=/bin/bash` or `single`) to get a root shell without
//! ever needing a valid credential — a well-known physical-access bypass.
//!
//! Reads the *generated* `/boot/grub/grub.cfg`, not `/etc/default/grub`, because that's what
//! actually controls boot behavior (grub.cfg is what `update-grub`/`grub-mkconfig` produces
//! from the source config — checking the source and not the generated output would miss a
//! host where the two have drifted). It's root-only readable on a stock install (verified on
//! this project's own dev machine — `Permission denied` as an unprivileged user), so this is
//! a privileged collector, unlike most of this crate's file-reading ones.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

const GRUB_CFG_PATHS: &[&str] = &["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"];

/// Pure/testable: true if `text` sets a GRUB password via either the plaintext `password`
/// directive or the (recommended, hashed) `password_pbkdf2` directive.
pub fn has_password_directive(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("password_pbkdf2 ") || line.starts_with("password ")
    })
}

pub struct GrubPasswordCollector;

impl Collector for GrubPasswordCollector {
    fn name(&self) -> &'static str {
        "grub_password"
    }

    fn is_applicable(&self) -> bool {
        GRUB_CFG_PATHS.iter().any(|p| Path::new(p).exists())
    }

    fn requires_privilege(&self) -> bool {
        true
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let path = GRUB_CFG_PATHS
            .iter()
            .find(|p| Path::new(p).exists())
            .ok_or_else(|| anyhow::anyhow!("no grub.cfg found"))?;
        let text = std::fs::read_to_string(path)?;
        let mut fact = Fact::new();
        fact.insert(
            "password_set".to_string(),
            Value::Bool(has_password_directive(&text)),
        );
        Ok(vec![fact])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_password_pbkdf2_directive() {
        let text = "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.ABCD\n";
        assert!(has_password_directive(text));
    }

    #[test]
    fn detects_plaintext_password_directive() {
        assert!(has_password_directive("password root hunter2\n"));
    }

    #[test]
    fn no_password_directive_is_the_common_default_case() {
        let text = "set default=0\nset timeout=5\nmenuentry 'Ubuntu' {\n  linux /vmlinuz\n}\n";
        assert!(!has_password_directive(text));
    }
}

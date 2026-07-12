//! Checks `/etc/issue` and `/etc/issue.net` for whether they're still the distro's default
//! auto-generated content or a real, deliberately-written legal warning — matches Lynis's
//! own `BANN-7126`/`BANN-7130` suggestions (confirmed by actually running Lynis against this
//! project's own dev machine, which has both files present and non-empty, yet Lynis still
//! flags both — because a non-empty file isn't the bar, a real warning is).

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// getty/PAM issue-file templating escapes (`\n` hostname, `\l` tty, `\s` OS name, `\r`
/// kernel release, `\m` architecture, `\v` kernel version) — present in essentially every
/// distro's stock `/etc/issue`, and not something a hand-written legal warning would
/// plausibly contain.
const GETTY_ESCAPES: &[&str] = &["\\n", "\\l", "\\s", "\\r", "\\m", "\\v"];

/// A real legal warning banner is virtually always going to use at least one of these words
/// somewhere; plain OS-identification text won't use any of them. Needed as a second signal
/// alongside `GETTY_ESCAPES` — caught live on this project's own dev machine, where
/// `/etc/issue.net` is just `"Ubuntu 26.04 LTS"` with *no* escape codes at all (Debian/Ubuntu's
/// stock `issue.net` template omits them, unlike `issue`), which the escape-code check alone
/// missed entirely.
const WARNING_KEYWORDS: &[&str] = &[
    "unauthorized",
    "prohibit",
    "consent",
    "monitor",
    "warning",
    "authorised",
    "authorized personnel",
    "legal action",
    "restricted",
];

/// Pure/testable: true if `text` still looks like the untouched distro default rather than a
/// real custom banner — either it carries getty's own templating escapes, or it simply
/// doesn't contain any language a real warning banner would.
pub fn looks_like_default_banner(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return true;
    }
    if GETTY_ESCAPES.iter().any(|esc| trimmed.contains(esc)) {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    !WARNING_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

pub struct BannersCollector;

impl Collector for BannersCollector {
    fn name(&self) -> &'static str {
        "banners"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/issue").exists() || Path::new("/etc/issue.net").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        for (path, label) in [("/etc/issue", "issue"), ("/etc/issue.net", "issue.net")] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let mut fact = Fact::new();
            fact.insert("file".to_string(), Value::String(label.to_string()));
            fact.insert(
                "is_default".to_string(),
                Value::Bool(looks_like_default_banner(&text)),
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
    fn stock_ubuntu_issue_content_reads_as_default() {
        // Real content read from this project's own dev machine's /etc/issue.
        assert!(looks_like_default_banner("Ubuntu 26.04 LTS \\n \\l\n"));
    }

    #[test]
    fn empty_file_reads_as_default() {
        assert!(looks_like_default_banner(""));
        assert!(looks_like_default_banner("   \n"));
    }

    #[test]
    fn a_real_custom_legal_warning_does_not_read_as_default() {
        let text = "Unauthorized access to this system is prohibited and will be prosecuted.\n";
        assert!(!looks_like_default_banner(text));
    }

    /// Regression test for a real bug caught by dogfooding against this project's own dev
    /// machine: `/etc/issue.net` there is exactly `"Ubuntu 26.04 LTS"` — no getty escape
    /// codes at all, since Debian/Ubuntu's stock `issue.net` template omits them (unlike
    /// `issue`). The escape-code check alone missed this entirely, reporting a still-default
    /// banner as if it were a real custom one.
    #[test]
    fn stock_issue_net_content_with_no_escape_codes_still_reads_as_default() {
        assert!(looks_like_default_banner("Ubuntu 26.04 LTS"));
    }
}

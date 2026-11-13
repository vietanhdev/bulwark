//! Checks `/etc/issue` and `/etc/issue.net` for a real, deliberately-written legal warning —
//! matches Lynis's own `BANN-7126`/`BANN-7130` suggestions (confirmed by actually running Lynis
//! against this project's own dev machine, which has both files present and non-empty, yet Lynis
//! still flags both — because a non-empty file isn't the bar, a real warning is).
//!
//! A banner file is one of four things, and telling them apart matters because the `fix banner`
//! autofix acts on exactly one of them:
//!
//!   * a **warning** — it says access is restricted. Nothing to report.
//!   * the **distribution's default** — getty's templating codes, or just the distribution's own
//!     name and version. Reported, and the only kind the fixer may replace.
//!   * **empty** — someone emptied it (often on purpose, to stop advertising the OS version).
//!     Reported, because there is still no warning, but it is somebody's choice: never replaced.
//!   * **customised** — text somebody wrote ("Welcome to prod-db-1") that carries no warning.
//!     Reported for the same reason, and never replaced.
//!
//! The classifier used to have two buckets, and everything without a warning word counted as "the
//! default" — so the fixer overwrote a host's own greeting, and an emptied file, with its banner.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// getty/agetty issue-file escapes (`\n` hostname, `\l` tty, `\s` OS name, `\r` kernel release,
/// `\m` architecture, `\v` kernel version, `\S` the os-release name Fedora and openSUSE use, …) —
/// present in essentially every distro's stock `/etc/issue`.
const GETTY_ESCAPES: &[&str] = &[
    "\\n", "\\l", "\\s", "\\r", "\\m", "\\v", "\\S", "\\o", "\\O", "\\d", "\\t", "\\u", "\\U",
    "\\4", "\\6", "\\b", "\\e",
];

/// A real legal warning banner is virtually always going to use at least one of these words
/// somewhere; plain OS-identification text won't use any of them.
const WARNING_KEYWORDS: &[&str] = &[
    "unauthorized",
    "unauthorised",
    "prohibit",
    "consent",
    "monitor",
    "warning",
    "authorised",
    "authorized personnel",
    "authorized access",
    "authorized use",
    "legal action",
    "restricted",
];

/// Words a stock banner wraps around the distribution's name ("Welcome to Alpine Linux 3.20",
/// "Kernel \r on an \m", "Red Hat Enterprise Linux release 9.4"). They identify nothing, so they
/// never make a banner someone's own.
const FILLER_WORDS: &[&str] = &[
    "welcome",
    "to",
    "kernel",
    "on",
    "an",
    "a",
    "release",
    "version",
    "linux",
    "gnu/linux",
];

/// What a banner file holds. See the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerKind {
    Warning,
    DistroDefault,
    Empty,
    Customised,
}

impl BannerKind {
    /// The word stored in the `content` fact.
    pub fn as_str(self) -> &'static str {
        match self {
            BannerKind::Warning => "warning",
            BannerKind::DistroDefault => "default",
            BannerKind::Empty => "empty",
            BannerKind::Customised => "custom",
        }
    }

    /// What the file holds, as the end of a sentence that starts with its path.
    fn found(self) -> &'static str {
        match self {
            BannerKind::Warning => "carries a warning that access is restricted",
            BannerKind::DistroDefault => {
                "still holds the distribution's default text (the OS name and version)"
            }
            BannerKind::Empty => "is empty",
            BannerKind::Customised => "holds text that does not say access is restricted",
        }
    }
}

/// Lowercased words of `text`, with surrounding punctuation removed ("(Core)" → "core").
fn words(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// The words `/etc/os-release` uses to name this distribution and its version.
fn os_release_words(os_release: &str) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut versions = Vec::new();
    for line in os_release.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']);
        match key.trim() {
            "NAME" | "PRETTY_NAME" | "ID" | "VERSION" | "VERSION_CODENAME" | "VARIANT" => {
                names.extend(words(value));
            }
            "VERSION_ID" => versions.extend(words(value)),
            _ => {}
        }
    }
    (names, versions)
}

/// True when `text` is only what a distribution ships: getty escapes, the distribution's own name
/// and version as `/etc/os-release` gives them, and filler words. One word from anywhere else — a
/// host name, a company, a greeting — makes it somebody's own text.
///
/// Without `os_release` there is nothing to compare names against, so only a banner made of
/// escapes and filler alone counts. That errs toward "customised", which is the safe side: a
/// banner wrongly called customised is left alone, one wrongly called default would be replaced.
fn is_distro_default(text: &str, os_release: Option<&str>) -> bool {
    let (names, versions) = os_release.map(os_release_words).unwrap_or_default();
    let mut without_escapes = text.to_string();
    let mut had_escape = false;
    for esc in GETTY_ESCAPES {
        if without_escapes.contains(esc) {
            had_escape = true;
            without_escapes = without_escapes.replace(esc, " ");
        }
    }
    let mut named_the_distro = false;
    for word in words(&without_escapes) {
        if FILLER_WORDS.contains(&word.as_str()) {
            continue;
        }
        let bare = word.trim_start_matches('v');
        // "3.20" in the banner against VERSION_ID "3.20.3", or the other way round.
        let is_version = bare.starts_with(|c: char| c.is_ascii_digit())
            && versions
                .iter()
                .chain(&names)
                .any(|v| v.trim_start_matches('v').starts_with(bare) || bare.starts_with(v));
        if names.contains(&word) || is_version {
            named_the_distro = true;
            continue;
        }
        return false;
    }
    had_escape || named_the_distro
}

/// Pure/testable: what `text` is. `os_release` is the contents of `/etc/os-release`, when there
/// is one.
pub fn classify_banner(text: &str, os_release: Option<&str>) -> BannerKind {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return BannerKind::Empty;
    }
    let lower = trimmed.to_ascii_lowercase();
    if WARNING_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return BannerKind::Warning;
    }
    if is_distro_default(trimmed, os_release) {
        BannerKind::DistroDefault
    } else {
        BannerKind::Customised
    }
}

/// This machine's `/etc/os-release` (or its `/usr/lib` fallback), for [`classify_banner`].
pub fn read_os_release() -> Option<String> {
    ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| super::read_capped(Path::new(p)).ok())
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
        let os_release = read_os_release();
        let mut rows = Vec::new();
        for (path, label) in [("/etc/issue", "issue"), ("/etc/issue.net", "issue.net")] {
            let Ok(text) = super::read_capped(Path::new(path)) else {
                continue;
            };
            rows.push(banner_fact(
                label,
                classify_banner(&text, os_release.as_deref()),
            ));
        }
        Ok(rows)
    }
}

fn banner_fact(label: &str, kind: BannerKind) -> Fact {
    let mut fact = Fact::new();
    fact.insert("file".to_string(), Value::String(label.to_string()));
    // The rule fires on `has_warning == false`. `is_default` says whether `fix banner` would
    // replace the file; `content` and `found` say what is there, in a word and in a phrase.
    fact.insert(
        "has_warning".to_string(),
        Value::Bool(kind == BannerKind::Warning),
    );
    fact.insert(
        "is_default".to_string(),
        Value::Bool(kind == BannerKind::DistroDefault),
    );
    fact.insert(
        "content".to_string(),
        Value::String(kind.as_str().to_string()),
    );
    fact.insert("found".to_string(), Value::String(kind.found().to_string()));
    fact
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\n\
                          VERSION=\"26.04 LTS (Resolute Raccoon)\"\nVERSION_CODENAME=resolute\nID=ubuntu\n";
    const FEDORA: &str = "NAME=\"Fedora Linux\"\nVERSION=\"43 (Container Image)\"\nID=fedora\n\
                          VERSION_ID=43\nPRETTY_NAME=\"Fedora Linux 43 (Container Image)\"\n";
    const ALPINE: &str = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n\
                          PRETTY_NAME=\"Alpine Linux v3.20\"\n";
    const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\n\
                          VERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n";

    #[test]
    fn stock_banners_read_as_the_distribution_default() {
        for (text, os) in [
            // Real content read from this project's own dev machine's /etc/issue and issue.net.
            // The second has no escape codes at all (Debian/Ubuntu's stock issue.net omits
            // them), which an escape-only check once missed entirely.
            ("Ubuntu 26.04 LTS \\n \\l\n", UBUNTU),
            ("Ubuntu 26.04 LTS\n", UBUNTU),
            ("\\S\nKernel \\r on \\m (\\l)\n", FEDORA),
            ("\\S\nKernel \\r on \\m\n", FEDORA),
            (
                "Welcome to Alpine Linux 3.20\nKernel \\r on an \\m (\\l)\n",
                ALPINE,
            ),
            ("Debian GNU/Linux 12 \\n \\l\n", DEBIAN),
            ("Debian GNU/Linux 12\n", DEBIAN),
        ] {
            assert_eq!(
                classify_banner(text, Some(os)),
                BannerKind::DistroDefault,
                "{text:?}"
            );
        }
    }

    /// The tester's banner: no warning words, so it is still reported — and it is not the
    /// distribution's text, so the fixer must never see it as replaceable.
    #[test]
    fn text_someone_wrote_is_customised_not_default() {
        for text in [
            "Welcome to prod-db-1!\n",
            "Welcome to prod-db-1 (\\l)\n",
            "ACME build farm\n",
            "Ubuntu 26.04 LTS - ask ops@example.com for an account\n",
            "Property of Example GmbH\n",
        ] {
            assert_eq!(
                classify_banner(text, Some(UBUNTU)),
                BannerKind::Customised,
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_empty_file_is_empty_not_default() {
        assert_eq!(classify_banner("", Some(UBUNTU)), BannerKind::Empty);
        assert_eq!(classify_banner("   \n", Some(UBUNTU)), BannerKind::Empty);
    }

    #[test]
    fn a_real_legal_warning_is_a_warning_even_with_getty_codes() {
        let text = "Unauthorized access to this system is prohibited and will be prosecuted.\n";
        assert_eq!(classify_banner(text, Some(UBUNTU)), BannerKind::Warning);
        assert_eq!(
            classify_banner("Authorized use only. Host \\n, line \\l\n", Some(UBUNTU)),
            BannerKind::Warning
        );
    }

    /// Without os-release there are no names to compare, so only escapes and filler count as the
    /// default; a name we cannot place is treated as someone's own text and left alone.
    #[test]
    fn without_os_release_only_escapes_and_filler_are_the_default() {
        assert_eq!(
            classify_banner("Kernel \\r on an \\m (\\l)\n", None),
            BannerKind::DistroDefault
        );
        assert_eq!(
            classify_banner("Ubuntu 26.04 LTS\n", None),
            BannerKind::Customised
        );
        // A different distribution's name is not this distribution's default.
        assert_eq!(
            classify_banner("Ubuntu 26.04 LTS\n", Some(FEDORA)),
            BannerKind::Customised
        );
    }

    #[test]
    fn the_facts_say_what_was_found_and_whether_the_fixer_would_act() {
        let f = banner_fact("issue", BannerKind::Customised);
        assert_eq!(f.get("has_warning"), Some(&Value::Bool(false)));
        assert_eq!(f.get("is_default"), Some(&Value::Bool(false)));
        assert_eq!(f.get("content"), Some(&Value::String("custom".into())));
        let f = banner_fact("issue", BannerKind::DistroDefault);
        assert_eq!(f.get("is_default"), Some(&Value::Bool(true)));
        let f = banner_fact("issue.net", BannerKind::Warning);
        assert_eq!(f.get("has_warning"), Some(&Value::Bool(true)));
        // Every row carries every field the rule reads or templates.
        for kind in [BannerKind::Empty, BannerKind::Warning] {
            let f = banner_fact("issue", kind);
            for k in ["file", "has_warning", "is_default", "content", "found"] {
                assert!(f.contains_key(k), "{k}");
            }
        }
    }
}

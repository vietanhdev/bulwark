//! High-precision secret detection over the *text* an AI coding assistant keeps on disk —
//! context files (`CLAUDE.md`, `AGENTS.md`), agent settings, MCP configs, `.env` files, and
//! chat/session transcripts. These are exactly the places a developer pastes an API key mid-
//! conversation ("here's my key, debug this") and then forgets it was ever written to disk.
//!
//! The pattern table is deliberately weighted toward providers whose tokens carry a fixed
//! prefix or an embedded literal (Anthropic's `sk-ant-…AA`, OpenAI's embedded `T3BlbkFJ`,
//! GitHub's `ghp_`), because those are near-zero-false-positive to match on structure alone —
//! see GitHub's own token-format writeup and the gitleaks/trufflehog rulesets this mirrors.
//! The one genuinely fuzzy pattern (a `KEY = value` assignment) is held to Medium and gated
//! against obvious placeholders so it doesn't cry wolf on `API_KEY=your-key-here`.
//!
//! Detection here is *content only* — whether the file is world-readable, git-tracked, or
//! ignored is a separate axis handled by `detectors`/`discovery`, so a leaked key surfaces its
//! blast radius (readable-by-others, committed) as its own finding rather than being conflated
//! into this one.

use crate::models::Severity;
use regex::Regex;
use std::sync::LazyLock;

/// One provider's detection rule. `provider` is the human label shown in a finding; `high_conf`
/// distinguishes structurally-verifiable tokens (fixed prefix/embedded literal/checksum) from
/// the single heuristic `KEY=value` pattern, which callers surface at a lower severity.
struct Pattern {
    provider: &'static str,
    re: Regex,
    high_conf: bool,
}

/// A single detected secret, already redacted for display — the raw bytes never leave this
/// module in a finding, only a masked form (`sk-ant-…AA` → `sk-ant-a…3f`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Human label, e.g. `"Anthropic API key"`.
    pub provider: String,
    /// 1-based line number the secret starts on — what the UI points the user at.
    pub line: usize,
    /// Masked rendering safe to show and store (`prefix…suffix`), never the full secret.
    pub redacted: String,
    /// High-confidence structural match (prefix/embedded-literal/checksum) vs. the heuristic
    /// assignment pattern. Callers map this to Critical/High vs. Medium.
    pub high_conf: bool,
}

/// The literal a redaction pass writes in place of a secret. Chosen so a *re-scan* of a
/// redacted file matches nothing here (it carries no provider prefix and its only long run,
/// `redacted`, is 8 chars — under every pattern's minimum), so redaction is idempotent.
pub const REDACTION_PLACEHOLDER: &str = "[bulwark:redacted-secret]";

/// Values that look like a secret assignment but are obviously a template/placeholder — a
/// `KEY=value` hit whose value is one of these (case-insensitively, ignoring surrounding
/// punctuation) is dropped rather than reported. Keeps the one fuzzy pattern honest.
const PLACEHOLDER_VALUES: &[&str] = &[
    "your_api_key",
    "your-api-key",
    "yourapikey",
    "your_api_key_here",
    "changeme",
    "example",
    "placeholder",
    "redacted",
    "xxxxxxxxxxxxxxxx",
    "0000000000000000",
    "1234567890abcdef",
    "todo",
    "none",
    "null",
];

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    // Every regex here is anchored on a structural feature (prefix or embedded literal), not
    // on generic entropy, so a match is a strong signal on its own. Grouped by provider so a
    // new one is a single push — the "data, not a rewrite" spirit the rule pack already has.
    let p = |provider: &'static str, re: &str, high_conf: bool| Pattern {
        provider,
        re: Regex::new(re).expect("static secret pattern must compile"),
        high_conf,
    };
    vec![
        p(
            "Anthropic API key",
            r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,120}",
            true,
        ),
        // OpenAI keys embed the literal `T3BlbkFJ` regardless of the project/service prefix.
        p(
            "OpenAI API key",
            r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}",
            true,
        ),
        p(
            "OpenAI API key",
            r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            true,
        ),
        p("OpenRouter API key", r"sk-or-v1-[0-9a-f]{64}", true),
        p("GitHub token", r"gh[posru]_[A-Za-z0-9]{36}", true),
        p(
            "GitHub fine-grained token",
            r"github_pat_[A-Za-z0-9_]{82}",
            true,
        ),
        p("GitLab token", r"glpat-[A-Za-z0-9_\-]{20}", true),
        p(
            "AWS access key ID",
            r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
            true,
        ),
        p("Google API key", r"AIza[0-9A-Za-z_\-]{35}", true),
        p("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}", true),
        p(
            "Slack webhook URL",
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}",
            true,
        ),
        p(
            "Stripe live secret key",
            r"(?:sk|rk)_live_[0-9A-Za-z]{16,}",
            true,
        ),
        p("Hugging Face token", r"hf_[A-Za-z0-9]{34,}", true),
        p("npm access token", r"npm_[A-Za-z0-9]{36}", true),
        p(
            "SendGrid API key",
            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            true,
        ),
        p(
            "PEM private key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            true,
        ),
        // Connection string with an inline password between `:` and `@`.
        p(
            "Database URL with inline password",
            r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@/\s]+:[^@/\s]{3,}@[^\s]+",
            true,
        ),
        // The one heuristic pattern — a KEY=value assignment. Deliberately last, Medium-only,
        // and further filtered by `is_placeholder_value` at the call site.
        p(
            "Possible hardcoded secret",
            r#"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{16,})"#,
            false,
        ),
    ]
});

fn line_of(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Masks a secret to a short, safe-to-display form: a few leading and trailing chars with the
/// middle elided. Short secrets collapse to all-asterisks so nothing recoverable leaks into a
/// finding, a log, or the on-disk findings database.
pub fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len().max(1));
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

fn is_placeholder_value(value: &str) -> bool {
    let v = value
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_ascii_lowercase();
    PLACEHOLDER_VALUES.iter().any(|p| v == *p)
        // A value that's a single repeated character (aaaa…, 0000…) is a template, not a key.
        || (v.len() >= 16 && v.chars().all(|c| c == v.chars().next().unwrap()))
}

/// Scans `text` for secrets, returning one [`SecretMatch`] per distinct hit. When a fuzzy
/// `KEY=value` assignment overlaps a high-confidence provider match on the same bytes, only the
/// provider match is kept — a hardcoded `ANTHROPIC_API_KEY=sk-ant-…` is *one* Anthropic finding,
/// not also a generic one.
pub fn scan_text(text: &str) -> Vec<SecretMatch> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut out: Vec<SecretMatch> = Vec::new();

    for pat in PATTERNS.iter() {
        for m in pat.re.find_iter(text) {
            // Skip a fuzzy assignment whose bytes are already claimed by a precise provider
            // match (they run first because the table lists them first).
            if !pat.high_conf && spans.iter().any(|&(s, e)| m.start() < e && s < m.end()) {
                continue;
            }

            let matched = m.as_str();
            let secret = if pat.high_conf {
                matched.to_string()
            } else {
                // For the assignment pattern the interesting part is the captured value, not
                // the `KEY=` prefix — mask and placeholder-filter on that.
                match pat.re.captures(matched).and_then(|c| c.get(1)) {
                    Some(v) => {
                        if is_placeholder_value(v.as_str()) {
                            continue;
                        }
                        v.as_str().to_string()
                    }
                    None => continue,
                }
            };

            spans.push((m.start(), m.end()));
            out.push(SecretMatch {
                provider: pat.provider.to_string(),
                line: line_of(text, m.start()),
                redacted: mask(&secret),
                high_conf: pat.high_conf,
            });
        }
    }

    out
}

/// Severity for a secret hit: a structurally-verified provider key is Critical (a live
/// credential, one paste away from account takeover); the heuristic assignment is Medium.
pub fn severity_for(m: &SecretMatch) -> Severity {
    if m.high_conf {
        Severity::Critical
    } else {
        Severity::Medium
    }
}

/// Rewrites `text`, replacing every detected secret's bytes with [`REDACTION_PLACEHOLDER`].
/// Returns the new text and the number of secrets replaced. Only high-confidence provider
/// secrets are redacted — the fuzzy `KEY=value` pattern is report-only, since blindly rewriting
/// a captured value risks mangling a legitimate non-secret that merely tripped the heuristic.
///
/// Replacement walks matches right-to-left so earlier byte offsets stay valid as later ones are
/// spliced out.
pub fn redact_text(text: &str) -> (String, usize) {
    let mut hits: Vec<(usize, usize)> = Vec::new();
    for pat in PATTERNS.iter() {
        if !pat.high_conf {
            continue;
        }
        for m in pat.re.find_iter(text) {
            if hits.iter().any(|&(s, e)| m.start() < e && s < m.end()) {
                continue;
            }
            hits.push((m.start(), m.end()));
        }
    }
    hits.sort_unstable();
    let count = hits.len();
    let mut out = text.to_string();
    for &(start, end) in hits.iter().rev() {
        out.replace_range(start..end, REDACTION_PLACEHOLDER);
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_anthropic_key() {
        let key = format!("sk-ant-api03-{}AA", "a".repeat(93));
        let text = format!("here is my key {key} please debug");
        let hits = scan_text(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].provider, "Anthropic API key");
        assert!(hits[0].high_conf);
        assert!(
            !hits[0].redacted.contains(&key),
            "must not echo the raw secret"
        );
    }

    #[test]
    fn detects_openai_embedded_literal() {
        let key = format!("sk-proj-{}T3BlbkFJ{}", "a".repeat(30), "b".repeat(30));
        let hits = scan_text(&key);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].provider, "OpenAI API key");
    }

    #[test]
    fn detects_github_pat() {
        // gitleaks:allow — synthetic token; the detector under test needs a real-shaped input.
        let hits = scan_text("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz"); // gitleaks:allow
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].provider, "GitHub token");
    }

    #[test]
    fn assignment_pattern_ignores_obvious_placeholders() {
        assert!(scan_text("API_KEY=your_api_key_here").is_empty());
        assert!(scan_text("password = changeme").is_empty());
        assert!(scan_text("api_key: \"xxxxxxxxxxxxxxxxxxxx\"").is_empty());
    }

    #[test]
    fn assignment_pattern_flags_a_real_looking_value_at_medium() {
        // gitleaks:allow — synthetic value; the detector under test needs a real-shaped input.
        let hits = scan_text("MY_SERVICE_TOKEN=a8Fk2Lm9Qp3Rn7Zx1Wc4"); // gitleaks:allow
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].high_conf);
        assert_eq!(severity_for(&hits[0]), Severity::Medium);
    }

    #[test]
    fn precise_provider_match_wins_over_generic_assignment() {
        let key = format!("sk-ant-api03-{}AA", "a".repeat(93));
        let hits = scan_text(&format!("ANTHROPIC_API_KEY={key}"));
        // One finding, and it's the Anthropic one — not also a generic "possible secret".
        assert_eq!(hits.len(), 1, "overlapping generic hit must be suppressed");
        assert_eq!(hits[0].provider, "Anthropic API key");
    }

    #[test]
    fn detects_pem_private_key_header() {
        let hits = scan_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].provider, "PEM private key");
    }

    #[test]
    fn detects_db_url_with_inline_password() {
        let hits = scan_text("DATABASE_URL=postgres://admin:s3cr3tPass@db.example.com:5432/app");
        assert!(hits
            .iter()
            .any(|h| h.provider == "Database URL with inline password"));
    }

    #[test]
    fn reports_correct_line_number() {
        let key = format!("sk-ant-api03-{}AA", "a".repeat(93));
        let text = format!("line one\nline two\n{key}\n");
        let hits = scan_text(&text);
        assert_eq!(hits[0].line, 3);
    }

    #[test]
    fn redaction_removes_the_secret_and_is_idempotent() {
        let key = format!("sk-ant-api03-{}AA", "a".repeat(93));
        let text = format!("key: {key}\nother line\n");
        let (redacted, count) = redact_text(&text);
        assert_eq!(count, 1);
        assert!(!redacted.contains(&key));
        assert!(redacted.contains(REDACTION_PLACEHOLDER));
        // A second pass finds nothing new — the placeholder is inert.
        let (again, count2) = redact_text(&redacted);
        assert_eq!(count2, 0);
        assert_eq!(again, redacted);
    }

    #[test]
    fn redaction_only_touches_high_confidence_secrets() {
        // A fuzzy assignment must be reported but NOT auto-rewritten.
        let text = "MY_TOKEN=a8Fk2Lm9Qp3Rn7Zx1Wc4\n";
        assert_eq!(scan_text(text).len(), 1);
        let (redacted, count) = redact_text(text);
        assert_eq!(count, 0);
        assert_eq!(redacted, text);
    }

    #[test]
    fn mask_never_reveals_a_short_secret() {
        assert_eq!(mask("short"), "*****");
        assert!(mask("sk-ant-api03-aaaaaaaaaa").contains('…'));
    }
}

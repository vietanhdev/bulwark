//! Secret detection over the *text* an AI coding assistant keeps on disk — context files
//! (`CLAUDE.md`, `AGENTS.md`), agent settings, MCP configs, `.env` files, and chat/session
//! transcripts. These are exactly the places a developer pastes an API key mid-conversation
//! ("here's my key, debug this") and then forgets it was ever written to disk.
//!
//! The rules are **data, not code** — 262 of them in `secret_rules.toml`, in gitleaks' format,
//! vendored from chub (MIT; see that file's header for provenance, and for why the crate itself is
//! not taken as a dependency). That matches how the rest of Bulwark works: adding a provider is
//! editing a TOML file, not writing Rust. It replaced a hand-rolled table of ~18 regexes, which
//! covered the obvious providers and nothing else.
//!
//! Three stages run in sequence, cheapest first:
//!
//! 1. **Keyword pre-filter.** A rule declares substrings that must appear before its regex is
//!    worth running at all. Without this, 262 regexes over a multi-megabyte transcript is slow.
//! 2. **Regex.** Capture group 1 is the secret where the pattern isolates one, else the whole match.
//! 3. **Entropy gate.** A rule may demand a minimum Shannon entropy of the captured value. This is
//!    what stops the deliberately broad `generic-api-key` pattern from firing on
//!    `api_key = "example"` — precisely the case a hand-rolled regex set gets wrong.
//!
//! Detection here is *content only*. Whether the file is world-readable, or sits unignored in a git
//! repo, is a separate axis handled by `detectors`/`discovery`, so a leaked key's blast radius is
//! its own finding rather than being conflated into this one.

use crate::models::Severity;
use aho_corasick::AhoCorasick;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::{LazyLock, OnceLock};

/// One rule as authored in `secret_rules.toml`. Unknown keys — notably gitleaks' `validate` CEL
/// blocks, which we deliberately don't evaluate — are ignored rather than rejected.
#[derive(Debug, Deserialize)]
struct RuleSpec {
    id: String,
    /// Optional: a few gitleaks rules match on path/allowlist alone and carry no pattern. Those
    /// have nothing for a content scanner to do, so they're skipped rather than treated as an
    /// error — hence `Option` rather than a required field.
    regex: Option<String>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RuleSpec>,
}

struct Rule {
    id: String,
    /// Human-facing name derived from the id (`anthropic-api-key` → `Anthropic API key`).
    provider: String,
    pattern: String,
    /// Compiled on first use, not at startup. Compiling all 262 patterns eagerly costs ~2.3s in
    /// release (far worse in debug) — unacceptable in front of every scan, and paid even by a run
    /// that matches nothing. With the keyword index below deciding which rules are even
    /// candidates, a typical file compiles a handful of regexes rather than the whole pack.
    re: OnceLock<Option<Regex>>,
    entropy: Option<f64>,
    /// False only for the deliberately-broad `generic-*` patterns, which are reported at a lower
    /// severity and never auto-redacted — rewriting a value that merely *looked* like a secret
    /// could corrupt a legitimate config.
    high_conf: bool,
}

impl Rule {
    fn regex(&self) -> Option<&Regex> {
        self.re.get_or_init(|| compile(&self.pattern).ok()).as_ref()
    }
}

/// The compiled rule pack plus the keyword index that decides which rules a given text could
/// possibly match.
///
/// This is the same shape gitleaks uses, and for the same reason: running 262 regexes over every
/// file is wasteful when a single Aho-Corasick pass can tell you that only three of them have any
/// chance of matching. The automaton is built once over every rule's keywords; scanning a text
/// runs it once, and only the rules whose keywords actually appeared are considered.
struct Pack {
    rules: Vec<Rule>,
    /// Keyword automaton. Pattern index → the rules that declared that keyword.
    keywords: AhoCorasick,
    rules_for_keyword: Vec<Vec<usize>>,
    /// Rules with no keywords at all: always candidates, since nothing can rule them out.
    always: Vec<usize>,
}

impl Pack {
    /// The rules worth running against `lowered`, as indices into `rules`.
    ///
    /// **Overlapping** iteration, not `find_iter`. Keywords overlap constantly — `api` is a
    /// substring of `sk-ant-api03` — and non-overlapping iteration reports only one of them, so
    /// the more specific keyword's rule never gets considered. That silently lost every Anthropic
    /// key in the text: precisely the class of bug where a scanner reports "clean" while missing
    /// the thing it exists to find.
    fn candidates(&self, lowered: &str) -> Vec<usize> {
        let mut hit = vec![false; self.rules.len()];
        for m in self.keywords.find_overlapping_iter(lowered) {
            for &r in &self.rules_for_keyword[m.pattern().as_usize()] {
                hit[r] = true;
            }
        }
        for &r in &self.always {
            hit[r] = true;
        }
        hit.iter()
            .enumerate()
            .filter(|(_, &h)| h)
            .map(|(i, _)| i)
            .collect()
    }
}

/// A single detected secret, already masked for display — the raw bytes never leave this module in
/// a finding, only a masked form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    /// Human label, e.g. `"Anthropic API key"`.
    pub provider: String,
    /// The rule that fired, e.g. `"anthropic-api-key"`.
    pub rule_id: String,
    /// 1-based line the secret starts on — what the UI points the user at.
    pub line: usize,
    /// Masked rendering, safe to show and store. Never the full secret.
    pub redacted: String,
    /// A structurally-identifiable provider token, as opposed to a heuristic `generic-*` hit.
    /// Callers map this to Critical vs. Medium; only these are auto-redactable.
    pub high_conf: bool,
}

/// The literal a redaction pass writes in place of a secret. Chosen so a *re-scan* of a redacted
/// file matches nothing: it carries no provider prefix, and its longest alphanumeric run is 8
/// characters — under every rule's minimum. That is what makes redaction idempotent.
pub const REDACTION_PLACEHOLDER: &str = "[bulwark:redacted-secret]";

/// Values that trip a broad pattern but are plainly a template. Entropy already catches most of
/// these; this is the belt to that pair of braces, and it keeps the intent legible.
const PLACEHOLDER_VALUES: &[&str] = &[
    "your_api_key",
    "your-api-key",
    "yourapikey",
    "your_api_key_here",
    "changeme",
    "example",
    "placeholder",
    "redacted",
    "todo",
    "none",
    "null",
];

/// Words that make an id read correctly once humanized: `aws-access-token` should render as
/// "AWS access token", not "Aws access token".
const ACRONYMS: &[(&str, &str)] = &[
    ("api", "API"),
    ("aws", "AWS"),
    ("gcp", "GCP"),
    ("jwt", "JWT"),
    ("ssh", "SSH"),
    ("pgp", "PGP"),
    ("gpg", "GPG"),
    ("url", "URL"),
    ("id", "ID"),
    ("pat", "PAT"),
    ("sso", "SSO"),
    ("npm", "npm"),
    ("pypi", "PyPI"),
    ("oauth", "OAuth"),
];

fn humanize(id: &str) -> String {
    let words: Vec<String> = id
        .split('-')
        .map(|w| {
            ACRONYMS
                .iter()
                .find(|(k, _)| *k == w)
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_else(|| w.to_string())
        })
        .collect();
    let mut s = words.join(" ");
    if let Some(first) = s.chars().next() {
        if first.is_lowercase() {
            s = first.to_uppercase().collect::<String>() + &s[first.len_utf8()..];
        }
    }
    s
}

/// The rule pack, compiled once.
///
/// A rule whose regex the `regex` crate can't compile — gitleaks' patterns target Go's RE2, which
/// is close but not identical — is **skipped, not fatal**: one bad pattern must not take the other
/// 261 down with it. `every_bundled_rule_compiles` asserts the skipped set is empty, so a
/// regression surfaces at test time rather than as silently missing coverage on a user's machine.
static PACK: LazyLock<Pack> = LazyLock::new(|| {
    let spec: RuleFile = toml::from_str(include_str!("secret_rules.toml"))
        .expect("the bundled secret rule pack must be valid TOML");

    let mut rules = Vec::new();
    let mut keyword_list: Vec<String> = Vec::new();
    let mut rules_for_keyword: Vec<Vec<usize>> = Vec::new();
    let mut always = Vec::new();

    for r in spec.rules {
        // A few gitleaks rules match on path/allowlist alone and carry no pattern. There is
        // nothing for a *content* scanner to do with those.
        let Some(pattern) = r.regex else { continue };

        let idx = rules.len();
        if r.keywords.is_empty() {
            always.push(idx);
        }
        for kw in &r.keywords {
            let kw = kw.to_lowercase();
            match keyword_list.iter().position(|k| *k == kw) {
                Some(k) => rules_for_keyword[k].push(idx),
                None => {
                    keyword_list.push(kw);
                    rules_for_keyword.push(vec![idx]);
                }
            }
        }

        let high_conf = !r.id.starts_with("generic-");
        rules.push(Rule {
            provider: humanize(&r.id),
            id: r.id,
            pattern,
            re: OnceLock::new(),
            entropy: r.entropy,
            high_conf,
        });
    }

    let keywords = AhoCorasick::new(&keyword_list).expect("keyword automaton must build");
    Pack {
        rules,
        keywords,
        rules_for_keyword,
        always,
    }
});

/// Compiles one rule pattern.
///
/// The size limit is raised well above the `regex` crate's 10 MB default. Three of the vendored
/// rules — `generic-api-key` among them, which is the one that catches a pasted secret no
/// provider-specific pattern knows about — are broad case-insensitive alternations that compile to
/// a program larger than that, and were being silently dropped. The limit is a guard against a
/// hostile *user-supplied* pattern; these patterns ship with the binary and are reviewed, so the
/// ceiling can be set by what they actually need.
fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(64 * 1024 * 1024)
        .build()
}

/// Shannon entropy of the byte distribution, in bits per character. A real 40-character token sits
/// around 4–5; English prose and template values sit well below.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn line_of(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Masks a secret to a short, safe-to-display form. Short secrets collapse to asterisks entirely,
/// so nothing recoverable reaches a finding, a log, or the database.
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
        // A value that is one repeated character (aaaa…, 0000…) is a template, not a key.
        || (v.len() >= 12 && {
            let mut cs = v.chars();
            match cs.next() {
                Some(first) => cs.all(|c| c == first),
                None => false,
            }
        })
}

/// Every hit for one rule against `text`, as `(span, secret)` pairs. The caller has already
/// established, via the keyword index, that this rule is worth running at all.
fn matches_for<'t>(rule: &Rule, text: &'t str) -> Vec<((usize, usize), &'t str)> {
    let Some(re) = rule.regex() else {
        // The pattern didn't compile. Skipped, never fatal — one bad rule must not take the pack
        // down — and `every_bundled_rule_compiles` is what stops that becoming silent lost cover.
        return Vec::new();
    };

    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let Some(whole) = caps.get(0) else { continue };
        // Group 1 is the secret where the pattern isolates one; otherwise the match itself is.
        let secret = caps.get(1).unwrap_or(whole);

        if let Some(min) = rule.entropy {
            if shannon_entropy(secret.as_str()) < min {
                continue;
            }
        }
        if !rule.high_conf && is_placeholder_value(secret.as_str()) {
            continue;
        }
        out.push(((whole.start(), whole.end()), secret.as_str()));
    }
    out
}

/// Scans `text`, returning one [`SecretMatch`] per distinct hit. Where a broad `generic-*` rule
/// overlaps a precise provider rule on the same bytes, only the provider match is kept — a
/// hardcoded `ANTHROPIC_API_KEY=sk-ant-…` is *one* Anthropic finding, not also a generic one.
pub fn scan_text(text: &str) -> Vec<SecretMatch> {
    let pack = &*PACK;
    let lowered = text.to_lowercase();
    let candidates = pack.candidates(&lowered);

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut out: Vec<SecretMatch> = Vec::new();

    // Precise rules first, so they claim their spans before the heuristic ones run.
    for high_conf_pass in [true, false] {
        for rule in candidates
            .iter()
            .map(|&i| &pack.rules[i])
            .filter(|r| r.high_conf == high_conf_pass)
        {
            for ((start, end), secret) in matches_for(rule, text) {
                if spans.iter().any(|&(s, e)| start < e && s < end) {
                    continue;
                }
                spans.push((start, end));
                out.push(SecretMatch {
                    provider: rule.provider.clone(),
                    rule_id: rule.id.clone(),
                    line: line_of(text, start),
                    redacted: mask(secret),
                    high_conf: rule.high_conf,
                });
            }
        }
    }

    out.sort_by_key(|m| m.line);
    out
}

/// Severity for a secret hit: a structurally-identifiable provider key is Critical (a live
/// credential, one paste away from account takeover); a heuristic `generic-*` hit is Medium.
pub fn severity_for(m: &SecretMatch) -> Severity {
    if m.high_conf {
        Severity::Critical
    } else {
        Severity::Medium
    }
}

/// Rewrites `text`, replacing every high-confidence secret with [`REDACTION_PLACEHOLDER`], and
/// returns the new text plus the number replaced.
///
/// Only high-confidence provider secrets are redacted. The `generic-*` patterns are report-only:
/// blindly rewriting a value that merely tripped a heuristic could corrupt a legitimate config,
/// and a scanner that damages your files in order to protect them has made a bad trade.
///
/// Replacement walks right-to-left so earlier offsets stay valid as later ones are spliced out.
pub fn redact_text(text: &str) -> (String, usize) {
    let pack = &*PACK;
    let lowered = text.to_lowercase();
    let candidates = pack.candidates(&lowered);

    let mut hits: Vec<(usize, usize)> = Vec::new();
    for rule in candidates
        .iter()
        .map(|&i| &pack.rules[i])
        .filter(|r| r.high_conf)
    {
        for ((start, end), _) in matches_for(rule, text) {
            if hits.iter().any(|&(s, e)| start < e && s < end) {
                continue;
            }
            hits.push((start, end));
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

    fn rule_ids(text: &str) -> Vec<String> {
        scan_text(text).into_iter().map(|m| m.rule_id).collect()
    }

    fn anthropic_key() -> String {
        format!("sk-ant-api03-{}AA", "a".repeat(93))
    }

    /// gitleaks' patterns target Go's RE2; the `regex` crate is close but not identical, so a rule
    /// that fails to compile is skipped rather than fatal. This test is what keeps that from
    /// silently costing coverage on a user's machine.
    /// gitleaks' patterns target Go's RE2; the `regex` crate is close but not identical, and a rule
    /// that fails to compile is skipped rather than fatal. This is what stops that costing coverage
    /// silently on a user's machine. It compiles the whole pack — the only place that happens, since
    /// the scanner itself compiles lazily.
    #[test]
    fn every_bundled_rule_compiles() {
        let pack = &*PACK;
        let failed: Vec<&str> = pack
            .rules
            .iter()
            .filter(|r| r.regex().is_none())
            .map(|r| r.id.as_str())
            .collect();
        assert!(
            failed.is_empty(),
            "these rules failed to compile and are silently not running: {failed:?}"
        );
        assert!(
            pack.rules.len() > 200,
            "expected the full vendored pack, got {}",
            pack.rules.len()
        );
    }

    /// Scanning an ordinary file must not pay for the whole rule pack. Compiling all 262 patterns
    /// eagerly measured ~2.3s in release (13s in debug) — in front of every scan, and paid even by
    /// a run that finds nothing. The keyword index plus lazy compilation is what makes a scan fast;
    /// this asserts it stays that way, because the regression would be invisible in a correctness
    /// test and merely make the product feel broken.
    #[test]
    fn scanning_an_ordinary_file_does_not_compile_the_whole_pack() {
        let prose = "# Project notes\n\nRun the tests before pushing. Keep functions small.\n";
        let start = std::time::Instant::now();
        let hits = scan_text(prose);
        let elapsed = start.elapsed();

        assert!(hits.is_empty());
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "scanning a short prose file took {elapsed:?} — the keyword index is not doing its job"
        );

        let compiled = PACK.rules.iter().filter(|r| r.re.get().is_some()).count();
        assert!(
            compiled < 40,
            "{compiled} of {} rules were compiled for a file with no secrets in it",
            PACK.rules.len()
        );
    }

    #[test]
    fn detects_anthropic_key() {
        let key = anthropic_key();
        let hits = scan_text(&format!("here is my key {key} please debug"));
        assert!(hits.iter().any(|h| h.rule_id == "anthropic-api-key"));
        assert!(hits[0].high_conf);
        assert!(
            !hits[0].redacted.contains(&key),
            "must never echo the raw secret"
        );
    }

    /// The segment lengths matter: OpenAI's format is a 20/58/74-char body either side of the
    /// embedded `T3BlbkFJ` literal, and the rule encodes exactly that. An invented length is not a
    /// valid key and *should* be rejected — the first version of this test used one, and the rule
    /// was right to ignore it.
    #[test]
    fn detects_openai_key() {
        let seg = "a1B2c3D4e5F6g7H8i9J0"; // 20 chars, mixed case + digits
        let key = format!("sk-proj-{seg}T3BlbkFJ{seg}");
        let ids = rule_ids(&format!("OPENAI_API_KEY={key}\n"));
        assert!(
            ids.contains(&"openai-api-key".to_string()),
            "expected the OpenAI rule to fire, got {ids:?}"
        );
    }

    #[test]
    fn detects_github_pat() {
        let ids = rule_ids("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz");
        assert!(
            ids.iter().any(|id| id.starts_with("github-")),
            "expected a github rule, got {ids:?}"
        );
    }

    /// The reason for adopting an entropy-gated pack: a broad pattern must not fire on an obvious
    /// template. This is exactly the case a hand-rolled regex set gets wrong.
    #[test]
    fn broad_patterns_ignore_low_entropy_placeholders() {
        for benign in [
            "API_KEY=your_api_key_here",
            "password = changeme",
            "api_key: \"xxxxxxxxxxxxxxxxxxxx\"",
            "# set your api key here before running",
        ] {
            assert!(
                scan_text(benign).is_empty(),
                "must not flag a template: {benign}"
            );
        }
    }

    #[test]
    fn ordinary_prose_is_not_flagged() {
        assert!(
            scan_text("# Project rules\nUse tabs. Write tests. Keep functions small.\n").is_empty()
        );
    }

    #[test]
    fn a_real_looking_generic_secret_is_medium_not_critical() {
        let hits = scan_text("MY_SERVICE_TOKEN=a8Fk2Lm9Qp3Rn7Zx1Wc4vB6yH0jD5sG");
        assert_eq!(hits.len(), 1, "got {hits:?}");
        assert!(!hits[0].high_conf);
        assert_eq!(severity_for(&hits[0]), Severity::Medium);
    }

    #[test]
    fn precise_provider_match_wins_over_the_generic_one() {
        let hits = scan_text(&format!("ANTHROPIC_API_KEY={}", anthropic_key()));
        assert_eq!(
            hits.len(),
            1,
            "the overlapping generic hit must be suppressed, got {hits:?}"
        );
        assert_eq!(hits[0].rule_id, "anthropic-api-key");
    }

    #[test]
    fn reports_the_correct_line_number() {
        let hits = scan_text(&format!("line one\nline two\n{}\n", anthropic_key()));
        assert_eq!(hits[0].line, 3);
    }

    #[test]
    fn redaction_removes_the_secret_and_is_idempotent() {
        let key = anthropic_key();
        let text = format!("key: {key}\nother line\n");

        let (redacted, count) = redact_text(&text);
        assert_eq!(count, 1);
        assert!(!redacted.contains(&key));
        assert!(redacted.contains(REDACTION_PLACEHOLDER));
        assert!(redacted.contains("other line"));

        let (again, count2) = redact_text(&redacted);
        assert_eq!(count2, 0, "the placeholder must be inert");
        assert_eq!(again, redacted);
    }

    #[test]
    fn redaction_only_touches_high_confidence_secrets() {
        let text = "MY_TOKEN=a8Fk2Lm9Qp3Rn7Zx1Wc4vB6yH0jD5sG\n";
        assert_eq!(scan_text(text).len(), 1, "it is still reported");
        let (redacted, count) = redact_text(text);
        assert_eq!(count, 0, "but never auto-rewritten");
        assert_eq!(redacted, text);
    }

    #[test]
    fn mask_never_reveals_a_short_secret() {
        assert_eq!(mask("short"), "*****");
        assert!(mask("sk-ant-api03-aaaaaaaaaa").contains('…'));
    }

    #[test]
    fn entropy_separates_a_real_token_from_prose() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("the quick brown fox jumps") < 4.5);
        assert!(shannon_entropy("a8Fk2Lm9Qp3Rn7Zx1Wc4vB6yH0jD5sG") > 4.0);
    }

    #[test]
    fn ids_are_humanized_for_display() {
        assert_eq!(humanize("anthropic-api-key"), "Anthropic API key");
        assert_eq!(humanize("aws-access-token"), "AWS access token");
        assert_eq!(humanize("private-key"), "Private key");
    }
}

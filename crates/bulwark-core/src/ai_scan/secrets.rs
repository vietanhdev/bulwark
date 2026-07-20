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
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
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
    /// A rule may only apply to certain files — `nuget-config-password` to `nuget.config`,
    /// `freemius-secret-key` to `.php`. See [`Rule::applies_to`].
    #[serde(default)]
    path: Option<String>,
    /// What this rule is *not* allowed to flag. See [`Allowlist`].
    #[serde(default)]
    allowlists: Vec<AllowlistSpec>,
}

/// A gitleaks allowlist: the suppression half of a rule. Ships in `secret_rules.toml` and, until
/// now, was parsed by nobody.
#[derive(Debug, Deserialize)]
struct AllowlistSpec {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    /// `"match"`, `"line"`, or absent — absent means the regexes test the secret itself.
    #[serde(rename = "regexTarget", default)]
    regex_target: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RuleSpec>,
    /// The file's `[allowlist]` table: suppressions that apply to every rule.
    #[serde(default)]
    allowlist: Option<AllowlistSpec>,
}

/// Which text an allowlist's regexes are tested against.
#[derive(Debug, Clone, Copy, PartialEq)]
enum AllowTarget {
    /// The captured secret. gitleaks' default when `regexTarget` is absent.
    Secret,
    /// The rule's whole match, context and all.
    Match,
    /// The entire line the match sits on.
    Line,
}

/// The suppression half of a rule — **the half we were throwing away.**
///
/// A gitleaks rule is a pair: a deliberately broad regex, plus an allowlist that carves the known
/// non-secrets back out of it. We vendored the regexes and dropped the allowlists on the floor, so
/// every rule fired on material upstream explicitly suppresses: `curl -u "${username}:${password}"`
/// reported as leaked credentials, Google's own published `AIzaSy…` documentation keys reported as
/// live GCP keys, and 1,446 stopwords' worth of `generic-api-key` noise. The data was sitting in
/// `secret_rules.toml` the whole time; nothing read it. `no_rule_fires_on_its_known_false_positives`
/// is what finally noticed.
///
/// Semantics are gitleaks': `regexes` test whatever [`AllowTarget`] names (the secret unless the
/// rule says otherwise), while `stopwords` always test the secret itself — a distinction worth
/// keeping exactly, since a stopword tested against the whole match would suppress a real key that
/// merely sat on a line mentioning `example`.
struct Allowlist {
    target: AllowTarget,
    regex_src: Vec<String>,
    /// Compiled on first use, for the same reason rule patterns are: a scan that matches nothing
    /// should not pay to build regexes it never runs.
    regexes: OnceLock<Vec<Regex>>,
    stopwords: Vec<String>,
    /// `generic-api-key` alone carries 1,446 stopwords — a linear scan per match would undo the
    /// work of the last commit, so they go in an automaton like the keyword index does.
    stopword_index: OnceLock<Option<AhoCorasick>>,
}

impl Allowlist {
    fn from_spec(spec: AllowlistSpec) -> Self {
        let target = match spec.regex_target.as_deref() {
            Some("match") => AllowTarget::Match,
            Some("line") => AllowTarget::Line,
            _ => AllowTarget::Secret,
        };
        Allowlist {
            target,
            regex_src: spec.regexes,
            regexes: OnceLock::new(),
            stopwords: spec.stopwords,
            stopword_index: OnceLock::new(),
        }
    }

    fn regexes(&self) -> &[Regex] {
        self.regexes.get_or_init(|| {
            self.regex_src
                .iter()
                .filter_map(|p| compile(&literalize_braces(p)).ok())
                .collect()
        })
    }

    /// How many of this allowlist's patterns the `regex` crate actually accepted. Equal to
    /// `regex_src.len()` unless one was dropped — which `every_allowlist_regex_compiles` forbids.
    #[cfg(test)]
    fn compiled_count(&self) -> usize {
        self.regexes().len()
    }

    fn stopword_index(&self) -> Option<&AhoCorasick> {
        self.stopword_index
            .get_or_init(|| {
                if self.stopwords.is_empty() {
                    return None;
                }
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(&self.stopwords)
                    .ok()
            })
            .as_ref()
    }

    /// Whether this allowlist says the hit is not a secret after all.
    fn allows(&self, secret: &str, whole: &str, line: &str) -> bool {
        let haystack = match self.target {
            AllowTarget::Secret => secret,
            AllowTarget::Match => whole,
            AllowTarget::Line => line,
        };
        if self.regexes().iter().any(|re| re.is_match(haystack)) {
            return true;
        }
        // Stopwords always test the secret, never the wider match (gitleaks' `StopWords` doc).
        self.stopword_index()
            .is_some_and(|index| index.is_match(secret))
    }
}

/// Escapes the braces in a Go pattern that Rust's `regex` would reject.
///
/// gitleaks' patterns target RE2, which treats `{` as a literal when it can't begin a repetition.
/// Rust's `regex` is stricter and rejects the pattern outright — so
/// `['"]?\$?{{[^}]+}}['"]?:['"]?\$?{{[^}]+}}['"]?`, the allowlist that exists precisely to suppress
/// `${{ github.actions }}` template syntax, failed to compile and was silently dropped. That single
/// dropped pattern is why `curl -u "${{ env.ID }}:${{ env.PASS }}"` kept being reported as leaked
/// credentials.
///
/// Escaping only the braces that *cannot* be a quantifier makes the pattern legal for Rust while
/// matching exactly the same text — `{{` was never a quantifier in the first place.
fn literalize_braces(pattern: &str) -> String {
    let b = pattern.as_bytes();
    let (mut out, mut i, mut in_class) = (String::new(), 0, false);
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            out.push('\\');
            out.push(b[i + 1] as char);
            i += 2;
            continue;
        }
        match b[i] {
            b'[' if !in_class => {
                in_class = true;
                out.push('[');
            }
            b']' if in_class => {
                in_class = false;
                out.push(']');
            }
            // Inside a character class a brace is already literal; outside, it's only legal if it
            // opens a real `{m}` / `{m,}` / `{m,n}`.
            b'{' if !in_class => match quantifier_len(&pattern[i..]) {
                Some(len) => {
                    out.push_str(&pattern[i..i + len]);
                    i += len;
                    continue;
                }
                None => out.push_str("\\{"),
            },
            b'}' if !in_class => out.push_str("\\}"),
            c => out.push(c as char),
        }
        i += 1;
    }
    out
}

/// Byte length of a valid repetition quantifier (`{2}`, `{2,}`, `{2,5}`) at the start of `s`.
fn quantifier_len(s: &str) -> Option<usize> {
    let close = s.find('}')?;
    let body = &s[1..close];
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit());
    let valid = match body.split_once(',') {
        Some((min, max)) => digits(min) && (max.is_empty() || digits(max)),
        None => digits(body),
    };
    valid.then_some(close + 1)
}

/// The line `offset` falls on — the haystack for an `AllowTarget::Line` allowlist.
fn line_at(text: &str, offset: usize) -> &str {
    let start = text[..offset].rfind('\n').map_or(0, |i| i + 1);
    let end = text[offset..].find('\n').map_or(text.len(), |i| offset + i);
    &text[start..end]
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
    /// What this rule must *not* flag, straight from the vendored pack.
    allowlists: Vec<Allowlist>,
    /// The file this rule applies to, if it is scoped to one. See [`Rule::applies_to`].
    path_src: Option<String>,
    path_re: OnceLock<Option<Regex>>,
}

impl Rule {
    fn regex(&self) -> Option<&Regex> {
        self.re.get_or_init(|| compile(&self.pattern).ok()).as_ref()
    }

    /// Whether this rule applies to the file being scanned.
    ///
    /// Five rules in the pack are scoped to a file: `nuget-config-password` means something in a
    /// `nuget.config` and nothing anywhere else, `freemius-secret-key` only in `.php`. We ignored
    /// the constraint and ran every rule against every file, so `<add key="Password" value="…"/>`
    /// in any XML — or a `sk_…` string in a chat transcript — was reported as a leaked credential.
    /// gitleaks treats `path` as a *required* condition, and so do we.
    ///
    /// When the path is unknown the rule does not apply: the condition it depends on cannot be
    /// established, and guessing "yes" is what produced the false positives. Every production caller
    /// knows the file it is scanning (`ai_scan` passes the artifact's path), so this only affects
    /// callers that scan a bare string.
    fn applies_to(&self, path: Option<&str>) -> bool {
        let Some(src) = &self.path_src else {
            return true; // unscoped: applies everywhere
        };
        let Some(path) = path else {
            return false;
        };
        self.path_re
            .get_or_init(|| compile(src).ok())
            .as_ref()
            .is_some_and(|re| re.is_match(path))
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
    /// The file's `[allowlist]` table — suppressions that apply to every rule.
    global_allowlist: Vec<Allowlist>,
}

impl Pack {
    /// The rules worth running against `lowered`, as indices into `rules`.
    ///
    /// **Overlapping** iteration, not `find_iter`. Keywords overlap constantly — `api` is a
    /// substring of `sk-ant-api03` — and non-overlapping iteration reports only one of them, so
    /// the more specific keyword's rule never gets considered. That silently lost every Anthropic
    /// key in the text: precisely the class of bug where a scanner reports "clean" while missing
    /// the thing it exists to find.
    ///
    /// Runs directly on the original `text`: the automaton is built ASCII-case-insensitive, so we
    /// never allocate a lowercased copy of the haystack. That copy used to be made once per file —
    /// up to 4 MB each across ~1800 transcript files on a real home directory — and was the reason
    /// a whole-machine scan could fail to finish.
    fn candidates(&self, text: &str) -> Vec<usize> {
        let mut hit = vec![false; self.rules.len()];
        for m in self.keywords.find_overlapping_iter(text) {
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
    let spec_allowlist = spec.allowlist;

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
            pattern: drop_leading_wildcard(&pattern),
            re: OnceLock::new(),
            entropy: r.entropy,
            high_conf,
            allowlists: r.allowlists.into_iter().map(Allowlist::from_spec).collect(),
            path_src: r.path,
            path_re: OnceLock::new(),
        });
    }

    // ASCII-case-insensitive so the scan can match keywords against the raw file text without first
    // allocating a lowercased copy of it (see `candidates`). Keywords are ASCII provider markers
    // (`sk-ant`, `AKIA`, `api`), so ASCII folding is exactly right.
    let keywords = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(&keyword_list)
        .expect("keyword automaton must build");
    Pack {
        rules,
        keywords,
        rules_for_keyword,
        always,
        global_allowlist: spec_allowlist
            .into_iter()
            .map(Allowlist::from_spec)
            .collect(),
    }
});

/// Strips the leading *optional* wildcard from a gitleaks pattern — the single change that makes a
/// whole-machine scan finish in seconds instead of hours.
///
/// Most of the pack's keyword-context rules are shaped like this:
///
/// ```text
/// [\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere|CO_API_KEY)…)(?:=|:|…)…([a-zA-Z0-9]{40})…
/// ^^^^^^^^^^^^^     ^^^^^^^^^^^^^
/// ```
///
/// Those two leading `{0,50}?` repeats exist only to pull neighbouring word characters into the
/// reported match. They are ruinous for the `regex` crate: a pattern that *starts* with a
/// variable-length character class has no literal prefix, so the engine can't build a
/// memchr/Teddy prefilter and must attempt a match at every byte offset, and the nested bounded
/// repeats blow out the lazy-DFA cache until it falls back to a far slower engine. Measured on a
/// real 4 MB Claude Code transcript, one such rule took **2.9 s**; with the prefix removed, the
/// same rule over the same input took **0.5 ms** and found exactly the same matches. Multiplied by
/// ~40 candidate rules across ~1800 transcripts, that difference is the whole reason an AI scan
/// used to peg a core for hours.
///
/// The rewrite is safe because the prefix is *optional* (`{0,…}`) and sits at the very start of an
/// unanchored search: if `PQ` can match anywhere then so can `Q`, and vice versa, so removing `P`
/// cannot add or remove a single detection. Only the *start offset* of the whole match moves — it
/// can no longer reach backwards over adjacent word characters — and that offset is used solely to
/// dedup overlapping spans, where a narrower span can only ever suppress *fewer* findings. The
/// secret itself is capture group 1 and is not touched.
///
/// Every condition below is a load-bearing guard, and anything not matching the exact expected
/// shape is returned unchanged — a rule that stays slow is a bug; a rule that silently stops
/// matching is a vulnerability:
///
/// - **the pattern must isolate its secret in a capture group** — for a rule with no group, the
///   whole match *is* the reported secret ([`matches_for`] falls back to it), so moving the match
///   start would change the reported and redacted bytes;
/// - **the repeat's minimum must be 0** — `[\w.-]{5,50}?` *requires* five leading characters, and
///   dropping it would make the rule match text it previously rejected;
/// - **the repeat must be lazy and bounded** — the shape gitleaks actually emits.
fn drop_leading_wildcard(pattern: &str) -> String {
    if !has_capture_group(pattern) {
        return pattern.to_string();
    }

    let mut out = String::new();
    let mut rest = pattern;

    // A leading inline-flag *directive* — `(?i)`, which most of the pack opens with — sets flags for
    // the whole pattern and consumes no text, so what follows it is still in leading position. Keep
    // it and look past it.
    let flags = inline_flags_len(rest);
    out.push_str(&rest[..flags]);
    rest = &rest[flags..];

    // The wildcard itself.
    rest = &rest[optional_class_repeat_len(rest)..];

    // gitleaks nests a second wildcard just inside a leading *group* opener (`(?i:`). Once the outer
    // one is gone that group opens the pattern, so the wildcard inside it is still in leading
    // position and the same reasoning applies.
    let opener = inline_group_opener_len(rest);
    if opener > 0 {
        let n = optional_class_repeat_len(&rest[opener..]);
        if n > 0 {
            out.push_str(&rest[..opener]);
            rest = &rest[opener + n..];
        }
    }

    out.push_str(rest);
    out
}

/// Byte length of a leading inline-flag directive — `(?i)`, `(?is)` — or 0 if `s` doesn't start with
/// one. Distinct from [`inline_group_opener_len`]: a directive ends at `)` and matches no text; a
/// group opener ends at `:` and wraps a subexpression.
fn inline_flags_len(s: &str) -> usize {
    let b = s.as_bytes();
    if !s.starts_with("(?") {
        return 0;
    }
    let mut i = 2;
    while i < b.len() && matches!(b[i], b'i' | b'm' | b's' | b'u' | b'x' | b'U' | b'R' | b'-') {
        i += 1;
    }
    if i > 2 && b.get(i) == Some(&b')') {
        i + 1
    } else {
        0
    }
}

/// Byte length of a leading **optional, lazy, bounded** character-class repeat (`[\w.-]{0,50}?`),
/// or 0 if `s` does not begin with exactly that shape. See [`drop_leading_wildcard`] for why each
/// of those three properties has to hold before the repeat can be removed.
fn optional_class_repeat_len(s: &str) -> usize {
    let b = s.as_bytes();
    if b.first() != Some(&b'[') {
        return 0;
    }

    // Walk to the class's closing `]`. A `]` immediately after `[` or `[^` is a literal member, not
    // the terminator, and `\]` is an escape — both would otherwise end the class early.
    let mut i = 1;
    if b.get(i) == Some(&b'^') {
        i += 1;
    }
    if b.get(i) == Some(&b']') {
        i += 1;
    }
    while i < b.len() && b[i] != b']' {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    if b.get(i) != Some(&b']') {
        return 0;
    }
    i += 1;

    // `{min,max}` — and nothing else. A bare `*`/`+`/`?`, or an open-ended `{0,}`, is a shape we
    // haven't reasoned about, so leave it alone.
    if b.get(i) != Some(&b'{') {
        return 0;
    }
    let body_start = i + 1;
    let Some(close) = b[body_start..].iter().position(|&c| c == b'}') else {
        return 0;
    };
    let Some((min, max)) = s[body_start..body_start + close].split_once(',') else {
        return 0; // `{40}` — an exact count, which is required, not optional.
    };
    // The minimum must be 0, or the repeat is a *requirement* and dropping it widens the rule.
    if min.trim() != "0" || max.trim().parse::<u32>().is_err() {
        return 0;
    }
    i = body_start + close + 1;

    // Lazy only (`?`). A greedy repeat is a shape gitleaks doesn't emit here.
    if b.get(i) != Some(&b'?') {
        return 0;
    }
    i + 1
}

/// Byte length of a leading non-capturing group opener — `(?:`, `(?i:`, `(?is:` — or 0 if `s`
/// doesn't start with one. A *capturing* `(` returns 0: its group numbering must not shift.
fn inline_group_opener_len(s: &str) -> usize {
    let b = s.as_bytes();
    if !s.starts_with("(?") {
        return 0;
    }
    let mut i = 2;
    while i < b.len() && matches!(b[i], b'i' | b'm' | b's' | b'u' | b'x' | b'U' | b'R' | b'-') {
        i += 1;
    }
    if b.get(i) == Some(&b':') {
        i + 1
    } else {
        0
    }
}

/// Whether `pattern` has a capturing group — i.e. whether it isolates the secret from its
/// surrounding context. `(?:…)`, `(?i:…)` and lookarounds don't capture; `(…)`, `(?P<n>…)` and
/// `(?<n>…)` do. A `(` inside a character class or behind a backslash is a literal.
fn has_capture_group(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            // `(` alone captures; `(?…)` generally doesn't, except the named forms `(?P<n>`/`(?<n>`.
            b'(' if !in_class
                && (b.get(i + 1) != Some(&b'?')
                    || matches!(b.get(i + 2), Some(&b'P') | Some(&b'<'))) =>
            {
                return true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

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
    let len = chars.len();
    // The revealed head/tail exists only to help a human recognize *which* key this is (e.g. an
    // `sk-ant-` prefix), never to expose recoverable material. So reveal at most ~1/8 of the
    // secret from each end (capped at 4 head / 3 tail), and nothing at all from a short one — the
    // previous fixed head4/tail3 leaked ~64% of an 11-char generic token.
    let reveal = len / 8;
    if len <= 12 || reveal == 0 {
        return "*".repeat(len.max(1));
    }
    let head: String = chars.iter().take(reveal.min(4)).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(reveal.min(3))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

/// A documentation-example credential, suppressed even for high-confidence rules. AWS's canonical
/// docs key (`AKIAIOSFODNN7EXAMPLE`) matches the real `AKIA…` pattern exactly, so without this it
/// fires CRITICAL on every AWS tutorial and README — gitleaks ships a dedicated `.+EXAMPLE$`
/// allowlist for precisely this, which this crate's slimmed rule loader had dropped. An `EXAMPLE`
/// suffix on a would-be key is the near-universal "this is fake" marker.
fn is_documentation_example(value: &str) -> bool {
    let v = value.trim_matches(|c: char| !c.is_alphanumeric());
    v.ends_with("EXAMPLE") || v.ends_with("EXAMPLEKEY")
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

/// One raw regex match, before dedup. `start`/`end` bound the **whole** match — which, for most
/// rules, deliberately reaches past the credential to anchor on the surrounding context: a `KEY =`
/// prefix before it and a terminator after it (`(?:\\?['"\x60]|[\s;]|\\[nr]|$)` — note that `[\s;]`
/// matches the line's own newline). `secret_start`/`secret_end` bound the credential alone (capture
/// group 1, where the pattern isolates one).
///
/// Keeping the two spans apart is the whole point: overlap resolution wants the wide span (so a
/// generic rule can't re-flag bytes a provider rule already claimed), but **redaction must rewrite
/// only the narrow one**. Replacing the wide span deleted whatever the pattern had consumed as its
/// terminator — most often the line ending, which silently joined the secret's line to the next.
struct RawMatch<'t> {
    start: usize,
    end: usize,
    secret_start: usize,
    secret_end: usize,
    secret: &'t str,
}

/// Every hit for one rule against `text`. The caller has already established, via the keyword
/// index, that this rule is worth running at all.
fn matches_for<'t>(pack: &Pack, rule: &Rule, text: &'t str) -> Vec<RawMatch<'t>> {
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
        if is_documentation_example(secret.as_str()) {
            continue;
        }
        if !rule.high_conf && is_placeholder_value(secret.as_str()) {
            continue;
        }
        // The rule's own suppressions, then the file-wide ones. This is the half of each gitleaks
        // rule that turns a deliberately broad pattern into a usable one — see `Allowlist`.
        let allowed = |a: &&Allowlist| {
            a.allows(
                secret.as_str(),
                whole.as_str(),
                line_at(text, whole.start()),
            )
        };
        if rule.allowlists.iter().any(|a| allowed(&a))
            || pack.global_allowlist.iter().any(|a| allowed(&a))
        {
            continue;
        }
        out.push(RawMatch {
            start: whole.start(),
            end: whole.end(),
            secret_start: secret.start(),
            secret_end: secret.end(),
            secret: secret.as_str(),
        });
    }
    out
}

/// A set of accepted, non-overlapping byte spans, keyed by start offset, with O(log n) overlap
/// queries. Replaces a linear `spans.iter().any(...)` scan whose cost was O(n²) in the number of
/// matches — a crafted file packed with thousands of secret-like values could otherwise turn a
/// scan into tens of seconds of pure CPU. Because accepted spans never overlap, a candidate
/// `[start, end)` overlaps the set iff the accepted span with the greatest start `< end` still
/// ends after `start`.
#[derive(Default)]
struct SpanSet(std::collections::BTreeMap<usize, usize>);

impl SpanSet {
    fn overlaps(&self, start: usize, end: usize) -> bool {
        self.0
            .range(..end)
            .next_back()
            .is_some_and(|(_, &e)| e > start)
    }
    fn insert(&mut self, start: usize, end: usize) {
        self.0.insert(start, end);
    }
}

/// Upper bound on distinct secret hits recorded for a single file. Real artifacts hold a handful;
/// this only caps a pathological/crafted file whose whole point is to amplify one 4 MB input into
/// a memory-blowing pile of findings. Far above any legitimate file, so it never truncates real
/// results silently.
const MAX_SECRETS_PER_TEXT: usize = 1000;

/// One deduplicated secret hit in `text`: the byte span **of the credential itself** (not of the
/// wider [`RawMatch`], whose context bytes belong to the surrounding file and must survive), the
/// index of the rule that matched, and the secret slice. This is the single detection primitive
/// behind *both* [`scan_text`] (which reports every hit) and [`redact_text`] (which rewrites only
/// the high-confidence ones), so redaction reuses the exact candidate prefilter, regex pass, and
/// overlap resolution rather than re-deriving them from scratch. The wide match span exists only
/// inside [`find_hits`], where dedup needs it; nothing downstream may see it.
struct Hit<'t> {
    secret_start: usize,
    secret_end: usize,
    rule: usize,
    secret: &'t str,
}

/// Finds every distinct secret hit in `text`, running the rule passes named in `passes` in order
/// (`true` = precise provider rules, `false` = heuristic `generic-*` rules). Earlier passes claim
/// their byte spans first, so a provider match always wins over a broad heuristic on the same
/// bytes. A full scan passes `[true, false]`; redaction passes `[true]` only, which skips the
/// heuristic regexes entirely — so redaction does strictly *less* work than a scan, never a second
/// full one. Runs the candidate prefilter directly on `text` (the automaton is case-insensitive),
/// so no lowercased copy of a multi-MB file is ever allocated.
fn find_hits<'t>(path: Option<&str>, text: &'t str, passes: &[bool]) -> Vec<Hit<'t>> {
    let pack = &*PACK;
    let candidates = pack.candidates(text);

    let mut spans = SpanSet::default();
    let mut hits: Vec<Hit<'t>> = Vec::new();

    'passes: for &high_conf_pass in passes {
        for &ri in &candidates {
            let rule = &pack.rules[ri];
            if rule.high_conf != high_conf_pass || !rule.applies_to(path) {
                continue;
            }
            for m in matches_for(pack, rule, text) {
                if spans.overlaps(m.start, m.end) {
                    continue;
                }
                spans.insert(m.start, m.end);
                hits.push(Hit {
                    secret_start: m.secret_start,
                    secret_end: m.secret_end,
                    rule: ri,
                    secret: m.secret,
                });
                if hits.len() >= MAX_SECRETS_PER_TEXT {
                    break 'passes;
                }
            }
        }
    }
    hits
}

/// Scans `text`, returning one [`SecretMatch`] per distinct hit. Where a broad `generic-*` rule
/// overlaps a precise provider rule on the same bytes, only the provider match is kept — a
/// hardcoded `ANTHROPIC_API_KEY=sk-ant-…` is *one* Anthropic finding, not also a generic one.
pub fn scan_text(text: &str) -> Vec<SecretMatch> {
    scan_text_in(None, text)
}

/// [`scan_text`] for a known file. Path-scoped rules only apply here.
pub fn scan_text_in(path: Option<&str>, text: &str) -> Vec<SecretMatch> {
    let pack = &*PACK;
    // Precise rules first (the `[true, false]` order), so they claim their spans before the
    // heuristic ones run.
    let mut out: Vec<SecretMatch> = find_hits(path, text, &[true, false])
        .into_iter()
        .map(|h| {
            let rule = &pack.rules[h.rule];
            SecretMatch {
                provider: rule.provider.clone(),
                rule_id: rule.id.clone(),
                line: line_of(text, h.secret_start),
                redacted: mask(h.secret),
                high_conf: rule.high_conf,
            }
        })
        .collect();

    out.sort_by_key(|m| m.line);
    out
}

/// Like [`scan_text`] but runs ONLY the high-confidence provider rules — the heuristic `generic-*`
/// regexes (the broadest and slowest in the pack) are skipped entirely. The AI scan uses this
/// because it reports high-confidence hits only; running the generic patterns and then discarding
/// their results was pure wasted CPU over every scanned file. All returned matches are high-conf.
pub fn scan_text_high_confidence(text: &str) -> Vec<SecretMatch> {
    scan_text_high_confidence_in(None, text)
}

/// [`scan_text_high_confidence`] for a known file. Path-scoped rules only apply here.
pub fn scan_text_high_confidence_in(path: Option<&str>, text: &str) -> Vec<SecretMatch> {
    let pack = &*PACK;
    let mut out: Vec<SecretMatch> = find_hits(path, text, &[true])
        .into_iter()
        .map(|h| {
            let rule = &pack.rules[h.rule];
            SecretMatch {
                provider: rule.provider.clone(),
                rule_id: rule.id.clone(),
                line: line_of(text, h.secret_start),
                redacted: mask(h.secret),
                high_conf: true,
            }
        })
        .collect();

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
    redact_text_in(None, text)
}

/// [`redact_text`] for a known file. Path-scoped rules only apply here.
pub fn redact_text_in(path: Option<&str>, text: &str) -> (String, usize) {
    // Reuse the scanner's exact detection primitive, but run ONLY the high-confidence pass. The
    // heuristic `generic-*` rules are report-only and must never be rewritten (blindly editing a
    // value that merely looked like a secret could corrupt a legitimate config), so skipping them
    // means redaction runs a strict subset of the scan's regexes — not a second full pass.
    // The credential's own span, NOT the wider regex match: most rules anchor on context they must
    // not consume — a `KEY =` prefix, a closing quote, and a terminator that is usually the line's
    // own newline (`[\s;]`). Replacing the wide span deleted all of it, so redacting `KEY=secret\n`
    // yielded `[bulwark:redacted-secret]` with the next line welded onto it — a corrupted `.env`
    // whose variable name was gone too. Only the secret's bytes may be rewritten.
    let mut hits: Vec<(usize, usize)> = find_hits(path, text, &[true])
        .into_iter()
        .map(|h| (h.secret_start, h.secret_end))
        .collect();
    if hits.is_empty() {
        return (text.to_string(), 0);
    }

    // Rebuild in a single left-to-right pass: copy each kept segment, then the placeholder. The old
    // approach spliced the secret out of a full copy once per hit, which reshuffles the whole tail
    // every time — quadratic in the number of secrets on a large transcript. Secret spans nest
    // inside the non-overlapping match spans (SpanSet), so they are themselves non-overlapping and
    // sorting by start makes the copy unambiguous.
    hits.sort_unstable_by_key(|&(start, _)| start);
    let count = hits.len();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in hits {
        out.push_str(&text[cursor..start]);
        out.push_str(REDACTION_PLACEHOLDER);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::Distribution;
    use rand::SeedableRng;
    use std::collections::BTreeSet;

    const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &str = "0123456789abcdef";

    fn rule_ids(text: &str) -> Vec<String> {
        scan_text(text).into_iter().map(|m| m.rule_id).collect()
    }

    /// The rule pack exactly as vendored, before [`drop_leading_wildcard`] touches it — the
    /// "before" side of the differential test below.
    fn raw_rules() -> Vec<(String, String, Vec<String>)> {
        let spec: RuleFile = toml::from_str(include_str!("secret_rules.toml")).unwrap();
        spec.rules
            .into_iter()
            .filter_map(|r| r.regex.map(|re| (r.id, re, r.keywords)))
            .collect()
    }

    /// The `path` condition of each path-scoped rule, by id.
    fn rule_paths() -> Vec<(String, String)> {
        let spec: RuleFile = toml::from_str(include_str!("secret_rules.toml")).unwrap();
        spec.rules
            .into_iter()
            .filter_map(|r| r.path.map(|p| (r.id, p)))
            .collect()
    }

    /// A file path that satisfies a rule's `path` condition — generated from the condition itself,
    /// the same way its secret is generated from its regex. A path-scoped rule (`nuget.config`,
    /// `*.php`) is inert without one, so a coverage test that scanned pathless text would report
    /// those rules as broken when they are merely not applicable.
    fn matching_path(id: &str) -> Option<String> {
        let pattern = rule_paths().into_iter().find(|(r, _)| r == id)?.1;
        let gen = SampleGen::new(&pattern)?;
        (0..40).find_map(|seed| gen.sample(seed))
    }

    /// Rewrites a rule's pattern into one a *generator* can produce a realistic secret from.
    ///
    /// Two adjustments, both of which only ever widen or narrow toward realism — and neither of
    /// which can weaken the test, because `generated_sample` verifies every candidate against the
    /// real, unmodified rule regex before returning it:
    ///
    /// - **Anchors (`\b`, `^`, `$`) are dropped.** They match no text, and `rand_regex` rejects
    ///   them outright.
    /// - **A `.` is pinned to what it actually stands for**, decided by whether it is quantified:
    ///   - a **bare** `.` is a literal dot — `hooks.slack.com`, `gems.contribsys.com`. Left as
    ///     "any character", the generator renders it `hooks\u{9742d}slack\u{d27e9}com`, which the
    ///     rule's regex still matches but which contains none of the literal keywords the pack's
    ///     prefilter needs to even consider the rule. Legal, and worthless.
    ///   - a **quantified** `.` (`.{8,}`, `.*`, `.+`) is a secret body — the value in
    ///     `<add key="Password" value="(.{8,})"/>`. Pinning *that* to a literal dot produces
    ///     `........`, whose Shannon entropy is zero, so the rule's own entropy gate throws it out
    ///     and the rule looks broken. It becomes `[A-Za-z0-9]` instead: a plausible credential.
    ///
    ///   Both substitutions produce text the original `.` still matches, so a generated sample stays
    ///   valid either way — this only decides whether it looks like the thing it stands for.
    ///
    /// Unicode is switched off for the same reason (see `generated_sample`): `\w` is Unicode-aware,
    /// so an unconstrained generator emits CJK where a real API key has ASCII.
    fn generatable_pattern(pattern: &str) -> String {
        let b = pattern.as_bytes();
        let (mut out, mut i, mut in_class) = (String::new(), 0, false);
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() {
                if !in_class && matches!(b[i + 1], b'b' | b'A' | b'z') {
                    i += 2;
                    continue;
                }
                out.push(b[i] as char);
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            match b[i] {
                b'[' if !in_class => {
                    in_class = true;
                    out.push('[');
                }
                b']' if in_class => {
                    in_class = false;
                    out.push(']');
                }
                // Zero-width outside a character class; inside one, `^`/`$` are literal members.
                b'^' | b'$' if !in_class => {}
                // Quantified → a secret body; bare → a literal dot. See the doc comment.
                b'.' if !in_class => {
                    if matches!(b.get(i + 1), Some(b'{' | b'*' | b'+' | b'?')) {
                        out.push_str("[A-Za-z0-9]");
                    } else {
                        out.push_str("\\.");
                    }
                }
                c => out.push(c as char),
            }
            i += 1;
        }
        out
    }

    /// A true positive for `pattern`: a random string the rule's own regex actually matches.
    ///
    /// This is gitleaks' own methodology (`secrets.NewSecret`, which feeds each rule's pattern to a
    /// regex-driven string generator). It beats a hand-written corpus on every axis that matters:
    /// it produces a genuine sample for *every* rule rather than the dozen someone thought to write
    /// by hand, it stays in sync automatically when the pack is re-synced with upstream, and it
    /// leaves no secret-shaped literal in the repository for a scanner — GitHub's or Bulwark's own —
    /// to flag.
    /// A reusable sampler for one rule: the generators and the verifying regex, built **once**.
    ///
    /// Built per-seed instead, this recompiled the rule's regex up to eighty times per rule (forty
    /// seeds × two Unicode modes) — and these are the pathologically slow patterns whose compilation
    /// this whole change exists to avoid. It cost two minutes on `cargo test`.
    struct SampleGen {
        /// The rule's real regex — the judge of whether a generated string is a true positive.
        verifier: Regex,
        /// ASCII first, Unicode as a fallback. With Unicode *off*, `\w`/`\d` mean their ASCII
        /// selves, so a "40-character alphanumeric API key" comes out looking like one rather than
        /// like 40 CJK ideographs — but a negated class (`[^"]{3,}`, which the curl and private-key
        /// rules are built from) may then draw bytes forming no valid UTF-8, and every seed is
        /// rejected. Unicode-on generation always yields valid UTF-8. Ugly samples beat no samples:
        /// a rule with no sample is a rule the coverage test cannot vouch for.
        generators: Vec<rand_regex::Regex>,
    }

    impl SampleGen {
        fn new(pattern: &str) -> Option<Self> {
            let verifier = compile(pattern).ok()?;
            let source = generatable_pattern(pattern);
            let generators = [false, true]
                .into_iter()
                .filter_map(|unicode| {
                    let hir = regex_syntax::ParserBuilder::new()
                        .unicode(unicode)
                        .utf8(unicode)
                        .build()
                        .parse(&source)
                        .ok()?;
                    rand_regex::Regex::with_hir(hir, 100).ok()
                })
                .collect::<Vec<_>>();
            (!generators.is_empty()).then_some(SampleGen {
                verifier,
                generators,
            })
        }

        /// One true positive, or `None` if this seed produced nothing the rule's own regex accepts.
        fn sample(&self, seed: u64) -> Option<String> {
            self.generators.iter().find_map(|gen| {
                // Sample bytes, not a `String`: `rand_regex`'s `String` sampler *panics* on a
                // non-UTF-8 draw, and with Unicode off that is routine. Bytes plus a `from_utf8`
                // check turn a crash into "try the next seed".
                // rand 0.10 removed `Rng::sample`; sampling now runs the other way round, from
                // the distribution given an rng.
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
                let bytes: Vec<u8> = gen.sample(&mut rng);
                let sample = String::from_utf8(bytes).ok()?;
                self.verifier.is_match(&sample).then_some(sample)
            })
        }
    }

    /// The generated secret placed in the kind of line it really leaks in, with the rule's keywords
    /// present — gitleaks' `GenerateSampleSecret`, whose samples look like `airtable_api_token =
    /// "<secret>"` for exactly this reason.
    ///
    /// The context is not decoration. Many rules are keyword-gated: an Airtable PAT is only
    /// considered when the word `airtable` appears nearby, so a bare token — however valid — is
    /// something the pack is *designed* to walk past. Testing the token alone would assert a
    /// behaviour the scanner deliberately doesn't have.
    fn sample_in_context(id: &str, keywords: &[String], sample: &str) -> String {
        let hint = if keywords.is_empty() {
            id.replace('-', "_")
        } else {
            keywords.join(" ")
        };
        format!(
            "# {hint}\n{}_token = \"{sample}\"\n",
            hint.replace(['.', '-'], "_")
        )
    }

    /// A deterministic high-entropy token, **generated rather than written as a literal**.
    ///
    /// This matters more than it looks. A 40-character high-entropy string sitting next to the word
    /// `aws` in a source file is, to every secret scanner on earth, indistinguishable from a real
    /// leaked key — there is no way for one to tell "test fixture" from "credential". An earlier
    /// version of this corpus hardcoded such strings and GitHub's push protection rejected the push,
    /// correctly. Bulwark's own scanner would flag them too, and a contributor grepping the tree
    /// would have to stop and check. Deriving the bytes at runtime keeps the corpus exactly as
    /// strong (the rules only care about alphabet, length, and entropy) while leaving nothing
    /// secret-shaped in the repository.
    ///
    /// xorshift64* rather than a `rand` dependency: this needs to be reproducible and dependency-
    /// free, not statistically excellent.
    fn synthetic_token(seed: u64, len: usize, alphabet: &str) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                let n = x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33;
                chars[n as usize % chars.len()]
            })
            .collect()
    }

    /// A corpus that actually makes the rules fire. Each rule's own keywords are spliced into the
    /// `KEY = "<token>"` shapes the keyword-context patterns are written for, across the token
    /// alphabets they expect (40-char alnum, hex, long base64-ish), so a large slice of the pack
    /// produces genuine matches rather than the corpus trivially matching nothing.
    ///
    /// Built **per rule**, from that rule's own keywords, rather than once from the whole pack's.
    /// A keyword-context rule can only fire near its own keywords, so a shared corpus would make
    /// every rule scan 260 other rules' text for nothing — and since the point of this test is to
    /// run the *original*, pathologically slow patterns, that waste cost six minutes on `cargo
    /// test`. Same coverage, a few KB per rule instead of a megabyte.
    fn positive_corpus(id: &str, keywords: &[String]) -> String {
        // The alphabets and lengths the pack's rules expect of a secret's body.
        let bodies = [
            synthetic_token(1, 40, ALNUM),
            synthetic_token(2, 40, LOWER),
            synthetic_token(3, 40, HEX),
            synthetic_token(4, 64, HEX),
            format!("00{}", synthetic_token(5, 41, ALNUM)), // the `00…` Okta shape
        ];

        let mut corpus = String::new();
        // The id doubles as a keyword-ish token: some rules key off the provider name that appears
        // in their id rather than off a declared keyword.
        for kw in std::iter::once(id.replace('-', "_")).chain(keywords.iter().cloned()) {
            for body in &bodies {
                corpus.push_str(&format!("{kw} = \"{body}\"\n"));
                corpus.push_str(&format!("{kw}: '{body}'\n"));
                corpus.push_str(&format!("export UPPER_{kw}={body}\n"));
            }
        }
        corpus
    }

    #[derive(Deserialize)]
    struct FpRule {
        id: String,
        false_positives_b64: Vec<String>,
    }
    #[derive(Deserialize)]
    struct FpFile {
        rule: Vec<FpRule>,
    }

    /// Decodes one base64 fixture.
    ///
    /// The corpus is stored encoded because a pile of *convincing* non-secrets is, to any pattern
    /// matcher, indistinguishable from a pile of secrets — which is exactly what makes them useful
    /// fixtures. In plaintext the file is rejected by this repo's own gitleaks pre-commit hook and
    /// by GitHub's push protection, both correctly. Rather than blunt either scanner, the 378
    /// secret-shaped strings simply never land in the tree in a form a scanner can recognise.
    ///
    /// Hand-rolled to avoid taking a dependency for six lines of test-only decoding.
    fn from_base64(s: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (mut bits, mut acc, mut out) = (0u32, 0u32, Vec::new());
        for c in s.bytes().filter(|&c| c != b'=') {
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .unwrap_or_else(|| panic!("corpus is not valid base64 (byte {c:?})"));
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        String::from_utf8(out).expect("every fixture decodes to text")
    }

    /// A dropped allowlist regex is a **silent false positive**, which is why this is an assertion
    /// and not a log line: nothing about the scan looks wrong, the rule just starts reporting
    /// template syntax as leaked credentials. Exactly that happened — gitleaks writes RE2, where a
    /// literal `{{` is fine, and Rust's `regex` rejects it, so the one allowlist pattern that
    /// suppresses `${{ env.PASS }}` never compiled and was quietly discarded. Same invariant as
    /// `every_bundled_rule_compiles`, on the half of the pack that says what *isn't* a secret.
    #[test]
    fn every_allowlist_regex_compiles() {
        let pack = &*PACK;
        let mut dropped = Vec::new();
        for rule in &pack.rules {
            for a in &rule.allowlists {
                if a.compiled_count() != a.regex_src.len() {
                    dropped.push(format!(
                        "{}: {} of {} allowlist regexes compiled",
                        rule.id,
                        a.compiled_count(),
                        a.regex_src.len()
                    ));
                }
            }
        }
        for a in &pack.global_allowlist {
            if a.compiled_count() != a.regex_src.len() {
                dropped.push(format!(
                    "[global]: {} of {} allowlist regexes compiled",
                    a.compiled_count(),
                    a.regex_src.len()
                ));
            }
        }
        assert!(
            dropped.is_empty(),
            "allowlist regexes silently dropped — the rules they belong to will now report \
             non-secrets:\n  {}",
            dropped.join("\n  ")
        );
    }

    #[test]
    fn go_braces_are_made_legal_for_rust_without_changing_what_they_match() {
        // The real gitleaks allowlist pattern that Rust rejected.
        let go = r#"['"]?\$?{{[^}]+}}['"]?"#;
        let fixed = literalize_braces(go);
        assert!(compile(go).is_err(), "the Go form is what Rust rejects");
        let re = compile(&fixed).expect("the fixed form must compile");
        assert!(re.is_match(r#""${{ env.ELK_PASS }}""#));
        assert!(!re.is_match("plain_value"));

        // A genuine quantifier must survive untouched.
        assert_eq!(literalize_braces(r"[a-z]{3,8}"), r"[a-z]{3,8}");
        assert_eq!(literalize_braces(r"\d{16}"), r"\d{16}");
        // Braces inside a class are already literal.
        assert_eq!(literalize_braces(r"[{}]+"), r"[{}]+");
    }

    /// **Detection coverage for the whole pack.** For every rule, generate a secret from that
    /// rule's own pattern, drop it in the kind of line it really leaks in, and assert the pack
    /// catches it — through the real keyword prefilter, entropy gate, placeholder filter and
    /// overlap dedup, not merely "the regex matches in isolation".
    ///
    /// This is the invariant the pack never had. `every_bundled_rule_compiles` proves a pattern
    /// parses; it says nothing about whether the rule can still catch *its own key* once the
    /// surrounding machinery has had its say. A keyword missing from a rule's `keywords` list, an
    /// entropy threshold a notch too high, a prefilter regression — each quietly switches a rule
    /// off while every existing test stays green, and the only symptom is a scanner that reports
    /// "clean". Modelled on gitleaks' `Validate(rule, tps, fps)`.
    ///
    /// The hard assertion is **no silent miss**: every generated secret must be reported by *some*
    /// rule. Which rule is deliberately softer, because sibling patterns genuinely overlap — a
    /// GitLab routable PAT is also a GitLab PAT, and whichever claims the span first is the one
    /// reported. The secret is caught either way, which is the property a user cares about. The
    /// exact-rule count is still asserted against a floor, so a mass regression can't hide behind
    /// that tolerance.
    #[test]
    fn every_rule_detects_a_secret_generated_from_its_own_pattern() {
        let mut missed = Vec::new();
        let mut unsampleable = Vec::new();
        let mut exact = 0;

        for (id, pattern, keywords) in raw_rules() {
            let gen = SampleGen::new(&pattern);
            let mut sampled = false;
            let mut caught = false;
            for seed in 0..40 {
                let Some(sample) = gen.as_ref().and_then(|g| g.sample(seed)) else {
                    continue;
                };
                sampled = true;
                let path = matching_path(&id);
                // Two presentations. Most rules match a *value* and need their keyword nearby, so
                // the assignment-line wrapper is what makes them fire. But a rule whose pattern
                // already carries its own context — `nuget-config-password` matches a whole
                // `<add key="Password" value="…"/>` element, the curl rules a whole command — is
                // damaged by being wrapped in one, so the bare sample is its realistic form. A rule
                // is covered if it catches its own secret in either.
                let hits = [sample_in_context(&id, &keywords, &sample), sample.clone()]
                    .iter()
                    .map(|text| scan_text_in(path.as_deref(), text))
                    .find(|hits| !hits.is_empty())
                    .unwrap_or_default();
                if !hits.is_empty() {
                    caught = true;
                    if hits.iter().any(|m| m.rule_id == id) {
                        exact += 1;
                        break;
                    }
                }
            }
            if !sampled {
                unsampleable.push(id);
            } else if !caught {
                missed.push(id);
            }
        }

        assert!(
            missed.is_empty(),
            "{} rule(s) did not detect a secret generated from their own pattern — those rules are \
             switched off in practice: {missed:?}",
            missed.len()
        );
        // A pattern the generator can't build a sample for is a gap in the *test*, not the pack —
        // tolerated, but bounded, so it can't quietly grow to swallow the pack.
        assert!(
            unsampleable.len() <= 3,
            "the generator handles too few rules to prove anything ({} unsampleable): \
             {unsampleable:?}",
            unsampleable.len()
        );
        assert!(
            exact >= 240,
            "only {exact} rules reported their own id — sibling-rule overlap explains a handful, \
             not a collapse"
        );
    }

    /// **The other half of correctness.** A scanner that flags everything is as useless as one that
    /// flags nothing, and the way a rule usually breaks is by getting *broader*, not narrower — a
    /// widened regex still passes every "does it catch the key" test while burying the user in
    /// noise. So: the placeholders, documentation examples, wrong-length and wrong-prefix tokens
    /// and low-entropy dummies that gitleaks records as the known false positives of each rule
    /// (378 of them across 79 rules, vendored in `tests/data/gitleaks_false_positives.toml`) must
    /// not fire.
    #[test]
    fn no_rule_fires_on_its_known_false_positives() {
        let data: FpFile = toml::from_str(include_str!(
            "../../tests/data/gitleaks_false_positives.toml"
        ))
        .expect("the vendored false-positive corpus must be valid TOML");

        // The one rule whose upstream fixtures we knowingly fail. gitleaks' own allowlist for
        // `curl-auth-header` is commented out in their source, so they carry the same false
        // positives; ours additionally predates their current regex. Listed rather than quietly
        // filtered, and the assertions below cut both ways — a *new* false positive fails, and so
        // does a gap that has silently been fixed, so this list cannot rot.
        const KNOWN_GAPS: &[&str] = &["curl-auth-header"];

        let mut checked = 0;
        let mut violations = Vec::new();
        let mut gaps_still_open = BTreeSet::new();
        for rule in &data.rule {
            for encoded in &rule.false_positives_b64 {
                let fp = &from_base64(encoded);
                checked += 1;
                if KNOWN_GAPS.contains(&rule.id.as_str()) {
                    if scan_text_high_confidence(fp)
                        .iter()
                        .any(|m| m.rule_id == rule.id)
                    {
                        gaps_still_open.insert(rule.id.clone());
                    }
                    continue;
                }
                // `scan_text_high_confidence` is what the AI scan actually reports (see
                // `ai_scan::scan_artifact`). The deliberately-broad `generic-*` heuristics are
                // excluded by that, and rightly: gitleaks reports them because it scans whole source
                // repositories, where `public_key = "…"` in a C++ header is worth a second look.
                // Bulwark never surfaces them, so holding them to gitleaks' fixtures would be
                // asserting a behaviour this scanner deliberately doesn't have.
                if scan_text_high_confidence(fp)
                    .iter()
                    .any(|m| m.rule_id == rule.id)
                {
                    let shown: String = fp.chars().take(60).collect();
                    violations.push(format!("{} fired on {shown:?}", rule.id));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "{} rule(s) flagged a known non-secret:\n  {}",
            violations.len(),
            violations.join("\n  ")
        );
        assert_eq!(
            gaps_still_open.iter().cloned().collect::<Vec<_>>(),
            KNOWN_GAPS,
            "KNOWN_GAPS is stale — a rule listed there no longer produces the false positive it was \
             excused for. Delete it from the list."
        );
        assert!(checked >= 300, "the corpus did not load ({checked} cases)");
    }

    /// **The safety net for the whole optimisation.** Dropping a pattern's leading wildcard is only
    /// legitimate if it cannot change a single detection, so assert exactly that, rule by rule, over
    /// a corpus built to make the pack fire: for every vendored rule, the original pattern and the
    /// rewritten one must capture *the same secrets at the same offsets*.
    ///
    /// This is what stands between a 100× speedup and a scanner that quietly stops finding keys.
    #[test]
    fn rewriting_a_pattern_never_changes_what_it_matches() {
        let mut rewritten = 0;
        let mut rules_that_fired = 0;

        for (id, original, keywords) in raw_rules() {
            // Real matching inputs, not guesses: samples generated from this very pattern, so the
            // comparison below happens where it actually counts — on text the rule fires on.
            let mut corpus = positive_corpus(&id, &keywords);
            let gen = SampleGen::new(&original);
            for seed in 0..8 {
                if let Some(s) = gen.as_ref().and_then(|g| g.sample(seed)) {
                    corpus.push_str(&sample_in_context(&id, &keywords, &s));
                }
            }
            let optimized = drop_leading_wildcard(&original);
            if optimized != original {
                rewritten += 1;
            }
            let (Ok(before), Ok(after)) = (compile(&original), compile(&optimized)) else {
                continue; // a pattern the regex crate rejects is skipped by the pack too
            };

            // Group 1 is the secret (falling back to the whole match, exactly as `matches_for`
            // does), which is the only span that reaches a finding or a redaction.
            let secrets = |re: &Regex| -> Vec<(usize, String)> {
                re.captures_iter(&corpus)
                    .filter_map(|c| {
                        let whole = c.get(0)?;
                        let s = c.get(1).unwrap_or(whole);
                        Some((s.start(), s.as_str().to_string()))
                    })
                    .collect()
            };

            let expected = secrets(&before);
            if !expected.is_empty() {
                rules_that_fired += 1;
            }
            assert_eq!(
                expected,
                secrets(&after),
                "rewriting `{id}` changed what it matches\n  original:  {original}\n  rewritten: {optimized}"
            );
        }

        // Guard against the test passing vacuously: the corpus has to actually exercise the pack,
        // and the optimisation has to actually be applying to most of it (if a future re-sync with
        // gitleaks changes the pattern shape, the scan silently gets slow again — that's a bug, and
        // this is where it surfaces).
        assert!(
            rules_that_fired >= 20,
            "corpus is too weak to prove anything: only {rules_that_fired} rules matched it"
        );
        assert!(
            rewritten >= 100,
            "expected the leading-wildcard rewrite to apply across the pack, but only {rewritten} \
             rules changed — has the vendored pattern shape drifted?"
        );
    }

    /// Every guard in [`drop_leading_wildcard`] exists because removing that repeat would otherwise
    /// change which text the rule matches. A pattern that doesn't match the exact expected shape has
    /// to come back byte-for-byte unchanged.
    #[test]
    fn a_pattern_is_only_rewritten_when_that_is_provably_safe() {
        // The real gitleaks shape: both leading wildcards go, the rest is untouched.
        assert_eq!(
            drop_leading_wildcard(
                r#"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere)[\s'"]{0,3})(?:=)([a-z0-9]{40})"#
            ),
            r#"(?i:(?:cohere)[\s'"]{0,3})(?:=)([a-z0-9]{40})"#
        );

        // The pack's most common shape: a global `(?i)` directive, which consumes no text, so the
        // wildcard behind it is still leading. The directive itself must survive.
        assert_eq!(
            drop_leading_wildcard(r#"(?i)[\w.-]{0,50}?(?:cohere)=([a-z0-9]{40})"#),
            r#"(?i)(?:cohere)=([a-z0-9]{40})"#
        );

        // A *required* prefix (min > 0) is part of what the rule matches — dropping it would make
        // the rule fire on text it used to reject.
        let required = r#"[\w.-]{5,50}?(?:key)=([a-z0-9]{40})"#;
        assert_eq!(drop_leading_wildcard(required), required);

        // An exact count is likewise required, not optional.
        let exact = r#"[\w.-]{50}(?:key)=([a-z0-9]{40})"#;
        assert_eq!(drop_leading_wildcard(exact), exact);

        // No capture group: the whole match *is* the reported secret, so its start offset is
        // load-bearing and must not move.
        let no_group = r#"[\w.-]{0,50}?AKIA[0-9A-Z]{16}"#;
        assert_eq!(drop_leading_wildcard(no_group), no_group);

        // Greedy, unbounded, or simply not a character class — all shapes we haven't reasoned
        // about, so all left alone.
        for untouched in [
            r#"[\w.-]{0,50}(?:key)=([a-z0-9]{40})"#,
            r#"[\w.-]{0,}?(?:key)=([a-z0-9]{40})"#,
            r#".*?(?:key)=([a-z0-9]{40})"#,
            r#"(?i)(?:key)=([a-z0-9]{40})"#,
        ] {
            assert_eq!(drop_leading_wildcard(untouched), untouched);
        }

        // A `]` as the first class member is a literal, not the class terminator.
        assert_eq!(
            drop_leading_wildcard(r#"[]\w]{0,9}?(?:key)=([a-z]{40})"#),
            r#"(?:key)=([a-z]{40})"#
        );
    }

    #[test]
    fn capture_groups_are_told_apart_from_the_non_capturing_kind() {
        assert!(has_capture_group(r#"(?:a)(b)"#));
        assert!(has_capture_group(r#"(?P<secret>b)"#));
        assert!(!has_capture_group(r#"(?:a)(?i:b)"#));
        assert!(!has_capture_group(r#"\(literal\)"#));
        assert!(!has_capture_group(r#"[(](?:a)"#)); // `(` inside a class is a literal
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
    ///
    /// Asserts on the *candidate* count, not on how many regexes have been compiled. `PACK` is a
    /// process-global whose `OnceLock`s accumulate across every test in the binary, so counting
    /// compiled regexes measures what the rest of the suite happened to touch first — it passed
    /// locally and failed on CI purely on thread scheduling, once the rule-validation tests (which
    /// deliberately exercise all 262 rules) started sharing the binary. The candidate count is a
    /// pure function of the text and the pack, and is the invariant actually worth pinning: the
    /// prefilter is what decides how many regexes a scan can ever compile or run.
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

        let candidates = PACK.candidates(prose).len();
        assert!(
            candidates < 40,
            "the keyword index selected {candidates} of {} rules for a file with no secrets in it",
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
        // The token is *generated*, not written out. It used to be the literal
        // `ghp_0123456789abcdefghijklmnopqrstuvwxyz`, which contains `abcdefghijklmnopqrstuvwxyz` —
        // one of the pack's own global stopwords, because a real PAT is never the alphabet. That
        // fixture only ever passed because the allowlists went unread; once they were honoured it
        // was correctly suppressed as the dummy it is. A realistic token is the right fixture, and
        // generating it keeps a live-looking `ghp_…` literal out of the repository.
        let pat = format!("ghp_{}", synthetic_token(11, 36, ALNUM));
        let ids = rule_ids(&format!("token: {pat}"));
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
    fn keyword_prefilter_still_matches_case_insensitively_without_lowercasing() {
        // The perf fix stopped allocating a lowercased copy of each file; the keyword automaton
        // is ASCII-case-insensitive instead. A provider marker written in a different case (an env
        // var like AWS_ACCESS_KEY_ID, whose rule keyword is the lowercase "akia") must still gate
        // its rule in. The 16 chars after the prefix are base32 (`[A-Z2-7]`), per the real rule.
        let hits = scan_text("AWS_ACCESS_KEY_ID=AKIAQRSTUVWXYZ234567");
        assert!(
            hits.iter().any(|m| m.rule_id == "aws-access-token"),
            "case-insensitive keyword match must still fire the rule, got {hits:?}"
        );
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
    fn redaction_preserves_the_line_ending_after_the_secret() {
        let key = anthropic_key();
        let text = format!("key: {key}\nother line\n");
        let (redacted, _) = redact_text(&text);
        assert_eq!(
            redacted,
            format!("key: {REDACTION_PLACEHOLDER}\nother line\n"),
            "only the secret's own bytes may be replaced"
        );
    }

    #[test]
    fn redaction_keeps_the_key_name_and_quotes_around_the_value() {
        // The worst shape of the whole-span bug. Most rules in the pack anchor on a `KEY =` prefix
        // *and* a closing delimiter, so the wide match ran from `ADAFRUIT` through the closing quote
        // and the newline. Redacting that span left `[bulwark:redacted-secret]NEXT=1` — the variable
        // name destroyed, the quoting unbalanced, and two lines welded into one. A `.env` rewritten
        // that way no longer parses.
        let text = "ADAFRUIT_API_KEY=\"a8fk2lm9qp3rn7zx1wc4vb6yh0jd5sg2\"\nNEXT=1\n";
        let (redacted, count) = redact_text(text);
        assert_eq!(count, 1);
        assert_eq!(
            redacted,
            format!("ADAFRUIT_API_KEY=\"{REDACTION_PLACEHOLDER}\"\nNEXT=1\n")
        );
    }

    #[test]
    fn redaction_never_changes_a_file_s_line_count() {
        // The invariant, stated directly: redaction replaces credentials in place. Whatever else it
        // does, it must not add or remove a single line ending anywhere in the file.
        let key = anthropic_key();
        let text = format!("# header\nA={key}\nB={key}\n\ntrailing\n");
        let (redacted, count) = redact_text(&text);
        assert_eq!(count, 2);
        assert!(!redacted.contains(&key));
        assert_eq!(
            redacted.lines().count(),
            text.lines().count(),
            "line count must be identical: {redacted:?}"
        );
        assert!(
            redacted.ends_with('\n'),
            "a trailing newline must survive: {redacted:?}"
        );
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
    fn mask_reveals_at_most_a_small_fraction() {
        // An 11-char token used to leak 7 of its 11 chars (head4…tail3); it must now be fully
        // masked — nothing recoverable in a stored/displayed finding.
        assert_eq!(mask("abcdefghijk"), "***********");
        assert!(!mask("abcdefghijk").contains('…'));
        // A 16-char secret reveals only 1/8 from each end (head2…tail2), not head4/tail3.
        let m = mask("abcdefghijklmnop");
        assert_eq!(m, "ab…op");
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

    #[test]
    fn the_canonical_aws_docs_example_key_is_not_flagged() {
        // AKIAIOSFODNN7EXAMPLE matches the real AKIA pattern but is AWS's published fake — it must
        // not fire, or every AWS tutorial in a repo trips a CRITICAL secret finding.
        assert!(is_documentation_example("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_documentation_example(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(!scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
            .iter()
            .any(|m| m.rule_id == "aws-access-token"));
        // ...but a real-shaped AKIA key that is NOT an example still fires.
        assert!(!is_documentation_example("AKIA2E0A8F3B1C9D4E7F"));
    }
}

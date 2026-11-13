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
    /// The rule's keywords, lowercased. See [`keyword_near`].
    keywords: Vec<String>,
    /// A structure the regex alone cannot check. See [`Shape`].
    shape: Shape,
}

/// What a match must look like beyond what its pattern says, for the two rules whose pattern
/// accepts text that is plainly not a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The pattern is the whole test.
    Any,
    /// A PEM block: a header, a base64 body, a footer. See [`private_key_block`].
    PrivateKey,
    /// Three segments, the first two decoding to JSON objects. See [`plausible_jwt`].
    Jwt,
}

impl Rule {
    /// The pattern the scanner runs: the vendored one after both pack-build rewrites. Worked out
    /// on first use, like the compile, so a scan pays only for the rules its text can match.
    fn final_pattern(&self) -> String {
        relax_terminator(&self.pattern)
    }

    fn regex(&self) -> Option<&Regex> {
        self.re
            .get_or_init(|| compile(&self.final_pattern()).ok())
            .as_ref()
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

/// How the parts of a rule id are written for people. A rule id is lower-case words joined by
/// hyphens (`npm-access-token`); a provider's name has its own spelling (`npm`, `xAI`,
/// `OpenRouter`), which no capitalisation rule can guess. A key is one word of the id or several
/// in a row (`new-relic`); the longest key that fits is used.
const NAMES: &[(&str, &str)] = &[
    // Terms.
    ("api", "API"),
    ("jwt", "JWT"),
    ("url", "URL"),
    ("id", "ID"),
    ("pat", "PAT"),
    ("ca", "CA"),
    ("ai", "AI"),
    ("scim", "SCIM"),
    ("yaml", "YAML"),
    ("oauth", "OAuth"),
    ("cicd", "CI/CD"),
    ("fine-grained", "fine-grained"),
    ("long-lived", "long-lived"),
    ("short-lived", "short-lived"),
    // A misspelling in the vendored id, which has to stay as it is there.
    ("personnal", "personal"),
    // GitLab's own abbreviations.
    ("ptt", "pipeline trigger token"),
    ("rrt", "runner registration token"),
    // Providers and tools.
    ("1password", "1Password"),
    ("age", "age"),
    ("assemblyai", "AssemblyAI"),
    ("aws", "AWS"),
    ("aws-amazon-bedrock", "Amazon Bedrock"),
    ("azure-ad", "Azure AD"),
    ("cisco-meraki", "Cisco Meraki"),
    ("clickhouse-cloud", "ClickHouse Cloud"),
    ("cloudflare", "Cloudflare"),
    ("curl", "curl"),
    ("deepseek", "DeepSeek"),
    ("defined-networking", "Defined Networking"),
    ("digitalocean", "DigitalOcean"),
    ("droneci", "Drone CI"),
    ("easypost", "EasyPost"),
    ("elevenlabs", "ElevenLabs"),
    ("endorlabs", "Endor Labs"),
    ("flyio", "Fly.io"),
    ("frameio", "Frame.io"),
    ("freshbooks", "FreshBooks"),
    ("gcp", "GCP"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("gocardless", "GoCardless"),
    ("grafana-cloud", "Grafana Cloud"),
    ("hashicorp", "HashiCorp"),
    ("hashicorp-tf", "HashiCorp Terraform"),
    ("hubspot", "HubSpot"),
    ("huggingface", "Hugging Face"),
    ("jfrog", "JFrog"),
    ("kubernetes", "Kubernetes"),
    ("kucoin", "KuCoin"),
    ("launchdarkly", "LaunchDarkly"),
    ("linkedin", "LinkedIn"),
    ("mailchimp", "Mailchimp"),
    ("maxmind", "MaxMind"),
    ("messagebird", "MessageBird"),
    ("microsoft-teams", "Microsoft Teams"),
    ("new-relic", "New Relic"),
    ("npm", "npm"),
    ("nuget", "NuGet"),
    ("nvidia", "NVIDIA"),
    ("nytimes", "New York Times"),
    ("octopus-deploy", "Octopus Deploy"),
    ("openai", "OpenAI"),
    ("openrouter", "OpenRouter"),
    ("openshift", "OpenShift"),
    ("planetscale", "PlanetScale"),
    ("posthog", "PostHog"),
    ("privateai", "Private AI"),
    ("pypi", "PyPI"),
    ("rapidapi", "RapidAPI"),
    ("readme", "ReadMe"),
    ("rubygems", "RubyGems"),
    ("sendgrid", "SendGrid"),
    ("settlemint", "SettleMint"),
    ("stability-ai", "Stability AI"),
    ("sumologic", "Sumo Logic"),
    ("togetherai", "Together AI"),
    ("travisci", "Travis CI"),
    ("vercel-ai-gateway", "Vercel AI Gateway"),
    ("weights-and-biases", "Weights & Biases"),
    ("xai", "xAI"),
];

/// The most words of an id one [`NAMES`] key spans.
const NAME_KEY_WORDS: usize = 3;

/// A rule id as a name for people: `anthropic-api-key` → "Anthropic API key", `npm-access-token` →
/// "npm access token". Only an ordinary first word gets a capital; a name from [`NAMES`] is
/// already spelled the way its owner spells it.
fn humanize(id: &str) -> String {
    let words: Vec<&str> = id.split('-').collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let named = (1..=NAME_KEY_WORDS.min(words.len() - i))
            .rev()
            .find_map(|n| {
                let key = words[i..i + n].join("-");
                NAMES
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, shown)| (n, *shown))
            });
        match named {
            Some((n, shown)) => {
                out.push(shown.to_string());
                i += n;
            }
            None => {
                let word = words[i];
                // The first word of the name, when it is an ordinary word, starts the phrase.
                let mut chars = word.chars();
                out.push(match chars.next() {
                    Some(first) if i == 0 => first.to_uppercase().chain(chars).collect(),
                    _ => word.to_string(),
                });
                i += 1;
            }
        }
    }
    out.join(" ")
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
        let shape = match r.id.as_str() {
            "private-key" => Shape::PrivateKey,
            "jwt" => Shape::Jwt,
            _ => Shape::Any,
        };
        rules.push(Rule {
            shape,
            provider: humanize(&r.id),
            id: r.id,
            pattern: drop_leading_wildcard(&pattern),
            re: OnceLock::new(),
            entropy: r.entropy,
            high_conf,
            allowlists: r.allowlists.into_iter().map(Allowlist::from_spec).collect(),
            path_src: r.path,
            path_re: OnceLock::new(),
            keywords: r.keywords.iter().map(|k| k.to_lowercase()).collect(),
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

/// The terminator 188 of the vendored patterns end with: after the key comes a quote (possibly
/// escaped), whitespace, a `;`, a literal `\n` / `\r`, or the end of the line.
const VENDORED_TERMINATOR: &str = r#"(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#;

/// How many fixed leading characters make a key "identified by its prefix". `hf_` and `r8_` are
/// the shortest real ones; two (`ey` for a JWT, the `s.` branch of an old Vault token) is too
/// little to tell a key from a word.
const MIN_KEY_PREFIX: usize = 3;

/// A character class with this many members or fewer is one fixed character written loosely
/// (`[MC]`, or `s` under `(?i)`, which Unicode folds to three code points), not part of a key's
/// body alphabet.
const FIXED_CHAR_CLASS: u32 = 3;

/// Lets a key that is identified by its own prefix end at ordinary punctuation.
///
/// The vendored terminator ([`VENDORED_TERMINATOR`]) accepts a key only when a quote, whitespace,
/// `;` or the end of the line follows it. In a source file that is how a key ends. In a chat
/// transcript or a shell history it is not: `my key is sk-ant-….`, `(the key sk-ant-…)`,
/// `**sk-ant-…**`, `?key=AIza…&x=1` and `echo sk-ant-… | pbcopy` were all walked past, for every
/// provider whose pattern carries the terminator — Anthropic, OpenAI, Google, Stripe, Groq,
/// Hugging Face, npm, SendGrid, OpenRouter and some seventy more.
///
/// For a rule whose key starts with a fixed prefix (`sk-ant-api03-`, `hf_`, `AIza`) the terminator
/// is not what identifies the key; the prefix is. All the terminator has to do there is make sure
/// the key has *ended*: that `sk_live_` plus ten characters is not the front of a longer word, a
/// file name or a function call. So for those rules, and only those, two more endings count:
///
/// 1. **One character that cannot continue a key, a word, a path or a call.** That is any
///    character except:
///    - the rule's own body alphabet (every character class inside its key group);
///    - ASCII letters, digits, `_` and `-`, so a key never ends in the middle of a word;
///    - `+`, `/` and `=`, so a prefix that happens to occur inside a base64 blob or a path does
///      not become a key the moment the text reaches one of them;
///    - an opening `(`, `[` or `{`: `GLC_CreateLightmapTextures(void)` is a function, and one of
///      the non-secrets gitleaks records for the Grafana rule;
///    - `.`, which gets the stricter rule below.
/// 2. **A full stop that ends a sentence**: one to three dots followed by a character from (1),
///    or by the end of the text. `…AA.` and `…AA...` end a key; `ico-7a38….png` (another recorded
///    non-secret) and `key.method()` do not.
///
/// The vendored alternatives are kept and the new ones are added after them, so every match the
/// original pattern finds, the rewritten one finds too
/// (`relaxing_a_terminator_only_ever_adds_matches`).
///
/// Left exactly as vendored:
///
/// - **keyword-and-value rules** whose value has no prefix (`adafruit … = ([a-z0-9_-]{32})`, about
///   a hundred of them) and the few whose key has no fixed start (a bare 40-hex Sourcegraph token,
///   a Facebook token that starts with digits). Their value is any run of common characters of
///   the right length; the terminator is what stops them matching inside a path, a hash or a
///   longer identifier;
/// - **a JWT** and the short `s.` Vault form, whose two fixed characters identify nothing;
/// - anything this function cannot read with certainty. A rule that stays strict misses a key
///   followed by a full stop; a rule relaxed by mistake reports things that are not keys.
fn relax_terminator(pattern: &str) -> String {
    use regex_syntax::hir::ClassUnicodeRange;
    let Some(body) = pattern.strip_suffix(VENDORED_TERMINATOR) else {
        return pattern.to_string();
    };
    let Some(mut not_an_ending) = prefixed_key_alphabet(body) else {
        return pattern.to_string();
    };
    for c in ['.', '(', '[', '{'] {
        not_an_ending.push(ClassUnicodeRange::new(c, c));
    }
    // What the vendored terminator accepts ends a key whatever the body's classes say: Fly.io's
    // pattern has a `\s` inside the key, and a space after `…AA.` must still end the sentence.
    if let Some(vendored_endings) = class_of(r#"[\s'"\x60;]"#) {
        not_an_ending.difference(&vendored_endings);
    }
    let ending = negated_class(&not_an_ending);
    let mut out = String::with_capacity(pattern.len() + 2 * ending.len() + 24);
    out.push_str(body);
    // The vendored alternatives first, unchanged, then the two new ones.
    out.push_str(&VENDORED_TERMINATOR[..VENDORED_TERMINATOR.len() - 1]);
    out.push('|');
    out.push_str(&ending);
    out.push_str(r"|\.{1,3}(?:");
    out.push_str(&ending);
    out.push_str("|$))");
    out
}

/// For a pattern that ends with its key, and whose key starts with at least [`MIN_KEY_PREFIX`]
/// fixed characters: every character that can occur in the key's body, plus the letters, digits
/// and base64 characters a key may never end against (see [`relax_terminator`]). `None` for every
/// other pattern.
fn prefixed_key_alphabet(body: &str) -> Option<regex_syntax::hir::ClassUnicode> {
    use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
    let hir = regex_syntax::parse(body).ok()?;
    let key = trailing_capture(&hir)?;
    if fixed_prefix(key).0 < MIN_KEY_PREFIX {
        return None;
    }
    let mut alphabet = ClassUnicode::new(
        [
            ('A', 'Z'),
            ('a', 'z'),
            ('0', '9'),
            ('_', '_'),
            ('-', '-'),
            ('+', '+'),
            ('/', '/'),
            ('=', '='),
        ]
        .map(|(a, b)| ClassUnicodeRange::new(a, b)),
    );
    body_classes(key, &mut alphabet)?;
    Some(alphabet)
}

/// The capture group a pattern ends with — the key, sitting right before the terminator. `None`
/// when the pattern ends with anything else. Deliberately not "capture group 1": a few vendored
/// patterns capture part of their keyword first (`sonar[_.-]?(login|token)`), and that group says
/// nothing about how the key is written.
fn trailing_capture(hir: &regex_syntax::hir::Hir) -> Option<&regex_syntax::hir::Hir> {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Capture(c) => Some(&c.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .rev()
            .find(|part| !matches!(part.kind(), HirKind::Look(_)))
            .and_then(|last| match last.kind() {
                HirKind::Capture(c) => Some(&*c.sub),
                _ => None,
            }),
        _ => None,
    }
}

fn class_size(class: &regex_syntax::hir::ClassUnicode) -> u32 {
    class
        .ranges()
        .iter()
        .map(|r| r.end() as u32 - r.start() as u32 + 1)
        .sum()
}

/// How many fixed characters `hir` is certain to start with, and whether it is fixed all the way
/// through (so that whatever follows it still counts as part of the prefix). An alternation is as
/// fixed as its least fixed branch: `(?:sk|rk)_(?:test|live|prod)_` is eleven characters at the
/// least, `(?:hvs\.|s\.)` only two.
fn fixed_prefix(hir: &regex_syntax::hir::Hir) -> (usize, bool) {
    use regex_syntax::hir::{Class, HirKind};
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => (0, true),
        HirKind::Literal(lit) => (String::from_utf8_lossy(&lit.0).chars().count(), true),
        HirKind::Class(Class::Unicode(c)) if class_size(c) <= FIXED_CHAR_CLASS => (1, true),
        HirKind::Class(_) => (0, false),
        HirKind::Capture(c) => fixed_prefix(&c.sub),
        HirKind::Repetition(r) => {
            let (len, whole) = fixed_prefix(&r.sub);
            let min = r.min as usize;
            if whole && r.max == Some(r.min) {
                (len * min, true)
            } else if whole {
                (len * min, false)
            } else {
                (if min >= 1 { len } else { 0 }, false)
            }
        }
        HirKind::Concat(parts) => {
            let mut total = 0;
            for part in parts {
                let (len, whole) = fixed_prefix(part);
                total += len;
                if !whole {
                    return (total, false);
                }
            }
            (total, true)
        }
        HirKind::Alternation(branches) => {
            let each: Vec<(usize, bool)> = branches.iter().map(fixed_prefix).collect();
            let shortest = each.iter().map(|(len, _)| *len).min().unwrap_or(0);
            // Branches of different lengths still leave what follows part of the prefix: every
            // way through has at least `shortest` fixed characters before it.
            (shortest, each.iter().all(|(_, whole)| *whole))
        }
    }
}

/// Adds every body character class under `hir` to `alphabet`. `None` if the pattern uses a
/// byte-oriented class, which no vendored rule does and this code has not been reasoned about.
fn body_classes(
    hir: &regex_syntax::hir::Hir,
    alphabet: &mut regex_syntax::hir::ClassUnicode,
) -> Option<()> {
    use regex_syntax::hir::{Class, HirKind};
    match hir.kind() {
        HirKind::Class(Class::Unicode(c)) => {
            if class_size(c) > FIXED_CHAR_CLASS {
                alphabet.union(c);
            }
        }
        HirKind::Class(Class::Bytes(_)) => return None,
        HirKind::Capture(c) => body_classes(&c.sub, alphabet)?,
        HirKind::Repetition(r) => body_classes(&r.sub, alphabet)?,
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            for part in parts {
                body_classes(part, alphabet)?;
            }
        }
        HirKind::Empty | HirKind::Literal(_) | HirKind::Look(_) => {}
    }
    Some(())
}

/// The members of a bracketed class written as a pattern.
fn class_of(pattern: &str) -> Option<regex_syntax::hir::ClassUnicode> {
    use regex_syntax::hir::{Class, HirKind};
    match regex_syntax::parse(pattern).ok()?.into_kind() {
        HirKind::Class(Class::Unicode(class)) => Some(class),
        _ => None,
    }
}

/// `[^…]` for a class, written with code-point escapes so no member needs quoting.
fn negated_class(class: &regex_syntax::hir::ClassUnicode) -> String {
    use std::fmt::Write;
    let mut out = String::from("[^");
    for r in class.ranges() {
        let _ = write!(out, "\\x{{{:X}}}", r.start() as u32);
        if r.end() != r.start() {
            let _ = write!(out, "-\\x{{{:X}}}", r.end() as u32);
        }
    }
    out.push(']');
    out
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
    matches_with(pack, rule, re, text)
}

/// [`matches_for`] with the regex named by the caller: the rule's own in a scan, and in the tests
/// the vendored pattern too, so both go through exactly the same filters.
fn matches_with<'t>(pack: &Pack, rule: &Rule, re: &Regex, text: &'t str) -> Vec<RawMatch<'t>> {
    let mut out = Vec::new();
    // `captures_at` in a loop, not `captures_iter`: a rejected private-key block has to be able to
    // hand the search back to a header inside it (see `private_key_block`).
    let mut at = 0;
    while at <= text.len() {
        let Some(caps) = re.captures_at(text, at) else {
            break;
        };
        let Some(whole) = caps.get(0) else { break };
        at = if whole.end() > whole.start() {
            whole.end()
        } else {
            // An empty match (no vendored pattern has one): step over one character.
            text[whole.end()..]
                .chars()
                .next()
                .map_or(text.len() + 1, |c| whole.end() + c.len_utf8())
        };
        // Group 1 is the secret where the pattern isolates one; otherwise the match itself is.
        let secret = caps.get(1).unwrap_or(whole);

        match rule.shape {
            Shape::Any => {}
            Shape::PrivateKey => match private_key_block(whole.as_str()) {
                KeyBlock::Plausible => {}
                KeyBlock::Not => continue,
                KeyBlock::NotButHeaderAt(inner) => {
                    at = whole.start() + inner;
                    continue;
                }
            },
            Shape::Jwt => {
                if !plausible_jwt(secret.as_str()) {
                    continue;
                }
            }
        }
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
        if rule.high_conf && !keyword_near(rule, text, whole.start(), whole.end()) {
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

/// What a `private-key` match turned out to be.
#[derive(Debug, PartialEq, Eq)]
enum KeyBlock {
    /// A header, a base64 body and a footer.
    Plausible,
    /// Not a key block.
    Not,
    /// Not a key block, but another `-----BEGIN` starts at this offset inside it: the search
    /// resumes there, because that header may open a real block.
    NotButHeaderAt(usize),
}

/// The fewest base64 characters a private key's body can have. The smallest real one, an Ed25519
/// key in PKCS#8, is 64; an example cut short after its first few characters is not a key.
const MIN_KEY_BODY: usize = 48;

/// The least variety a key body has, in bits per character. Real key material is close to six.
/// This only has to tell it from a placeholder made of one or two repeated characters (`AAAA…`,
/// `xxxx…`, `ABAB…`); the structure checks do the rest.
const MIN_KEY_BODY_ENTROPY: f64 = 1.5;

/// Whether a `private-key` match is a key block or only looks like the start of one.
///
/// The vendored pattern is `-----BEGIN … PRIVATE KEY-----`, at least 64 characters of anything,
/// then the next `KEY-----`. Nothing says the block must close or hold a key, so a header quoted
/// in prose pairs with the next header in the file: a transcript that printed
/// `-----BEGIN RSA PRIVATE KEY-----` forty thousand times was reported as a thousand private keys,
/// each offered for redaction. A block counts only when it has an `-----END` footer, no second
/// header inside it, and a body that is base64 with the variety real key material has.
fn private_key_block(block: &str) -> KeyBlock {
    const DASHES: &str = "-----";
    // The header is `-----BEGIN…-----`: it ends at the first run of dashes after its own.
    let Some(header_end) = block
        .get(DASHES.len()..)
        .and_then(|rest| rest.find(DASHES))
        .map(|i| i + 2 * DASHES.len())
    else {
        return KeyBlock::Not;
    };
    let rest = &block[header_end..];
    // ASCII upper-casing keeps every byte offset.
    let upper = rest.to_ascii_uppercase();
    if let Some(inner) = upper.find("-----BEGIN") {
        return KeyBlock::NotButHeaderAt(header_end + inner);
    }
    let Some(footer) = upper.rfind("-----END") else {
        return KeyBlock::Not;
    };
    if plausible_key_body(&rest[..footer]) {
        KeyBlock::Plausible
    } else {
        KeyBlock::Not
    }
}

/// Whether the text between a PEM header and footer is key material: whole lines of base64,
/// enough of them, and not one or two characters repeated. Line breaks may be real or written as `\n` (a
/// key pasted into a JSON transcript); `Name: value` armor lines and a PGP checksum line are
/// skipped.
fn plausible_key_body(body: &str) -> bool {
    // Turn escaped line breaks (`\n`, `\r`, however many backslashes) into real ones.
    let mut lines = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            lines.push(c);
            continue;
        }
        while chars.peek() == Some(&'\\') {
            chars.next();
        }
        if matches!(chars.peek(), Some('n' | 'r' | 't')) {
            chars.next();
            lines.push('\n');
        }
    }
    // Key material comes as lines of base64 and nothing else. A line with a space or any other
    // character in it is prose, and prose is mostly letters too, so lines are judged whole.
    let mut key_material = String::new();
    let mut other = 0;
    for line in lines.lines() {
        // A quoted or indented block (`> `, `| `) still holds whole base64 lines.
        let line = line.trim_start_matches(['>', '|', ' ', '\t']).trim_end();
        if line.is_empty() || line.contains(':') || line.starts_with('=') {
            continue;
        }
        if line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        {
            key_material.push_str(line);
        } else {
            other += line.chars().count();
        }
    }
    key_material.len() >= MIN_KEY_BODY
        && key_material.len() >= other * 9
        && shannon_entropy(&key_material) >= MIN_KEY_BODY_ENTROPY
}

/// Decodes base64 in either alphabet (standard or URL-safe), with or without padding.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in text.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Whether a `jwt` match is a signed token: three segments, of which the first decodes to a JSON
/// object naming its algorithm (`alg` is required by RFC 7515) and the second to a JSON object.
///
/// The vendored pattern makes the signature optional and checks nothing about the other two, so
/// `eyJ….eyJ….` — two base64 words and a dot, which is how a truncated token, a doc example and a
/// repeated header all look — was a finding, and a redactable one. Without a signature there is
/// nothing a server would accept; without a header that decodes there is no token at all.
fn plausible_jwt(token: &str) -> bool {
    // A token quoted inside JSON can carry escaped slashes.
    let token = token.replace('\\', "");
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    let object = |segment: &str| {
        base64_decode(segment)
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(serde_json::Value::is_object)
    };
    !signature.trim_end_matches('=').is_empty()
        && object(header).is_some_and(|h| h.get("alg").is_some_and(|a| a.is_string()))
        && object(payload).is_some()
}

/// How far before a match, on the same line, a rule's keyword may sit and still vouch for it.
const KEYWORD_WINDOW: usize = 128;

/// Whether one of the rule's keywords is in the match or just before it on the same line.
///
/// The keyword index is a *prefilter*: it picks rules by whether their keyword appears anywhere in
/// the file. For a rule whose pattern carries its own marker (`ghp_…`, `AKIA…`) that is enough. But
/// a few provider rules have a branch with no marker at all — `sourcegraph-access-token` also
/// accepts any bare 40-hex string, which is exactly a git commit SHA. In a source file gitleaks
/// can live with that; in an agent transcript, where a mention of "sourcegraph" and dozens of
/// commit hashes share one file, every hash became a reported "leaked token" (eight on one real
/// home directory, none of them secrets). A finding we report at high severity, and offer to
/// redact, has to carry its own evidence, so the keyword must be local to the match.
fn keyword_near(rule: &Rule, text: &str, start: usize, end: usize) -> bool {
    if rule.keywords.is_empty() {
        return true;
    }
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let mut from = start.saturating_sub(KEYWORD_WINDOW).max(line_start);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let window = text[from..end].to_ascii_lowercase();
    rule.keywords.iter().any(|k| window.contains(k.as_str()))
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

/// The most secrets one text is *reported* to hold. Real files hold a handful; this caps a crafted
/// file whose point is to turn one 4 MB input into a memory-filling pile of findings. A scan that
/// stops here says so ([`SecretScan::more`]), so a report never reads "1,000 keys" for a file that
/// holds 2,500. Redaction has no such limit: a span is two numbers, and a redaction that stopped
/// part-way would leave keys in a file it then calls clean.
pub const MAX_SECRETS_PER_TEXT: usize = 1000;

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
///
/// Stops after `limit` hits. The second value is true when it stopped there with at least one more
/// hit still to record.
fn find_hits<'t>(
    path: Option<&str>,
    text: &'t str,
    passes: &[bool],
    limit: usize,
) -> (Vec<Hit<'t>>, bool) {
    let pack = &*PACK;
    let candidates = pack.candidates(text);

    let mut spans = SpanSet::default();
    let mut hits: Vec<Hit<'t>> = Vec::new();
    let mut more = false;

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
                if hits.len() >= limit {
                    more = true;
                    break 'passes;
                }
                spans.insert(m.start, m.end);
                hits.push(Hit {
                    secret_start: m.secret_start,
                    secret_end: m.secret_end,
                    rule: ri,
                    secret: m.secret,
                });
            }
        }
    }
    (hits, more)
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
    let mut out: Vec<SecretMatch> = find_hits(path, text, &[true, false], MAX_SECRETS_PER_TEXT)
        .0
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
///
/// Returns at most [`MAX_SECRETS_PER_TEXT`] matches and does not say whether there were more; a
/// caller that reports the count to a person should use [`scan_high_confidence`].
pub fn scan_text_high_confidence_in(path: Option<&str>, text: &str) -> Vec<SecretMatch> {
    scan_high_confidence(path, text).matches
}

/// What a scan of one text found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretScan {
    /// The secrets found, in line order: at most [`MAX_SECRETS_PER_TEXT`] of them.
    pub matches: Vec<SecretMatch>,
    /// True when the text holds more secrets than `matches` lists. The scan stopped at the limit,
    /// so the real number is "more than [`MAX_SECRETS_PER_TEXT`]", not `matches.len()`.
    pub more: bool,
}

/// The high-confidence provider keys in `text` (see [`scan_text_high_confidence`]), together with
/// whether the scan stopped at [`MAX_SECRETS_PER_TEXT`]. `path` is the file the text came from,
/// for the few rules that apply to one kind of file only.
pub fn scan_high_confidence(path: Option<&str>, text: &str) -> SecretScan {
    let pack = &*PACK;
    let (hits, more) = find_hits(path, text, &[true], MAX_SECRETS_PER_TEXT);
    let mut matches: Vec<SecretMatch> = hits
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

    matches.sort_by_key(|m| m.line);
    SecretScan { matches, more }
}

/// Severity for a secret hit: a structurally-identifiable provider key is High (a real credential
/// that should be rotated, but sitting in a local file the user owns rather than exposed to the
/// network, so it does not rank with an attacker-reachable hole); a heuristic `generic-*` hit is
/// Medium.
pub fn severity_for(m: &SecretMatch) -> Severity {
    if m.high_conf {
        Severity::High
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
    // No limit here, unlike a scan: stopping part-way would leave keys in a file that the caller
    // then reports as redacted.
    let mut hits: Vec<(usize, usize)> = find_hits(path, text, &[true], usize::MAX)
        .0
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
                // A private key and a JWT have structure a random string does not (a body, a
                // footer, segments that decode), so their samples are built, not drawn.
                let Some(sample) = structured_sample(&id, seed)
                    .or_else(|| gen.as_ref().and_then(|g| g.sample(seed)))
                else {
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

        // Rules whose upstream fixtures we knowingly fail. Empty since `curl-auth-header` started
        // requiring 16+ character token values (its upstream false positives were short demo
        // values). Kept as a list, and the assertions below cut both ways — a *new* false positive
        // fails, and so does a gap that has silently been fixed, so this list cannot rot.
        const KNOWN_GAPS: &[&str] = &[];

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

    /// Every vendored rule whose terminator [`relax_terminator`] changes: (id, vendored pattern
    /// without its terminator, keywords).
    fn relaxed_rules() -> Vec<(String, String, Vec<String>)> {
        raw_rules()
            .into_iter()
            .filter(|(_, pattern, _)| relax_terminator(pattern) != *pattern)
            .map(|(id, pattern, keywords)| {
                let body = pattern
                    .strip_suffix(VENDORED_TERMINATOR)
                    .expect("only a pattern with the vendored terminator is relaxed")
                    .to_string();
                (id, body, keywords)
            })
            .collect()
    }

    fn base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .chain([0u8, 0].iter())
                .take(3)
                .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            }
        }
        out
    }

    /// A signed-looking token built at run time: a real header, a claims object, random bytes for
    /// the signature.
    fn sample_jwt(seed: u64) -> String {
        let claims = format!(
            r#"{{"sub":"{}","iat":1700000000}}"#,
            synthetic_token(seed + 1, 12, ALNUM)
        );
        format!(
            "{}.{}.{}",
            base64url(br#"{"alg":"HS256","typ":"JWT"}"#),
            base64url(claims.as_bytes()),
            synthetic_token(seed + 2, 43, ALNUM)
        )
    }

    /// A PEM block with a random body, built at run time. `newline` is what separates its lines:
    /// a real line break, or the two characters `\n` as a key pasted into a JSON transcript has.
    fn sample_private_key(seed: u64, newline: &str) -> String {
        let base64 = format!("{ALNUM}+/");
        let body: Vec<String> = (0..12)
            .map(|i| synthetic_token(seed * 100 + i + 1, 64, &base64))
            .collect();
        format!(
            "-----BEGIN RSA PRIVATE KEY-----{newline}{}{newline}-----END RSA PRIVATE KEY-----",
            body.join(newline)
        )
    }

    fn structured_sample(id: &str, seed: u64) -> Option<String> {
        match id {
            "jwt" => Some(sample_jwt(seed)),
            "private-key" => Some(sample_private_key(seed, "\n")),
            _ => None,
        }
    }

    /// The rules whose terminator [`relax_terminator`] changes, pinned. A re-sync with upstream
    /// that adds a prefixed rule, or changes the shape of one, shows up here as a difference to
    /// look at instead of as a silent change in what is reported.
    const RELAXED: &[&str] = &[
        "adobe-client-secret",
        "alibaba-access-key-id",
        "anthropic-admin-api-key",
        "anthropic-api-key",
        "authress-service-client-access-key",
        "aws-amazon-bedrock-api-key-long-lived",
        "cerebras-api-key",
        "cloudflare-origin-ca-key",
        "cursor-api-key",
        "databricks-api-token",
        "deepseek-api-key",
        "defined-networking-api-token",
        "digitalocean-access-token",
        "digitalocean-pat",
        "digitalocean-refresh-token",
        "dropbox-short-lived-api-token",
        "elevenlabs-api-key",
        "endorlabs-api-key",
        "endorlabs-api-secret",
        "facebook-page-access-token",
        "figma-personal-access-token",
        "flyio-access-token",
        "gcp-api-key",
        "gocardless-api-token",
        "grafana-api-key",
        "grafana-cloud-api-token",
        "grafana-service-account-token",
        "groq-api-key",
        "heroku-api-key-v2",
        "huggingface-access-token",
        "huggingface-organization-api-token",
        "infracost-api-token",
        "intra42-client-secret",
        "lob-api-key",
        "lob-pub-api-key",
        "mailgun-private-api-token",
        "mailgun-pub-key",
        "mapbox-api-token",
        "new-relic-browser-api-token",
        "new-relic-insert-key",
        "new-relic-user-api-key",
        "notion-api-token",
        "npm-access-token",
        "nvidia-api-key",
        "octopus-deploy-api-key",
        "openai-api-key",
        "openrouter-api-key",
        "plaid-api-token",
        "planetscale-api-token",
        "planetscale-oauth-token",
        "planetscale-password",
        "posthog-personal-api-key",
        "posthog-project-api-key",
        "postman-api-token",
        "prefect-api-token",
        "pulumi-api-token",
        "readme-api-token",
        "replicate-api-token",
        "rubygems-api-token",
        "scalingo-api-token",
        "sendgrid-api-token",
        "sendinblue-api-token",
        "sentry-user-token",
        "settlemint-application-access-token",
        "settlemint-personal-access-token",
        "settlemint-service-access-token",
        "shippo-api-token",
        "square-access-token",
        "stability-ai-api-key",
        "stripe-access-token",
        "togetherai-api-key",
        "twitter-bearer-token",
        "typeform-api-token",
        "vault-batch-token",
        "vercel-ai-gateway-key",
        "vercel-app-access-token",
        "vercel-app-refresh-token",
        "vercel-integration-token",
        "vercel-personal-access-token",
        "weights-and-biases-api-key-v1",
        "xai-api-key",
        "yandex-access-token",
        "yandex-api-key",
    ];

    #[test]
    fn the_terminator_is_relaxed_for_prefixed_keys_and_nothing_else() {
        let relaxed: Vec<String> = relaxed_rules().into_iter().map(|(id, _, _)| id).collect();
        assert_eq!(
            relaxed, RELAXED,
            "the set of rules with a relaxed terminator changed: check each difference, then \
             update RELAXED"
        );

        // Shapes that must come back byte for byte.
        let t = VENDORED_TERMINATOR;
        for untouched in [
            // A keyword and a value: the value has no prefix of its own.
            format!(
                r#"(?i)(?:adafruit)[\s'"]{{0,3}}(?:=|:)[\x60'"\s=]{{0,5}}([a-z0-9_-]{{32}}){t}"#
            ),
            // Two fixed characters identify nothing (a JWT, the short Vault form).
            format!(r"\b(ey[a-zA-Z0-9]{{17,}}\.ey[a-zA-Z0-9_-]{{17,}}){t}"),
            format!(r"\b((?:hvs\.[\w-]{{90,120}}|s\.(?i:[a-z0-9]{{24}}))){t}"),
            // One branch with no prefix at all (a bare 40-hex Sourcegraph token).
            format!(r"\b(sgp_[a-f0-9]{{40}}|[a-f0-9]{{40}}){t}"),
            // An optional prefix is no prefix.
            format!(r"((?:squ_|sqp_)?[a-z0-9=_\-]{{40}}){t}"),
            // The group before the terminator is the key, not whichever group comes first.
            format!(r"(?:sonar[_.-]?(login|token))=([a-z0-9]{{40}}){t}"),
            // No capture group, and no terminator.
            format!(r"\bAKIA[A-Z2-7]{{16}}{t}"),
            r"\b(ghp_[0-9a-zA-Z]{36})\b".to_string(),
        ] {
            assert_eq!(relax_terminator(&untouched), untouched);
        }

        // A relaxed pattern keeps every vendored alternative and adds to them.
        let vendored = format!(r"\b(abc_[a-f0-9]{{20}}){t}");
        let relaxed = relax_terminator(&vendored);
        assert!(
            relaxed.starts_with(&vendored[..vendored.len() - 1]),
            "{relaxed}"
        );
        let re = compile(&relaxed).unwrap();
        let key = format!("abc_{}", synthetic_token(3, 20, HEX));
        for (after, expected) in [
            (".", true),
            (". Then", true),
            ("...", true),
            (")", true),
            (",x", true),
            (":", true),
            ("@host", true),
            ("&x=1", true),
            ("|pbcopy", true),
            ("。", true),
            // Still part of a longer word, a base64 run or a path: not this key.
            ("g", false),
            ("0", false),
            ("_x", false),
            ("-x", false),
            ("/x", false),
            ("+x", false),
            ("=", false),
            // A function call, an index, a file name, a method: an identifier, not a key.
            ("(void);", false),
            ("[0]", false),
            ("{x}", false),
            (".png", false),
            (".method()", false),
        ] {
            assert_eq!(re.is_match(&format!("{key}{after}")), expected, "{after:?}");
        }

        // A body that itself allows `.`: sentence punctuation after the key ends it, a dot inside
        // a longer token does not.
        let dotted = compile(&relax_terminator(&format!(r"\b(SG\.[a-z0-9.]{{20}}){t}"))).unwrap();
        let key = format!("SG.{}", synthetic_token(5, 20, LOWER));
        assert!(dotted.is_match(&format!("{key}. Then")));
        assert!(dotted.is_match(&format!("{key}.")));
        assert!(dotted.is_match(&format!("{key}...\n")));
        assert!(!dotted.is_match(&format!("{key}.more")));
        assert!(!dotted.is_match(&format!("{key}x")));
    }

    /// What follows a key in chat, in prose and on a command line.
    const TAILS: &[&str] = &[
        ".",
        ",",
        ")",
        "]",
        "}",
        "*",
        "&",
        "|",
        "\"",
        "'",
        "`",
        ">",
        "<",
        "\n",
        " ",
        ":",
        "!",
        "?",
        "**",
        "&x=1",
        "|pbcopy",
        "\\n",
        "\\\"",
        "\\u0026x=1",
        ". Next",
        ", then",
        ").",
        "</key>",
        "。",
    ];

    /// The key in a string generated from a relaxed rule's pattern: the outermost group that the
    /// match ends with.
    fn trailing_key<'a>(body: &Regex, sample: &'a str) -> Option<&'a str> {
        let caps = body.captures(sample)?;
        let end = caps.get(0)?.end();
        caps.iter()
            .skip(1)
            .flatten()
            .find(|g| g.end() == end)
            .map(|g| g.as_str())
    }

    /// The defect this rewrite fixes, as a property of the whole pack: a key generated from each
    /// relaxed rule's own pattern is reported, and redacted, whatever comes after it — a full
    /// stop, a closing bracket, markdown emphasis, the rest of a URL, a pipe. Before, only
    /// whitespace, a quote, `;` or the end of the line would do, and a key in an ordinary sentence
    /// was missed.
    #[test]
    fn a_prefixed_key_is_found_whatever_follows_it() {
        let mut unsampled = Vec::new();
        let mut missed = Vec::new();
        let mut wrong_span = Vec::new();
        for (id, body, keywords) in relaxed_rules() {
            let gen = SampleGen::new(&body).expect("a relaxed rule's pattern compiles");
            let body_re = compile(&body).unwrap();
            let alphabet = prefixed_key_alphabet(&body).unwrap();
            let path = matching_path(&id);
            let hint = if keywords.is_empty() {
                id.replace('-', "_")
            } else {
                keywords.join(" ")
            };
            // A sample the pack reports in the form that always worked (a space after it), so a
            // miss below is about the character that follows and nothing else.
            let found = (0..40).find_map(|seed| {
                let sample = gen.sample(seed)?;
                let key = trailing_key(&body_re, &sample)?.to_string();
                let text = format!("{hint}: {sample} ok\n");
                (!scan_text_high_confidence_in(path.as_deref(), &text).is_empty())
                    .then_some((sample, key))
            });
            let Some((sample, key)) = found else {
                unsampled.push(id);
                continue;
            };
            for tail in TAILS {
                let text = format!("{hint}: {sample}{tail}\n");
                let hits = scan_text_high_confidence_in(path.as_deref(), &text);
                let (redacted, count) = redact_text_in(path.as_deref(), &text);
                if hits.is_empty() || count == 0 || redacted.contains(&key) {
                    missed.push(format!("{id} followed by {tail:?}"));
                    continue;
                }
                // Where the next character cannot belong to the key, the key ends exactly there:
                // what followed it is still in the file after redaction.
                let next = tail.chars().next().unwrap();
                if !alphabet
                    .ranges()
                    .iter()
                    .any(|r| r.start() <= next && next <= r.end())
                    && !redacted.contains(&format!("{REDACTION_PLACEHOLDER}{tail}"))
                {
                    wrong_span.push(format!("{id} followed by {tail:?}"));
                }
            }
        }
        assert!(
            unsampled.is_empty(),
            "no usable sample, so nothing was tested for: {unsampled:?}"
        );
        assert!(
            missed.is_empty(),
            "{} key(s) not found: {missed:?}",
            missed.len()
        );
        assert!(
            wrong_span.is_empty(),
            "redaction took more than the key: {wrong_span:?}"
        );
    }

    /// The safety net for the relaxation, in the style of the one for [`drop_leading_wildcard`]:
    /// rule by rule, everything the vendored pattern captures the rewritten one captures too, at
    /// the same offset. The rewrite may only add.
    #[test]
    fn relaxing_a_terminator_only_ever_adds_matches() {
        let mut widened = 0;
        for (id, body, keywords) in relaxed_rules() {
            let vendored = drop_leading_wildcard(&format!("{body}{VENDORED_TERMINATOR}"));
            let before = compile(&vendored).unwrap();
            let after = compile(&relax_terminator(&vendored)).unwrap();

            let hint = if keywords.is_empty() {
                id.replace('-', "_")
            } else {
                keywords.join(" ")
            };
            let mut corpus = positive_corpus(&id, &keywords);
            let gen = SampleGen::new(&body);
            for seed in 0..8 {
                let Some(sample) = gen.as_ref().and_then(|g| g.sample(seed)) else {
                    continue;
                };
                corpus.push_str(&sample_in_context(&id, &keywords, &sample));
                for tail in TAILS {
                    corpus.push_str(&format!("{hint}: {sample}{tail}\n"));
                }
                // Run on into a longer word, and into a base64 run.
                corpus.push_str(&format!(
                    "{hint}: {sample}Zz9Zz9Zz9\n{hint}: {sample}/Zz9+Zz9=\n"
                ));
            }

            let secrets = |re: &Regex| -> BTreeSet<(usize, String)> {
                re.captures_iter(&corpus)
                    .filter_map(|c| {
                        let whole = c.get(0)?;
                        let s = c.get(1).unwrap_or(whole);
                        Some((s.start(), s.as_str().to_string()))
                    })
                    .collect()
            };
            let (old, new) = (secrets(&before), secrets(&after));
            let lost: Vec<_> = old.difference(&new).map(|(at, _)| *at).collect();
            assert!(
                lost.is_empty(),
                "relaxing `{id}` lost matches at offsets {lost:?}"
            );
            if new.len() > old.len() {
                widened += 1;
            }
        }
        assert!(
            widened >= 75,
            "only {widened} of {} relaxed rules matched anything new: the corpus is too weak to \
             prove the comparison",
            RELAXED.len()
        );
    }

    /// The other side of the relaxation: a key-shaped string that *runs on* — into a call, an
    /// index, a file extension, a path, a longer word, a base64 run — is an identifier or a file
    /// name, and the relaxed rule reports exactly what the vendored one did there (for most rules,
    /// nothing). Two of these shapes are non-secrets gitleaks records for the pack
    /// (`GLC_CreateLightmapTextures(void)`, `ico-<hash>.png`).
    #[test]
    fn a_key_shape_that_runs_on_is_not_newly_reported() {
        const RUNS_ON: &[&str] = &[
            "(void);",
            "[0]",
            "{x}",
            ".png",
            ".method()",
            ".example.com",
            "/extra",
            "-suffix",
            "_suffix",
            "Zz9",
            "=",
            "==",
            "+Zz9",
        ];
        let pack = &*PACK;
        let mut extra = Vec::new();
        let mut checked = 0;
        for (id, body, keywords) in relaxed_rules() {
            let rule = pack.rules.iter().find(|r| r.id == id).unwrap();
            let vendored = compile(&rule.pattern).unwrap();
            let gen = SampleGen::new(&body).unwrap();
            let hint = if keywords.is_empty() {
                id.replace('-', "_")
            } else {
                keywords.join(" ")
            };
            let Some(sample) = (0..40).find_map(|seed| {
                let sample = gen.sample(seed)?;
                (!matches_for(pack, rule, &format!("{hint}: {sample} ok\n")).is_empty())
                    .then_some(sample)
            }) else {
                continue;
            };
            for cont in RUNS_ON {
                let text = format!("{hint}: {sample}{cont}\n");
                let spans = |re: &Regex| -> Vec<(usize, usize)> {
                    matches_with(pack, rule, re, &text)
                        .iter()
                        .map(|m| (m.secret_start, m.secret_end))
                        .collect()
                };
                checked += 1;
                if spans(&vendored) != spans(rule.regex().unwrap()) {
                    extra.push(format!("{id} followed by {cont:?}"));
                }
            }
        }
        assert!(checked > 900, "{checked}");
        assert!(
            extra.is_empty(),
            "reported although the key shape runs on: {extra:?}"
        );
    }

    /// Whether the vendored terminator would have accepted what follows `at`.
    fn vendored_terminator_follows(text: &str, at: usize) -> bool {
        let rest = &text[at..];
        let rest = rest.strip_prefix('\\').map_or(rest, |unescaped| {
            if unescaped.starts_with(['\'', '"', '`', 'n', 'r']) {
                // `\"` and the literal `\n` are both accepted; reduce them to the quote case.
                "\""
            } else {
                rest
            }
        });
        rest.is_empty()
            || rest.starts_with(['\'', '"', '`', ';'])
            || rest.starts_with(char::is_whitespace)
    }

    /// The text files of this repository: its guides, rules, scripts and source. Full of
    /// key-shaped things that are not keys — placeholders, patterns, prefixes in prose, hashes,
    /// lock files — which makes it a fair corpus of plausible non-secret text.
    fn repository_text() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        const SKIP: &[&str] = &["target", "node_modules", ".git", "dist", "cache", "vendor"];
        const TEXT: &[&str] = &[
            "md", "rs", "ts", "tsx", "js", "mjs", "cjs", "json", "yaml", "yml", "toml", "sh", "py",
            "txt", "html", "css", "xml", "lock", "spec", "desktop", "conf",
        ];
        walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_entry(|e| {
                !e.file_name()
                    .to_str()
                    .is_some_and(|name| SKIP.contains(&name))
            })
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| TEXT.contains(&x))
            })
            .filter(|e| e.metadata().is_ok_and(|m| m.len() <= 1024 * 1024))
            .filter_map(|e| {
                let text = std::fs::read_to_string(e.path()).ok()?;
                let name = e
                    .path()
                    .strip_prefix(&root)
                    .unwrap_or(e.path())
                    .display()
                    .to_string();
                Some((name, text))
            })
            .collect()
    }

    /// **Zero new false positives on real text.** Every match a relaxed rule makes in this
    /// repository that the vendored terminator would have refused — a key-shaped string followed
    /// by punctuation, in several megabytes of documentation, rule files, scripts and source that
    /// contain no real key. There are none, and a change that makes one appear has to explain it.
    #[test]
    fn relaxed_terminators_report_nothing_new_in_this_repository() {
        let files = repository_text();
        if files.len() < 200 {
            // A source package that carries only this crate has no repository around it.
            eprintln!(
                "skipped: only {} text files found around this crate",
                files.len()
            );
            return;
        }
        let pack = &*PACK;
        let relaxed: Vec<&Rule> = pack
            .rules
            .iter()
            .filter(|r| r.final_pattern() != r.pattern)
            .collect();
        assert_eq!(relaxed.len(), RELAXED.len());

        let (mut bytes, mut ran, mut old_style) = (0usize, 0usize, 0usize);
        let mut new_matches = Vec::new();
        for (name, text) in &files {
            bytes += text.len();
            let lower = text.to_ascii_lowercase();
            for rule in &relaxed {
                if !rule.keywords.iter().any(|k| lower.contains(k.as_str())) {
                    continue;
                }
                ran += 1;
                for m in matches_for(pack, rule, text) {
                    if vendored_terminator_follows(text, m.secret_end) {
                        old_style += 1;
                        continue;
                    }
                    let next: String = text[m.secret_end..].chars().take(1).collect();
                    new_matches.push(format!(
                        "{} in {name}:{} — {} followed by {next:?}",
                        rule.id,
                        line_of(text, m.secret_start),
                        mask(m.secret)
                    ));
                }
            }
        }
        println!(
            "{} files, {bytes} bytes, {ran} rule runs, {old_style} match(es) the vendored \
             terminator also accepts, {} new",
            files.len(),
            new_matches.len()
        );
        assert!(
            bytes > 2_000_000 && ran > 100,
            "the corpus is too small to mean anything: {bytes} bytes, {ran} rule runs"
        );
        assert!(
            new_matches.is_empty(),
            "a relaxed terminator reports text the vendored one refused:\n  {}",
            new_matches.join("\n  ")
        );
    }

    /// A transcript-shaped text of about `size` bytes: JSON lines of prose, paths, hashes, base64
    /// and command lines, dense with the words and prefixes the pack's keywords look for, and with
    /// a key followed by punctuation every few hundred lines.
    fn transcript_like(size: usize) -> String {
        let prefixes = [
            "sk-", "sk_live_", "key-", "api-", "hf_", "npm_", "AIza", "SG.", "gsk_", "xai-", "pk.",
            "sl.", "live_", "test_", "dapi", "EAAA", "t1.", "glc_", "r8_", "pul-",
        ];
        let mut out = String::with_capacity(size + 4096);
        let mut i = 0u64;
        while out.len() < size {
            i += 1;
            let word = synthetic_token(i, 9, LOWER);
            let hash = synthetic_token(i * 7, 40, HEX);
            let blob = synthetic_token(i * 13, 120, &format!("{ALNUM}+/"));
            let prefix = prefixes[i as usize % prefixes.len()];
            out.push_str(&format!(
                "{{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":\"I ran `git log` in /home/dev/src/{word}/lib.rs and commit {hash} changed the {prefix}{word} handling; the api key and token docs mention {prefix}... (see https://example.invalid/{word}?id={i}&ref={hash}). Output: {blob}==\\n\"}}}}\n"
            ));
            if i.is_multiple_of(300) {
                let key = format!("sk-ant-api03-{}AA", synthetic_token(i, 93, ALNUM));
                let tail = TAILS[i as usize / 300 % TAILS.len()];
                out.push_str(&format!(
                    "{{\"type\":\"user\",\"message\":\"my key is {key}{tail}\"}}\n"
                ));
            }
        }
        out
    }

    /// The cost of the relaxation, measured: every relaxed rule the keyword index selects for a
    /// 4 MB transcript-shaped file, run with the vendored terminator and with the relaxed one.
    /// The leading-wildcard story (a 1.5 s scan that used to take minutes) is the reason to
    /// measure a regex change and not assume. Ignored by default: it is a measurement, and only a
    /// release build's numbers mean anything.
    ///
    /// `cargo test -p bulwark-core --release --lib -- --ignored --nocapture relaxed_terminators_cost`
    #[test]
    #[ignore = "a benchmark: run it in a release build"]
    fn relaxed_terminators_cost_about_the_same_on_a_4mb_transcript() {
        let text = transcript_like(4 * 1024 * 1024);
        let pack = &*PACK;
        let candidates = pack.candidates(&text);
        let relaxed: Vec<&Rule> = candidates
            .iter()
            .map(|&i| &pack.rules[i])
            .filter(|r| r.high_conf && r.final_pattern() != r.pattern)
            .collect();
        let compiled: Vec<(&Rule, Regex, Regex)> = relaxed
            .iter()
            .map(|r| {
                (
                    *r,
                    compile(&r.pattern).unwrap(),
                    compile(&r.final_pattern()).unwrap(),
                )
            })
            .collect();
        let time = |relaxed: bool| {
            let mut best = std::time::Duration::MAX;
            let mut found = 0;
            for _ in 0..3 {
                let start = std::time::Instant::now();
                found = compiled
                    .iter()
                    .map(|(rule, vendored, rewritten)| {
                        let re = if relaxed { rewritten } else { vendored };
                        matches_with(pack, rule, re, &text).len()
                    })
                    .sum::<usize>();
                best = best.min(start.elapsed());
            }
            (best, found)
        };
        let (before, found_before) = time(false);
        let (after, found_after) = time(true);
        let start = std::time::Instant::now();
        let whole = scan_high_confidence(None, &text);
        let whole_time = start.elapsed();
        println!(
            "{} bytes, {} candidate rules of which {} relaxed\n\
             relaxed rules, vendored terminator: {before:?} ({found_before} matches)\n\
             relaxed rules, relaxed terminator:  {after:?} ({found_after} matches)\n\
             whole high-confidence scan as shipped: {whole_time:?} ({} findings)",
            text.len(),
            candidates.len(),
            compiled.len(),
            whole.matches.len()
        );
        assert!(
            found_after > found_before,
            "the corpus has keys before punctuation"
        );
        assert!(
            after < before * 3 + std::time::Duration::from_millis(50),
            "the relaxed terminator made these rules much slower: {before:?} -> {after:?}"
        );
    }

    #[test]
    fn two_markers_and_no_key_are_not_a_private_key() {
        // A header that is never closed, repeated: each one used to pair with the next.
        let unclosed = format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n", "A".repeat(70)).repeat(50);
        assert!(scan_text_high_confidence(&unclosed).is_empty());
        assert_eq!(redact_text(&unclosed).1, 0);
        // Closed, but the "body" is one repeated character, prose, or cut short. (Assembled from
        // parts, so that no marker pair with text between them sits in this file for a scanner.)
        let block = |body: &str| {
            format!(
                "{0}BEGIN PRIVATE KEY{0}\n{body}\n{0}END PRIVATE KEY{0}\n",
                "-----"
            )
        };
        for not_a_key in [
            block(&"A".repeat(200)),
            block("Paste the contents of your key file here, between the two marker lines, then save."),
            block(&format!(
                "{}...\n(rest of the key left out of this example on purpose)",
                synthetic_token(4, 30, ALNUM)
            )),
        ] {
            assert!(
                scan_text_high_confidence(&not_a_key).is_empty(),
                "{:?}",
                &not_a_key[..60]
            );
        }
    }

    #[test]
    fn a_real_private_key_block_is_still_found() {
        for (label, text) in [
            ("plain", sample_private_key(1, "\n")),
            // Pasted into a JSON transcript: its line breaks are the two characters `\n`.
            (
                "json",
                format!("{{\"message\":\"{}\"}}\n", sample_private_key(2, "\\n")),
            ),
            ("crlf", sample_private_key(3, "\r\n")),
            // An encrypted key carries `Name: value` lines before its body.
            (
                "armor",
                sample_private_key(4, "\n").replacen(
                    "-----\n",
                    "-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n",
                    1,
                ),
            ),
            // After a header that was only quoted in prose. The quoted header used to swallow the
            // real one; now the search resumes at the real one.
            (
                "after a quoted header",
                format!(
                    "The file starts with -----BEGIN RSA PRIVATE KEY----- and is long.\n\n{}\n",
                    sample_private_key(5, "\n")
                ),
            ),
        ] {
            let hits = scan_text_high_confidence(&text);
            assert_eq!(hits.len(), 1, "{label}: {hits:?}");
            assert_eq!(hits[0].rule_id, "private-key", "{label}");
            let (redacted, count) = redact_text(&text);
            assert_eq!(count, 1, "{label}");
            assert!(!redacted.contains("-----END"), "{label}: {redacted}");
        }
        // The smallest real key, an Ed25519 one in PKCS#8, has a 64-character body.
        let small = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            synthetic_token(9, 64, ALNUM)
        );
        assert_eq!(scan_text_high_confidence(&small).len(), 1);
    }

    #[test]
    fn a_jwt_needs_three_segments_and_a_header_that_decodes() {
        let real = sample_jwt(1);
        let hits = scan_text_high_confidence(&format!("Authorization: Bearer {real}\n"));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule_id, "jwt");

        let header = base64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = base64url(br#"{"sub":"1234567890","name":"A"}"#);
        for not_a_token in [
            // No signature: nothing a server would accept.
            format!("{header}.{claims}."),
            // The same header ten times over, with dots between.
            format!("{header}.").repeat(10),
            // Two base64 words that decode to nothing in particular.
            format!(
                "ey{}.ey{}.{}",
                synthetic_token(1, 30, ALNUM),
                synthetic_token(2, 30, ALNUM),
                synthetic_token(3, 43, ALNUM)
            ),
            // A header with no algorithm.
            format!(
                "{}.{claims}.{}",
                base64url(br#"{"typ":"JWT","kid":"abcdef"}"#),
                synthetic_token(3, 43, ALNUM)
            ),
        ] {
            let text = format!("token {not_a_token}\n");
            assert!(
                scan_text_high_confidence(&text).is_empty(),
                "{:?}",
                scan_text_high_confidence(&text)
            );
            assert_eq!(redact_text(&text).1, 0);
        }
        assert!(plausible_jwt(&real));
        // Escaped slashes, as a token quoted inside JSON can have, do not hide it.
        assert!(plausible_jwt(&real.replacen('.', "\\.", 0)));
    }

    #[test]
    fn a_scan_says_when_it_stopped_at_the_limit_and_redaction_has_none() {
        let key = |i: u64| format!("ghp_{}", synthetic_token(i + 1, 36, ALNUM));
        let lines = |n: u64| {
            (0..n)
                .map(|i| format!("k{i} {}\n", key(i)))
                .collect::<String>()
        };

        let over = lines(2500);
        let scan = scan_high_confidence(None, &over);
        assert_eq!(scan.matches.len(), MAX_SECRETS_PER_TEXT);
        assert!(scan.more, "2,500 keys are more than the limit");
        // The older entry point returns the same matches, without the flag.
        assert_eq!(scan_text_high_confidence(&over).len(), MAX_SECRETS_PER_TEXT);
        // Redaction takes all of them: none may be left in a file reported as redacted.
        let (redacted, count) = redact_text(&over);
        assert_eq!(count, 2500);
        assert!(scan_text_high_confidence(&redacted).is_empty());

        let exact = lines(MAX_SECRETS_PER_TEXT as u64);
        let scan = scan_high_confidence(None, &exact);
        assert_eq!(scan.matches.len(), MAX_SECRETS_PER_TEXT);
        assert!(!scan.more, "exactly the limit is not more than the limit");

        let few = scan_high_confidence(None, &lines(3));
        assert_eq!((few.matches.len(), few.more), (3, false));
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
    fn a_commit_hash_is_not_a_token_because_a_keyword_is_somewhere_in_the_file() {
        // A transcript mentions Sourcegraph once, and later quotes a commit hash. The rule's bare
        // 40-hex branch used to report the hash as a leaked Sourcegraph token.
        let sha = synthetic_token(7, 40, "0123456789abcdef");
        let far = format!(
            "We looked at sourcegraph for code search.\n{}\nThe fix landed in commit {sha} yesterday.\n",
            "filler ".repeat(40)
        );
        assert!(
            scan_text(&far)
                .iter()
                .all(|m| m.rule_id != "sourcegraph-access-token"),
            "{:?}",
            scan_text(&far)
        );
        // Right next to its keyword it is still reported — that is how a real legacy token looks.
        let near = format!("SOURCEGRAPH_TOKEN={sha}\n");
        assert!(scan_text(&near)
            .iter()
            .any(|m| m.rule_id == "sourcegraph-access-token"));
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
    fn providers_are_spelled_the_way_they_spell_themselves() {
        for (id, shown) in [
            // The three that were reported: "Npm", "Openrouter", "Xai".
            ("npm-access-token", "npm access token"),
            ("openrouter-api-key", "OpenRouter API key"),
            ("xai-api-key", "xAI API key"),
            ("github-fine-grained-pat", "GitHub fine-grained PAT"),
            ("huggingface-access-token", "Hugging Face access token"),
            ("new-relic-user-api-key", "New Relic user API key"),
            ("weights-and-biases-api-key", "Weights & Biases API key"),
            ("hashicorp-tf-api-token", "HashiCorp Terraform API token"),
            (
                "aws-amazon-bedrock-api-key-long-lived",
                "Amazon Bedrock API key long-lived",
            ),
            ("gitlab-cicd-job-token", "GitLab CI/CD job token"),
            ("gitlab-ptt", "GitLab pipeline trigger token"),
            ("1password-secret-key", "1Password secret key"),
            (
                "airtable-personnal-access-token",
                "Airtable personal access token",
            ),
            ("stability-ai-api-key", "Stability AI API key"),
            ("jwt", "JWT"),
            ("curl-auth-header", "curl auth header"),
        ] {
            assert_eq!(humanize(id), shown);
        }
        // No name in the pack is left with a lower-case start by accident: the only ones that
        // begin lower-case are the names that are written that way.
        let lower: Vec<String> = raw_rules()
            .into_iter()
            .map(|(id, _, _)| humanize(&id))
            .filter(|name| name.starts_with(|c: char| c.is_lowercase()))
            .collect();
        for name in &lower {
            assert!(
                ["npm ", "xAI ", "curl ", "age "]
                    .iter()
                    .any(|p| name.starts_with(p)),
                "{name}"
            );
        }
        // Every key in the table is used by some rule, so the table cannot collect dead entries.
        let ids: Vec<String> = raw_rules().into_iter().map(|(id, _, _)| id).collect();
        for (key, _) in NAMES {
            let used = ids.iter().any(|id| {
                id == key
                    || id.starts_with(&format!("{key}-"))
                    || id.ends_with(&format!("-{key}"))
                    || id.contains(&format!("-{key}-"))
            });
            assert!(used, "unused: {key}");
        }
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

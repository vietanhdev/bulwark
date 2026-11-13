//! The one way text from a scanned file gets into a finding.
//!
//! A finding is printed, written to `--json`, stored in the database and forwarded in alerts. A
//! config file is written by whoever wrote the repository. So nothing read from one may reach a
//! finding as it is: an MCP server's address can carry a token in its query, a permission entry can
//! be a whole `curl -H 'Authorization: …'` command, and a server's *name* is whatever its author
//! typed. A detector that quoted any of those quoted the credential. [`shown`] is what every
//! detector quotes through instead, and [`super::Detection::new`] applies it again to the finished
//! text, so a detector that forgets still cannot print a key the secret pack knows.

use crate::ai_scan::secrets;
use crate::collectors::dev_tools::url_origin;
use regex::{Captures, Regex};
use std::sync::OnceLock;

/// The longest quoted value or evidence line a finding keeps.
pub(crate) const SHOWN_MAX: usize = 160;

/// How much of one line is looked at. The rest of a longer line (a minified file is one line) is
/// not shown, so it need not be read.
const WINDOW: usize = 4096;

/// What a masked value becomes.
const MASK: &str = "***";

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("a fixed pattern compiles"))
}

/// A `scheme://…` address: an IPv6 literal in brackets if there is one, then everything up to
/// whitespace, a quote, or a closing bracket (the address is usually *inside* something:
/// `Shell(curl https://host)`, `[link](https://host)`).
fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r#"(?i)\b[a-z][a-z0-9+.-]*://(?:\[[0-9a-f:.%]+\])?[^\s'"<>\x60)\]}]*"#,
    )
}

/// `user:password@host` with no scheme in front (`git clone bot:tok@github.com/x`). The host must
/// look like one — a dotted name ending in letters, `localhost`, or a dotted quad — so a package
/// spec such as `npm:thing@1.2.3` is left alone.
fn userinfo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r#"(?i)\b[a-z0-9._%+~-]+:[^\s:@/'"<>]+@((?:[a-z0-9-]+\.)+[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})\b"#,
    )
}

/// The words that make a name say "what follows is a credential".
const SECRET_NAME: &str = r"(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|apikey|access[_-]?key|private[_-]?key|authorization|credentials?|bearer|cookie|session[_-]?id|signature)";

/// What can follow the name: a quoted value (whole, spaces and all) or a bare one. An HTTP auth
/// scheme word in front of a bare value (`Authorization: Bearer …`) is kept and the value after
/// it masked.
const SECRET_VALUE: &str = r#"(?P<scheme>(?:bearer|basic|token|digest|apikey|negotiate)\s+)?(?:"(?P<dq>[^"]*)"?|'(?P<sq>[^']*)'?|(?P<bare>[^\s'"<>,;&|)}\]]+))"#;

/// `NAME=value`, `NAME: value`, `"NAME": "value"`, `-H 'X-Api-Key: value'`, `?token=value`.
fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        &format!(
            r#"(?i)(?P<name>[a-z0-9_.-]*{SECRET_NAME}[a-z0-9_-]*["']?\s*[=:]\s*){SECRET_VALUE}"#
        ),
    )
}

/// `--token value`, `--api-key value`: a flag named for a credential, then its value.
fn flag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        &format!(r#"(?i)(?P<name>--?[a-z0-9-]*{SECRET_NAME}[a-z0-9-]*\s+){SECRET_VALUE}"#),
    )
}

/// curl's `-u user:password`.
fn curl_user_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r#"(?P<name>(?:^|\s)(?:-u|--user)[=\s]+['"]?)(?P<bare>[^\s'":]+:[^\s'"]+)"#,
    )
}

/// A long run of key-like characters, for the credential nothing above names: a positional
/// argument, a provider the pack has no pattern for.
fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[A-Za-z0-9_+=-]{20,}")
}

/// A value that only points at a secret kept somewhere else: `${NAME}`, `$NAME`, `$(command)`,
/// `%NAME%`, `{env:NAME}`, or a placeholder Bulwark itself wrote. Showing it gives nothing away,
/// and it is exactly what a reader needs to see.
fn points_elsewhere(value: &str) -> bool {
    let v = value.trim();
    v.is_empty()
        || v.starts_with('$')
        || v.starts_with("{env:")
        || v.starts_with("{file:")
        || v.starts_with("{{")
        || v.starts_with("[bulwark:")
        || v == MASK
        // The next flag, not a value.
        || v.starts_with('-')
        || (v.len() > 2 && v.starts_with('%') && v.ends_with('%'))
        || (v.starts_with('<') && v.ends_with('>'))
}

/// Replaces the value in a `name value` match with [`MASK`], unless it only points elsewhere.
fn mask_value(caps: &Captures) -> String {
    let name = caps.name("name").map_or("", |m| m.as_str());
    let scheme = caps.name("scheme").map_or("", |m| m.as_str());
    let (value, quote) = if let Some(v) = caps.name("dq") {
        (v.as_str(), "\"")
    } else if let Some(v) = caps.name("sq") {
        (v.as_str(), "'")
    } else {
        (caps.name("bare").map_or("", |m| m.as_str()), "")
    };
    if points_elsewhere(value) {
        return caps[0].to_string();
    }
    // A quoted value holds its scheme word inside the quotes; keep that word, mask the rest.
    let inner_scheme = ["Bearer ", "Basic ", "Token ", "bearer ", "basic ", "token "]
        .iter()
        .find(|s| !quote.is_empty() && value.starts_with(**s))
        .copied()
        .unwrap_or("");
    if !inner_scheme.is_empty() && points_elsewhere(&value[inner_scheme.len()..]) {
        return caps[0].to_string();
    }
    format!("{name}{scheme}{quote}{inner_scheme}{MASK}{quote}")
}

/// Whether a run of key-like characters is random enough, and digit-heavy enough, to be a
/// credential and not a long identifier or package name: at least three digits making up a tenth
/// of it, at least three letters, and close to four bits of entropy per character.
fn looks_random(token: &str) -> bool {
    let digits = token.chars().filter(char::is_ascii_digit).count();
    let letters = token.chars().filter(char::is_ascii_alphabetic).count();
    digits >= 3 && digits * 10 >= token.len() && letters >= 3 && entropy(token) >= 3.5
}

fn entropy(s: &str) -> f64 {
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

/// `raw`, made safe to quote in a finding and cut to [`SHOWN_MAX`] characters.
///
/// In order:
/// 1. every `scheme://` address becomes its scheme, host and port
///    ([`url_origin`]): the path, the query and any `user:password@` are dropped;
/// 2. every key the secret pack recognises becomes the redaction placeholder;
/// 3. `user:password@host` without a scheme loses the part before the `@`;
/// 4. the value of anything named like a credential (`--token x`, `X-Api-Key: x`,
///    `PASSWORD=x`, `Authorization: Bearer x`, curl's `-u user:x`) is masked, unless it only
///    points at one (`${TOKEN}`);
/// 5. any other long random-looking run of characters is masked;
/// 6. control, invisible and bidirectional characters are replaced, so the text shows as its
///    bytes read.
pub(crate) fn shown(raw: &str) -> String {
    shown_up_to(raw, SHOWN_MAX)
}

/// [`shown`] with another length limit.
pub(crate) fn shown_up_to(raw: &str, max_chars: usize) -> String {
    let raw = raw.trim().trim_start_matches('\u{feff}');
    // Look at a bounded part of a very long line, and cut it between words: a key cut in half no
    // longer looks like a key to any of the steps below.
    let window = match raw.char_indices().nth(WINDOW) {
        None => raw,
        Some((end, _)) => {
            let head = &raw[..end];
            head.rfind(char::is_whitespace).map_or("", |i| &head[..i])
        }
    };
    let cut = window.len() < raw.len();

    // Addresses first: what is dropped with a path or a query needs no further masking, and the
    // placeholder a key becomes is not left half inside an address.
    let text = url_re().replace_all(window, |c: &Captures| url_origin(&c[0]));
    let text = secrets::redact_text(&text).0;
    let text = userinfo_re().replace_all(&text, |c: &Captures| format!("{MASK}@{}", &c[1]));
    let text = assignment_re().replace_all(&text, mask_value);
    let text = flag_re().replace_all(&text, mask_value);
    let text = curl_user_re().replace_all(&text, mask_value);
    let text = token_re().replace_all(&text, |c: &Captures| {
        if looks_random(&c[0]) {
            MASK.to_string()
        } else {
            c[0].to_string()
        }
    });

    let mut out: String = crate::engine::display_safe(&text)
        .chars()
        .take(max_chars)
        .collect();
    if cut || text.chars().count() > max_chars {
        out.push('…');
    }
    out
}

/// The backstop [`super::Detection::new`] runs over a finished explanation or evidence string:
/// only the steps that cannot change Bulwark's own wording (known keys, unsafe characters,
/// length). The detectors have already passed every quoted value through [`shown`]; this is for
/// the one that some day will not.
pub(crate) fn backstop(text: String, max_chars: usize) -> String {
    let (redacted, found) = secrets::redact_text(&text);
    let text = if found > 0 { redacted } else { text };
    let safe = crate::engine::display_safe(&text);
    if safe.chars().count() <= max_chars {
        return safe.into_owned();
    }
    let mut out: String = safe.chars().take(max_chars).collect();
    out.push('…');
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A deterministic random-looking token, generated so no key-shaped literal is in the source.
    pub(crate) fn token(seed: u64, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                ALPHABET[(x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as usize % ALPHABET.len()]
                    as char
            })
            .collect()
    }

    #[test]
    fn an_address_keeps_only_scheme_host_and_port() {
        let key = format!("ghp_{}", token(1, 36));
        for (raw, expected) in [
            (
                format!("https://mcp.example.invalid/mcp?token={key}"),
                "https://mcp.example.invalid".to_string(),
            ),
            (
                format!("https://user:{key}@mcp.example.invalid:8443/x"),
                "https://mcp.example.invalid:8443".to_string(),
            ),
            (
                "curl https://x.invalid/i.sh | sh".to_string(),
                "curl https://x.invalid | sh".to_string(),
            ),
            (
                "http://[::1]:4000/v1".to_string(),
                "http://[::1]:4000".to_string(),
            ),
            // An address inside brackets: the bracket is not part of it.
            (
                format!("Shell(curl -H X-Token={key} https://api.example.invalid)"),
                format!(
                    "Shell(curl -H X-Token={} https://api.example.invalid)",
                    secrets::REDACTION_PLACEHOLDER
                ),
            ),
            (
                "see [docs](https://docs.example.invalid/a/b), then".to_string(),
                "see [docs](https://docs.example.invalid), then".to_string(),
            ),
        ] {
            let out = shown(&raw);
            assert_eq!(out, expected);
            assert!(!out.contains(&key));
        }
    }

    #[test]
    fn a_named_credential_is_masked_and_a_reference_is_kept() {
        // Short enough that only its name gives it away: the secret pack has no rule for it.
        // (Put together here, and the commands below from parts, so that nothing in this file
        // reads as a credential to a scanner.)
        let secret = ["hunter2", "Pw0rd"].join("-");
        let secret = secret.as_str();
        let user_flag = "-u";
        for raw in [
            format!("curl -H 'Authorization: Bearer {secret}' api"),
            format!("curl -H \"X-Api-Key: {secret}\" api"),
            format!("Shell(curl -H X-Token={secret} api)"),
            format!("tool --token {secret} --verbose"),
            format!("tool --api-key={secret}"),
            format!("API_TOKEN={secret} ./run.sh"),
            format!("\"password\": \"{secret}\""),
            format!("\"Authorization\": \"Bearer {secret}\""),
            format!("curl {user_flag} bot:{secret} api"),
            format!("git clone bot:{secret}@git.example.invalid/x"),
            format!("psql --password {secret}"),
            format!("x?access_token={secret}&y=1"),
        ] {
            let out = shown(&raw);
            assert!(!out.contains(secret), "{raw} -> {out}");
            // Masked by name, or taken whole by a pack rule that knows the command's shape.
            assert!(
                out.contains(MASK) || out.contains(secrets::REDACTION_PLACEHOLDER),
                "{raw} -> {out}"
            );
        }
        // The scheme word and the rest of the command survive.
        assert_eq!(
            shown(&format!("curl -H 'Authorization: Bearer {secret}' api")),
            "curl -H 'Authorization: Bearer ***' api"
        );
        // A reference to a secret kept elsewhere is what the reader should see.
        for kept in [
            "\"Authorization\": \"Bearer ${GITHUB_TOKEN}\"",
            "API_TOKEN=$(pass show api) ./run.sh",
            "tool --token $TOKEN",
            "\"api_key\": \"{env:OPENAI_API_KEY}\"",
            "password: %DB_PASSWORD%",
        ] {
            assert_eq!(shown(kept), kept);
        }
    }

    #[test]
    fn a_key_the_pack_knows_and_one_it_does_not_are_both_masked() {
        let known = format!("sk-ant-api03-{}AA", token(2, 93));
        let unknown = token(3, 40);
        let out = shown(&format!("npx -y some-server {known} {unknown} --port 8080"));
        assert!(!out.contains(&known) && !out.contains(&unknown), "{out}");
        assert!(out.starts_with("npx -y some-server "), "{out}");
        assert!(out.ends_with(" --port 8080"), "{out}");
    }

    #[test]
    fn ordinary_evidence_is_left_as_it_is() {
        for plain in [
            "npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /",
            "docker run -v /var/run/docker.sock:/var/run/docker.sock img:1",
            "\"permissions\": {\"allow\": [\"Bash(*)\"], \"defaultMode\": \"bypassPermissions\"}",
            "Bash(curl:*)",
            "uvx --from mcp-server-postgres-enterprise-edition-v2 serve",
            "deno run -A npm:thing@1.2.3",
            "\"chat.tools.autoApprove\": true, // dangerous",
            "approval_policy=never + sandbox_mode=danger-full-access",
            "données 日本語",
        ] {
            assert_eq!(shown(plain), plain);
        }
    }

    #[test]
    fn unsafe_characters_are_replaced_and_long_text_is_cut_between_words() {
        assert_eq!(shown("a\u{202E}b\u{1b}[31mc"), "a\u{FFFD}b\u{FFFD}[31mc");
        let long = "word ".repeat(100);
        let out = shown(&long);
        assert_eq!(out.chars().count(), SHOWN_MAX + 1);
        assert!(out.ends_with('…'));
        // A key that straddles the part of a huge line that is looked at is never shown in part.
        let key = format!("ghp_{}", token(4, 36));
        let line = format!("{}{key}", "x ".repeat((WINDOW - 20) / 2));
        assert!(!shown(&line).contains("ghp_"));
        // One enormous word shows as nothing at all.
        assert_eq!(shown(&"a".repeat(WINDOW + 10)), "…");
    }

    #[test]
    fn the_backstop_masks_a_known_key_and_leaves_wording_alone() {
        let key = format!("ghp_{}", token(5, 36));
        let prose = "The token: none is set, and password = unset here.";
        assert_eq!(backstop(prose.to_string(), 700), prose);
        let out = backstop(format!("allows \"{key}\" without asking"), 700);
        assert!(!out.contains(&key));
        assert!(out.contains(secrets::REDACTION_PLACEHOLDER));
        assert_eq!(backstop("x".repeat(10), 5), "xxxxx…");
    }
}

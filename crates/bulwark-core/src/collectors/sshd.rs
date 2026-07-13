use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct SshdConfigCollector;

const MAIN_CONFIG: &str = "/etc/ssh/sshd_config";
const CONFIG_DIR: &str = "/etc/ssh";

/// The security-relevant sshd directives, as `(directive-lowercased, snake_case fact key,
/// compiled-in OpenSSH default)`. Defaults are from `man 5 sshd_config` (OpenSSH 9.x/10.x).
///
/// Seeding these before parsing is the fix for the collector's most damaging bug. A stock
/// `sshd_config` — on Ubuntu, Debian, and upstream — comments out nearly every directive and
/// relies on the compiled-in defaults. The old parser emitted only directives that were literally
/// present, so on a default install the fact map was almost empty, every SSH rule referenced a key
/// that wasn't there, and the condition evaluator raised `MissingField` — which the engine treats
/// as an error, not a finding. The result: **none** of the SSH rules evaluated on a default host,
/// including `BLWK-SSH-001`, even though `PasswordAuthentication`'s default is `yes` and the host
/// therefore *does* accept password logins. Absence of the directive is evidence the default is in
/// effect, not evidence of nothing — so we make the default explicit and let an actual directive
/// override it.
const SSHD_DEFAULTS: &[(&str, &str, &str)] = &[
    // Default `yes` — this is the one that MUST fire BLWK-SSH-001 on a stock install.
    ("passwordauthentication", "password_authentication", "yes"),
    ("permitrootlogin", "permit_root_login", "prohibit-password"),
    ("permitemptypasswords", "permit_empty_passwords", "no"),
    ("x11forwarding", "x11_forwarding", "no"),
    // Default `yes` — forwarding is on unless disabled. A true (if minor) finding on most hosts.
    ("allowtcpforwarding", "allow_tcp_forwarding", "yes"),
    ("permituserenvironment", "permit_user_environment", "no"),
    ("permittunnel", "permit_tunnel", "no"),
    ("strictmodes", "strict_modes", "yes"),
    ("gatewayports", "gateway_ports", "no"),
    ("allowagentforwarding", "allow_agent_forwarding", "yes"),
    ("maxauthtries", "max_auth_tries", "6"),
];

/// Coerces a directive value the way rules expect: a purely-numeric value becomes a JSON number
/// (so `max_auth_tries > 6` works), everything else a lowercased string (so `== "yes"` works).
fn coerce_value(value: &str) -> Value {
    value
        .parse::<i64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(value.to_ascii_lowercase()))
}

/// sshd_config directives are CamelCase; rule conditions read snake_case. Used only as a fallback
/// for directives outside [`SSHD_DEFAULTS`] — the known ones are mapped by exact table lookup so
/// that an all-caps or all-lowercase spelling (both valid: OpenSSH keywords are case-insensitive)
/// still resolves to the right key, which a mechanical de-camel-case would mangle.
fn to_snake_case(directive: &str) -> String {
    let mut out = String::with_capacity(directive.len() + 4);
    for (i, c) in directive.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Splits one config line into `(keyword, value)`. OpenSSH accepts either whitespace or "optionally
/// whitespace and exactly one `=`" as the separator (`Key Value`, `Key=Value`, `Key = Value`), so
/// all three are handled — the old whitespace-only split silently dropped `Key=Value` lines.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let sep = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..sep];
    let rest = line[sep..].trim_start();
    let rest = rest.strip_prefix('=').map(str::trim_start).unwrap_or(rest);
    let value = rest.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Flattens a config into an ordered list of global-scope directive lines, expanding `Include`
/// directives inline (via `resolve`, which maps an include glob to the text of each matching file
/// in sorted order) and stopping at the first `Match` block.
///
/// Both behaviors are load-bearing for correctness on real hosts:
///   * Ubuntu/Debian ship `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of the file, and cloud
///     images drop overrides there. Not following the include means reading a config that a drop-in
///     may have completely overridden — the scanner could report the exact opposite of the truth.
///   * A `Match` block's directives apply conditionally (to one user/group/address), not globally.
///     Parsing them as global settings produced both false positives (a `Match User ci` relaxation
///     read as host-wide) and false negatives (a per-group tightening masking a lax global default).
///     Everything before the first `Match` is the global scope.
fn flatten_global_lines(text: &str, resolve: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first = line
            .split(|c: char| c.is_whitespace() || c == '=')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if first == "match" {
            break; // end of the global scope
        }
        if first == "include" {
            if let Some((_, glob)) = split_directive(line) {
                for included in resolve(glob) {
                    out.extend(flatten_global_lines(&included, resolve));
                }
            }
            continue;
        }
        out.push(line.to_string());
    }
    out
}

/// Parses sshd_config text into a flat fact map, following `Include`s through `resolve` and
/// applying OpenSSH's real semantics: defaults for absent directives, first-obtained value wins,
/// global scope only. Split from disk access so it is unit-testable with fixture text and a fake
/// include resolver.
pub fn parse_sshd_config_with(text: &str, resolve: &dyn Fn(&str) -> Vec<String>) -> Fact {
    // Start from the compiled-in defaults; explicit directives override, absent ones stand.
    let mut fact = Fact::new();
    for (_, snake, default) in SSHD_DEFAULTS {
        fact.insert(snake.to_string(), coerce_value(default));
    }

    // OpenSSH uses the FIRST obtained value for most keywords, so once a key is set explicitly, a
    // later line for the same key is ignored. (The old comment claimed "later directives win",
    // which was the opposite of both OpenSSH and the code's own `or_insert` behavior.)
    let mut explicitly_set: HashSet<String> = HashSet::new();
    for line in flatten_global_lines(text, resolve) {
        let Some((keyword, value)) = split_directive(&line) else {
            continue;
        };
        let kw_lower = keyword.to_ascii_lowercase();
        let key = SSHD_DEFAULTS
            .iter()
            .find(|(directive, _, _)| *directive == kw_lower)
            .map(|(_, snake, _)| (*snake).to_string())
            .unwrap_or_else(|| to_snake_case(keyword));
        if explicitly_set.contains(&key) {
            continue; // first-wins
        }
        explicitly_set.insert(key.clone());
        fact.insert(key, coerce_value(value));
    }
    fact
}

/// Convenience wrapper with no include resolution — for callers that only have the literal text of
/// a single file (currently the unit tests).
#[cfg(test)]
pub fn parse_sshd_config(text: &str) -> Fact {
    parse_sshd_config_with(text, &|_| Vec::new())
}

/// Reads the files matched by an sshd `Include` glob, in the sorted order OpenSSH applies (earlier
/// names take precedence, consistent with first-wins). Relative patterns resolve against
/// `/etc/ssh`. Supports the `<dir>/<prefix>*<suffix>` shape that real configs use
/// (`sshd_config.d/*.conf`); a pattern with no `*` is treated as an exact filename.
fn resolve_include_glob(pattern: &str) -> Vec<String> {
    let full = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{CONFIG_DIR}/{pattern}")
    };
    let Some((dir, file_pat)) = full.rsplit_once('/') else {
        return Vec::new();
    };
    let (prefix, suffix) = match file_pat.split_once('*') {
        Some((p, s)) => (p, s),
        None => (file_pat, ""),
    };
    let has_wildcard = file_pat.contains('*');
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if has_wildcard {
                name.starts_with(prefix) && name.ends_with(suffix)
            } else {
                name == file_pat
            }
        })
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect()
}

impl Collector for SshdConfigCollector {
    fn name(&self) -> &'static str {
        "sshd_config"
    }

    fn is_applicable(&self) -> bool {
        Path::new(MAIN_CONFIG).exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let text = std::fs::read_to_string(MAIN_CONFIG)?;
        Ok(vec![parse_sshd_config_with(&text, &resolve_include_glob)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stock_config_relying_on_defaults_still_flags_password_auth() {
        // The regression that shipped: a config that sets nothing (every directive commented out)
        // used to yield an empty fact map, so BLWK-SSH-001 hit MissingField and never fired — even
        // though OpenSSH's PasswordAuthentication default is `yes` and the host DOES accept
        // passwords. The default must now be explicit.
        let fact =
            parse_sshd_config("# everything here is commented out\n#PasswordAuthentication no\n");
        assert_eq!(
            fact.get("password_authentication").unwrap(),
            "yes",
            "absent directive must resolve to the insecure OpenSSH default, not nothing"
        );
        assert_eq!(fact.get("permit_root_login").unwrap(), "prohibit-password");
        assert_eq!(fact.get("max_auth_tries").unwrap(), &Value::from(6));
    }

    #[test]
    fn an_explicit_directive_overrides_the_seeded_default() {
        let fact = parse_sshd_config("PasswordAuthentication no\n");
        assert_eq!(fact.get("password_authentication").unwrap(), "no");
    }

    #[test]
    fn parses_common_directives() {
        let text =
            "PasswordAuthentication yes\nPermitRootLogin no\n# comment\nPermitEmptyPasswords no\n";
        let fact = parse_sshd_config(text);
        assert_eq!(fact.get("password_authentication").unwrap(), "yes");
        assert_eq!(fact.get("permit_root_login").unwrap(), "no");
        assert_eq!(fact.get("permit_empty_passwords").unwrap(), "no");
    }

    #[test]
    fn accepts_equals_separator_and_case_insensitive_keywords() {
        // All three are valid OpenSSH syntax the old whitespace-only, camel-case-only parser
        // mangled: `passwordauthentication=yes` was dropped entirely, `PERMITROOTLOGIN` became a
        // key full of underscores.
        let fact = parse_sshd_config(
            "passwordauthentication=yes\nPERMITROOTLOGIN yes\npermitemptypasswords = yes\n",
        );
        assert_eq!(fact.get("password_authentication").unwrap(), "yes");
        assert_eq!(fact.get("permit_root_login").unwrap(), "yes");
        assert_eq!(fact.get("permit_empty_passwords").unwrap(), "yes");
    }

    #[test]
    fn first_value_wins_like_openssh() {
        let fact = parse_sshd_config("PasswordAuthentication no\nPasswordAuthentication yes\n");
        assert_eq!(
            fact.get("password_authentication").unwrap(),
            "no",
            "OpenSSH takes the first value, not the last"
        );
    }

    #[test]
    fn match_block_directives_do_not_leak_into_the_global_scope() {
        // Directives inside a Match apply only to that match. A relaxation for one CI account must
        // not read as a host-wide setting.
        let fact = parse_sshd_config(
            "PasswordAuthentication no\nMatch User ci\n  PasswordAuthentication yes\n  PermitRootLogin yes\n",
        );
        assert_eq!(
            fact.get("password_authentication").unwrap(),
            "no",
            "the Match-scoped `yes` must not override the global `no`"
        );
        // PermitRootLogin only ever appeared inside the Match, so globally it's still the default.
        assert_eq!(fact.get("permit_root_login").unwrap(), "prohibit-password");
    }

    #[test]
    fn include_directives_are_followed_and_drop_ins_win() {
        // Ubuntu ships `Include .../sshd_config.d/*.conf` at the top; a drop-in there overrides the
        // main file (first-wins + include-at-top). Simulate the included file via a fake resolver.
        let main = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n";
        let resolve = |glob: &str| {
            assert!(glob.contains("sshd_config.d"));
            vec!["PasswordAuthentication yes\n".to_string()]
        };
        let fact = parse_sshd_config_with(main, &resolve);
        assert_eq!(
            fact.get("password_authentication").unwrap(),
            "yes",
            "the drop-in is included first, so its value wins over the main file"
        );
    }

    #[test]
    fn snake_case_conversion_matches_rule_field_names() {
        assert_eq!(
            to_snake_case("PasswordAuthentication"),
            "password_authentication"
        );
        assert_eq!(to_snake_case("PermitRootLogin"), "permit_root_login");
    }

    #[test]
    fn numeric_directives_are_stored_as_numbers_not_strings() {
        let text = "MaxAuthTries 999\nPort 22\nPermitRootLogin no\n";
        let fact = parse_sshd_config(text);
        assert_eq!(fact.get("max_auth_tries").unwrap(), &Value::from(999));
        assert_eq!(fact.get("port").unwrap(), &Value::from(22));
        assert_eq!(fact.get("permit_root_login").unwrap(), "no");
    }
}

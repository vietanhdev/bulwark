use super::Collector;
use crate::etc::{io_error, is_absent, read_config_file};
use crate::models::Fact;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct SshdConfigCollector;

/// sshd gives up with "Too many recursive configuration includes" past this depth
/// (`SERVCONF_MAX_DEPTH` in servconf.c).
const MAX_INCLUDE_DEPTH: usize = 16;

/// One security-relevant sshd directive.
struct Known {
    /// The keyword, lowercased (OpenSSH keywords are case-insensitive).
    directive: &'static str,
    /// The snake_case fact key the rules read.
    field: &'static str,
    /// The compiled-in OpenSSH default, from `man 5 sshd_config` (OpenSSH 9.x/10.x).
    default: &'static str,
    /// Whether the keyword may be set inside a `Match` block (`SSHCFG_ALL` in servconf.c's keyword
    /// table). `StrictModes` and `PermitUserEnvironment` are global only.
    in_match: bool,
}

/// The directives the SSH rules read.
///
/// Seeding the defaults before parsing is the fix for the collector's most damaging bug. A stock
/// `sshd_config` — on Ubuntu, Debian, and upstream — comments out nearly every directive and
/// relies on the compiled-in defaults. The old parser emitted only directives that were literally
/// present, so on a default install the fact map was almost empty, every SSH rule referenced a key
/// that wasn't there, and the condition evaluator raised `MissingField` — which the engine treats
/// as an error, not a finding. The result: **none** of the SSH rules evaluated on a default host,
/// including `BLWK-SSH-001`, even though `PasswordAuthentication`'s default is `yes` and the host
/// therefore *does* accept password logins. Absence of the directive is evidence the default is in
/// effect, not evidence of nothing — so we make the default explicit and let an actual directive
/// override it.
const SSHD_DEFAULTS: &[Known] = &[
    // Default `yes` — this is the one that MUST fire BLWK-SSH-001 on a stock install.
    known(
        "passwordauthentication",
        "password_authentication",
        "yes",
        true,
    ),
    known(
        "permitrootlogin",
        "permit_root_login",
        "prohibit-password",
        true,
    ),
    known("permitemptypasswords", "permit_empty_passwords", "no", true),
    known("x11forwarding", "x11_forwarding", "no", true),
    // Default `yes` — forwarding is on unless disabled. A true (if minor) finding on most hosts.
    known("allowtcpforwarding", "allow_tcp_forwarding", "yes", true),
    known(
        "permituserenvironment",
        "permit_user_environment",
        "no",
        false,
    ),
    known("permittunnel", "permit_tunnel", "no", true),
    known("strictmodes", "strict_modes", "yes", false),
    known("gatewayports", "gateway_ports", "no", true),
    known(
        "allowagentforwarding",
        "allow_agent_forwarding",
        "yes",
        true,
    ),
    known("maxauthtries", "max_auth_tries", "6", true),
];

const fn known(
    directive: &'static str,
    field: &'static str,
    default: &'static str,
    in_match: bool,
) -> Known {
    Known {
        directive,
        field,
        default,
        in_match,
    }
}

/// The other keywords sshd accepts inside a `Match` block — the `SSHCFG_ALL` entries of the
/// keyword table in OpenSSH 9.6's servconf.c that are not already in [`SSHD_DEFAULTS`]. Only the
/// handling of a `Match all` block depends on this list (see [`parse_sshd_config_with`]); a
/// keyword missing from it is treated as global.
const OTHER_MATCH_KEYWORDS: &[&str] = &[
    "acceptenv",
    "allowgroups",
    "allowstreamlocalforwarding",
    "allowusers",
    "authenticationmethods",
    "authorizedkeyscommand",
    "authorizedkeyscommanduser",
    "authorizedkeysfile",
    "authorizedprincipalscommand",
    "authorizedprincipalscommanduser",
    "authorizedprincipalsfile",
    "banner",
    "casignaturealgorithms",
    "challengeresponseauthentication",
    "channeltimeout",
    "chrootdirectory",
    "clientalivecountmax",
    "clientaliveinterval",
    "denygroups",
    "denyusers",
    "disableforwarding",
    "exposeauthinfo",
    "forcecommand",
    "gssapiauthentication",
    "hostbasedacceptedalgorithms",
    "hostbasedacceptedkeytypes",
    "hostbasedauthentication",
    "hostbasedusesnamefrompacketonly",
    "ignorerhosts",
    "ipqos",
    "kbdinteractiveauthentication",
    "kerberosauthentication",
    "loglevel",
    "logverbose",
    "maxsessions",
    "permitlisten",
    "permitopen",
    "permittty",
    "permituserrc",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "pubkeyauthentication",
    "pubkeyauthoptions",
    "rdomain",
    "rekeylimit",
    "requiredrsasize",
    "revokedkeys",
    "setenv",
    "streamlocalbindmask",
    "streamlocalbindunlink",
    "subsystem",
    "trustedusercakeys",
    "unusedconnectiontimeout",
    "x11displayoffset",
    "x11uselocalhost",
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

/// Splits one config line into `(keyword, rest of the line)`, the way sshd's `strdelim` does: the
/// keyword ends at whitespace or at "optionally whitespace and exactly one `=`" (`Key Value`,
/// `Key=Value`, `Key = Value`), and may itself be in double quotes. `None` for a blank line, a
/// comment, and a keyword with nothing after it (which sshd refuses).
pub(crate) fn split_keyword(line: &str) -> Option<(&str, &str)> {
    const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];
    // sshd drops leading blanks when it loads the file and trailing ones (plus a form feed) when it
    // reads the line, so a CRLF file parses like any other.
    let line = line
        .trim_start_matches(WHITESPACE)
        .trim_end_matches([' ', '\t', '\r', '\n', '\x0c']);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (keyword, rest) = if let Some(quoted) = line.strip_prefix('"') {
        let end = quoted.find('"')?;
        (
            &quoted[..end],
            quoted[end + 1..].trim_start_matches(WHITESPACE),
        )
    } else {
        let sep = line.find(|c: char| WHITESPACE.contains(&c) || c == '=' || c == '"')?;
        let keyword = &line[..sep];
        let rest = &line[sep..];
        let rest = match rest.strip_prefix('=') {
            Some(after) => after.trim_start_matches(WHITESPACE),
            None => {
                let rest = rest.trim_start_matches(WHITESPACE);
                rest.strip_prefix('=')
                    .map(|after| after.trim_start_matches(WHITESPACE))
                    .unwrap_or(rest)
            }
        };
        (keyword, rest)
    };
    if keyword.is_empty() || rest.is_empty() {
        return None;
    }
    Some((keyword, rest))
}

/// Splits what follows a keyword into its arguments, the way sshd's `argv_split` does: blanks
/// separate arguments, single or double quotes group one (and are removed), a backslash escapes a
/// quote, a backslash or — outside quotes — a space, and `#` starts a comment. `None` when a quote
/// is left open, which sshd refuses.
///
/// One deliberate difference: sshd 8.7 and later start a comment only where an argument would
/// start, so `yes#x` is one (invalid) argument and the server does not start; before 8.7 the
/// loader cut every line at its first `#`, so the same text meant `yes`. Ending the argument at an
/// unquoted `#` gives the value the only sshd that accepts such a line would use.
pub(crate) fn split_args(rest: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = rest.chars().collect();
    let mut args = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' || chars[i] == '\t' {
            i += 1;
            continue;
        }
        if chars[i] == '#' {
            break;
        }
        let mut quote: Option<char> = None;
        let mut arg = String::new();
        let mut comment = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                match chars.get(i + 1) {
                    Some(&next)
                        if next == '\''
                            || next == '"'
                            || next == '\\'
                            || (quote.is_none() && next == ' ') =>
                    {
                        arg.push(next);
                        i += 1;
                    }
                    _ => arg.push(c),
                }
            } else if quote.is_none() && (c == ' ' || c == '\t') {
                break;
            } else if quote.is_none() && c == '#' {
                comment = true;
                break;
            } else if quote.is_none() && (c == '"' || c == '\'') {
                quote = Some(c);
            } else if quote == Some(c) {
                quote = None;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if quote.is_some() {
            return None;
        }
        args.push(arg);
        if comment {
            break;
        }
    }
    Some(args)
}

/// Which lines of the configuration are in force for every connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Before any `Match` line.
    Global,
    /// After `Match all`, which every connection matches.
    MatchAll,
    /// After a `Match` with a condition (a user, a group, an address, …). Its lines apply to some
    /// connections only, so they say nothing about the host as a whole.
    Conditional,
}

/// One configuration file: where it is, and what it says.
pub(crate) struct ConfigFile {
    pub path: String,
    pub text: String,
}

/// Maps one `Include` pattern (as written in the file, quotes already removed) to each file it
/// matches, in the order sshd reads them. An error means a matched file could not be read, which
/// leaves the whole configuration undetermined.
pub(crate) type IncludeResolver<'a> = dyn Fn(&str) -> anyhow::Result<Vec<ConfigFile>> + 'a;

/// What the `<field>_from` fact says for a setting no file makes.
pub(crate) const BUILT_IN_DEFAULT: &str = "OpenSSH's built-in default (no file sets it)";

/// The suffix of the fact naming the file a setting came from: `password_authentication_from`.
/// A finding names that file, so a user changes the setting where it is made — and on a system
/// that keeps the vendor's settings in `/usr/etc` learns not to edit a file the next package
/// update replaces.
pub(crate) const FROM_SUFFIX: &str = "_from";

/// The first value seen for each key and the file it came from, kept apart for the global scope
/// and for `Match all` blocks.
#[derive(Default)]
struct Seen {
    global: BTreeMap<String, (Value, String)>,
    match_all: BTreeMap<String, (Value, String)>,
}

impl Seen {
    fn record(&mut self, keyword: &str, args: &[String], scope: Scope, origin: &str) {
        let lower = keyword.to_ascii_lowercase();
        let (key, in_match, value) = match SSHD_DEFAULTS.iter().find(|k| k.directive == lower) {
            // Every directive the rules read takes one argument.
            Some(k) => (k.field.to_string(), k.in_match, args[0].clone()),
            None => (
                to_snake_case(keyword),
                OTHER_MATCH_KEYWORDS.contains(&lower.as_str()),
                args.join(" "),
            ),
        };
        let seen = if scope == Scope::MatchAll && in_match {
            &mut self.match_all
        } else {
            &mut self.global
        };
        // sshd keeps the first value it obtains for a keyword; a later line is ignored.
        seen.entry(key)
            .or_insert_with(|| (coerce_value(&value), origin.to_string()));
    }
}

/// Walks one file's text, following `Include`s. The checks below are each taken from servconf.c
/// (`process_server_config_line_depth`), not inferred from configs seen in the wild.
fn walk(
    file: &ConfigFile,
    mut scope: Scope,
    depth: usize,
    resolve: &IncludeResolver,
    seen: &mut Seen,
) -> anyhow::Result<()> {
    if depth > MAX_INCLUDE_DEPTH {
        anyhow::bail!(
            "sshd_config includes are nested more than {MAX_INCLUDE_DEPTH} deep (a file that \
             includes itself?) — sshd refuses such a configuration"
        );
    }
    for line in file.text.split('\n') {
        let Some((keyword, rest)) = split_keyword(line) else {
            continue;
        };
        let Some(args) = split_args(rest) else {
            continue; // an open quote: sshd rejects the line
        };
        if keyword.eq_ignore_ascii_case("match") {
            // `Match all` is the one condition true for every connection. Any other criterion
            // needs a user, host or address, so its block is conditional.
            scope = if args.len() == 1 && args[0].eq_ignore_ascii_case("all") {
                Scope::MatchAll
            } else {
                Scope::Conditional
            };
            continue;
        }
        if scope == Scope::Conditional {
            // Includes too: sshd reads a file included from a conditional block only to check its
            // syntax, and nothing in it can take effect.
            continue;
        }
        if keyword.eq_ignore_ascii_case("include") {
            // Several patterns may follow one Include. A `Match` inside an included file ends with
            // that file: sshd restores the including file's state afterwards.
            for pattern in &args {
                for included in resolve(pattern)? {
                    walk(&included, scope, depth + 1, resolve, seen)?;
                }
            }
            continue;
        }
        if args.is_empty() {
            continue; // only a comment after the keyword: sshd rejects the line
        }
        seen.record(keyword, &args, scope, &file.path);
    }
    Ok(())
}

/// Parses sshd_config text into a flat fact map of the values in force for every connection,
/// following `Include`s through `resolve`. `origin` is the file the text came from. Split from disk
/// access so it is unit-testable with fixture text and a fake include resolver.
///
/// Each directive the rules read also gets a `<field>_from` fact: the file whose line set the value
/// in force, or [`BUILT_IN_DEFAULT`].
///
/// The semantics are OpenSSH's own:
///   * **Defaults** stand for directives that are absent.
///   * **The first value wins.** Once a keyword is set, a later line for it is ignored.
///   * **`Include` is expanded where it appears.** Ubuntu/Debian ship
///     `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of the file, and cloud images drop
///     overrides there. Not following the include means reading a config that a drop-in may have
///     completely overridden — the scanner could report the exact opposite of the truth.
///   * **A conditional `Match` block is not global.** Its directives apply to one user, group or
///     address. Reading them as host-wide produced both false positives (a `Match User ci`
///     relaxation) and false negatives (a per-group tightening masking a lax global default).
///   * **`Match all` is global, and it overrides.** For each connection sshd parses the file a
///     second time, collecting only what matching `Match` blocks set, and copies those values over
///     the global ones (`parse_server_match_config`, `copy_set_server_options`). Every connection
///     matches `Match all`, so a value set there replaces the global value even when the global
///     line comes first — `PasswordAuthentication no` followed by `Match all` and
///     `PasswordAuthentication yes` accepts passwords. The few keywords that are not allowed in a
///     `Match` block are not copied; inside `Match all` they behave like any other global line.
pub(crate) fn parse_sshd_config_with(
    text: &str,
    origin: &str,
    resolve: &IncludeResolver,
) -> anyhow::Result<Fact> {
    let mut seen = Seen::default();
    let main = ConfigFile {
        path: origin.to_string(),
        text: text.to_string(),
    };
    walk(&main, Scope::Global, 0, resolve, &mut seen)?;

    // Start from the compiled-in defaults; explicit directives override, absent ones stand.
    let mut values: BTreeMap<String, (Value, String)> = SSHD_DEFAULTS
        .iter()
        .map(|k| {
            (
                k.field.to_string(),
                (coerce_value(k.default), BUILT_IN_DEFAULT.to_string()),
            )
        })
        .collect();
    values.extend(seen.global);
    values.extend(seen.match_all);
    let mut fact = Fact::new();
    for (key, (value, from)) in values {
        if SSHD_DEFAULTS.iter().any(|k| k.field == key) {
            fact.insert(format!("{key}{FROM_SUFFIX}"), Value::String(from));
        }
        fact.insert(key, value);
    }
    Ok(fact)
}

/// Convenience wrapper with no include resolution — for callers that only have the literal text of
/// a single file (currently the unit tests).
#[cfg(test)]
pub fn parse_sshd_config(text: &str) -> Fact {
    parse_sshd_config_with(text, "sshd_config", &|_| Ok(Vec::new()))
        .expect("no includes to fail on")
}

/// One part of a file-name pattern.
enum Atom {
    /// `*`
    Star,
    /// `?`
    Any,
    Literal(u8),
    /// `[...]`: the ranges it lists, and whether it is negated (`[!...]`).
    Set(Vec<(u8, u8)>, bool),
}

impl Atom {
    fn matches(&self, byte: u8) -> bool {
        match self {
            Atom::Star | Atom::Any => true,
            Atom::Literal(b) => *b == byte,
            Atom::Set(ranges, negated) => {
                ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&byte)) != *negated
            }
        }
    }
}

/// The byte ranges of a POSIX character class in the C locale, which is what sshd runs in.
fn class_ranges(name: &[u8]) -> Option<Vec<(u8, u8)>> {
    Some(match name {
        b"alpha" => vec![(b'a', b'z'), (b'A', b'Z')],
        b"digit" => vec![(b'0', b'9')],
        b"alnum" => vec![(b'a', b'z'), (b'A', b'Z'), (b'0', b'9')],
        b"upper" => vec![(b'A', b'Z')],
        b"lower" => vec![(b'a', b'z')],
        b"xdigit" => vec![(b'0', b'9'), (b'a', b'f'), (b'A', b'F')],
        b"space" => vec![(b' ', b' '), (b'\t', b'\r')],
        b"blank" => vec![(b' ', b' '), (b'\t', b'\t')],
        b"punct" => vec![(b'!', b'/'), (b':', b'@'), (b'[', b'`'), (b'{', b'~')],
        b"print" => vec![(b' ', b'~')],
        b"graph" => vec![(b'!', b'~')],
        b"cntrl" => vec![(0, 31), (127, 127)],
        _ => return None,
    })
}

/// Parses a bracket expression starting just after its `[`. Returns the atom and how many bytes
/// it used, or `None` when there is no closing `]` (the `[` is then an ordinary character).
fn parse_bracket(p: &[u8]) -> Option<(Atom, usize)> {
    let mut i = 0;
    let negated = matches!(p.first(), Some(b'!' | b'^'));
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let c = *p.get(i)?;
        if c == b']' && !first {
            return Some((Atom::Set(ranges, negated), i + 1));
        }
        first = false;
        if c == b'[' && p.get(i + 1) == Some(&b':') {
            if let Some(len) = p[i + 2..].windows(2).position(|w| w == b":]") {
                if let Some(class) = class_ranges(&p[i + 2..i + 2 + len]) {
                    ranges.extend(class);
                    i += len + 4;
                    continue;
                }
            }
        }
        let (lo, used) = if c == b'\\' {
            (*p.get(i + 1)?, 2)
        } else {
            (c, 1)
        };
        i += used;
        // `a-z`, unless the `-` is the last character before the `]`.
        if p.get(i) == Some(&b'-') && p.get(i + 1).is_some_and(|next| *next != b']') {
            let (hi, used) = if p[i + 1] == b'\\' {
                (*p.get(i + 2)?, 3)
            } else {
                (p[i + 1], 2)
            };
            i += used;
            ranges.push((lo, hi));
        } else {
            ranges.push((lo, lo));
        }
    }
}

/// Parses one path component of a glob(7) pattern: `*`, `?`, `[...]`, and `\` to take the next
/// character literally.
fn parse_component(pattern: &[u8]) -> Vec<Atom> {
    let mut atoms = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'*' => atoms.push(Atom::Star),
            b'?' => atoms.push(Atom::Any),
            b'[' => match parse_bracket(&pattern[i + 1..]) {
                Some((set, used)) => {
                    atoms.push(set);
                    i += used;
                }
                None => atoms.push(Atom::Literal(b'[')),
            },
            b'\\' if i + 1 < pattern.len() => {
                i += 1;
                atoms.push(Atom::Literal(pattern[i]));
            }
            other => atoms.push(Atom::Literal(other)),
        }
        i += 1;
    }
    atoms
}

/// Whether `name` matches the whole pattern. Linear in both lengths: on a mismatch it goes back to
/// the last `*` only, so a pattern full of stars cannot stall the scan.
fn atoms_match(atoms: &[Atom], name: &[u8]) -> bool {
    let (mut a, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if matches!(atoms.get(a), Some(Atom::Star)) {
            star = Some((a, n));
            a += 1;
        } else if atoms.get(a).is_some_and(|atom| atom.matches(name[n])) {
            a += 1;
            n += 1;
        } else if let Some((star_a, star_n)) = star {
            a = star_a + 1;
            n = star_n + 1;
            star = Some((star_a, star_n + 1));
        } else {
            return false;
        }
    }
    atoms[a..].iter().all(|atom| matches!(atom, Atom::Star))
}

/// The paths an absolute pattern matches, as sshd's `glob(pattern, 0, …)` call returns them:
/// wildcards may appear in any component, a name starting with `.` is matched only by a pattern
/// that spells the dot out, and the result is in byte order (sshd_config(5): "processed in lexical
/// order"). A folder that cannot be listed is an error, not "no match": the drop-in that changes
/// the answer may be inside it.
fn glob_paths(pattern: &str) -> anyhow::Result<Vec<PathBuf>> {
    let components: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let mut found = vec![PathBuf::from("/")];
    for (i, component) in components.iter().enumerate() {
        let last = i + 1 == components.len();
        let atoms = parse_component(component.as_bytes());
        let mut next = Vec::new();
        if atoms.iter().all(|atom| matches!(atom, Atom::Literal(_))) {
            let name: Vec<u8> = atoms
                .iter()
                .map(|atom| match atom {
                    Atom::Literal(b) => *b,
                    _ => unreachable!("checked just above"),
                })
                .collect();
            let name = String::from_utf8_lossy(&name).into_owned();
            next.extend(found.iter().map(|dir| dir.join(&name)));
        } else {
            let dot_spelled_out = matches!(atoms.first(), Some(Atom::Literal(b'.')));
            for dir in &found {
                let entries = match std::fs::read_dir(dir) {
                    Ok(entries) => entries,
                    Err(e) if is_absent(&e) => continue,
                    Err(e) => return Err(io_error("list", dir, e)),
                };
                for entry in entries {
                    let name = entry.map_err(|e| io_error("list", dir, e))?.file_name();
                    let bytes = name.as_encoded_bytes();
                    if bytes.first() == Some(&b'.') && !dot_spelled_out {
                        continue;
                    }
                    if !atoms_match(&atoms, bytes) {
                        continue;
                    }
                    let path = dir.join(&name);
                    if last || path.is_dir() {
                        next.push(path);
                    }
                }
            }
        }
        found = next;
    }
    // A name spelled out in full counts only if something is there (a broken link included, as for
    // glob itself: sshd then fails to open it, and so do we).
    let mut matched = Vec::new();
    for path in found {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => matched.push(path),
            Err(e) if is_absent(&e) => {}
            Err(e) => return Err(io_error("read", &path, e)),
        }
    }
    matched.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    Ok(matched)
}

/// Reads the files one `Include` pattern matches, in the order sshd applies them. A pattern that
/// does not start with `/` is relative to `config_dir` (`/etc/ssh`), whichever file it appears in
/// — the vendor's `/usr/etc/ssh/sshd_config` included (measured with `sshd -T`).
/// No match is not an error (sshd carries on too); a matched file that cannot be read is, because
/// the values it sets are then unknown — skipping it would report whatever the readable files say
/// as if it were the whole configuration.
fn read_includes(config_dir: &Path, pattern: &str) -> anyhow::Result<Vec<ConfigFile>> {
    if pattern.starts_with('~') {
        // sshd passes this to glob as it is, without expanding `~`, so what it matches depends on
        // the folder sshd was started from.
        anyhow::bail!(
            "sshd_config has an Include starting with '~', which sshd does not expand — cannot \
             tell which files it reads"
        );
    }
    let full = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{}/{pattern}", config_dir.display())
    };
    glob_paths(&full)?
        .iter()
        .map(|path| {
            Ok(ConfigFile {
                path: path.display().to_string(),
                text: read_config_file(path)?,
            })
        })
        .collect()
}

/// The include resolver for the real system: patterns are relative to `/etc/ssh`.
pub(crate) fn resolve_include_glob(pattern: &str) -> anyhow::Result<Vec<ConfigFile>> {
    read_includes(Path::new(crate::etc::SSHD_CONFIG_DIR), pattern)
}

/// The effective configuration of the sshd whose main file is `main` and whose relative includes
/// resolve against `config_dir`, with `config_file` naming the main file.
fn read_effective_config(main: &Path, config_dir: &Path) -> anyhow::Result<Fact> {
    let text = read_config_file(main)?;
    let origin = main.display().to_string();
    let mut fact = parse_sshd_config_with(&text, &origin, &|pattern| {
        read_includes(config_dir, pattern)
    })?;
    fact.insert("config_file".to_string(), Value::String(origin));
    Ok(fact)
}

impl Collector for SshdConfigCollector {
    fn name(&self) -> &'static str {
        "sshd_config"
    }

    /// `/etc/ssh/sshd_config`, or on a system that keeps the vendor's file in `/usr/etc` and has no
    /// `/etc` copy, that one (see [`crate::etc`]).
    fn is_applicable(&self) -> bool {
        crate::etc::SSHD_CONFIG.in_use().is_some()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let main = crate::etc::SSHD_CONFIG
            .in_use()
            .ok_or_else(|| anyhow::anyhow!("no sshd_config: it was removed during the scan"))?;
        Ok(vec![read_effective_config(
            &main,
            Path::new(crate::etc::SSHD_CONFIG_DIR),
        )?])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Included files with made-up names, for a fake include resolver.
    pub(crate) fn included(texts: &[&str]) -> Vec<ConfigFile> {
        texts
            .iter()
            .enumerate()
            .map(|(i, text)| ConfigFile {
                path: format!("/etc/ssh/sshd_config.d/{i}.conf"),
                text: text.to_string(),
            })
            .collect()
    }

    fn get<'a>(fact: &'a Fact, key: &str) -> &'a Value {
        fact.get(key)
            .unwrap_or_else(|| panic!("no '{key}' in the fact"))
    }

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
    fn a_trailing_comment_is_not_part_of_the_value() {
        // sshd reads all three as `yes`. The value used to be "yes # bad", which no rule matched:
        // empty passwords allowed, and a clean report.
        let fact = parse_sshd_config(
            "PasswordAuthentication yes # we allow it\nPermitEmptyPasswords yes # bad\n\
             PermitRootLogin yes #x\nMaxAuthTries 10 # generous\nX11Forwarding yes\t# tab\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "yes");
        assert_eq!(get(&fact, "permit_empty_passwords"), "yes");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
        assert_eq!(get(&fact, "max_auth_tries"), &Value::from(10));
        assert_eq!(get(&fact, "x11_forwarding"), "yes");
    }

    #[test]
    fn a_comment_does_not_turn_a_safe_value_into_a_finding() {
        // The benign side of the same fix: the word "yes" inside a comment is not a value.
        let fact = parse_sshd_config(
            "PasswordAuthentication no # was yes until the audit\n\
             PermitEmptyPasswords no # never yes\n# PermitRootLogin yes\n\
             PermitRootLogin prohibit-password # not yes\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "no");
        assert_eq!(get(&fact, "permit_empty_passwords"), "no");
        assert_eq!(get(&fact, "permit_root_login"), "prohibit-password");
    }

    #[test]
    fn quotes_around_a_value_are_removed() {
        let fact = parse_sshd_config(
            "PasswordAuthentication \"yes\"\nPermitEmptyPasswords 'yes'\n\
             \"PermitRootLogin\" \"yes\"\nGatewayPorts \"no\"\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "yes");
        assert_eq!(get(&fact, "permit_empty_passwords"), "yes");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
        assert_eq!(get(&fact, "gateway_ports"), "no");
    }

    #[test]
    fn argument_splitting_follows_sshd() {
        let args = |s: &str| split_args(s).unwrap();
        assert_eq!(args("yes"), ["yes"]);
        assert_eq!(
            args("a.conf  b.conf\t\"c d.conf\""),
            ["a.conf", "b.conf", "c d.conf"]
        );
        assert_eq!(args("\"with # hash\" # comment"), ["with # hash"]);
        assert_eq!(args("one\\ arg \\\"q\\\""), ["one arg", "\"q\""]);
        assert_eq!(args("# only a comment"), [] as [&str; 0]);
        assert!(split_args("\"open quote").is_none());
        // Before OpenSSH 8.7 a `#` anywhere ended the line; later versions refuse this spelling.
        assert_eq!(args("yes#x"), ["yes"]);
    }

    #[test]
    fn crlf_line_endings_and_extra_blanks_are_tolerated() {
        let fact = parse_sshd_config(
            "PasswordAuthentication no\r\nPermitRootLogin yes\r\n  X11Forwarding\t\tyes   \n\
             MaxAuthTries 010\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "no");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
        assert_eq!(get(&fact, "x11_forwarding"), "yes");
        // sshd reads integers in base ten: 010 is ten, not eight.
        assert_eq!(get(&fact, "max_auth_tries"), &Value::from(10));
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
    fn match_all_applies_to_every_connection_and_overrides_the_global_value() {
        // `sshd -T` prints yes/yes/yes for this file: what a matching Match block sets is copied
        // over the global values, and every connection matches `Match all`.
        let fact = parse_sshd_config(
            "PasswordAuthentication no\nPermitRootLogin no\nMatch all\n\
             PasswordAuthentication yes\nPermitRootLogin yes\nPermitEmptyPasswords yes\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "yes");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
        assert_eq!(get(&fact, "permit_empty_passwords"), "yes");

        // With nothing global before it, and spelled differently.
        let fact = parse_sshd_config("match ALL # everyone\nPasswordAuthentication no\n");
        assert_eq!(get(&fact, "password_authentication"), "no");
    }

    #[test]
    fn match_all_after_a_conditional_block_is_global_again() {
        let fact = parse_sshd_config(
            "Match User ci\nPasswordAuthentication yes\nX11Forwarding yes\n\
             Match all\nPasswordAuthentication no\nAllowTcpForwarding no\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "no");
        assert_eq!(get(&fact, "allow_tcp_forwarding"), "no");
        assert_eq!(
            get(&fact, "x11_forwarding"),
            "no",
            "the conditional block's value stays conditional"
        );
    }

    #[test]
    fn the_first_match_all_value_wins_among_match_all_blocks() {
        let fact = parse_sshd_config(
            "Match all\nPasswordAuthentication no\nMatch all\nPasswordAuthentication yes\n",
        );
        assert_eq!(get(&fact, "password_authentication"), "no");
    }

    #[test]
    fn a_global_only_keyword_in_match_all_does_not_override() {
        // StrictModes is not allowed in a Match block, so sshd never copies it over the global
        // value: inside `Match all` it is one more global line, and the first one wins.
        let fact = parse_sshd_config("StrictModes yes\nMatch all\nStrictModes no\n");
        assert_eq!(get(&fact, "strict_modes"), "yes");
        let fact = parse_sshd_config("Match all\nStrictModes no\n");
        assert_eq!(get(&fact, "strict_modes"), "no");
    }

    #[test]
    fn a_match_with_a_condition_is_never_read_as_match_all() {
        // Benign input for the Match-all rule: none of these is the unconditional form.
        for line in [
            "Match User all",
            "Match Group all",
            "Match Address 10.0.0.0/8",
            "Match all User bob",
            "Match User alice Address 192.0.2.0/24",
        ] {
            let fact = parse_sshd_config(&format!(
                "PasswordAuthentication no\n{line}\nPasswordAuthentication yes\n"
            ));
            assert_eq!(get(&fact, "password_authentication"), "no", "{line}");
        }
    }

    #[test]
    fn include_directives_are_followed_and_drop_ins_win() {
        // Ubuntu ships `Include .../sshd_config.d/*.conf` at the top; a drop-in there overrides the
        // main file (first-wins + include-at-top). Simulate the included file via a fake resolver.
        let main = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n";
        let resolve = |glob: &str| {
            assert!(glob.contains("sshd_config.d"));
            Ok(included(&["PasswordAuthentication yes\n"]))
        };
        let fact = parse_sshd_config_with(main, "sshd_config", &resolve).unwrap();
        assert_eq!(
            fact.get("password_authentication").unwrap(),
            "yes",
            "the drop-in is included first, so its value wins over the main file"
        );
    }

    #[test]
    fn every_pattern_on_an_include_line_is_read_in_order() {
        let main = "Include /etc/ssh/a.conf \"/etc/ssh/b c.conf\" # two files\n\
                    PermitRootLogin no\nPasswordAuthentication no\n";
        let asked = std::cell::RefCell::new(Vec::new());
        let resolve = |pattern: &str| {
            asked.borrow_mut().push(pattern.to_string());
            Ok(included(&[match pattern {
                "/etc/ssh/a.conf" => "X11Forwarding yes\n",
                _ => "PermitRootLogin yes\nX11Forwarding no\n",
            }]))
        };
        let fact = parse_sshd_config_with(main, "sshd_config", &resolve).unwrap();
        assert_eq!(
            *asked.borrow(),
            ["/etc/ssh/a.conf", "/etc/ssh/b c.conf"],
            "both patterns, unquoted, and not the comment"
        );
        assert_eq!(get(&fact, "x11_forwarding"), "yes", "a.conf comes first");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
        assert_eq!(get(&fact, "password_authentication"), "no");
    }

    #[test]
    fn a_match_inside_an_included_file_ends_with_that_file() {
        let main = "Include extra.conf\nPasswordAuthentication yes\nPermitRootLogin yes\n";
        let resolve = |_: &str| {
            Ok(included(&[
                "Match User bob\nPasswordAuthentication no\nPermitRootLogin no\n",
            ]))
        };
        let fact = parse_sshd_config_with(main, "sshd_config", &resolve).unwrap();
        assert_eq!(get(&fact, "password_authentication"), "yes");
        assert_eq!(get(&fact, "permit_root_login"), "yes");
    }

    #[test]
    fn an_include_under_a_conditional_match_is_not_followed() {
        // Nothing in it can apply globally, so a file there that this scan cannot read must not
        // make the whole result undetermined either.
        let main = "PasswordAuthentication no\nMatch User ci\nInclude ci.conf\n";
        let resolve = |_: &str| -> anyhow::Result<Vec<ConfigFile>> {
            panic!("an include inside a conditional block was read")
        };
        let fact = parse_sshd_config_with(main, "sshd_config", &resolve).unwrap();
        assert_eq!(get(&fact, "password_authentication"), "no");
    }

    #[test]
    fn an_include_under_match_all_is_part_of_that_block() {
        let main = "PasswordAuthentication no\nMatch all\nInclude late.conf\n";
        let resolve = |_: &str| Ok(included(&["PasswordAuthentication yes\n"]));
        let fact = parse_sshd_config_with(main, "sshd_config", &resolve).unwrap();
        assert_eq!(get(&fact, "password_authentication"), "yes");
    }

    #[test]
    fn an_include_that_cannot_be_read_fails_the_whole_parse() {
        let main = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n";
        let resolve = |_: &str| -> anyhow::Result<Vec<ConfigFile>> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
        };
        assert!(parse_sshd_config_with(main, "sshd_config", &resolve).is_err());
    }

    #[test]
    fn a_file_that_includes_itself_is_an_error_not_a_hang() {
        let resolve = |_: &str| Ok(included(&["Include loop.conf\n"]));
        let err =
            parse_sshd_config_with("Include loop.conf\n", "sshd_config", &resolve).unwrap_err();
        assert!(err.to_string().contains("nested"), "{err}");
    }

    /// A finding names the file whose line is in force, so a user changes it there — and on a
    /// system with the vendor's file in `/usr/etc` learns that the value comes from a file the next
    /// package update replaces.
    #[test]
    fn each_value_names_the_file_that_set_it() {
        let main = "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding yes\n\
                    PasswordAuthentication no\nMatch all\nGatewayPorts yes\n";
        let resolve = |_: &str| Ok(included(&["PasswordAuthentication yes\n"]));
        let fact = parse_sshd_config_with(main, "/usr/etc/ssh/sshd_config", &resolve).unwrap();
        assert_eq!(
            get(&fact, "password_authentication_from"),
            "/etc/ssh/sshd_config.d/0.conf"
        );
        assert_eq!(
            get(&fact, "x11_forwarding_from"),
            "/usr/etc/ssh/sshd_config"
        );
        assert_eq!(
            get(&fact, "gateway_ports_from"),
            "/usr/etc/ssh/sshd_config",
            "a Match all value names its file too"
        );
        assert_eq!(get(&fact, "permit_root_login_from"), BUILT_IN_DEFAULT);
        // Only the directives the rules read get one; other keywords stay as they were.
        assert!(!fact.contains_key("include_from"));
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

    #[test]
    fn file_name_patterns_match_like_glob() {
        let m = |pattern: &str, name: &str| {
            atoms_match(&parse_component(pattern.as_bytes()), name.as_bytes())
        };
        assert!(m("*.conf", "50-cloud-init.conf"));
        assert!(!m("*.conf", "50-cloud-init.conf.bak"));
        assert!(m("[0-9]?-*.conf", "50-cloud.conf"));
        assert!(!m("[0-9]?-*.conf", "a0-cloud.conf"));
        assert!(!m("[0-9]?-*.conf", "5-cloud.conf"));
        assert!(m("[!0-9]*", "cloud.conf"));
        assert!(!m("[!0-9]*", "5.conf"));
        assert!(m("[[:digit:]][[:digit:]]-*", "60-x"));
        assert!(m("[]a]x", "]x"));
        assert!(m("[a-]x", "-x"));
        assert!(m("a\\*b", "a*b"));
        assert!(!m("a\\*b", "aXb"));
        assert!(
            m("[x", "[x"),
            "an unclosed bracket is an ordinary character"
        );
        assert!(m("*a*b*c*", "xxaxxbxxcxx"));
        assert!(!m("*a*b*c*", "xxaxxcxxbxx"));
        assert!(m("50-*", "50-"));
    }

    #[cfg(unix)]
    mod on_disk {
        use super::*;
        use std::fs;

        /// A throw-away `/etc/ssh`: `sshd_config` plus whatever the test adds.
        fn etc_ssh(main: &str) -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join("sshd_config.d")).unwrap();
            fs::write(dir.path().join("sshd_config"), main).unwrap();
            dir
        }

        fn effective(dir: &tempfile::TempDir) -> anyhow::Result<Fact> {
            read_effective_config(&dir.path().join("sshd_config"), dir.path())
        }

        fn is_root() -> bool {
            // SAFETY: geteuid has no preconditions and cannot fail.
            unsafe { libc::geteuid() == 0 }
        }

        #[test]
        fn drop_ins_are_read_in_name_order_and_the_first_wins() {
            // The cloud-image layout from the bug report, with a relative Include.
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPasswordAuthentication no\n");
            let d = dir.path().join("sshd_config.d");
            fs::write(
                d.join("60-cloudimg-settings.conf"),
                "PasswordAuthentication no\n",
            )
            .unwrap();
            fs::write(d.join("50-cloud-init.conf"), "PasswordAuthentication yes\n").unwrap();
            fs::write(d.join("10-notes.txt"), "PasswordAuthentication no\n").unwrap();
            fs::write(d.join(".hidden.conf"), "PasswordAuthentication no\n").unwrap();
            assert_eq!(
                get(&effective(&dir).unwrap(), "password_authentication"),
                "yes"
            );
        }

        #[test]
        fn wildcards_work_in_brackets_and_in_folder_names() {
            for include in [
                "Include {}/sshd_config.d/[0-9]?-*.conf",
                "Include {}/*/50-*.conf",
                "Include \"{}/sshd_config.d/*.conf\"",
                "Include sshd_config.d/5[[:digit:]]-x.conf",
            ] {
                let dir = etc_ssh("");
                let include = include.replace("{}", &dir.path().display().to_string());
                fs::write(
                    dir.path().join("sshd_config"),
                    format!("{include}\nPasswordAuthentication no\n"),
                )
                .unwrap();
                fs::write(
                    dir.path().join("sshd_config.d/50-x.conf"),
                    "PasswordAuthentication yes\n",
                )
                .unwrap();
                assert_eq!(
                    get(&effective(&dir).unwrap(), "password_authentication"),
                    "yes",
                    "{include}"
                );
            }
        }

        #[test]
        fn a_pattern_that_matches_nothing_is_not_an_error() {
            // Benign: the stock Debian Include on a machine with no drop-ins, and a named file
            // that is not there. sshd starts with both.
            let dir = etc_ssh(
                "Include sshd_config.d/*.conf\nInclude missing.conf nowhere/*.conf\n\
                 PasswordAuthentication no\n",
            );
            assert_eq!(
                get(&effective(&dir).unwrap(), "password_authentication"),
                "no"
            );
        }

        #[test]
        fn a_sub_folder_matched_by_the_pattern_is_read_as_empty() {
            let dir = etc_ssh("Include sshd_config.d/*\nPasswordAuthentication no\n");
            fs::create_dir(dir.path().join("sshd_config.d/sub")).unwrap();
            fs::write(
                dir.path().join("sshd_config.d/sub/x"),
                "PasswordAuthentication yes\n",
            )
            .unwrap();
            assert_eq!(
                get(&effective(&dir).unwrap(), "password_authentication"),
                "no"
            );
        }

        #[test]
        fn nested_includes_are_followed() {
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPermitRootLogin no\n");
            fs::create_dir(dir.path().join("sshd_config.d/sub")).unwrap();
            fs::write(
                dir.path().join("sshd_config.d/10-nest.conf"),
                "Include sshd_config.d/sub/*\n",
            )
            .unwrap();
            fs::write(
                dir.path().join("sshd_config.d/sub/x"),
                "PermitRootLogin yes\n",
            )
            .unwrap();
            assert_eq!(get(&effective(&dir).unwrap(), "permit_root_login"), "yes");
        }

        #[test]
        fn bytes_that_are_not_utf8_do_not_hide_the_file() {
            // One Latin-1 "é" in a comment. The drop-in used to be skipped whole, and the main
            // file refused, with no error either way.
            let latin1 = b"# caf\xe9 comment\nPasswordAuthentication yes\nPermitRootLogin yes\n";
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPasswordAuthentication no\n");
            fs::write(dir.path().join("sshd_config.d/10-latin1.conf"), latin1).unwrap();
            let fact = effective(&dir).unwrap();
            assert_eq!(get(&fact, "password_authentication"), "yes");
            assert_eq!(get(&fact, "permit_root_login"), "yes");

            let dir = etc_ssh("");
            fs::write(dir.path().join("sshd_config"), latin1).unwrap();
            assert_eq!(
                get(&effective(&dir).unwrap(), "password_authentication"),
                "yes"
            );
        }

        #[test]
        fn a_matched_file_that_cannot_be_opened_is_an_error() {
            // A broken link: sshd exits on it. Skipping it would report the rest as the whole.
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPasswordAuthentication no\n");
            std::os::unix::fs::symlink(
                dir.path().join("gone.conf"),
                dir.path().join("sshd_config.d/50-link.conf"),
            )
            .unwrap();
            let err = effective(&dir).unwrap_err();
            assert!(err.to_string().contains("50-link.conf"), "{err}");
        }

        #[test]
        fn a_pipe_among_the_drop_ins_is_an_error_not_a_hang() {
            let dir = etc_ssh("Include sshd_config.d/*.conf\n");
            let fifo = dir.path().join("sshd_config.d/50-pipe.conf");
            let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the call.
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
            let err = effective(&dir).unwrap_err();
            assert!(err.to_string().contains("not a regular file"), "{err}");
        }

        /// Tumbleweed's layout: no `/etc/ssh/sshd_config`, the vendor file includes the admin's
        /// drop-ins first and the vendor's after them. `sshd -T` there: a drop-in in either folder
        /// takes effect, and the admin's wins over the vendor's.
        #[test]
        fn the_vendor_file_and_both_drop_in_folders_are_read_in_sshds_order() {
            let root = tempfile::tempdir().unwrap();
            let etc = root.path().join("etc/ssh");
            let usr = root.path().join("usr/etc/ssh");
            fs::create_dir_all(etc.join("sshd_config.d")).unwrap();
            fs::create_dir_all(usr.join("sshd_config.d")).unwrap();
            fs::write(
                usr.join("sshd_config"),
                format!(
                    "Include {e}/sshd_config.d/*.conf\nInclude {u}/sshd_config.d/*.conf\n\
                     X11Forwarding yes\n",
                    e = etc.display(),
                    u = usr.display()
                ),
            )
            .unwrap();
            fs::write(
                usr.join("sshd_config.d/50-b.conf"),
                "MaxAuthTries 2\nGatewayPorts yes\n",
            )
            .unwrap();
            fs::write(etc.join("sshd_config.d/50-b.conf"), "MaxAuthTries 4\n").unwrap();
            let fact = read_effective_config(&usr.join("sshd_config"), &etc).unwrap();
            assert_eq!(get(&fact, "max_auth_tries"), &Value::from(4));
            assert_eq!(
                get(&fact, "max_auth_tries_from"),
                &Value::from(etc.join("sshd_config.d/50-b.conf").display().to_string())
            );
            assert_eq!(get(&fact, "gateway_ports"), "yes");
            assert_eq!(get(&fact, "x11_forwarding"), "yes");
            assert_eq!(
                get(&fact, "config_file"),
                &Value::from(usr.join("sshd_config").display().to_string())
            );
        }

        /// A collector over a throw-away folder, to drive the real engine.
        struct TempSshd(PathBuf);
        impl Collector for TempSshd {
            fn name(&self) -> &'static str {
                "sshd_config"
            }
            fn collect(&self) -> anyhow::Result<Vec<Fact>> {
                Ok(vec![read_effective_config(
                    &self.0.join("sshd_config"),
                    &self.0,
                )?])
            }
        }

        fn scan(dir: &tempfile::TempDir, privileged: bool) -> crate::models::ScanRun {
            let rules =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ssh-remote-access");
            let collectors: Vec<Box<dyn Collector>> =
                vec![Box::new(TempSshd(dir.path().to_path_buf()))];
            let profile = crate::engine::Profile {
                os: Some(crate::models::OperatingSystem::Linux),
                needs: vec!["server".to_string()],
            };
            crate::engine::run_scan(rules.as_path(), &collectors, privileged, &profile)
        }

        fn ssh_rule(id: &str) -> bool {
            id.starts_with("BLWK-SSH-0") && id < "BLWK-SSH-012"
        }

        /// The reported bug, end to end: a root scan sees the weak drop-in; an ordinary user's
        /// scan cannot read it and used to list every SSH rule as evaluated and report none, which
        /// closed the root scan's findings in the database.
        #[test]
        fn a_drop_in_the_scan_may_not_read_leaves_the_ssh_rules_unevaluated() {
            if is_root() {
                return; // root reads a mode-000 file; the container CI jobs run as root
            }
            use std::os::unix::fs::PermissionsExt;
            let dir = etc_ssh("Include sshd_config.d/*.conf\n");
            let weak = dir.path().join("sshd_config.d/50-cloud-init.conf");
            fs::write(
                &weak,
                "PasswordAuthentication yes\nPermitRootLogin yes\nPermitEmptyPasswords yes\n",
            )
            .unwrap();
            fs::write(
                dir.path().join("sshd_config.d/60-cloudimg-settings.conf"),
                "PasswordAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\n",
            )
            .unwrap();

            // While it is readable (the root scan): the three findings.
            let seen = scan(&dir, false);
            for id in ["BLWK-SSH-001", "BLWK-SSH-002", "BLWK-SSH-003"] {
                assert!(seen.findings.iter().any(|f| f.rule_id == id), "{id}");
            }
            let mut store = crate::store::Store::open_in_memory().unwrap();
            store.persist_and_reconcile(&seen).unwrap();

            fs::set_permissions(&weak, fs::Permissions::from_mode(0o000)).unwrap();
            let blind = scan(&dir, false);
            fs::set_permissions(&weak, fs::Permissions::from_mode(0o600)).unwrap();

            assert!(
                !blind.rules_evaluated.iter().any(|id| ssh_rule(id)),
                "no SSH rule may count as evaluated: {:?}",
                blind.rules_evaluated
            );
            assert!(!blind.findings.iter().any(|f| ssh_rule(&f.rule_id)));
            assert_eq!(
                blind.privileged_collectors_skipped,
                ["sshd_config"],
                "reported as needing admin rights"
            );
            assert!(
                blind.collector_errors.is_empty(),
                "{:?}",
                blind.collector_errors
            );

            // And the earlier findings stay open.
            store.persist_and_reconcile(&blind).unwrap();
            let open = store.open_findings().unwrap();
            for id in ["BLWK-SSH-001", "BLWK-SSH-002", "BLWK-SSH-003"] {
                assert!(open.iter().any(|f| f.rule_id == id), "{id} was closed");
            }
        }

        #[test]
        fn a_drop_in_folder_the_scan_may_not_list_is_undetermined_too() {
            if is_root() {
                return;
            }
            use std::os::unix::fs::PermissionsExt;
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPasswordAuthentication no\n");
            let d = dir.path().join("sshd_config.d");
            fs::set_permissions(&d, fs::Permissions::from_mode(0o000)).unwrap();
            let blind = scan(&dir, false);
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(blind.privileged_collectors_skipped, ["sshd_config"]);
            assert!(!blind.rules_evaluated.iter().any(|id| ssh_rule(id)));
        }

        /// Any other failure to read a matched include is shown, and the rules still do not count
        /// as evaluated. Under a privileged scan a permission error is shown too.
        #[test]
        fn a_broken_include_is_a_visible_collector_error() {
            let dir = etc_ssh("Include sshd_config.d/*.conf\nPasswordAuthentication no\n");
            std::os::unix::fs::symlink(
                dir.path().join("gone.conf"),
                dir.path().join("sshd_config.d/50-link.conf"),
            )
            .unwrap();
            for privileged in [false, true] {
                let run = scan(&dir, privileged);
                assert_eq!(run.collector_errors.len(), 1, "{:?}", run.collector_errors);
                assert_eq!(run.collector_errors[0].collector, "sshd_config");
                assert!(run.collector_errors[0].message.contains("50-link.conf"));
                assert!(!run.rules_evaluated.iter().any(|id| ssh_rule(id)));
                assert!(run.privileged_collectors_skipped.is_empty());
            }
        }

        /// The benign side: an ordinary scan of a config whose drop-ins are all readable is
        /// evaluated in full, and a hardened one produces no SSH finding.
        #[test]
        fn readable_drop_ins_are_evaluated_and_a_hardened_config_is_quiet() {
            let dir = etc_ssh(
                "Include sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin no\n\
                 AllowTcpForwarding no\nAllowAgentForwarding no\nMaxAuthTries 3 # low\n",
            );
            fs::write(
                dir.path().join("sshd_config.d/50-site.conf"),
                "X11Forwarding no # not needed\nGatewayPorts \"no\"\n",
            )
            .unwrap();
            let run = scan(&dir, false);
            assert!(
                run.collector_errors.is_empty(),
                "{:?}",
                run.collector_errors
            );
            assert!(run.privileged_collectors_skipped.is_empty());
            for n in 1..=11 {
                let id = format!("BLWK-SSH-{n:03}");
                assert!(run.rules_evaluated.contains(&id), "{id} not evaluated");
            }
            let fired: Vec<_> = run.findings.iter().map(|f| &f.rule_id).collect();
            assert!(fired.is_empty(), "{fired:?}");
        }
    }
}

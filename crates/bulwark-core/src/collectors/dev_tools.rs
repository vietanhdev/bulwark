//! Developer-tool settings that quietly switch a security control off: Git skipping TLS checks or
//! trusting every repository, the SSH client skipping host-key checks or forwarding the agent to
//! every server, npm/yarn/pip installing over plain HTTP or without certificate checks, and a
//! Docker API exposed without TLS. Each is a one-line setting added once to get past an error and
//! then forgotten — and each turns an ordinary network position (a café Wi-Fi, a compromised
//! proxy, a malicious repo) into code execution or stolen credentials on the developer's machine.
//!
//! One fact row per config file that exists. Every row carries every flag (false when it doesn't
//! apply to that kind of file), so each rule can filter on `kind` and its own flag. A file that
//! exists but can't be read yields a row *without* the flags: the rule then raises `MissingField`
//! and the scan reports a collector error, never a confident "nothing insecure here".
//!
//! Only settings that weaken security are reported, and only where they apply broadly: Git's
//! `http.sslVerify` scoped to one URL, `ForwardAgent yes` for one named host, or a plain-HTTP
//! registry on `localhost` are deliberate and narrow, and are left alone.

use super::{user_homes, Collector};
use crate::models::{Fact, OperatingSystem};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct DevToolConfigCollector;

const ALL_OS: &[OperatingSystem] = &[
    OperatingSystem::Linux,
    OperatingSystem::Macos,
    OperatingSystem::Windows,
];

/// Every flag a rule can read; all are present (false by default) on a readable row.
const FLAGS: &[&str] = &[
    "ssl_verify_off",
    "safe_directory_any",
    "ext_protocol_allowed",
    "host_key_checks_off",
    "agent_forwarding_all",
    "strict_ssl_off",
    "http_registry",
    "trusted_host",
    "docker_api_unprotected",
    "install_scripts_auto",
    "no_release_cooldown",
];

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Flags {
    pub ssl_verify_off: bool,
    pub safe_directory_any: bool,
    pub ext_protocol_allowed: bool,
    pub host_key_checks_off: bool,
    pub agent_forwarding_all: bool,
    pub strict_ssl_off: bool,
    pub http_registry: bool,
    pub trusted_host: bool,
    pub docker_api_unprotected: bool,
    /// npm's user settings leave package install scripts on (the npm default).
    pub install_scripts_auto: bool,
    /// npm's user settings set no waiting period for newly published versions.
    pub no_release_cooldown: bool,
    /// The offending value, for the explanation (e.g. the http:// URL).
    pub detail: String,
}

fn is_false(v: &str) -> bool {
    matches!(
        v.trim().trim_matches('"').to_ascii_lowercase().as_str(),
        "false" | "no" | "off" | "0"
    )
}

/// A plain-HTTP URL that leaves this machine (`http://localhost:4873` for a local Verdaccio is fine).
fn remote_http(url: &str) -> bool {
    let u = url
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    let Some(rest) = u.strip_prefix("http://") else {
        return false;
    };
    !is_local(authority_host(rest))
}

/// The host of `host[:port]`, `[v6]:port` or `user@host…` (anything after the authority dropped).
fn authority_host(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport.split(':').next().unwrap_or(""),
    }
}

/// What a finding may say about a URL from a config file: scheme, host and port only. A registry
/// URL often carries credentials (`http://user:token@host/`) or a token in its path or query, and
/// a finding is stored, shown and forwarded, so none of that is kept. Anything that is not a plain
/// host name or address is described rather than quoted.
pub(crate) fn url_origin(url: &str) -> String {
    let u = url.trim().trim_matches(['"', '\'']);
    let (scheme, rest) = match u.split_once("://") {
        Some((s, r))
            if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+') =>
        {
            (format!("{}://", s.to_ascii_lowercase()), r)
        }
        Some(_) => return "an address in this file".into(),
        None => (String::new(), u),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let (host, port) = match hostport.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, p)) => (format!("[{h}]"), p.strip_prefix(':').unwrap_or("")),
            None => return "an address in this file".into(),
        },
        None => match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p),
            None => (hostport.to_string(), ""),
        },
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if !host_ok || !port.chars().all(|c| c.is_ascii_digit()) || port.len() > 5 {
        return "an address in this file".into();
    }
    if port.is_empty() {
        format!("{scheme}{host}")
    } else {
        format!("{scheme}{host}:{port}")
    }
}

fn is_local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "")
}

fn local_host(h: &str) -> bool {
    let h = h.trim().trim_matches('"').to_ascii_lowercase();
    is_local(authority_host(&h))
}

// ---- Git ----------------------------------------------------------------------------------------

/// `text` without a leading byte-order mark. A Windows editor writes one, the tool that owns the
/// file reads past it, and a parser that does not sees a first line that is not what it says: a
/// `.npmrc` starting `<BOM>strict-ssl=false` used to be read as setting nothing.
fn without_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// A Git config value as Git reads it (git-config(1), "Syntax"): leading white space dropped, a
/// `#` or `;` outside double quotes starts a comment, trailing white space outside quotes is
/// dropped, the quotes themselves go, and `\"`, `\\`, `\n`, `\t` are escapes.
///
/// The comment characters need no space before them. `sslVerify = false ; note` and
/// `sslVerify = false<TAB># note` both set `false`; reading only ` #` as a comment turned the
/// first into the value `false ; note`, which is not `false`, and the setting went unreported.
fn git_config_value(raw: &str) -> String {
    let mut out = String::new();
    // Length of `out` up to the last character that must be kept (anything quoted, or not a
    // space).
    let mut keep = 0;
    let mut quoted = false;
    let mut chars = raw.trim_start().chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                keep = out.len();
            }
            '\\' => {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => {}
                }
                keep = out.len();
            }
            '#' | ';' if !quoted => break,
            c => {
                out.push(c);
                if quoted || !c.is_whitespace() {
                    keep = out.len();
                }
            }
        }
    }
    out.truncate(keep);
    out
}

/// Parses a Git config file (INI with `[section]` / `[section "sub"]` headers, case-insensitive
/// section and key names), following git-config(1): a variable may follow its section header on
/// the same line, a line ending in a backslash continues on the next, and a `#` or `;` outside
/// quotes starts a comment anywhere on a line.
pub(crate) fn parse_git_config(text: &str) -> Flags {
    let mut f = Flags::default();
    let (mut section, mut sub) = (String::new(), None::<String>);
    let mut continued = String::new();
    for raw in without_bom(text).lines() {
        // A value can run on over several lines.
        if let Some(head) = raw.strip_suffix('\\') {
            continued.push_str(head);
            continue;
        }
        let logical = std::mem::take(&mut continued) + raw;
        let mut line = logical.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(after_bracket) = line.strip_prefix('[') {
            // The header ends at the first `]` outside quotes: a subsection name is quoted and may
            // contain one.
            let mut quoted = false;
            let Some(close) = after_bracket.char_indices().find_map(|(i, c)| {
                if c == '"' {
                    quoted = !quoted;
                }
                (c == ']' && !quoted).then_some(i)
            }) else {
                continue;
            };
            let h = &after_bracket[..close];
            let mut parts = h.splitn(2, char::is_whitespace);
            section = parts.next().unwrap_or("").to_ascii_lowercase();
            sub = parts
                .next()
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty());
            // `[http.https://host]` is the older spelling of a URL-scoped section.
            if let Some((s, rest)) = section.clone().split_once('.') {
                section = s.to_string();
                sub = Some(rest.to_string());
            }
            // What follows the header on the same line is a variable like any other.
            line = after_bracket[close + 1..].trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
        }
        // A name is letters, digits and `-`; then `= value`, or nothing at all (boolean true).
        let name_end = line
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(line.len());
        let key = line[..name_end].to_ascii_lowercase();
        let rest = line[name_end..].trim_start();
        let value = match rest.strip_prefix('=') {
            Some(v) => Some(git_config_value(v)),
            None if rest.is_empty() || rest.starts_with(['#', ';']) => None,
            None => continue,
        };
        // No `=` at all is true; `=` with nothing after it is false, as Git reads it.
        let off = value
            .as_deref()
            .is_some_and(|v| v.is_empty() || is_false(v));
        let value = value.unwrap_or_else(|| "true".to_string());
        match (section.as_str(), sub.as_deref(), key.as_str()) {
            ("http", None, "sslverify") if off => {
                f.ssl_verify_off = true;
                f.detail = "http.sslVerify = false".into();
            }
            ("safe", None, "directory") if value == "*" => {
                f.safe_directory_any = true;
            }
            ("protocol", None, "allow") if value.eq_ignore_ascii_case("always") => {
                f.ext_protocol_allowed = true;
            }
            ("protocol", Some(p), "allow")
                if p.eq_ignore_ascii_case("ext") && value.eq_ignore_ascii_case("always") =>
            {
                f.ext_protocol_allowed = true;
            }
            _ => {}
        }
    }
    f
}

// ---- SSH client ---------------------------------------------------------------------------------

/// Parses an OpenSSH client config. Only settings that apply to *every* host count: those before
/// the first `Host`/`Match` block, or inside a `Host *` block.
pub(crate) fn parse_ssh_client_config(text: &str) -> Flags {
    let mut f = Flags::default();
    let mut global = true;
    for raw in without_bom(text).lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.to_ascii_lowercase(),
                v.trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                    .trim(),
            ),
            None => continue,
        };
        match key.as_str() {
            "host" => {
                global = value.split_whitespace().any(|p| p.trim_matches('"') == "*");
                continue;
            }
            "match" => {
                global = value.trim().eq_ignore_ascii_case("all");
                continue;
            }
            _ => {}
        }
        if !global {
            continue;
        }
        let v = value.trim_matches('"').to_ascii_lowercase();
        match key.as_str() {
            "stricthostkeychecking" if matches!(v.as_str(), "no" | "off") => {
                f.host_key_checks_off = true;
                f.detail = "StrictHostKeyChecking no".into();
            }
            "userknownhostsfile" if v == "/dev/null" || v == "nul" => {
                f.host_key_checks_off = true;
                f.detail = format!("UserKnownHostsFile {value}");
            }
            "forwardagent" if v == "yes" => f.agent_forwarding_all = true,
            _ => {}
        }
    }
    f
}

// ---- npm / yarn ---------------------------------------------------------------------------------

/// `.npmrc` (`key=value`) and yarn v1 `.yarnrc` (`key value`).
pub(crate) fn parse_npmrc(text: &str) -> Flags {
    let mut f = Flags::default();
    for raw in without_bom(text).lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            },
        };
        let key = key.trim_matches('"').to_ascii_lowercase();
        if key == "strict-ssl" && is_false(value) {
            f.strict_ssl_off = true;
        }
        if (key == "registry" || key.ends_with(":registry")) && remote_http(value) {
            f.http_registry = true;
            f.detail = url_origin(value);
        }
    }
    f
}

/// npm's user-level supply-chain settings, from `~/.npmrc` (empty text when the file is absent).
/// Both keys are in npm's config reference: `ignore-scripts` (default false) and
/// `min-release-age` (days; npm 11.10+, off by default). `before` pins installs to a date, which
/// is a cooldown too. Only the user file is read: a project or system npmrc can still override it.
pub(crate) fn parse_npm_user_practices(text: &str) -> Flags {
    let mut scripts_off = false;
    let mut cooldown = false;
    for raw in without_bom(text).lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim().trim_matches('"').to_ascii_lowercase().as_str() {
            "ignore-scripts" => scripts_off = value.eq_ignore_ascii_case("true"),
            "min-release-age" => cooldown = value.parse::<f64>().is_ok_and(|days| days > 0.0),
            "before" if !value.is_empty() && value != "null" => cooldown = true,
            _ => {}
        }
    }
    Flags {
        install_scripts_auto: !scripts_off,
        no_release_cooldown: !cooldown,
        ..Flags::default()
    }
}

/// bun's user-level waiting period: `[install] minimumReleaseAge`, in seconds, default off (bun's
/// bunfig reference). `None` when the file is not valid TOML.
pub(crate) fn parse_bun_user_practices(text: &str) -> Option<Flags> {
    let table: toml::Table = without_bom(text).parse().ok()?;
    let set = table
        .get("install")
        .and_then(|i| i.get("minimumReleaseAge"))
        .is_some_and(|v| {
            v.as_integer().is_some_and(|n| n > 0) || v.as_float().is_some_and(|n| n > 0.0)
        });
    Some(Flags {
        no_release_cooldown: !set,
        ..Flags::default()
    })
}

/// uv's user-level waiting period: top-level `exclude-newer`, a timestamp or a duration such as
/// "1 week"; `false` or absent means off (uv's settings reference). `None` for invalid TOML.
pub(crate) fn parse_uv_user_practices(text: &str) -> Option<Flags> {
    let table: toml::Table = without_bom(text).parse().ok()?;
    let set = table
        .get("exclude-newer")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.trim().is_empty());
    Some(Flags {
        no_release_cooldown: !set,
        ..Flags::default()
    })
}

/// One package manager whose user-level settings are checked for what they leave *unset*.
struct UserPractices {
    kind: &'static str,
    tool: &'static str,
    /// The config file to read (and to name in the finding), whether or not it exists yet.
    config: PathBuf,
    parse: fn(&str) -> Option<Flags>,
    how_to_fix: &'static str,
}

/// The package managers this home shows in use (a config file or the tool's own data folder).
fn user_practices(home: &Path) -> Vec<UserPractices> {
    let any = |paths: &[&str]| paths.iter().any(|p| home.join(p).exists());
    let mut out = Vec::new();
    if uses_npm(home) {
        out.push(UserPractices {
            kind: "npm_user",
            tool: "npm",
            config: home.join(".npmrc"),
            parse: |t| Some(parse_npm_user_practices(t)),
            how_to_fix: "Run 'npm config set min-release-age 7' for a 7-day waiting period (needs npm 11.10 or newer; check with 'npm --version'). For an urgent security patch, override once: 'npm install <package> --min-release-age=0'.",
        });
    }
    if any(&[".bunfig.toml", ".bun"]) {
        out.push(UserPractices {
            kind: "bun_user",
            tool: "bun",
            config: home.join(".bunfig.toml"),
            parse: parse_bun_user_practices,
            how_to_fix: "Add these two lines to ~/.bunfig.toml for a 7-day waiting period (the value is in seconds): '[install]' and 'minimumReleaseAge = 604800'. Exempt a package you trust with 'minimumReleaseAgeExcludes'.",
        });
    }
    let uv_config = if cfg!(windows) {
        home.join("AppData/Roaming/uv/uv.toml")
    } else {
        home.join(".config/uv/uv.toml")
    };
    if any(&[
        ".config/uv",
        ".cache/uv",
        ".local/share/uv",
        "AppData/Roaming/uv",
        "AppData/Local/uv",
    ]) {
        out.push(UserPractices {
            kind: "uv_user",
            tool: "uv",
            config: uv_config,
            parse: parse_uv_user_practices,
            how_to_fix: "Add the line 'exclude-newer = \"1 week\"' to ~/.config/uv/uv.toml (on Windows: %APPDATA%\\uv\\uv.toml). For one urgent install, pass '--exclude-newer' with today's date.",
        });
    }
    out
}

/// Whether this home shows npm in use: its user config or its cache folder exists.
fn uses_npm(home: &Path) -> bool {
    home.join(".npmrc").is_file()
        || home.join(".npm").is_dir()
        || home.join("AppData/Local/npm-cache").is_dir()
}

/// Yarn Berry `.yarnrc.yml`: `enableStrictSsl: false`, `npmRegistryServer: "http://…"`.
pub(crate) fn parse_yarnrc_yml(text: &str) -> Flags {
    let mut f = Flags::default();
    for raw in without_bom(text).lines() {
        let line = raw.trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim() {
            "enableStrictSsl" if is_false(v) => f.strict_ssl_off = true,
            "npmRegistryServer" if remote_http(v) => {
                f.http_registry = true;
                f.detail = url_origin(v);
            }
            _ => {}
        }
    }
    f
}

// ---- pip ----------------------------------------------------------------------------------------

/// `pip.conf` / `pip.ini`: `index-url` / `extra-index-url` over plain HTTP, or any `trusted-host`
/// (which turns off certificate checks for that host). Values may continue on indented lines.
pub(crate) fn parse_pip_conf(text: &str) -> Flags {
    let mut f = Flags::default();
    let mut current: Option<String> = None;
    for raw in without_bom(text).lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let continuation = raw.starts_with(' ') || raw.starts_with('\t');
        let (key, value) = if continuation {
            match &current {
                Some(k) => (k.clone(), raw.trim().to_string()),
                None => continue,
            }
        } else if raw.trim_start().starts_with('[') {
            current = None;
            continue;
        } else {
            match raw.split_once(['=', ':']) {
                Some((k, v)) => {
                    let k = k.trim().to_ascii_lowercase().replace('_', "-");
                    current = Some(k.clone());
                    (k, v.trim().to_string())
                }
                None => continue,
            }
        };
        for item in value.split_whitespace() {
            match key.as_str() {
                "index-url" | "extra-index-url" | "find-links" if remote_http(item) => {
                    f.http_registry = true;
                    f.detail = url_origin(item);
                }
                "trusted-host" if !local_host(item) => {
                    f.trusted_host = true;
                    if f.detail.is_empty() {
                        f.detail = url_origin(item);
                    }
                }
                _ => {}
            }
        }
    }
    f
}

// ---- Docker -------------------------------------------------------------------------------------

/// `/etc/docker/daemon.json`: a loopback `tcp://` entry in `hosts` without `tlsverify: true`.
///
/// Only loopback bindings count here. An API bound to `0.0.0.0` or a LAN address is exposed to the
/// network, which BLWK-NET-003/005 already report from what is actually listening on port 2375 —
/// reporting it from the config as well would show one problem twice. A loopback binding is
/// invisible to those rules, yet still lets any program or user on this computer become root.
pub(crate) fn parse_docker_daemon_json(text: &str) -> Option<Flags> {
    let v: Value = serde_json::from_str(without_bom(text)).ok()?;
    let mut f = Flags::default();
    let tls_verify = v.get("tlsverify").and_then(Value::as_bool).unwrap_or(false);
    let local: Vec<String> = v
        .get("hosts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|h| h.strip_prefix("tcp://").map(|rest| (h, rest)))
                .filter(|(_, rest)| {
                    let host = rest.rsplit_once(':').map_or(*rest, |(h, _)| h);
                    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
                })
                .map(|(h, _)| url_origin(h))
                .collect()
        })
        .unwrap_or_default();
    if !local.is_empty() && !tls_verify {
        f.docker_api_unprotected = true;
        f.detail = local.join(", ");
    }
    Some(f)
}

/// Docker Desktop's settings: "Expose daemon on tcp://localhost:2375 without TLS".
pub(crate) fn parse_docker_desktop_settings(text: &str) -> Option<Flags> {
    let v: Value = serde_json::from_str(without_bom(text)).ok()?;
    let mut f = Flags::default();
    let on = v.as_object().is_some_and(|o| {
        o.iter().any(|(k, val)| {
            k.eq_ignore_ascii_case("exposeDockerAPIOnTCP2375") && val.as_bool() == Some(true)
        })
    });
    if on {
        f.docker_api_unprotected = true;
        f.detail = "tcp://localhost:2375 (Docker Desktop)".into();
    }
    Some(f)
}

// ---- collection ---------------------------------------------------------------------------------

/// (kind, path, parser) for every file that exists. Parsers returning `None` mean "unparseable".
type Parser = fn(&str) -> Option<Flags>;

fn candidate_files() -> Vec<(&'static str, PathBuf, Parser, Option<PathBuf>)> {
    let mut found: Vec<(&'static str, PathBuf, Parser, Option<PathBuf>)> = Vec::new();
    for home in user_homes() {
        found.extend(
            home_candidates(&home)
                .into_iter()
                .map(|(kind, path, parser)| (kind, path, parser, Some(home.clone()))),
        );
    }
    found.extend(
        system_candidates()
            .into_iter()
            .map(|(kind, path, parser)| (kind, path, parser, None)),
    );
    // The same file can be reached twice (e.g. root's home under a privileged scan).
    let mut seen = std::collections::HashSet::new();
    found.retain(|(_, p, _, _)| seen.insert(p.clone()));
    found
}

/// The config files under one home folder.
fn home_candidates(home: &Path) -> Vec<(&'static str, PathBuf, Parser)> {
    let mut out: Vec<(&'static str, PathBuf, Parser)> = Vec::new();
    let git: Parser = |t| Some(parse_git_config(t));
    let ssh: Parser = |t| Some(parse_ssh_client_config(t));
    let npm: Parser = |t| Some(parse_npmrc(t));
    let yarn: Parser = |t| Some(parse_yarnrc_yml(t));
    let pip: Parser = |t| Some(parse_pip_conf(t));
    let desktop: Parser = parse_docker_desktop_settings;

    {
        out.push(("git", home.join(".gitconfig"), git));
        out.push(("git", home.join(".config").join("git").join("config"), git));
        out.push(("ssh", home.join(".ssh").join("config"), ssh));
        out.push(("npm", home.join(".npmrc"), npm));
        out.push(("npm", home.join(".yarnrc"), npm));
        out.push(("npm", home.join(".yarnrc.yml"), yarn));
        out.push(("pip", home.join(".pip").join("pip.conf"), pip));
        out.push((
            "pip",
            home.join(".config").join("pip").join("pip.conf"),
            pip,
        ));
        out.push((
            "pip",
            home.join("Library/Application Support/pip/pip.conf"),
            pip,
        ));
        for name in ["settings.json", "settings-store.json"] {
            out.push((
                "docker",
                home.join(".docker").join("desktop").join(name),
                desktop,
            ));
            out.push((
                "docker",
                home.join("Library/Group Containers/group.com.docker")
                    .join(name),
                desktop,
            ));
        }
    }
    out
}

/// Config files outside any home: system-wide ones, and on Windows the per-user folders that are
/// found through the environment and not through a home path.
fn system_candidates() -> Vec<(&'static str, PathBuf, Parser)> {
    let mut out: Vec<(&'static str, PathBuf, Parser)> = Vec::new();
    let git: Parser = |t| Some(parse_git_config(t));
    let ssh: Parser = |t| Some(parse_ssh_client_config(t));
    let pip: Parser = |t| Some(parse_pip_conf(t));
    let daemon: Parser = parse_docker_daemon_json;
    let desktop: Parser = parse_docker_desktop_settings;
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            out.push(("pip", appdata.join("pip").join("pip.ini"), pip));
            for name in ["settings.json", "settings-store.json"] {
                out.push(("docker", appdata.join("Docker").join(name), desktop));
            }
        }
        if let Some(pd) = std::env::var_os("ProgramData").map(PathBuf::from) {
            out.push((
                "docker",
                pd.join("docker").join("config").join("daemon.json"),
                daemon,
            ));
        }
    } else {
        out.push(("git", PathBuf::from("/etc/gitconfig"), git));
        out.push(("ssh", PathBuf::from("/etc/ssh/ssh_config"), ssh));
        out.push(("pip", PathBuf::from("/etc/pip.conf"), pip));
        out.push(("docker", PathBuf::from("/etc/docker/daemon.json"), daemon));
    }
    out
}

fn fact_for(kind: &str, path: &Path, parsed: Option<Flags>) -> Fact {
    let mut fact = Fact::new();
    fact.insert("kind".into(), Value::String(kind.into()));
    fact.insert("path".into(), Value::String(path.display().to_string()));
    // Unreadable or unparseable: no flags, so every rule on this row reports "could not check".
    let Some(f) = parsed else {
        fact.insert(
            crate::homefs::COULD_NOT_READ.into(),
            Value::String(
                "it could not be read or its contents could not be parsed (also true of a link that leaves the home folder, or a pipe)".into(),
            ),
        );
        return fact;
    };
    let values = [
        f.ssl_verify_off,
        f.safe_directory_any,
        f.ext_protocol_allowed,
        f.host_key_checks_off,
        f.agent_forwarding_all,
        f.strict_ssl_off,
        f.http_registry,
        f.trusted_host,
        f.docker_api_unprotected,
        f.install_scripts_auto,
        f.no_release_cooldown,
    ];
    for (k, v) in FLAGS.iter().zip(values) {
        fact.insert((*k).into(), Value::Bool(v));
    }
    fact.insert("detail".into(), Value::String(f.detail));
    fact
}

impl Collector for DevToolConfigCollector {
    fn name(&self) -> &'static str {
        "dev_tool_config"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        ALL_OS
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut facts = Vec::new();
        // One row per package manager in use, for the settings whose *absence* matters
        // (DEV-010, DEV-011). A missing config file means the tool's defaults; an unreadable or
        // unparseable one leaves the flags undetermined, so the rule reports "could not check".
        use crate::homefs::{open_system_file, read_in_home, read_start, HomeFile};
        const CAP: u64 = super::MAX_COLLECTOR_READ_BYTES;
        for home in user_homes() {
            for p in user_practices(&home) {
                // Missing means the tool's defaults. A pipe, a link leaving the home folder or an
                // unreadable file is "could not check": the row carries no flags.
                let parsed = match read_in_home(&home, &p.config, CAP) {
                    HomeFile::Missing => (p.parse)(""),
                    HomeFile::Refused => None,
                    HomeFile::Found(text) => (p.parse)(&text),
                };
                let mut fact = fact_for(p.kind, &p.config, parsed);
                fact.insert("tool".into(), Value::String(p.tool.into()));
                fact.insert("how_to_fix".into(), Value::String(p.how_to_fix.into()));
                facts.push(fact);
            }
        }
        for (kind, path, parse, home) in candidate_files() {
            // A missing file is simply absent. One that exists but may not be read (a pipe, a
            // link out of the home folder) gets a row without flags, so its rules report it.
            let text = match &home {
                Some(home) => read_in_home(home, &path, CAP),
                None => match open_system_file(&path) {
                    HomeFile::Found(file) => match read_start(file, CAP) {
                        Some(text) => HomeFile::Found(text),
                        None => HomeFile::Refused,
                    },
                    HomeFile::Missing => HomeFile::Missing,
                    HomeFile::Refused => HomeFile::Refused,
                },
            };
            let parsed = match text {
                HomeFile::Missing => continue,
                HomeFile::Refused => None,
                HomeFile::Found(text) => parse(&text),
            };
            facts.push(fact_for(kind, &path, parsed));
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_user_practices_read_only_the_documented_keys() {
        // npm's defaults: scripts run, no waiting period.
        let d = parse_npm_user_practices("");
        assert!(d.install_scripts_auto && d.no_release_cooldown);
        let hardened = parse_npm_user_practices("ignore-scripts=true\nmin-release-age=7\n");
        assert_eq!(hardened, Flags::default());
        // `before` is a cooldown too; a zero or commented-out age is not.
        assert!(!parse_npm_user_practices("before=2026-01-01\n").no_release_cooldown);
        assert!(parse_npm_user_practices("min-release-age=0\n").no_release_cooldown);
        assert!(
            parse_npm_user_practices("; min-release-age=7\n# ignore-scripts=true\n")
                .install_scripts_auto
        );
        assert!(parse_npm_user_practices("ignore-scripts=false\n").install_scripts_auto);
        // Unrelated settings change nothing, and never set another rule's flag.
        let other =
            parse_npm_user_practices("registry=https://registry.npmjs.org/\nsave-exact=true\n");
        assert!(other.install_scripts_auto && !other.http_registry && !other.strict_ssl_off);
    }

    #[test]
    fn bun_and_uv_waiting_periods_use_the_documented_keys() {
        // Defaults (no file, or a file about something else): no waiting period.
        assert!(parse_bun_user_practices("").unwrap().no_release_cooldown);
        assert!(parse_uv_user_practices("").unwrap().no_release_cooldown);
        assert!(
            parse_bun_user_practices("[install]\nexact = true\n")
                .unwrap()
                .no_release_cooldown
        );
        assert!(
            parse_uv_user_practices("[pip]\nindex-url = \"https://pypi.org/simple\"\n")
                .unwrap()
                .no_release_cooldown
        );
        // Set as each tool documents it.
        assert_eq!(
            parse_bun_user_practices("[install]\nminimumReleaseAge = 259200\n"),
            Some(Flags::default())
        );
        assert_eq!(
            parse_uv_user_practices("exclude-newer = \"1 week\"\n"),
            Some(Flags::default())
        );
        assert_eq!(
            parse_uv_user_practices("exclude-newer = \"2026-01-01T00:00:00Z\"\n"),
            Some(Flags::default())
        );
        // Explicitly off, or zero.
        assert!(
            parse_bun_user_practices("[install]\nminimumReleaseAge = 0\n")
                .unwrap()
                .no_release_cooldown
        );
        assert!(
            parse_uv_user_practices("exclude-newer = false\n")
                .unwrap()
                .no_release_cooldown
        );
        // Invalid TOML is undetermined, never "fine".
        assert_eq!(parse_bun_user_practices("[install\nx"), None);
        assert_eq!(parse_uv_user_practices("exclude-newer = "), None);
    }

    #[test]
    fn package_manager_rows_need_evidence_of_use() {
        let home = tempfile::tempdir().unwrap();
        assert!(user_practices(home.path()).is_empty());
        std::fs::create_dir_all(home.path().join(".bun")).unwrap();
        std::fs::create_dir_all(home.path().join(".cache/uv")).unwrap();
        let kinds: Vec<_> = user_practices(home.path()).iter().map(|p| p.kind).collect();
        assert_eq!(kinds, ["bun_user", "uv_user"]);
    }

    #[test]
    fn a_url_in_a_finding_keeps_only_scheme_host_and_port() {
        // Built at runtime so no credential-shaped literal is committed.
        let secret = format!("tok{}", "Z9y8".repeat(6));
        for (url, want) in [
            (
                format!("http://user:{secret}@registry.example/simple"),
                "http://registry.example",
            ),
            (
                format!("http://registry.example:8081/repo?token={secret}"),
                "http://registry.example:8081",
            ),
            (
                format!("http://{secret}@[2001:db8::1]:8080/"),
                "http://[2001:db8::1]:8080",
            ),
            (
                "\"http://registry.example/\"".to_string(),
                "http://registry.example",
            ),
            (format!("user:{secret}@pypi.example"), "pypi.example"),
            (
                "tcp://127.0.0.1:2375/x\u{1b}[2J".to_string(),
                "tcp://127.0.0.1:2375",
            ),
            ("http://bad host/".to_string(), "an address in this file"),
        ] {
            let got = url_origin(&url);
            assert_eq!(got, want, "{url}");
            assert!(!got.contains(&secret));
        }
        // End to end through each parser that records a URL.
        let npm = parse_npmrc(&format!("registry=http://u:{secret}@npm.example/\n"));
        let yarn = parse_yarnrc_yml(&format!(
            "npmRegistryServer: \"http://u:{secret}@yarn.example/\"\n"
        ));
        let pip = parse_pip_conf(&format!(
            "[global]\nindex-url = http://u:{secret}@pip.example/simple\n"
        ));
        for (f, host) in [
            (npm, "http://npm.example"),
            (yarn, "http://yarn.example"),
            (pip, "http://pip.example"),
        ] {
            assert!(f.http_registry);
            assert_eq!(f.detail, host);
        }
    }

    #[test]
    fn npm_user_row_needs_evidence_that_npm_is_used() {
        let home = tempfile::tempdir().unwrap();
        assert!(!uses_npm(home.path()));
        std::fs::create_dir(home.path().join(".npm")).unwrap();
        assert!(uses_npm(home.path()));
    }

    #[test]
    fn git_flags_only_global_weakening() {
        let f = parse_git_config("[http]\n\tsslVerify = false\n[safe]\n\tdirectory = *\n");
        assert!(f.ssl_verify_off && f.safe_directory_any);
        // Scoped to one URL, or a specific safe directory: deliberate and narrow.
        let f = parse_git_config(
            "[http \"https://intranet.example.com/\"]\n\tsslVerify = false\n\
             [http.https://other.example.com/]\n  sslverify = false\n\
             [safe]\n\tdirectory = /srv/repo\n[credential]\n\thelper = store\n",
        );
        assert_eq!(f, Flags::default());
        // ext:: transport, either spelling.
        assert!(parse_git_config("[protocol \"ext\"]\n\tallow = always\n").ext_protocol_allowed);
        assert!(parse_git_config("[protocol]\nallow = always\n").ext_protocol_allowed);
        assert!(!parse_git_config("[protocol \"file\"]\n\tallow = always\n").ext_protocol_allowed);
        // A plausible, ordinary config raises nothing.
        let ordinary = "[user]\n\tname = A\n\temail = a@example.com\n[core]\n\teditor = vim\n\
                        [http]\n\tpostBuffer = 524288000\n\tsslVerify = true\n[init]\n\tdefaultBranch = main\n";
        assert_eq!(parse_git_config(ordinary), Flags::default());
    }

    #[test]
    fn git_comments_start_at_a_hash_or_a_semicolon_with_or_without_a_space() {
        // Missed before: only " #" was read as the start of a comment.
        for off in [
            "[http]\n\tsslVerify = false ; temp workaround\n",
            "[http]\n\tsslVerify = false\t# temp\n",
            "[http]\n\tsslVerify = false;note\n",
            "[http]\n\tsslVerify = false#note\n",
            "[http]\n\tsslVerify = \"false\" ; quoted\n",
            "[http]\r\n\tsslVerify = false ; crlf\r\n",
            "[HTTP]\nsslverify=no\n",
            // A variable may follow its section header on the same line.
            "[http] sslVerify = false\n",
            "[http] sslVerify = false ; note\n",
            // An empty value is false to Git; a continued line is one line.
            "[http]\n\tsslVerify =\n",
            "[http]\n\tsslVerify = \\\n\t\tfalse\n",
            // Behind a byte-order mark.
            "\u{feff}[http]\n\tsslVerify = false\n",
        ] {
            assert!(parse_git_config(off).ssl_verify_off, "{off:?}");
        }
        for on in [
            // Commented out, or not `false` at all.
            "[http]\n\t# sslVerify = false\n",
            "[http]\n\t; sslVerify = false\n",
            "[http]\n\tsslVerify = true ; was false\n",
            "[http]\n\tsslVerify = true # false\n",
            "[http]\n\tsslVerify\n",
            // A `;` or `#` inside quotes is part of the value, so this is not `false`.
            "[http]\n\tsslVerify = \"false ; not a comment\"\n",
            // Scoped to one host: a deliberate, narrow choice.
            "[http \"https://git.corp.invalid\"] sslVerify = false\n",
            "[http \"https://h.invalid/a]b\"]\n\tsslVerify = false\n",
            "[core] editor = vim\n",
        ] {
            assert!(!parse_git_config(on).ssl_verify_off, "{on:?}");
        }
        assert_eq!(git_config_value(" a b  # c"), "a b");
        assert_eq!(git_config_value(" \"a ; b\"  ; c"), "a ; b");
        assert_eq!(git_config_value("x \" y \" "), "x  y ");
        assert_eq!(git_config_value("a\\\"b"), "a\"b");
        assert!(parse_git_config("[safe]\n\tdirectory = \"*\" ; everything\n").safe_directory_any);
        assert!(!parse_git_config("[safe]\n\tdirectory = /srv/repo ; *\n").safe_directory_any);
        assert!(
            parse_git_config("[protocol \"ext\"]\n\tallow = always# why\n").ext_protocol_allowed
        );
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_setting() {
        assert!(parse_npmrc("\u{feff}strict-ssl=false\nignore-scripts=true\n").strict_ssl_off);
        assert!(parse_npmrc("\u{feff}registry=http://registry.corp.invalid/\n").http_registry);
        assert!(
            !parse_npm_user_practices("\u{feff}ignore-scripts=true\nmin-release-age=7\n")
                .install_scripts_auto
        );
        assert!(parse_yarnrc_yml("\u{feff}enableStrictSsl: false\n").strict_ssl_off);
        assert!(parse_ssh_client_config("\u{feff}StrictHostKeyChecking no\n").host_key_checks_off);
        assert!(
            parse_pip_conf("\u{feff}[global]\ntrusted-host = pypi.corp.invalid\n").trusted_host
        );
        assert!(
            parse_docker_desktop_settings("\u{feff}{\"exposeDockerAPIOnTCP2375\": true}")
                .unwrap()
                .docker_api_unprotected
        );
        assert!(
            !parse_bun_user_practices("\u{feff}[install]\nminimumReleaseAge = 604800\n")
                .unwrap()
                .no_release_cooldown
        );
        // And nothing is invented for a file that sets nothing.
        assert_eq!(parse_npmrc("\u{feff}"), Flags::default());
    }

    #[test]
    fn ssh_flags_only_settings_for_every_host() {
        let global = "StrictHostKeyChecking no\nHost *\n  ForwardAgent yes\n";
        let f = parse_ssh_client_config(global);
        assert!(f.host_key_checks_off && f.agent_forwarding_all);
        // Per-host settings are deliberate choices for that host.
        let scoped =
            "Host build\n  HostName 10.0.0.5\n  ForwardAgent yes\n  StrictHostKeyChecking no\n\
                      Host *\n  ServerAliveInterval 30\n  StrictHostKeyChecking accept-new\n";
        assert_eq!(parse_ssh_client_config(scoped), Flags::default());
        assert!(
            parse_ssh_client_config("Host *\n  UserKnownHostsFile=/dev/null\n").host_key_checks_off
        );
        // Ubuntu's stock ssh_config: everything relevant commented out.
        let stock = "Host *\n#   ForwardAgent no\n#   StrictHostKeyChecking ask\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n";
        assert_eq!(parse_ssh_client_config(stock), Flags::default());
    }

    #[test]
    fn npm_yarn_and_pip_flag_plain_http_and_disabled_tls() {
        let f = parse_npmrc("registry=http://registry.example.com/\nstrict-ssl=false\n");
        assert!(f.http_registry && f.strict_ssl_off);
        assert!(parse_npmrc("@acme:registry=http://npm.acme.example/\n").http_registry);
        // HTTPS, or a local registry such as Verdaccio, is fine; so is a token line.
        let ok = "registry=https://registry.npmjs.org/\n@me:registry=http://localhost:4873/\n\
                  //registry.npmjs.org/:_authToken=${NPM_TOKEN}\n";
        assert_eq!(parse_npmrc(ok), Flags::default());
        assert!(
            parse_npmrc("strict-ssl false\n").strict_ssl_off,
            "yarn v1 spelling"
        );
        let y =
            parse_yarnrc_yml("enableStrictSsl: false\nnpmRegistryServer: \"http://r.example\"\n");
        assert!(y.strict_ssl_off && y.http_registry);

        let p = parse_pip_conf(
            "[global]\nindex-url = https://pypi.org/simple\nextra-index-url =\n    http://pkgs.example.com/simple\ntrusted-host = pkgs.example.com\n",
        );
        assert!(p.http_registry && p.trusted_host);
        let local =
            "[global]\nindex-url = http://localhost:3141/root/pypi\ntrusted-host = localhost\n";
        assert_eq!(parse_pip_conf(local), Flags::default());
        // IPv6 loopback, with and without a port, is local too.
        assert_eq!(
            parse_pip_conf(
                "[global]\nindex-url = http://[::1]:3141/simple\ntrusted-host = [::1]:3141\n"
            ),
            Flags::default()
        );
        assert!(!parse_npmrc("registry=http://[::1]:4873/\n").http_registry);
        assert!(parse_npmrc("registry=http://[2001:db8::1]:4873/\n").http_registry);
    }

    #[test]
    fn docker_api_without_tls_is_flagged() {
        let f = parse_docker_daemon_json(
            r#"{"hosts":["unix:///var/run/docker.sock","tcp://127.0.0.1:2375"]}"#,
        )
        .unwrap();
        assert!(f.docker_api_unprotected);
        // Network-wide exposure is BLWK-NET-003/005's, from the live port — not reported twice.
        let net = r#"{"hosts":["tcp://0.0.0.0:2375"]}"#;
        assert!(
            !parse_docker_daemon_json(net)
                .unwrap()
                .docker_api_unprotected
        );
        let tls = r#"{"hosts":["tcp://0.0.0.0:2376"],"tlsverify":true,"tlscacert":"/x"}"#;
        assert!(
            !parse_docker_daemon_json(tls)
                .unwrap()
                .docker_api_unprotected
        );
        assert!(
            !parse_docker_daemon_json(r#"{"log-driver":"json-file"}"#)
                .unwrap()
                .docker_api_unprotected
        );
        assert!(parse_docker_daemon_json("not json").is_none());
        assert!(
            parse_docker_desktop_settings(r#"{"exposeDockerAPIOnTCP2375":true}"#)
                .unwrap()
                .docker_api_unprotected
        );
        assert!(
            parse_docker_desktop_settings(r#"{"ExposeDockerAPIOnTCP2375":true}"#)
                .unwrap()
                .docker_api_unprotected
        );
        assert!(
            !parse_docker_desktop_settings(r#"{"exposeDockerAPIOnTCP2375":false}"#)
                .unwrap()
                .docker_api_unprotected
        );
    }

    #[test]
    fn an_unreadable_file_carries_no_flags() {
        let f = fact_for("git", Path::new("/x/.gitconfig"), None);
        assert!(
            !f.contains_key("ssl_verify_off"),
            "absent, so the rule reports an error"
        );
        let f = fact_for("git", Path::new("/x/.gitconfig"), Some(Flags::default()));
        for k in FLAGS {
            assert_eq!(f.get(*k), Some(&Value::Bool(false)), "{k}");
        }
    }
}

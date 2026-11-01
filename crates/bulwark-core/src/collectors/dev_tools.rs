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

use super::{read_capped, user_homes, Collector};
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

fn is_local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "")
}

fn local_host(h: &str) -> bool {
    let h = h.trim().trim_matches('"').to_ascii_lowercase();
    is_local(authority_host(&h))
}

// ---- Git ----------------------------------------------------------------------------------------

/// Parses a Git config file (INI with `[section]` / `[section "sub"]` headers, case-insensitive
/// section and key names).
pub(crate) fn parse_git_config(text: &str) -> Flags {
    let mut f = Flags::default();
    let (mut section, mut sub) = (String::new(), None::<String>);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(h) = line.strip_prefix('[').and_then(|l| l.split(']').next()) {
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
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            // A bare key is boolean true.
            None => (line.to_ascii_lowercase(), "true".to_string()),
        };
        let value = value.split(" #").next().unwrap_or("").trim().to_string();
        match (section.as_str(), sub.as_deref(), key.as_str()) {
            ("http", None, "sslverify") if is_false(&value) => {
                f.ssl_verify_off = true;
                f.detail = "http.sslVerify = false".into();
            }
            ("safe", None, "directory") if value.trim_matches('"') == "*" => {
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
    for raw in text.lines() {
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
    for raw in text.lines() {
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
            f.detail = value.trim_matches('"').to_string();
        }
    }
    f
}

/// Yarn Berry `.yarnrc.yml`: `enableStrictSsl: false`, `npmRegistryServer: "http://…"`.
pub(crate) fn parse_yarnrc_yml(text: &str) -> Flags {
    let mut f = Flags::default();
    for raw in text.lines() {
        let line = raw.trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim() {
            "enableStrictSsl" if is_false(v) => f.strict_ssl_off = true,
            "npmRegistryServer" if remote_http(v) => {
                f.http_registry = true;
                f.detail = v.trim().trim_matches('"').to_string();
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
    for raw in text.lines() {
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
                    f.detail = item.to_string();
                }
                "trusted-host" if !local_host(item) => {
                    f.trusted_host = true;
                    if f.detail.is_empty() {
                        f.detail = item.to_string();
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
    let v: Value = serde_json::from_str(text).ok()?;
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
                .map(|(h, _)| h.to_string())
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
    let v: Value = serde_json::from_str(text).ok()?;
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

fn candidate_files() -> Vec<(&'static str, PathBuf, Parser)> {
    let mut out: Vec<(&'static str, PathBuf, Parser)> = Vec::new();
    let git: Parser = |t| Some(parse_git_config(t));
    let ssh: Parser = |t| Some(parse_ssh_client_config(t));
    let npm: Parser = |t| Some(parse_npmrc(t));
    let yarn: Parser = |t| Some(parse_yarnrc_yml(t));
    let pip: Parser = |t| Some(parse_pip_conf(t));
    let daemon: Parser = parse_docker_daemon_json;
    let desktop: Parser = parse_docker_desktop_settings;

    for home in user_homes() {
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
    // The same file can be reached twice (e.g. root's home under a privileged scan).
    let mut seen = std::collections::HashSet::new();
    out.retain(|(_, p, _)| seen.insert(p.clone()));
    out
}

fn fact_for(kind: &str, path: &Path, parsed: Option<Flags>) -> Fact {
    let mut fact = Fact::new();
    fact.insert("kind".into(), Value::String(kind.into()));
    fact.insert("path".into(), Value::String(path.display().to_string()));
    // Unreadable or unparseable: no flags, so every rule on this row reports a collector error.
    let Some(f) = parsed else {
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
        for (kind, path, parse) in candidate_files() {
            // A symlink is followed only to a regular file; a missing file is simply absent.
            if !path.is_file() {
                continue;
            }
            let parsed = read_capped(&path).ok().and_then(|t| parse(&t));
            facts.push(fact_for(kind, &path, parsed));
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

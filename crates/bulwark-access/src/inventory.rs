//! Passive, metadata-only inventories of the credential stores developer tools keep in the home
//! directory. Each reader parses a tool's own files — it never runs the tool — and keeps only
//! names, storage kind and expiry. Secret values are read past, never stored or serialized;
//! organisation-identifying values (an SSO start URL) are used for matching only.
//!
//! One shape for every provider (`Inventory`), so a new secrets manager is one reader plus one
//! catalog entry in the app.
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_FILE: u64 = 1024 * 1024;
const MAX_CACHE_FILES: usize = 64;
const MAX_ITEMS: usize = 1024;

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Storage {
    /// Written out in a readable file.
    Plaintext,
    /// Held by the OS keychain or a credential helper backed by one.
    Keychain,
    /// Fetched by an external helper/process; where it keeps the secret is up to that helper.
    Helper,
    /// A short-lived session token cached by the tool.
    Session,
    /// Kept in memory only for a while (git's `cache` helper).
    Memory,
    /// Configuration only: the entry holds no credential itself (an assumed role, a plain profile).
    Config,
    /// Taken from an environment variable at run time (`${NPM_TOKEN}`): the file holds no secret.
    Environment,
}

#[derive(Debug, Serialize, Clone)]
pub struct Item {
    pub name: String,
    pub kind: &'static str,
    pub storage: Storage,
    pub detail: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub provider: &'static str,
    pub observed_at: DateTime<Utc>,
    /// Home-relative files that were read, for "where did this come from".
    pub sources: Vec<String>,
    pub items: Vec<Item>,
}

/// Static, typed errors: no path, file content or parser message is ever serialized.
#[derive(Debug, Serialize, PartialEq)]
pub struct InventoryError {
    pub code: &'static str,
    pub message: &'static str,
}

/// True only when the whole value is a reference (`${NAME}`, or ini's `%(name)s`): anything else,
/// including `${USER}literal`, is treated as written down and never echoed.
fn env_reference(value: &str) -> Option<&str> {
    let v = value.trim().trim_matches(['"', '\'']);
    let name = v
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .or_else(|| v.strip_prefix("%(").and_then(|r| r.strip_suffix(")s")))?;
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    (first_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(name)
}

/// A host name with an optional port, and nothing else: credentials can never pass this.
fn host_ok(host: &str) -> bool {
    let (name, port) = host.split_once(':').unwrap_or((host, ""));
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && port.chars().all(|c| c.is_ascii_digit())
}

/// `scheme://[user[:pass]@]host[:port][/path]` with the user information removed, or None when
/// what is left is not a plain host.
fn strip_userinfo(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host_ok(host).then(|| {
        if path.is_empty() {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}/{path}")
        }
    })
}

fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

/// A regular file (not a symlink) under the size cap, as text.
/// A file in the home folder, through `bulwark_core::homefs`: a regular file, or a link (the file
/// or a folder above it) that stays inside home. A pipe, a link leaving home, or a file over the
/// size cap is not read.
fn read_home_file(home: &Path, path: &Path) -> Option<String> {
    capped(bulwark_core::homefs::open_in_home(home, path).found()?)
}

/// A file that is not under the home folder by design (a system config, or a config folder named
/// by an environment variable). Regular files only; never blocks on a pipe.
fn read_file(path: &Path) -> Option<String> {
    capped(bulwark_core::homefs::open_system_file(path).found()?)
}

fn capped(file: std::fs::File) -> Option<String> {
    if file.metadata().ok()?.len() > MAX_FILE {
        return None;
    }
    bulwark_core::homefs::read_start(file, MAX_FILE)
}

/// A short program or account name that is safe to show: nothing but letters, digits and `._-`.
fn plain_word(s: &str) -> Option<&str> {
    (!s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
    .then_some(s)
}

/// INI-style sections as (header, key → value). Keys are lowercased; comments dropped.
fn ini_sections(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut out: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            out.push((line[1..line.len() - 1].trim().to_string(), BTreeMap::new()));
        } else if let (Some((k, v)), Some(last)) = (line.split_once(['=', ':']), out.last_mut()) {
            last.1
                .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    out
}

/// Where the GitHub CLI keeps `hosts.yml`: `%APPDATA%\\GitHub CLI` on Windows (per gh's config
/// docs), `$XDG_CONFIG_HOME/gh` or `~/.config/gh` elsewhere. `GH_CONFIG_DIR` overrides all, as for gh.
fn gh_hosts(home: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os("GH_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("hosts.yml");
    }
    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(appdata).join("GitHub CLI").join("hosts.yml");
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("gh").join("hosts.yml");
    }
    home.join(".config/gh/hosts.yml")
}

pub fn present(home: &Path, provider: &str) -> bool {
    let exists = |rel: &str| home.join(rel).exists();
    match provider {
        "aws-cli" => exists(".aws/config") || exists(".aws/credentials"),
        "docker" => exists(".docker/config.json"),
        "git" => {
            exists(".gitconfig")
                || exists(".config/git/config")
                || exists(".git-credentials")
                || git_system_configs().iter().any(|p| p.exists())
        }
        "github-cli" => gh_hosts(home).exists(),
        "aws-vault" => exists(".local/bin/aws-vault"),
        "npm" => exists(".npmrc"),
        "pypi" => exists(".pypirc"),
        "kubernetes" => exists(".kube/config"),
        _ => false,
    }
}

pub fn read(home: &Path, provider: &str, now: DateTime<Utc>) -> Result<Inventory, InventoryError> {
    let (provider, sources, mut items) = match provider {
        "aws-cli" => (
            "aws-cli",
            vec![".aws/config", ".aws/credentials"],
            aws_cli(home, now),
        ),
        "docker" => ("docker", vec![".docker/config.json"], docker(home)),
        "git" => (
            "git",
            vec![".gitconfig", ".config/git/config", ".git-credentials"],
            git(home),
        ),
        "github-cli" => ("github-cli", vec![], github_cli(home)),
        "npm" => ("npm", vec![".npmrc"], from_file(home, ".npmrc", npm_items)),
        "pypi" => (
            "pypi",
            vec![".pypirc"],
            from_file(home, ".pypirc", pypi_items),
        ),
        "kubernetes" => (
            "kubernetes",
            vec![".kube/config"],
            from_file(home, ".kube/config", kube_items),
        ),
        _ => {
            return Err(InventoryError {
                code: "failed",
                message: "This secrets manager is not supported.",
            })
        }
    };
    let mut found: Vec<String> = sources
        .iter()
        // Listed only when actually readable, so "read from ~/.npmrc" is never claimed for a file
        // that was skipped (an unreadable file, or a link leaving home).
        .filter(|rel| read_home_file(home, &home.join(rel)).is_some())
        .map(|rel| format!("~/{rel}"))
        .collect();
    if provider == "github-cli" && gh_hosts(home).exists() {
        found.push("GitHub CLI hosts.yml".into());
    }
    if provider == "git" && git_system_configs().iter().any(|p| p.exists()) {
        found.push("system gitconfig".into());
    }
    if found.is_empty() {
        return Err(InventoryError {
            code: "unavailable",
            message: "No configuration for this tool was found in your home folder.",
        });
    }
    items.retain(|i| {
        label_ok(&i.name) && i.detail.len() <= 256 && !i.detail.chars().any(char::is_control)
    });
    items.truncate(MAX_ITEMS);
    Ok(Inventory {
        provider,
        observed_at: now,
        sources: found,
        items,
    })
}

// ---------------------------------------------------------------------------------------------
// AWS CLI

/// SSO token caches as (start URL, expiry). Client-registration files (which carry a
/// `clientSecret`) are skipped; the access token itself is never kept.
fn aws_sso_expiries(home: &Path) -> Vec<(String, DateTime<Utc>)> {
    let dir = home.join(".aws/sso/cache");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let json_files = entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .take(MAX_CACHE_FILES);
    for entry in json_files {
        let path: PathBuf = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(text) = read_home_file(home, &path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if json.get("clientSecret").is_some() || json.get("accessToken").is_none() {
            continue;
        }
        let (Some(url), Some(exp)) = (
            json.get("startUrl").and_then(|v| v.as_str()),
            json.get("expiresAt").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let parsed = DateTime::parse_from_rfc3339(exp)
            .map(|d| d.with_timezone(&Utc))
            .or_else(|_| {
                // Older CLIs wrote "2026-01-01T00:00:00UTC".
                DateTime::parse_from_rfc3339(&exp.replace("UTC", "Z"))
                    .map(|d| d.with_timezone(&Utc))
            });
        if let Ok(expiry) = parsed {
            out.push((url.to_string(), expiry));
        }
    }
    out
}

pub(crate) fn aws_cli_items(
    config: &str,
    credentials: &str,
    sso: &[(String, DateTime<Utc>)],
    now: DateTime<Utc>,
) -> Vec<Item> {
    let sections = ini_sections(config);
    let sessions: BTreeMap<&str, &BTreeMap<String, String>> = sections
        .iter()
        .filter_map(|(h, kv)| h.strip_prefix("sso-session ").map(|n| (n.trim(), kv)))
        .collect();
    let static_in_credentials: BTreeMap<String, bool> = ini_sections(credentials)
        .into_iter()
        .map(|(h, kv)| (h, kv.contains_key("aws_access_key_id")))
        .collect();
    let mut items = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (header, kv) in &sections {
        let name = if header == "default" {
            "default"
        } else if let Some(n) = header.strip_prefix("profile ") {
            n.trim()
        } else {
            continue;
        };
        seen.insert(name.to_string());
        let start_url = kv.get("sso_start_url").cloned().or_else(|| {
            kv.get("sso_session")
                .and_then(|s| sessions.get(s.as_str()))
                .and_then(|s| s.get("sso_start_url").cloned())
        });
        let (storage, detail, expires_at) = if kv.contains_key("aws_access_key_id")
            || static_in_credentials.get(name).copied().unwrap_or(false)
        {
            (Storage::Plaintext, "Access key in a file".to_string(), None)
        } else if let Some(url) = start_url {
            let expiry = sso.iter().filter(|(u, _)| *u == url).map(|(_, e)| *e).max();
            let detail = match expiry {
                Some(e) if e > now => "IAM Identity Center · signed in",
                Some(_) => "IAM Identity Center · session expired",
                None => "IAM Identity Center · not signed in",
            };
            (Storage::Session, detail.to_string(), expiry)
        } else if kv.contains_key("credential_process") {
            (
                Storage::Helper,
                "credential_process helper".to_string(),
                None,
            )
        } else if kv.contains_key("role_arn") {
            let mfa = if kv.contains_key("mfa_serial") {
                " with MFA"
            } else {
                ""
            };
            (Storage::Config, format!("Assumes a role{mfa}"), None)
        } else {
            (Storage::Config, "Settings only".to_string(), None)
        };
        items.push(Item {
            name: name.to_string(),
            kind: "profile",
            storage,
            detail,
            expires_at,
        });
    }
    for (name, has_key) in static_in_credentials {
        if has_key && !seen.contains(&name) {
            items.push(Item {
                name,
                kind: "profile",
                storage: Storage::Plaintext,
                detail: "Access key in a file".into(),
                expires_at: None,
            });
        }
    }
    items
}

fn aws_cli(home: &Path, now: DateTime<Utc>) -> Vec<Item> {
    aws_cli_items(
        &read_home_file(home, &home.join(".aws/config")).unwrap_or_default(),
        &read_home_file(home, &home.join(".aws/credentials")).unwrap_or_default(),
        &aws_sso_expiries(home),
        now,
    )
}

// ---------------------------------------------------------------------------------------------
// Docker

/// A Docker credential helper's name, when it is a plain word.
fn helper_label(name: &str) -> String {
    match plain_word(name) {
        Some(n) => format!("docker-credential-{n}"),
        None => "A credential helper".to_string(),
    }
}

pub(crate) fn docker_items(text: &str) -> Vec<Item> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let store = json
        .get("credsStore")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let helpers: BTreeMap<String, String> = json
        .get("credHelpers")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|h| (k.clone(), h.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let mut items = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if let Some(auths) = json.get("auths").and_then(|v| v.as_object()) {
        for (registry, entry) in auths {
            seen.insert(registry.clone());
            let inline = ["auth", "identitytoken"].iter().any(|k| {
                entry
                    .get(k)
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
            });
            let (storage, detail) = if inline {
                (
                    Storage::Plaintext,
                    "Login stored in config.json".to_string(),
                )
            } else if let Some(h) = helpers.get(registry).map(String::as_str).or(store) {
                (Storage::Keychain, helper_label(h))
            } else {
                (Storage::Config, "No stored login".to_string())
            };
            items.push(Item {
                name: registry.clone(),
                kind: "registry",
                storage,
                detail,
                expires_at: None,
            });
        }
    }
    for (registry, helper) in helpers {
        if !seen.contains(&registry) {
            items.push(Item {
                name: registry,
                kind: "registry",
                storage: Storage::Keychain,
                detail: helper_label(&helper),
                expires_at: None,
            });
        }
    }
    items
}

fn docker(home: &Path) -> Vec<Item> {
    read_home_file(home, &home.join(".docker/config.json"))
        .map(|t| docker_items(&t))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Git

fn git_helper_storage(helper: &str) -> Storage {
    let name = helper.split_whitespace().next().unwrap_or("");
    let name = name
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .trim_start_matches("git-credential-");
    match name {
        "store" => Storage::Plaintext,
        "cache" => Storage::Memory,
        "libsecret" | "osxkeychain" | "manager" | "manager-core" | "wincred" | "gnome-keyring" => {
            Storage::Keychain
        }
        _ => Storage::Helper,
    }
}

/// Every `helper` value per `[credential …]` section, in order. Git runs all of them; an empty
/// value clears the ones before it.
fn git_helpers(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            out.push((line[1..line.len() - 1].trim().to_string(), Vec::new()));
        } else if let (Some((k, v)), Some(last)) = (line.split_once('='), out.last_mut()) {
            if k.trim().eq_ignore_ascii_case("helper") {
                let v = v.trim().trim_matches('"');
                if v.is_empty() {
                    last.1.clear();
                } else {
                    last.1.push(v.to_string());
                }
            }
        }
    }
    out
}

pub(crate) fn git_items(configs: &[String], credentials: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for text in configs {
        for (header, helpers) in git_helpers(text) {
            let lower = header.to_ascii_lowercase();
            let Some(rest) = lower.strip_prefix("credential") else {
                continue;
            };
            let raw_scope = rest.trim().trim_matches('"');
            // A scope URL may carry user:password@ — keep the host and path only.
            let scope = if raw_scope.is_empty() {
                String::new()
            } else {
                match strip_userinfo(raw_scope) {
                    Some(s) => s,
                    None => continue,
                }
            };
            for helper in &helpers {
                let helper = helper.as_str();
                // Shell helpers ("!f() { … }") can embed anything; show only that one is used.
                let detail = if helper.starts_with('!') {
                    "Shell command helper".to_string()
                } else {
                    helper.split_whitespace().next().unwrap_or("").to_string()
                };
                items.push(Item {
                    name: if scope.is_empty() {
                        "All hosts".into()
                    } else {
                        scope.clone()
                    },
                    kind: "helper",
                    storage: if helper.starts_with('!') {
                        Storage::Helper
                    } else {
                        git_helper_storage(helper)
                    },
                    detail,
                    expires_at: None,
                });
            }
        }
    }
    let mut hosts = std::collections::BTreeSet::new();
    for line in credentials
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        // https://user:token@host/path → host only. A line without user@ or with anything but a
        // plain host left over is dropped rather than risk showing part of a credential.
        let Some((_, rest)) = line.split_once("://") else {
            continue;
        };
        let Some((_, after_at)) = rest.rsplit_once('@') else {
            continue;
        };
        let host = after_at.split('/').next().unwrap_or("");
        if host_ok(host) {
            hosts.insert(host.to_string());
        }
    }
    items.extend(hosts.into_iter().map(|h| Item {
        name: h,
        kind: "host",
        storage: Storage::Plaintext,
        detail: "Saved in ~/.git-credentials".into(),
        expires_at: None,
    }));
    items
}

/// Git's system-level config files, where installers set the default credential helper (Git for
/// Windows sets `manager`; Apple's git sets `osxkeychain`). Read passively; git is never run.
fn git_system_configs() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gitconfig")];
    #[cfg(target_os = "macos")]
    paths.extend([
        PathBuf::from("/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig"),
        PathBuf::from("/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig"),
    ]);
    #[cfg(windows)]
    for var in ["ProgramFiles", "ProgramW6432"] {
        if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            paths.push(PathBuf::from(dir).join("Git").join("etc").join("gitconfig"));
        }
    }
    paths.dedup();
    paths
}

fn git(home: &Path) -> Vec<Item> {
    let user: Vec<String> = [".gitconfig", ".config/git/config"]
        .iter()
        .filter_map(|rel| read_home_file(home, &home.join(rel)))
        .collect();
    let system: Vec<String> = git_system_configs()
        .iter()
        .filter_map(|p| read_file(p))
        .collect();
    let mut items = git_items(&system, "");
    for item in &mut items {
        item.name = format!("{} (system)", item.name);
    }
    items.extend(git_items(
        &user,
        &read_home_file(home, &home.join(".git-credentials")).unwrap_or_default(),
    ));
    items
}

// ---------------------------------------------------------------------------------------------
// GitHub CLI

/// `hosts.yml` is a small, flat YAML: top-level host keys, then indented fields. A token field
/// means the CLI fell back to storing it in the file; without one it lives in the keychain.
pub(crate) fn github_cli_items(text: &str) -> Vec<Item> {
    let mut items: Vec<(String, Option<String>, bool)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        if indent == 0 && value.is_empty() {
            items.push((key.trim().to_string(), None, false));
        } else if let Some(last) = items.last_mut() {
            match key.trim() {
                "user" if !value.is_empty() && indent <= 4 => last.1 = Some(value.to_string()),
                "oauth_token" if !value.is_empty() => last.2 = true,
                _ => {}
            }
        }
    }
    items
        .into_iter()
        .map(|(host, user, plaintext)| Item {
            name: host,
            kind: "host",
            storage: if plaintext {
                Storage::Plaintext
            } else {
                Storage::Keychain
            },
            detail: user
                .and_then(|u| plain_word(&u).map(|u| format!("Signed in as {u}")))
                .unwrap_or_else(|| "Account not shown".into()),
            expires_at: None,
        })
        .collect()
}

fn github_cli(home: &Path) -> Vec<Item> {
    read_home_file(home, &gh_hosts(home))
        .or_else(|| read_file(&gh_hosts(home)))
        .map(|t| github_cli_items(&t))
        .unwrap_or_default()
}

fn from_file(home: &Path, rel: &str, parse: fn(&str) -> Vec<Item>) -> Vec<Item> {
    read_home_file(home, &home.join(rel))
        .map(|t| parse(&t))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// npm, PyPI, Kubernetes

/// Registry logins in `.npmrc` (`//host/path/:_authToken=…`): host only, and whether the value is
/// written out or taken from the environment.
pub(crate) fn npm_items(text: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(field) = ["_authToken", "_auth", "_password"]
            .iter()
            .find(|f| key.ends_with(&format!(":{f}")))
        else {
            continue;
        };
        let scope = key
            .trim_end_matches(&format!(":{field}"))
            .trim_start_matches("//")
            .trim_end_matches('/');
        let host = scope.split('/').next().unwrap_or(scope);
        let value = value.trim().trim_matches('"');
        // A registry key can carry `user:pass@host`; only a plain host is ever shown.
        if !host_ok(host) || value.is_empty() {
            continue;
        }
        let (storage, detail) = if let Some(var) = env_reference(value) {
            (Storage::Environment, format!("Token from ${{{var}}}"))
        } else {
            (Storage::Plaintext, "Token written in .npmrc".to_string())
        };
        items.push(Item {
            name: host.to_string(),
            kind: "registry",
            storage,
            detail,
            expires_at: None,
        });
    }
    items
}

/// Package indexes in `.pypirc`. No password means twine asks the keyring (or prompts).
pub(crate) fn pypi_items(text: &str) -> Vec<Item> {
    ini_sections(text)
        .into_iter()
        .filter(|(h, kv)| {
            h != "distutils"
                && (kv.contains_key("username")
                    || kv.contains_key("password")
                    || kv.contains_key("repository"))
        })
        .map(|(name, kv)| {
            let (storage, detail) = match kv.get("password").map(|p| p.trim()) {
                Some(p) if env_reference(p).is_some() => (
                    Storage::Environment,
                    "Password from an interpolated value".to_string(),
                ),
                Some(p) if !p.is_empty() => (
                    Storage::Plaintext,
                    "Password written in .pypirc".to_string(),
                ),
                _ => (
                    Storage::Config,
                    "No password stored; twine uses your keyring or asks".to_string(),
                ),
            };
            Item {
                name,
                kind: "index",
                storage,
                detail,
                expires_at: None,
            }
        })
        .collect()
}

/// Users in a kubeconfig and how each authenticates. Only key names are inspected; embedded
/// tokens and key data are recognised and skipped, never kept.
pub(crate) fn kube_items(text: &str) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut in_users = false;
    // Indentation of the users list's own items; deeper "- name:" lines (exec env) are not users.
    let mut item_indent: Option<usize> = None;
    let mut current: Option<(String, Option<(Storage, String)>)> = None;
    let finish = |items: &mut Vec<Item>, current: Option<(String, Option<(Storage, String)>)>| {
        if let Some((name, auth)) = current {
            let (storage, detail) =
                auth.unwrap_or((Storage::Config, "No credentials in this file".into()));
            items.push(Item {
                name,
                kind: "user",
                storage,
                detail,
                expires_at: None,
            });
        }
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        // A top-level key starts a new section; a list item at column 0 ("- name: x", as kubectl
        // writes them) still belongs to the section above it.
        if indent == 0 && !trimmed.starts_with("- ") {
            in_users = trimmed.starts_with("users:");
            item_indent = None;
            if !in_users {
                finish(&mut items, current.take());
            }
            continue;
        }
        if !in_users {
            continue;
        }
        let user_item = trimmed.starts_with("- ") && *item_indent.get_or_insert(indent) == indent;
        if let Some(rest) = trimmed.strip_prefix("- name:").filter(|_| user_item) {
            finish(&mut items, current.take());
            current = Some((rest.trim().trim_matches(['"', '\'']).to_string(), None));
            continue;
        }
        let Some((key, value)) = trimmed.trim_start_matches("- ").split_once(':') else {
            continue;
        };
        let value = value.trim();
        let Some((_, auth)) = current.as_mut() else {
            continue;
        };
        let found = match key.trim() {
            // auth-provider config keeps long-lived OIDC tokens and client secrets in the file too.
            "token" | "client-key-data" | "password" | "id-token" | "refresh-token"
            | "access-token" | "client-secret"
                if !value.is_empty() && value != "null" =>
            {
                Some((
                    Storage::Plaintext,
                    "Credential embedded in the kubeconfig".to_string(),
                ))
            }
            "exec" => Some((Storage::Helper, "Exec plugin".to_string())),
            "command" if matches!(auth, Some((Storage::Helper, _))) => {
                // The program's name only: never its arguments, which can hold a token.
                let first = value
                    .trim_matches(['"', '\''])
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                let program = first.rsplit(['/', '\\']).next().unwrap_or("");
                Some((
                    Storage::Helper,
                    match plain_word(program) {
                        Some(p) => format!("Exec plugin: {p}"),
                        None => "Exec plugin".to_string(),
                    },
                ))
            }
            "auth-provider" => Some((Storage::Helper, "Auth provider plugin".to_string())),
            "client-key" | "tokenFile" if !value.is_empty() => {
                Some((Storage::Config, "Key in a separate file".to_string()))
            }
            _ => None,
        };
        // An embedded secret outranks anything else found for the same user.
        if let Some(f) = found {
            if !matches!(auth, Some((Storage::Plaintext, _))) {
                *auth = Some(f);
            }
        }
    }
    finish(&mut items, current.take());
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built at runtime so no credential-shaped literal sits in the source.
    fn secret() -> String {
        format!("tok{}", "Z9y8".repeat(8))
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn aws_profiles_are_classified_without_keeping_values() {
        let s = secret();
        let config = format!(
            "[default]\nregion = us-east-1\n[profile dev]\nsso_session = corp\nsso_account_id = 1\n\
             [sso-session corp]\nsso_start_url = https://corp.example/start\n\
             [profile ci]\naws_access_key_id = {s}\n[profile admin]\nrole_arn = arn:aws:iam::1:role/a\nmfa_serial = arn:x\n\
             [profile op]\ncredential_process = op read x\n"
        );
        let creds = format!("[legacy]\naws_access_key_id = {s}\naws_secret_access_key = {s}\n");
        let sso = vec![(
            "https://corp.example/start".to_string(),
            now() + chrono::Duration::hours(2),
        )];
        let items = aws_cli_items(&config, &creds, &sso, now());
        let by: BTreeMap<_, _> = items.iter().map(|i| (i.name.as_str(), i)).collect();
        assert_eq!(by["dev"].storage, Storage::Session);
        assert_eq!(by["dev"].detail, "IAM Identity Center · signed in");
        assert!(by["dev"].expires_at.is_some());
        assert_eq!(by["ci"].storage, Storage::Plaintext);
        assert_eq!(by["legacy"].storage, Storage::Plaintext);
        assert_eq!(by["admin"].detail, "Assumes a role with MFA");
        assert_eq!(by["op"].storage, Storage::Helper);
        assert_eq!(by["default"].storage, Storage::Config);
        let json = serde_json::to_string(&items).unwrap();
        assert!(
            !json.contains(&s) && !json.contains("corp.example"),
            "{json}"
        );
    }

    #[test]
    fn docker_registries_show_where_each_login_lives() {
        let s = secret();
        let text = format!(
            r#"{{"auths":{{"ghcr.io":{{"auth":"{s}"}},"docker.io":{{}}}},"credsStore":"secretservice","credHelpers":{{"123.dkr.ecr.aws":"ecr-login"}}}}"#
        );
        let items = docker_items(&text);
        let by: BTreeMap<_, _> = items.iter().map(|i| (i.name.as_str(), i)).collect();
        assert_eq!(by["ghcr.io"].storage, Storage::Plaintext);
        assert_eq!(by["docker.io"].detail, "docker-credential-secretservice");
        assert_eq!(by["123.dkr.ecr.aws"].detail, "docker-credential-ecr-login");
        assert!(!serde_json::to_string(&items).unwrap().contains(&s));
        assert!(docker_items("not json").is_empty());
    }

    #[test]
    fn git_helpers_and_stored_hosts_keep_hosts_only() {
        let s = secret();
        let config = "[credential]\n\thelper = store\n[credential \"https://github.com\"]\n\thelper = !gh auth git-credential\n[credential \"https://gitlab.example\"]\n\thelper = libsecret\n".to_string();
        let creds = format!("https://me:{s}@github.com\nhttps://bot:{s}@gitlab.example/group\n");
        let items = git_items(&[config], &creds);
        let json = serde_json::to_string(&items).unwrap();
        assert!(
            !json.contains(&s) && !json.contains("\"me") && !json.contains("bot"),
            "{json}"
        );
        assert_eq!(items[0].storage, Storage::Plaintext);
        assert_eq!(items[1].detail, "Shell command helper");
        assert_eq!(items[2].storage, Storage::Keychain);
        assert!(items
            .iter()
            .any(|i| i.kind == "host" && i.name == "gitlab.example"));
    }

    #[test]
    fn github_cli_tells_file_tokens_from_keychain_tokens() {
        let s = secret();
        let text = format!(
            "github.com:\n    users:\n        octo:\n    git_protocol: https\n    user: octo\nghe.example:\n    oauth_token: {s}\n    user: dev\n"
        );
        let items = github_cli_items(&text);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].storage, Storage::Keychain);
        assert_eq!(items[0].detail, "Signed in as octo");
        assert_eq!(items[1].storage, Storage::Plaintext);
        assert!(!serde_json::to_string(&items).unwrap().contains(&s));
    }

    #[test]
    fn npm_logins_show_host_and_whether_the_token_is_written_down() {
        let s = secret();
        let text = format!(
            "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={s}\n//npm.pkg.github.com/:_authToken=${{GH_TOKEN}}\n"
        );
        let items = npm_items(&text);
        assert_eq!(items.len(), 2);
        assert_eq!(
            (items[0].name.as_str(), items[0].storage),
            ("registry.npmjs.org", Storage::Plaintext)
        );
        assert_eq!(
            (items[1].name.as_str(), items[1].storage),
            ("npm.pkg.github.com", Storage::Environment)
        );
        assert!(!serde_json::to_string(&items).unwrap().contains(&s));
    }

    #[test]
    fn pypi_indexes_tell_stored_passwords_from_keyring_use() {
        let s = secret();
        let text = format!("[distutils]\nindex-servers = pypi testpypi\n[pypi]\nusername = __token__\npassword = {s}\n[testpypi]\nrepository = https://test.pypi.org/legacy/\nusername = __token__\n");
        let items = pypi_items(&text);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].storage, Storage::Plaintext);
        assert_eq!(items[1].storage, Storage::Config);
        assert!(!serde_json::to_string(&items).unwrap().contains(&s));
    }

    #[test]
    fn kube_users_are_classified_by_how_they_authenticate() {
        let s = secret();
        let text = format!(
            "apiVersion: v1\nclusters:\n- name: dev\n  cluster:\n    server: https://k.example\nusers:\n- name: admin\n  user:\n    token: {s}\n- name: eks\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token]\n- name: certfile\n  user:\n    client-certificate: /home/me/c.crt\n    client-key: /home/me/c.key\ncurrent-context: dev\n"
        );
        let items = kube_items(&text);
        let by: BTreeMap<_, _> = items.iter().map(|i| (i.name.as_str(), i)).collect();
        assert_eq!(by.len(), 3, "{items:?}");
        assert_eq!(by["admin"].storage, Storage::Plaintext);
        assert_eq!(by["eks"].detail, "Exec plugin: aws");
        assert_eq!(by["certfile"].detail, "Key in a separate file");
        assert!(!serde_json::to_string(&items).unwrap().contains(&s));
    }

    #[test]
    fn hostile_inputs_never_put_a_secret_into_a_name_or_detail() {
        let s = secret();
        let npm = npm_items(&format!("//reg.example/:_authToken=${{NPM_USER}}{s}\n"));
        assert_eq!(npm[0].storage, Storage::Plaintext);
        let creds =
            format!("https://me:pa/{s}@host.example\nhttps://{s}\nhttps://u:{s}@ok.example/x\n");
        let config = format!("[credential \"https://user:{s}@scoped.example\"]\n\thelper = store\n\thelper = libsecret\n");
        let git = git_items(&[config], &creds);
        let json = serde_json::to_string(&(npm, &git)).unwrap();
        assert!(!json.contains(&s), "{json}");
        assert!(git.iter().any(|i| i.name == "https://scoped.example"));
        assert_eq!(
            git.iter().filter(|i| i.kind == "helper").count(),
            2,
            "every helper value counts"
        );
        assert!(git.iter().any(|i| i.name == "ok.example"));
    }

    #[test]
    fn kube_exec_env_entries_are_not_users_and_oidc_tokens_count() {
        let s = secret();
        let text = format!(
            "users:\n- name: eks\n  user:\n    exec:\n      command: aws\n      env:\n      - name: AWS_PROFILE\n        value: dev\n- name: oidc\n  user:\n    auth-provider:\n      name: oidc\n      config:\n        id-token: {s}\n"
        );
        let items = kube_items(&text);
        assert_eq!(items.len(), 2, "{items:?}");
        assert_eq!(items[0].detail, "Exec plugin: aws");
        assert_eq!(items[1].storage, Storage::Plaintext);
    }

    #[test]
    fn pypirc_colon_separator_matches_the_scan_rule() {
        let s = secret();
        assert_eq!(
            pypi_items(&format!("[pypi]\nusername: __token__\npassword: {s}\n"))[0].storage,
            Storage::Plaintext
        );
    }

    #[cfg(unix)]
    #[test]
    fn links_inside_home_are_read_and_links_out_of_home_are_not() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("dotfiles")).unwrap();
        std::fs::write(
            home.path().join("dotfiles/npmrc"),
            "//a.example/:_authToken=${T}\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            home.path().join("dotfiles/npmrc"),
            home.path().join(".npmrc"),
        )
        .unwrap();
        assert_eq!(read(home.path(), "npm", now()).unwrap().items.len(), 1);
        std::fs::write(outside.path().join("pypirc"), "[pypi]\nusername = u\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("pypirc"), home.path().join(".pypirc"))
            .unwrap();
        assert_eq!(
            read(home.path(), "pypi", now()).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn names_shown_from_config_files_are_plain_words_or_generic() {
        let s = secret();
        // npm: credentials in the registry key; kube: a token in the command's arguments;
        // docker and gh: a helper or account name with control characters.
        assert!(npm_items(&format!("//user:{s}@reg.example/:_authToken=${{T}}\n")).is_empty());
        let kube = kube_items(&format!(
            "users:\n- name: a\n  user:\n    exec:\n      command: /usr/bin/sh -c 'curl -H token:{s}'\n"
        ));
        assert_eq!(kube[0].detail, "Exec plugin: sh");
        let docker =
            docker_items("{\"auths\":{\"r.example\":{}},\"credsStore\":\"x\\u001b[2J y\"}");
        assert_eq!(docker[0].detail, "A credential helper");
        let gh = github_cli_items("github.com:\n    user: me\u{1b}[31m\n");
        assert_eq!(gh[0].detail, "Account not shown");
        let json = serde_json::to_string(&(kube, docker, gh)).unwrap();
        assert!(!json.contains(&s) && !json.contains("\\u001b"), "{json}");
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_link_out_of_home_or_a_pipe_is_not_read() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join(".docker")).unwrap();
        std::fs::write(
            outside.path().join(".docker/config.json"),
            "{\"auths\":{\"r.example\":{\"auth\":\"x\"}}}",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path().join(".docker"), home.path().join(".docker"))
            .unwrap();
        assert_eq!(
            read(home.path(), "docker", now()).unwrap_err().code,
            "unavailable"
        );
        let fifo = std::ffi::CString::new(home.path().join(".npmrc").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert_eq!(
            read(home.path(), "npm", now()).unwrap_err().code,
            "unavailable"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn a_missing_tool_is_unavailable_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let err = read(dir.path(), "docker", now()).unwrap_err();
        assert_eq!(err.code, "unavailable");
        assert!(!present(dir.path(), "github-cli"));
    }

    /// Manual smoke test on a real home directory: prints counts only (no names, no values) and
    /// asserts nothing that looks like a key reaches the serialized inventory.
    #[test]
    #[ignore = "reads the real home directory; run by hand"]
    fn real_home_smoke() {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap();
        for p in [
            "aws-cli",
            "docker",
            "git",
            "github-cli",
            "npm",
            "pypi",
            "kubernetes",
        ] {
            match read(&home, p, Utc::now()) {
                Ok(inv) => {
                    let json = serde_json::to_string(&inv).unwrap();
                    for marker in [
                        "AKIA",
                        "ASIA",
                        "ghp_",
                        "gho_",
                        "github_pat_",
                        "sk-",
                        "glpat-",
                    ] {
                        assert!(
                            !json.contains(marker),
                            "{p}: serialized inventory contains {marker}"
                        );
                    }
                    let mut counts = BTreeMap::new();
                    for i in &inv.items {
                        *counts.entry(format!("{:?}", i.storage)).or_insert(0) += 1;
                    }
                    println!("{p}: {} items {:?}", inv.items.len(), counts);
                }
                Err(e) => println!("{p}: {}", e.code),
            }
        }
    }
}

//! Developer credential stores in the scanning user's home: cloud keys, registry logins, package
//! tokens. One fact row per store that exists, carrying only metadata, flags and counts — never a
//! byte of the credential itself, so nothing secret can reach a finding, a log or the database.
//!
//! Three-state per the collector invariant: a kind-specific field (`long_lived_keys`,
//! `inline_auths`, ...) is emitted only when the file was actually read and parsed. If it couldn't
//! be, the field is omitted, the rule's condition raises `MissingField`, and the scan reports a
//! collector error rather than a confident "no plaintext credentials here".

use super::Collector;
use crate::models::Fact;
use regex::Regex;
use serde_json::Value;
use std::path::Path;
use std::sync::OnceLock;

pub struct CredentialStoresCollector;

/// Known stores, as (kind, path relative to the home directory).
const STORES: &[(&str, &str)] = &[
    ("aws_credentials", ".aws/credentials"),
    ("git_credentials", ".git-credentials"),
    ("docker_config", ".docker/config.json"),
    ("npmrc", ".npmrc"),
    ("pypirc", ".pypirc"),
    ("netrc", ".netrc"),
    ("kube_config", ".kube/config"),
    (
        "gcloud_adc",
        ".config/gcloud/application_default_credentials.json",
    ),
    ("gcloud_credentials_db", ".config/gcloud/credentials.db"),
    ("huggingface_token", ".cache/huggingface/token"),
    ("huggingface_token", ".huggingface/token"),
    ("railway_config", ".railway/config.json"),
    // Developer tools that fall back to a plain token file (CRED-009). Windows keeps several under
    // %APPDATA%, which is AppData/Roaming in the home folder.
    ("gh_hosts", ".config/gh/hosts.yml"),
    ("gh_hosts", "AppData/Roaming/GitHub CLI/hosts.yml"),
    ("cargo_credentials", ".cargo/credentials.toml"),
    ("cargo_credentials", ".cargo/credentials"),
    (
        "terraform_credentials",
        ".terraform.d/credentials.tfrc.json",
    ),
    (
        "terraform_credentials",
        "AppData/Roaming/terraform.d/credentials.tfrc.json",
    ),
    ("gem_credentials", ".gem/credentials"),
    ("composer_auth", ".config/composer/auth.json"),
    ("composer_auth", ".composer/auth.json"),
    ("composer_auth", "AppData/Roaming/Composer/auth.json"),
    ("netrc", "_netrc"),
    // Shell history: commands typed with a key on the line (CRED-010). Only the most recent part
    // of a large file is read. The PowerShell paths are PSReadLine's documented defaults.
    ("shell_history", ".bash_history"),
    ("shell_history", ".zsh_history"),
    ("shell_history", ".zhistory"),
    ("shell_history", ".histfile"),
    ("shell_history", ".local/share/fish/fish_history"),
    (
        "shell_history",
        ".local/share/powershell/PSReadLine/ConsoleHost_history.txt",
    ),
    (
        "shell_history",
        "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    ),
    // Read for long-lived keys only; a normal ~/.aws/config holds no secret and is world-readable.
    ("aws_config", ".aws/config"),
    // Shell startup files: read for secrets exported as literals. World-readable by default, so
    // their permissions are not a finding (CRED-004 excludes this kind).
    ("shell_startup", ".bashrc"),
    ("shell_startup", ".bash_profile"),
    ("shell_startup", ".profile"),
    ("shell_startup", ".zshrc"),
    ("shell_startup", ".zprofile"),
    ("shell_startup", ".zshenv"),
    ("shell_startup", ".config/fish/config.fish"),
    // PowerShell profiles: PowerShell 7 and Windows PowerShell on Windows, pwsh elsewhere.
    (
        "shell_startup",
        "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    ),
    ("shell_startup", "Documents/PowerShell/profile.ps1"),
    (
        "shell_startup",
        "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
    ),
    ("shell_startup", "Documents/WindowsPowerShell/profile.ps1"),
    (
        "shell_startup",
        ".config/powershell/Microsoft.PowerShell_profile.ps1",
    ),
];

/// Long-lived IAM user keys start with `AKIA`; temporary STS keys start with `ASIA` and are not
/// what this check is about.
fn aws_long_lived_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?im)^\s*aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}\s*$").expect("valid regex")
    })
}

/// Number of long-lived access key IDs in an AWS credentials file.
pub fn count_aws_long_lived_keys(text: &str) -> usize {
    aws_long_lived_key_re().find_iter(text).count()
}

/// Number of stored credential lines in a `git-credential-store` file (one URL per line).
pub fn count_git_credential_entries(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count()
}

/// For a Docker `config.json`: (registry logins stored inline, whether a `credsStore` is set).
/// `None` when the file isn't valid JSON, so the caller can leave the facts undetermined.
pub fn docker_config_summary(text: &str) -> Option<(usize, bool)> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let inline = json
        .get("auths")
        .and_then(|a| a.as_object())
        .map(|auths| {
            auths
                .values()
                .filter(|entry| {
                    ["auth", "identitytoken"].iter().any(|k| {
                        entry
                            .get(k)
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.is_empty())
                    })
                })
                .count()
        })
        .unwrap_or(0);
    let creds_store = json
        .get("credsStore")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    Some((inline, creds_store))
}

fn shell_assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `export NAME=value`, `NAME=value`, fish `set -gx NAME value`, csh `setenv NAME value`.
        Regex::new(
            // `NAME=value` (optionally after `export`) needs the `=`; only fish/csh forms take a
            // space, so an ordinary command such as `load_api_key prod-key-2024` never matches.
            r#"^\s*(?:(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=|(?:set\s+-[a-zA-Z]*x[a-zA-Z]*|setenv)\s+([A-Za-z_][A-Za-z0-9_]*)\s+)(['"]?)([^'"\s]*)['"]?\s*(?:#.*)?$"#,
        )
        .expect("valid regex")
    })
}

fn powershell_assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `$env:NAME = 'value'` and `[Environment]::SetEnvironmentVariable('NAME', 'value', ...)`.
        Regex::new(
            r#"(?i)^\s*(?:\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*|\[(?:System\.)?Environment\]::SetEnvironmentVariable\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*)(['"])([^'"]*)['"]"#,
        )
        .expect("valid regex")
    })
}

/// Whether an environment variable name says it holds a secret.
fn secret_like_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const MARKERS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
    ];
    const NOT_A_VALUE: &[&str] = &[
        "_FILE",
        "_PATH",
        "_DIR",
        "_URL",
        "_HELPER",
        "_CMD",
        "_COMMAND",
        "_TYPE",
        "_REGION",
        "_NAME",
        "_ENDPOINT",
        "_HOST",
        "_ID",
    ];
    MARKERS.iter().any(|m| upper.contains(m)) && !NOT_A_VALUE.iter().any(|s| upper.ends_with(s))
}

/// Whether a literal looks like a real credential rather than a flag, path, reference or
/// placeholder: long, mixed letters and digits, no expansion, no path.
fn credential_like_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.len() >= 16
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && value.chars().any(|c| c.is_ascii_digit())
        && !value.contains('$')
        && !value.contains('`')
        && !value.starts_with('/')
        && !value.starts_with('~')
        && !value.starts_with('\\')
        && !(value.len() > 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic())
        && !value.starts_with('<')
        && ![
            "changeme",
            "example",
            "placeholder",
            "your_",
            "your-",
            "xxxx",
            "redacted",
            "dummy",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// Names (never values) of secret-like variables a shell startup file sets to a literal.
pub fn exported_secret_names(text: &str) -> Vec<String> {
    let lines = || text.lines().filter(|l| !l.trim_start().starts_with('#'));
    let mut names: Vec<String> = lines()
        .filter_map(|l| shell_assignment_re().captures(l))
        .filter_map(|c| {
            let name = c.get(1).or_else(|| c.get(2))?.as_str();
            (secret_like_name(name) && credential_like_value(&c[4])).then(|| name.to_string())
        })
        .collect();
    names.extend(
        lines()
            .filter_map(|l| powershell_assignment_re().captures(l))
            .filter_map(|c| {
                let name = c.get(1).or_else(|| c.get(2))?.as_str();
                (secret_like_name(name) && credential_like_value(&c[4])).then(|| name.to_string())
            }),
    );
    names.sort();
    names.dedup();
    names
}

fn env_reference_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Only a value that is *entirely* a reference (`${NAME}`, or ini's `%(name)s`) holds no secret;
    // `${USER}hunter2` is a reference followed by a literal and counts as plain text.
    RE.get_or_init(|| {
        Regex::new(r"^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|%\([A-Za-z_][A-Za-z0-9_]*\)s)$")
            .expect("valid regex")
    })
}

/// True when a configured value is only a reference to an environment variable.
pub fn is_env_reference(value: &str) -> bool {
    env_reference_re().is_match(value.trim().trim_matches(['"', '\'']))
}

/// npm auth entries (`_authToken`, `_auth`, `_password`) holding a literal rather than a `${VAR}`
/// reference.
pub fn count_npm_plaintext_tokens(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.split_once('='))
        .filter(|(k, v)| {
            let key = k.trim();
            let value = v.trim().trim_matches('"');
            (key.ends_with("_authToken") || key.ends_with("_auth") || key.ends_with("_password"))
                && !value.is_empty()
                && !is_env_reference(value)
        })
        .count()
}

/// `password` entries in a `.pypirc` holding a literal (not an interpolation).
pub fn count_pypirc_passwords(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.split_once(['=', ':']))
        .filter(|(k, v)| {
            let value = v.trim();
            k.trim().eq_ignore_ascii_case("password")
                && !value.is_empty()
                && !is_env_reference(value)
        })
        .count()
}

/// Static credentials embedded in a kubeconfig: bearer tokens, client key data, basic-auth
/// passwords. Exec plugins and file references (`client-key: /path`) are not counted.
pub fn count_kube_static_credentials(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .map(|l| l.trim_start_matches("- "))
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, v)| {
            let value = v.trim().trim_matches(['"', '\'']);
            // auth-provider config holds long-lived OIDC tokens and client secrets as well.
            matches!(
                k.trim(),
                "token"
                    | "client-key-data"
                    | "password"
                    | "id-token"
                    | "refresh-token"
                    | "access-token"
                    | "client-secret"
            ) && !value.is_empty()
                && value != "null"
        })
        .count()
}

/// What a shell history file gives away: how many keys, which services, and where (never a value).
#[derive(Debug, PartialEq, Eq, Default)]
pub struct HistorySecrets {
    pub count: usize,
    /// Distinct service names, e.g. "GitHub Personal Access Token".
    pub kinds: Vec<String>,
    /// Line numbers of the first few, for finding them in the file.
    pub lines: Vec<usize>,
}

/// Keys typed into a shell command and saved in its history. Uses the high-confidence provider
/// patterns only (a recognisable GitHub, AWS, OpenAI… key), so an ordinary long argument is not
/// reported. `first_line` is the file line the text starts at (1 unless only the tail was read).
pub fn history_secrets(text: &str, first_line: usize) -> HistorySecrets {
    let hits = crate::ai_scan::secrets::scan_text_high_confidence(text);
    let mut kinds: Vec<String> = hits.iter().map(|h| h.provider.clone()).collect();
    kinds.sort();
    kinds.dedup();
    let mut lines: Vec<usize> = hits.iter().map(|h| h.line + first_line - 1).collect();
    lines.dedup();
    lines.truncate(5);
    HistorySecrets {
        count: hits.len(),
        kinds,
        lines,
    }
}

/// Display name for a CRED-009 store kind.
pub fn token_file_tool(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "gh_hosts" => "GitHub CLI",
        "cargo_credentials" => "Cargo",
        "terraform_credentials" => "Terraform",
        "gem_credentials" => "RubyGems",
        "composer_auth" => "Composer",
        "netrc" => "netrc",
        _ => return None,
    })
}

/// Literal login tokens in one of the CRED-009 token files. Counts entries; never keeps a value.
pub fn count_token_file_entries(kind: &str, text: &str) -> Option<usize> {
    let literal = |v: &str| {
        let v = v.trim().trim_matches(['"', '\'']);
        !v.is_empty() && !is_env_reference(v) && v != "null"
    };
    Some(match kind {
        "gh_hosts" => text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("oauth_token:"))
            .filter(|v| literal(v))
            .count(),
        "cargo_credentials" => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .filter(|(k, v)| k.trim() == "token" && literal(v))
            .count(),
        "gem_credentials" => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(": "))
            .filter(|(k, v)| {
                let k = k.trim_start_matches(':');
                (k.ends_with("api_key") || k.starts_with("http://") || k.starts_with("https://"))
                    && literal(v)
            })
            .count(),
        "netrc" => {
            let words: Vec<&str> = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .flat_map(str::split_whitespace)
                .collect();
            words
                .windows(2)
                .filter(|w| w[0] == "password" && literal(w[1]))
                .count()
        }
        "terraform_credentials" | "composer_auth" if text.trim().is_empty() => 0,
        "terraform_credentials" => {
            let json: Value = serde_json::from_str(text).ok()?;
            json.get("credentials")
                .and_then(Value::as_object)
                .map(|hosts| {
                    hosts
                        .values()
                        .filter(|h| h.get("token").and_then(Value::as_str).is_some_and(literal))
                        .count()
                })
                .unwrap_or(0)
        }
        "composer_auth" => {
            let json: Value = serde_json::from_str(text).ok()?;
            let mut n = 0;
            for (section, field) in [
                ("http-basic", Some("password")),
                ("bearer", None),
                ("github-oauth", None),
                ("gitlab-token", None),
                ("gitlab-oauth", None),
                ("bitbucket-oauth", Some("consumer-secret")),
            ] {
                if let Some(hosts) = json.get(section).and_then(Value::as_object) {
                    n += hosts
                        .values()
                        .filter(|v| match field {
                            Some(f) => v.get(f).and_then(Value::as_str).is_some_and(literal),
                            None => {
                                v.as_str().is_some_and(literal)
                                    || v.get("token").and_then(Value::as_str).is_some_and(literal)
                            }
                        })
                        .count();
                }
            }
            n
        }
        _ => return None,
    })
}

/// True if any configured helper is Git's plaintext `store` helper.
pub fn helper_is_plaintext_store(helpers: &str) -> bool {
    helpers
        .lines()
        .map(str::trim)
        .any(|h| h == "store" || h.starts_with("store ") || h.ends_with("git-credential-store"))
}

fn store_fact(home: &Path, kind: &str, rel: &str) -> Option<Fact> {
    use crate::homefs::{open_in_home, HomeFile};
    let link = home.join(rel);
    let mut fact = Fact::new();
    fact.insert("path".into(), Value::String(link.display().to_string()));
    fact.insert("kind".into(), Value::String(kind.to_string()));
    // One open, then every decision from that descriptor (see `homefs`): a link is followed only
    // while it stays inside the home folder, and a pipe, a link leaving home or a file the home's
    // owner does not own is refused. A refused row carries no facts, so every rule on it reports
    // "could not check" instead of passing silently.
    let file = match open_in_home(home, &link) {
        HomeFile::Missing => return None,
        HomeFile::Refused => {
            fact.insert(
                crate::homefs::COULD_NOT_READ.into(),
                Value::String(crate::homefs::REFUSED.into()),
            );
            return Some(fact);
        }
        HomeFile::Found(file) => file,
    };
    let meta = file.metadata().ok()?;
    // Without Unix modes (Windows) the permission facts stay undetermined rather than guessed.
    if let Some(mode) = crate::platform::file_mode(&meta).map(|m| m & 0o777) {
        fact.insert("mode".into(), Value::String(format!("{mode:03o}")));
        fact.insert("readable_by_others".into(), Value::Bool(mode & 0o044 != 0));
    }

    if kind == "shell_history" {
        // Unreadable history leaves the count undetermined, like every other store.
        if let Some((text, first_line)) =
            crate::homefs::read_end(file, super::MAX_COLLECTOR_READ_BYTES)
        {
            // `first_line` is unknown when the part before the tail was too large to count.
            let found = history_secrets(&text, first_line.unwrap_or(1));
            fact.insert("secrets_found".into(), Value::from(found.count));
            fact.insert("secret_kinds".into(), Value::String(found.kinds.join(", ")));
            let lines = found
                .lines
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let place = match first_line {
                Some(_) if found.lines.len() == 1 => format!("line {lines}"),
                Some(_) => format!("lines {lines}"),
                None => "near the end of the file".to_string(),
            };
            fact.insert("secret_lines".into(), Value::String(place));
        }
        return Some(fact);
    }
    let needs_content = matches!(
        kind,
        "aws_credentials"
            | "aws_config"
            | "git_credentials"
            | "docker_config"
            | "shell_startup"
            | "npmrc"
            | "pypirc"
            | "kube_config"
    ) || token_file_tool(kind).is_some();
    if needs_content {
        if let Some(text) = crate::homefs::read_start(file, super::MAX_COLLECTOR_READ_BYTES) {
            match kind {
                "aws_credentials" | "aws_config" => {
                    fact.insert(
                        "long_lived_keys".into(),
                        Value::from(count_aws_long_lived_keys(&text)),
                    );
                }
                "shell_startup" => {
                    let names = exported_secret_names(&text);
                    fact.insert("exported_secrets".into(), Value::from(names.len()));
                    // A file can set any number of them; name the first few.
                    const SHOWN: usize = 10;
                    let mut listed = names
                        .iter()
                        .take(SHOWN)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    if names.len() > SHOWN {
                        listed.push_str(&format!(" and {} more", names.len() - SHOWN));
                    }
                    fact.insert("secret_names".into(), Value::String(listed));
                }
                "npmrc" => {
                    fact.insert(
                        "plaintext_tokens".into(),
                        Value::from(count_npm_plaintext_tokens(&text)),
                    );
                }
                "pypirc" => {
                    fact.insert(
                        "plaintext_tokens".into(),
                        Value::from(count_pypirc_passwords(&text)),
                    );
                }
                k if token_file_tool(k).is_some() => {
                    // Unparseable JSON leaves the count undetermined (a collector error), never 0.
                    if let Some(n) = count_token_file_entries(k, &text) {
                        fact.insert("plaintext_tokens".into(), Value::from(n));
                    }
                    fact.insert(
                        "tool".into(),
                        Value::String(token_file_tool(k).unwrap_or(k).to_string()),
                    );
                }
                "kube_config" => {
                    fact.insert(
                        "static_credentials".into(),
                        Value::from(count_kube_static_credentials(&text)),
                    );
                }
                "git_credentials" => {
                    fact.insert(
                        "stored_entries".into(),
                        Value::from(count_git_credential_entries(&text)),
                    );
                }
                "docker_config" => {
                    if let Some((inline, creds_store)) = docker_config_summary(&text) {
                        fact.insert("inline_auths".into(), Value::from(inline));
                        fact.insert("creds_store".into(), Value::Bool(creds_store));
                    }
                }
                _ => {}
            }
        }
    }
    Some(fact)
}

/// One CRED-009 token file found under a home folder, for the app's Secrets inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFile {
    pub tool: &'static str,
    /// Home-relative, for display (`~/.cargo/credentials.toml`).
    pub path: String,
    /// Literal tokens in the file; None when it could not be read or parsed.
    pub tokens: Option<usize>,
}

/// Every CRED-009 token file present under `home`, read the same way the scan reads it (same
/// parser, same symlink rule), so the inventory and the rule can never disagree. No value is kept.
pub fn token_files(home: &Path) -> Vec<TokenFile> {
    STORES
        .iter()
        .filter_map(|(kind, rel)| {
            let tool = token_file_tool(kind)?;
            let fact = store_fact(home, kind, rel)?;
            Some(TokenFile {
                tool,
                path: format!("~/{rel}"),
                tokens: fact
                    .get("plaintext_tokens")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize),
            })
        })
        .collect()
}

/// Every `helper` value under a `[credential]` or `[credential "<url>"]` section.
pub fn git_credential_helpers(config: &str) -> Vec<String> {
    let mut in_credential = false;
    let mut helpers = Vec::new();
    for line in config.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let header = line
                .trim_start_matches('[')
                .trim_start()
                .to_ascii_lowercase();
            in_credential = header.starts_with("credential");
            continue;
        }
        if in_credential {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("helper") {
                    helpers.push(value.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    helpers
}

/// Git's user-level credential helper for `home`, read from the config files themselves
/// (`~/.gitconfig` and `~/.config/git/config`). Git is not run: under a root scan it would parse a
/// config the home's owner controls, following its includes to any file and waiting forever on a
/// pipe. The cost is that a helper set only in an included file is not seen. No row when neither
/// file exists; a row without `helper_store` when one could not be read.
fn git_helper_fact(home: &Path) -> Option<Fact> {
    use crate::homefs::{read_in_home, HomeFile};
    let mut fact = Fact::new();
    fact.insert(
        "path".into(),
        Value::String(home.join(".gitconfig").display().to_string()),
    );
    fact.insert("kind".into(), Value::String("git_config".into()));
    let mut seen = false;
    let mut plaintext = false;
    for rel in [".gitconfig", ".config/git/config"] {
        match read_in_home(home, &home.join(rel), super::MAX_COLLECTOR_READ_BYTES) {
            HomeFile::Missing => {}
            HomeFile::Refused => {
                fact.insert(
                    "path".into(),
                    Value::String(home.join(rel).display().to_string()),
                );
                fact.insert(
                    crate::homefs::COULD_NOT_READ.into(),
                    Value::String(crate::homefs::REFUSED.into()),
                );
                return Some(fact);
            }
            HomeFile::Found(text) => {
                seen = true;
                plaintext |= helper_is_plaintext_store(&git_credential_helpers(&text).join("\n"));
            }
        }
    }
    if !seen {
        return None;
    }
    fact.insert("helper_store".into(), Value::Bool(plaintext));
    Some(fact)
}

impl Collector for CredentialStoresCollector {
    fn name(&self) -> &'static str {
        "credential_stores"
    }

    fn supported_os(&self) -> &'static [crate::models::OperatingSystem] {
        // Every store is a file under the home folder, the same on Windows (%USERPROFILE%). On
        // Windows there are no Unix modes, so the permission facts stay absent and CRED-004 is
        // limited to Linux and macOS.
        &[
            crate::models::OperatingSystem::Linux,
            crate::models::OperatingSystem::Macos,
            crate::models::OperatingSystem::Windows,
        ]
    }

    fn is_applicable(&self) -> bool {
        !super::user_homes().is_empty()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        for home in super::user_homes() {
            for (kind, rel) in STORES {
                rows.extend(store_fact(&home, kind, rel));
            }
            rows.extend(git_helper_fact(&home));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential-shaped value built at runtime so no key-like literal lives in the source.
    fn fake_secret() -> String {
        format!("sk{}", "a1B2".repeat(8))
    }

    #[test]
    fn shell_startup_reports_names_of_literal_secrets_only() {
        let v = fake_secret();
        let text = format!(
            "export OPENAI_API_KEY={v}\nexport GITHUB_TOKEN=\"{v}\"\nset -gx ANTHROPIC_API_KEY {v}\nAWS_SECRET_ACCESS_KEY='{v}'\n"
        );
        assert_eq!(
            exported_secret_names(&text),
            [
                "ANTHROPIC_API_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "GITHUB_TOKEN",
                "OPENAI_API_KEY"
            ]
        );
        // The value never appears in what the collector keeps.
        assert!(!exported_secret_names(&text).join(",").contains(&v));
    }

    #[test]
    fn shell_startup_ignores_references_paths_flags_and_placeholders() {
        let benign = "\
export GITHUB_TOKEN=$(gh auth token)
export OPENAI_API_KEY=\"$(secret-tool lookup service openai)\"
export NPM_TOKEN=${NPM_TOKEN}
export AWS_SHARED_CREDENTIALS_FILE=/home/me/.aws/credentials
export VAULT_TOKEN_PATH=/run/user/1000/token1234567890
export GIT_ASKPASS_HELPER=askpass
export HISTSIZE=100000000000000000
export API_KEY=your_api_key_here_123456
export SECRET_KEY=changeme1234567890
# export OPENAI_API_KEY=sk-commentedoutvalue12345678
export PATH=$HOME/bin:$PATH
export PASSWORD_STORE_DIR=~/.password-store
alias token='op read op://dev/token123456789/credential'
";
        assert!(
            exported_secret_names(benign).is_empty(),
            "{:?}",
            exported_secret_names(benign)
        );
    }

    #[test]
    fn powershell_profiles_report_literal_secrets_only() {
        let v = fake_secret();
        let text = format!(
            "$env:OPENAI_API_KEY = '{v}'\n[Environment]::SetEnvironmentVariable(\"GITHUB_TOKEN\", \"{v}\", \"User\")\n$env:Path = \"C:\\tools;$env:Path\"\n$env:API_TOKEN = (op read op://dev/token)\n$env:SECRET_KEY = \"$(Get-Secret dev)\"\n"
        );
        assert_eq!(
            exported_secret_names(&text),
            ["GITHUB_TOKEN", "OPENAI_API_KEY"]
        );
    }

    #[test]
    fn token_files_count_literal_tokens_only() {
        let v = fake_secret();
        let cases = [
            (
                "gh_hosts",
                format!("github.com:\n    oauth_token: {v}\n    user: me\n"),
                1,
            ),
            (
                "gh_hosts",
                "github.com:\n    users:\n        me:\n    user: me\n".to_string(),
                0,
            ),
            (
                "cargo_credentials",
                format!("[registry]\ntoken = \"{v}\"\n"),
                1,
            ),
            (
                "cargo_credentials",
                "[registry]\nglobal-credential-providers = [\"cargo:libsecret\"]\n".to_string(),
                0,
            ),
            (
                "terraform_credentials",
                format!(r#"{{"credentials":{{"app.terraform.io":{{"token":"{v}"}}}}}}"#),
                1,
            ),
            (
                "gem_credentials",
                format!("---\n:rubygems_api_key: {v}\n"),
                1,
            ),
            (
                "composer_auth",
                format!(
                    r#"{{"http-basic":{{"repo.example":{{"username":"u","password":"{v}"}}}},"github-oauth":{{"github.com":"{v}"}}}}"#
                ),
                2,
            ),
            (
                "netrc",
                format!(
                    "machine api.example\n  login me\n  password {v}\nmachine other login me\n"
                ),
                1,
            ),
            ("netrc", "machine api.example login me\n".to_string(), 0),
        ];
        for (kind, text, want) in cases {
            assert_eq!(
                count_token_file_entries(kind, &text),
                Some(want),
                "{kind}: {text}"
            );
        }
        assert_eq!(
            count_token_file_entries("terraform_credentials", "not json"),
            None
        );
    }

    /// A GitHub-token-shaped value built at runtime, so no key-like literal is committed.
    fn fake_github_token() -> String {
        format!(
            "ghp_{}",
            "a1B2c3D4e5".repeat(4).chars().take(36).collect::<String>()
        )
    }

    #[test]
    fn history_reports_service_and_line_never_the_key() {
        let key = fake_github_token();
        let text = format!(
            "ls -la\ncd project\n: 1700000000:0;export GITHUB_TOKEN={key}\ngit push\ncurl -H \"Authorization: token {key}\" https://api.github.com/user\n"
        );
        let found = history_secrets(&text, 1);
        assert_eq!(found.count, 2, "{found:?}");
        assert_eq!(found.lines, [3, 5]);
        assert!(
            found
                .kinds
                .iter()
                .any(|k| k.to_lowercase().contains("github")),
            "{:?}",
            found.kinds
        );
        assert!(!format!("{found:?}").contains(&key));
        // When only the tail of a big file was read, line numbers still match the file.
        assert_eq!(history_secrets(&text, 1001).lines, [1003, 1005]);
    }

    #[test]
    fn ordinary_history_is_not_reported() {
        let benign = "\
git commit -m 'rotate the api key and remove the old token'
export PATH=$HOME/.local/bin:$PATH
export GITHUB_TOKEN=$(gh auth token)
aws s3 ls s3://my-bucket --profile dev
ssh -i ~/.ssh/id_ed25519 deploy@server.example
docker login ghcr.io -u me --password-stdin
openssl rand -hex 32
git checkout 3f2a9c1d8b7e6f5a4c3b2a1908f7e6d5c4b3a291
curl -fsSL https://example.com/install.sh | sh
kubectl get secret app -o jsonpath='{.data.password}'
";
        assert_eq!(history_secrets(benign, 1), HistorySecrets::default());
    }

    #[test]
    fn history_tail_keeps_file_line_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bash_history");
        let key = fake_github_token();
        // Larger than the read cap, with the key on the last line.
        let filler = "echo hello world, this is an ordinary command line\n";
        let lines = (crate::collectors::MAX_COLLECTOR_READ_BYTES as usize / filler.len()) + 500;
        let mut body = filler.repeat(lines);
        body.push_str(&format!("export GITHUB_TOKEN={key}\n"));
        fs::write(&path, body).unwrap();
        let fact = store_fact(dir.path(), "shell_history", ".bash_history").unwrap();
        assert_eq!(fact.get("secrets_found"), Some(&Value::from(1)));
        assert_eq!(
            fact.get("secret_lines"),
            Some(&Value::String(format!("line {}", lines + 1)))
        );
        assert!(!format!("{fact:?}").contains(&key));
    }

    #[test]
    fn git_helpers_are_read_from_the_config_without_running_git() {
        let config = "[user]\n\tname = A\n[credential]\n\thelper = cache\n\thelper = store\n[credential \"https://x.example\"]\n\thelper = libsecret\n[core]\n\thelper = store\n";
        assert_eq!(
            git_credential_helpers(config),
            ["cache", "store", "libsecret"]
        );
        let home = tempfile::tempdir().unwrap();
        assert!(
            git_helper_fact(home.path()).is_none(),
            "no config, nothing to check"
        );
        fs::write(home.path().join(".gitconfig"), config).unwrap();
        let fact = git_helper_fact(home.path()).unwrap();
        assert_eq!(fact.get("helper_store"), Some(&Value::Bool(true)));
        fs::write(
            home.path().join(".gitconfig"),
            "[credential]\n\thelper = libsecret\n",
        )
        .unwrap();
        assert_eq!(
            git_helper_fact(home.path()).unwrap().get("helper_store"),
            Some(&Value::Bool(false))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_or_an_escaping_folder_link_never_blocks_or_leaks() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // A folder link leaving home: the classic way to point a root scan at someone else's file.
        fs::create_dir_all(outside.path().join(".aws")).unwrap();
        fs::write(
            outside.path().join(".aws/credentials"),
            format!("[default]\naws_access_key_id = {}\n", fake_akia()),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path().join(".aws"), home.path().join(".aws")).unwrap();
        let fact = store_fact(home.path(), "aws_credentials", ".aws/credentials").unwrap();
        assert!(
            !fact.contains_key("long_lived_keys") && !fact.contains_key("mode"),
            "{fact:?}"
        );
        // A pipe where a config file should be.
        for name in [".gitconfig", ".bash_history"] {
            let c = std::ffi::CString::new(home.path().join(name).to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }
        let started = std::time::Instant::now();
        assert!(!git_helper_fact(home.path())
            .unwrap()
            .contains_key("helper_store"));
        let history = store_fact(home.path(), "shell_history", ".bash_history").unwrap();
        assert!(!history.contains_key("secrets_found"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn a_long_list_of_exported_names_is_cut() {
        let home = tempfile::tempdir().unwrap();
        let v = fake_secret();
        let body: String = (0..40)
            .map(|i| format!("export SERVICE{i}_TOKEN={v}\n"))
            .collect();
        fs::write(home.path().join(".bashrc"), body).unwrap();
        let fact = store_fact(home.path(), "shell_startup", ".bashrc").unwrap();
        assert_eq!(fact.get("exported_secrets"), Some(&Value::from(40)));
        let names = fact.get("secret_names").and_then(Value::as_str).unwrap();
        assert!(
            names.ends_with("and 30 more") && names.matches(", ").count() == 9,
            "{names}"
        );
    }

    #[test]
    fn token_files_report_tool_path_and_count_only() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".cargo")).unwrap();
        let v = fake_secret();
        fs::write(
            home.path().join(".cargo/credentials.toml"),
            format!("[registry]\ntoken = \"{v}\"\n"),
        )
        .unwrap();
        fs::write(home.path().join(".netrc"), "machine x login y\n").unwrap();
        let files = token_files(home.path());
        assert!(files.contains(&TokenFile {
            tool: "Cargo",
            path: "~/.cargo/credentials.toml".into(),
            tokens: Some(1)
        }));
        assert!(files.contains(&TokenFile {
            tool: "netrc",
            path: "~/.netrc".into(),
            tokens: Some(0)
        }));
        assert!(!format!("{files:?}").contains(&v));
    }

    #[test]
    fn npmrc_counts_literal_tokens_not_env_references() {
        let v = fake_secret();
        let text = format!(
            "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={v}\n//npm.pkg.github.com/:_authToken=${{GH_TOKEN}}\n; //x/:_authToken={v}\n"
        );
        assert_eq!(count_npm_plaintext_tokens(&text), 1);
        assert_eq!(
            count_npm_plaintext_tokens("save-exact=true\nengine-strict=true\n"),
            0
        );
    }

    #[test]
    fn pypirc_counts_literal_passwords_only() {
        let v = fake_secret();
        let text = format!(
            "[pypi]\nusername = __token__\npassword = {v}\n[test]\npassword = ${{TEST_PYPI}}\n"
        );
        assert_eq!(count_pypirc_passwords(&text), 1);
        assert_eq!(
            count_pypirc_passwords(
                "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\n"
            ),
            0
        );
    }

    #[test]
    fn kubeconfig_counts_embedded_credentials_not_exec_plugins_or_file_refs() {
        let v = fake_secret();
        let embedded = format!(
            "users:\n- name: admin\n  user:\n    token: {v}\n- name: cert\n  user:\n    client-key-data: {v}\n"
        );
        assert_eq!(count_kube_static_credentials(&embedded), 2);
        let exec = "users:\n- name: eks\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token, --cluster-name, dev]\n- name: file\n  user:\n    client-key: /home/me/.kube/client.key\n    client-certificate: /home/me/.kube/client.crt\n";
        assert_eq!(count_kube_static_credentials(exec), 0);
    }
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    // Built at runtime so no secret-shaped literal sits in the source tree.
    fn fake_akia() -> String {
        format!("AKIA{}", "X".repeat(16))
    }

    #[test]
    fn counts_only_long_lived_aws_keys() {
        let text = format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = x\n\n[tmp]\naws_access_key_id = ASIA{}\n",
            fake_akia(),
            "Y".repeat(16)
        );
        assert_eq!(count_aws_long_lived_keys(&text), 1);
        assert_eq!(count_aws_long_lived_keys("[sso]\nsso_start_url = x\n"), 0);
    }

    #[test]
    fn git_credential_entries_skip_blank_and_comment_lines() {
        assert_eq!(
            count_git_credential_entries(
                "https://u:t@github.com\n\n# note\nhttps://u:t@example.org\n"
            ),
            2
        );
        assert_eq!(count_git_credential_entries("\n"), 0);
    }

    #[test]
    fn docker_summary_tells_inline_logins_from_a_creds_store() {
        assert_eq!(
            docker_config_summary(r#"{"auths":{"r.io":{"auth":"abc"},"q.io":{}}}"#),
            Some((1, false))
        );
        assert_eq!(
            docker_config_summary(r#"{"auths":{"r.io":{}},"credsStore":"secretservice"}"#),
            Some((0, true))
        );
        assert_eq!(docker_config_summary("not json"), None);
    }

    #[test]
    fn plaintext_store_helper_is_recognised() {
        assert!(helper_is_plaintext_store("store\n"));
        assert!(helper_is_plaintext_store("store --file ~/.creds\n"));
        assert!(!helper_is_plaintext_store("!gh auth git-credential\n"));
        assert!(!helper_is_plaintext_store("libsecret\n"));
    }

    #[cfg(unix)]
    #[test]
    fn store_fact_reports_mode_and_never_content() {
        let home = tempfile::tempdir().unwrap();
        let aws = home.path().join(".aws");
        fs::create_dir_all(&aws).unwrap();
        let file = aws.join("credentials");
        fs::write(
            &file,
            format!("[default]\naws_access_key_id = {}\n", fake_akia()),
        )
        .unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let fact = store_fact(home.path(), "aws_credentials", ".aws/credentials").unwrap();
        assert_eq!(fact["long_lived_keys"], Value::from(1));
        assert_eq!(fact["readable_by_others"], Value::Bool(true));
        assert_eq!(fact["mode"], Value::String("644".into()));
        let rendered = serde_json::to_string(&fact).unwrap();
        assert!(
            !rendered.contains("AKIA"),
            "a key ID must never enter a fact"
        );
    }

    #[test]
    fn unparseable_docker_config_leaves_facts_undetermined() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".docker")).unwrap();
        fs::write(home.path().join(".docker/config.json"), "{broken").unwrap();
        let fact = store_fact(home.path(), "docker_config", ".docker/config.json").unwrap();
        assert!(!fact.contains_key("inline_auths"));
        assert!(!fact.contains_key("creds_store"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_home_is_followed_like_a_dotfile_manager_link() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join("dotfiles")).unwrap();
        let target = home.path().join("dotfiles/npmrc");
        fs::write(
            &target,
            format!("//r.example/:_authToken={}\n", fake_secret()),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, home.path().join(".npmrc")).unwrap();
        let fact = store_fact(home.path(), "npmrc", ".npmrc").unwrap();
        assert_eq!(fact.get("plaintext_tokens"), Some(&Value::from(1)));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_leaving_home_is_not_followed_and_leaves_facts_undetermined() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("netrc");
        fs::write(&target, "machine x login y password z1234567890abcdef").unwrap();
        std::os::unix::fs::symlink(&target, home.path().join(".netrc")).unwrap();
        let fact = store_fact(home.path(), "netrc", ".netrc").unwrap();
        assert!(!fact.contains_key("plaintext_tokens"));
        assert!(!fact.contains_key("readable_by_others"));
    }

    #[test]
    fn partial_env_references_and_command_lines_are_not_mistaken() {
        let v = fake_secret();
        // A reference followed by a literal is still a written-down secret.
        let npm = format!("//r/:_authToken=${{NPM_USER}}{v}\n");
        assert_eq!(count_npm_plaintext_tokens(&npm), 1);
        assert_eq!(count_pypirc_passwords("[pypi]\npassword = %(PYPI)s\n"), 0);
        // Commands whose first word looks secret-like are not assignments.
        let commands =
            "load_api_key openai-prod-2024-key-abc123\nrefresh_token myprofile1234567890\n";
        assert!(exported_secret_names(commands).is_empty());
        let key_id = format!("export AWS_ACCESS_KEY_ID={}\n", fake_akia());
        assert!(exported_secret_names(&key_id).is_empty());
        let win_path = "$env:API_TOKEN_STORE = 'C:\\Users\\me\\secrets\\token1234567890.txt'\n";
        assert!(exported_secret_names(win_path).is_empty());
        let oidc = format!(
            "users:\n- name: oidc\n  user:\n    auth-provider:\n      config:\n        id-token: {v}\n"
        );
        assert_eq!(count_kube_static_credentials(&oidc), 1);
        assert_eq!(count_token_file_entries("composer_auth", "  "), Some(0));
        let gem = format!(":https://gems.example: {v}\n");
        assert_eq!(count_token_file_entries("gem_credentials", &gem), Some(1));
    }
}

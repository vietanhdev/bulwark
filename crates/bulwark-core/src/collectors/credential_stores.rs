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
use std::process::Command;
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

/// True if any configured helper is Git's plaintext `store` helper.
pub fn helper_is_plaintext_store(helpers: &str) -> bool {
    helpers
        .lines()
        .map(str::trim)
        .any(|h| h == "store" || h.starts_with("store ") || h.ends_with("git-credential-store"))
}

fn store_fact(home: &Path, kind: &str, rel: &str) -> Option<Fact> {
    let path = home.join(rel);
    // Never follow a symlink out of the home directory; only regular files are stores.
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut fact = Fact::new();
    fact.insert("path".into(), Value::String(path.display().to_string()));
    fact.insert("kind".into(), Value::String(kind.to_string()));
    // Without Unix modes (Windows) the permission facts stay undetermined rather than guessed.
    if let Some(mode) = crate::platform::file_mode(&meta).map(|m| m & 0o777) {
        fact.insert("mode".into(), Value::String(format!("{mode:03o}")));
        fact.insert("readable_by_others".into(), Value::Bool(mode & 0o044 != 0));
    }

    let needs_content = matches!(
        kind,
        "aws_credentials" | "git_credentials" | "docker_config"
    );
    if needs_content {
        if let Ok(text) = super::read_capped(&path) {
            match kind {
                "aws_credentials" => {
                    fact.insert(
                        "long_lived_keys".into(),
                        Value::from(count_aws_long_lived_keys(&text)),
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

/// Git's global credential helper for `home`, asked of git itself so includes and XDG config are
/// honoured. `None` when git isn't installed or the answer couldn't be read.
fn git_helper_fact(home: &Path) -> Option<Fact> {
    let out = Command::new("git")
        .args(["config", "--global", "--get-all", "credential.helper"])
        .env("HOME", home)
        .env_remove("GIT_CONFIG_GLOBAL")
        .output()
        .ok()?;
    let helper_store = match out.status.code() {
        Some(0) => helper_is_plaintext_store(&String::from_utf8_lossy(&out.stdout)),
        // `git config --get` exits 1 when the key isn't set: a definite "no helper".
        Some(1) => false,
        _ => return None,
    };
    let mut fact = Fact::new();
    fact.insert(
        "path".into(),
        Value::String(home.join(".gitconfig").display().to_string()),
    );
    fact.insert("kind".into(), Value::String("git_config".into()));
    fact.insert("helper_store".into(), Value::Bool(helper_store));
    Some(fact)
}

impl Collector for CredentialStoresCollector {
    fn name(&self) -> &'static str {
        "credential_stores"
    }

    fn supported_os(&self) -> &'static [crate::models::OperatingSystem] {
        super::LINUX_AND_MACOS
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
    fn symlinked_store_is_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("elsewhere");
        fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, home.path().join(".netrc")).unwrap();
        assert!(store_fact(home.path(), "netrc", ".netrc").is_none());
    }
}

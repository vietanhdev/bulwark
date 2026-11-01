//! Where alerts go — Telegram and e-mail — and which ones are worth sending.
//!
//! **Configuration only; nothing here sends anything.** `bulwark-core` makes no network calls
//! (architecture doc §10), so delivery lives in the CLI front-door (`bulwarkctl/src/notify.rs`),
//! which hands each message to the system `curl`. Keeping the model here lets the GUI read and
//! write the same settings without a second copy of the rules.
//!
//! Sending alerts off the machine is **opt-in and explicit**: nothing is configured by default, and
//! the settings page says plainly that the message content goes to Telegram's servers or the mail
//! provider. Messages carry machine names, severities and issue titles — never evidence, file
//! contents or secrets.
//!
//! Secrets (the bot token, the SMTP password) are kept out of the database, in a separate
//! owner-only file beside it, so copying or sharing a findings database never leaks them.

use crate::fleet::{Alert, AlertKind};
use crate::models::Severity;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEY_CONFIG: &str = "notify_config";
const KEY_LAST_ERROR: &str = "notify_last_error";
const KEY_LAST_SENT: &str = "notify_last_sent_at";
pub const KEY_LAST_REPORT: &str = "notify_last_report_at";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotifyConfig {
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    #[serde(default)]
    pub email: Option<EmailConfig>,
    /// New issues below this severity aren't sent (they still show in the app).
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,
    #[serde(default)]
    pub events: EventToggles,
    /// Also alert on new issues found on this computer, not only on remote machines.
    #[serde(default = "yes")]
    pub include_this_computer: bool,
    /// The desktop app sends the summary report once a day. (From a terminal, schedule
    /// `bulwarkctl notify report` with cron instead.)
    #[serde(default)]
    pub daily_report: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            telegram: None,
            email: None,
            min_severity: default_min_severity(),
            events: EventToggles::default(),
            include_this_computer: true,
            daily_report: false,
        }
    }
}

fn default_min_severity() -> Severity {
    Severity::Medium
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelegramConfig {
    pub enabled: bool,
    /// Numeric chat id (negative for groups) or `@channelname`.
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailConfig {
    pub enabled: bool,
    /// `smtps://host:465` (TLS) or `smtp://host:587` (STARTTLS, required). Plain, unencrypted
    /// `smtp://` is accepted only for a relay on this machine (`localhost`).
    pub smtp_url: String,
    #[serde(default)]
    pub username: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventToggles {
    #[serde(default = "yes")]
    pub new_issues: bool,
    #[serde(default = "yes")]
    pub unreachable: bool,
    #[serde(default = "yes")]
    pub back_online: bool,
    /// Host key / identity changes. On by default, and the settings page warns before disabling.
    #[serde(default = "yes")]
    pub security: bool,
    #[serde(default = "yes")]
    pub needs_attention: bool,
}

impl Default for EventToggles {
    fn default() -> Self {
        EventToggles {
            new_issues: true,
            unreachable: true,
            back_online: true,
            security: true,
            needs_attention: true,
        }
    }
}

/// Secrets, stored apart from the database (see the module docs).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NotifySecrets {
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<String>,
}

impl NotifyConfig {
    pub fn any_channel_enabled(&self) -> bool {
        self.telegram.as_ref().is_some_and(|t| t.enabled)
            || self.email.as_ref().is_some_and(|e| e.enabled)
    }

    /// Whether this alert passes the user's filters.
    pub fn wants(&self, alert: &Alert) -> bool {
        match alert.kind {
            AlertKind::NewIssues => self.events.new_issues && alert.severity >= self.min_severity,
            AlertKind::Unreachable => self.events.unreachable,
            AlertKind::BackOnline => self.events.back_online,
            AlertKind::SecurityWarning => self.events.security,
            AlertKind::NeedsAttention => self.events.needs_attention,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(t) = &self.telegram {
            validate_chat_id(&t.chat_id)?;
        }
        if let Some(e) = &self.email {
            validate_smtp_url(&e.smtp_url)?;
            validate_address(&e.from).map_err(|m| format!("From: {m}"))?;
            if e.to.is_empty() {
                return Err("add at least one recipient".into());
            }
            for t in &e.to {
                validate_address(t).map_err(|m| format!("To: {m}"))?;
            }
            if let Some(u) = &e.username {
                if u.chars().any(char::is_control) {
                    return Err("the SMTP user name contains control characters".into());
                }
            }
        }
        Ok(())
    }
}

/// A numeric chat id (groups are negative) or a public `@channel` name.
pub fn validate_chat_id(id: &str) -> Result<(), String> {
    let id = id.trim();
    let numeric = {
        let digits = id.strip_prefix('-').unwrap_or(id);
        !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
    };
    let channel = id
        .strip_prefix('@')
        .is_some_and(|n| n.len() >= 5 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    if numeric || channel {
        Ok(())
    } else {
        Err(
            "a Telegram chat id is a number (e.g. 123456789, or -100… for a group) or @channelname"
                .into(),
        )
    }
}

/// A bare e-mail address. CR/LF are the security-relevant part: an address ends up in a mail
/// header, and a newline there would let a value inject extra headers or recipients.
pub fn validate_address(a: &str) -> Result<(), String> {
    let a = a.trim();
    if a.chars()
        .any(|c| c.is_control() || c.is_whitespace() || "<>,;\"".contains(c))
    {
        return Err(format!("\"{a}\" isn't a plain e-mail address"));
    }
    match a.split_once('@') {
        Some((l, d)) if !l.is_empty() && d.contains('.') && !d.starts_with('.') => Ok(()),
        _ => Err(format!("\"{a}\" isn't an e-mail address")),
    }
}

/// `smtps://` always; `smtp://` (upgraded with mandatory STARTTLS) for remote servers; unencrypted
/// only to a relay on this machine.
pub fn validate_smtp_url(url: &str) -> Result<(), String> {
    let u = url.trim();
    let rest = u
        .strip_prefix("smtps://")
        .or_else(|| u.strip_prefix("smtp://"))
        .ok_or("the server must start with smtps:// (or smtp:// for STARTTLS)")?;
    let host = smtp_host(rest);
    if host.is_empty() {
        return Err("the server address is missing a host name".into());
    }
    if u.chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\')
    {
        return Err("the server address contains characters that aren't allowed".into());
    }
    Ok(())
}

fn smtp_host(rest: &str) -> &str {
    let hostport = rest.split('/').next().unwrap_or("");
    if let Some(v6) = hostport.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("");
    }
    hostport.split(':').next().unwrap_or("")
}

/// True for `smtp://localhost…` — the only case delivered without TLS.
pub fn is_local_plain_smtp(url: &str) -> bool {
    url.trim()
        .strip_prefix("smtp://")
        .is_some_and(|rest| matches!(smtp_host(rest), "localhost" | "127.0.0.1" | "::1"))
}

pub fn secrets_path(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
        .join("notify-secrets.json")
}

pub fn load(store: &mut Store) -> anyhow::Result<NotifyConfig> {
    Ok(match store.get_setting(KEY_CONFIG)? {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => NotifyConfig::default(),
    })
}

pub fn save(store: &mut Store, cfg: &NotifyConfig) -> anyhow::Result<()> {
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    store.set_setting(KEY_CONFIG, &serde_json::to_string(cfg)?)
}

pub fn load_secrets(path: &Path) -> NotifySecrets {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Writes the secrets file owner-only (0600), creating it that way rather than tightening after
/// the fact, so there is no moment at which it is readable by others.
pub fn save_secrets(path: &Path, secrets: &NotifySecrets) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(secrets)?.as_bytes())?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// What the settings page shows: the config, whether each secret is set (never the secret), and
/// the outcome of the last delivery.
#[derive(Debug, Clone, Serialize)]
pub struct NotifyStatus {
    pub config: NotifyConfig,
    pub telegram_token_set: bool,
    pub smtp_password_set: bool,
    pub last_error: Option<String>,
    pub last_sent_at: Option<String>,
}

pub fn status(store: &mut Store, db_path: &Path) -> anyhow::Result<NotifyStatus> {
    let secrets = load_secrets(&secrets_path(db_path));
    Ok(NotifyStatus {
        config: load(store)?,
        telegram_token_set: secrets.telegram_bot_token.is_some(),
        smtp_password_set: secrets.smtp_password.is_some(),
        last_error: store.get_setting(KEY_LAST_ERROR)?.filter(|s| !s.is_empty()),
        last_sent_at: store.get_setting(KEY_LAST_SENT)?.filter(|s| !s.is_empty()),
    })
}

/// Records the outcome of a delivery attempt, so a broken channel is visible in the app rather
/// than failing silently in a background process.
pub fn record_delivery(store: &mut Store, error: Option<&str>) -> anyhow::Result<()> {
    match error {
        Some(e) => store.set_setting(KEY_LAST_ERROR, e),
        None => {
            store.set_setting(KEY_LAST_ERROR, "")?;
            store.set_setting(KEY_LAST_SENT, &chrono::Utc::now().to_rfc3339())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_injection_is_refused_in_addresses() {
        assert!(validate_address("ops@example.com").is_ok());
        assert!(validate_address("ops@example.com\r\nBcc: evil@x.com").is_err());
        assert!(validate_address("a@b.com, c@d.com").is_err());
        assert!(validate_address("Ops <ops@example.com>").is_err());
        assert!(validate_address("nodomain").is_err());
    }

    #[test]
    fn smtp_must_be_encrypted_unless_local() {
        assert!(validate_smtp_url("smtps://smtp.gmail.com:465").is_ok());
        assert!(validate_smtp_url("smtp://smtp.example.com:587").is_ok());
        assert!(validate_smtp_url("http://smtp.example.com").is_err());
        assert!(validate_smtp_url("smtps://").is_err());
        assert!(is_local_plain_smtp("smtp://localhost:25"));
        assert!(!is_local_plain_smtp("smtp://mail.example.com:25"));
        assert!(!is_local_plain_smtp("smtps://localhost:465"));
    }

    #[test]
    fn chat_ids_are_numbers_or_channels() {
        for ok in ["123456789", "-1001234567890", "@bulwark_alerts"] {
            assert!(validate_chat_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "abc", "@ab", "12 34", "-"] {
            assert!(validate_chat_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn filters_respect_severity_and_toggles() {
        let cfg = NotifyConfig::default();
        let mk = |kind, severity| Alert {
            machine: "m".into(),
            kind,
            severity,
            title: String::new(),
            body: String::new(),
        };
        assert!(cfg.wants(&mk(AlertKind::NewIssues, Severity::High)));
        assert!(!cfg.wants(&mk(AlertKind::NewIssues, Severity::Low)));
        assert!(cfg.wants(&mk(AlertKind::SecurityWarning, Severity::Critical)));
        let mut quiet = cfg.clone();
        quiet.events.back_online = false;
        assert!(!quiet.wants(&mk(AlertKind::BackOnline, Severity::Info)));
    }

    #[test]
    fn secrets_round_trip_and_stay_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = secrets_path(&dir.path().join("bulwark.db"));
        assert_eq!(load_secrets(&p), NotifySecrets::default());
        let s = NotifySecrets {
            telegram_bot_token: Some("123:abc".into()),
            smtp_password: None,
        };
        save_secrets(&p, &s).unwrap();
        assert_eq!(load_secrets(&p), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn config_round_trips_through_settings_and_is_validated() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(load(&mut store).unwrap(), NotifyConfig::default());
        let mut cfg = NotifyConfig {
            telegram: Some(TelegramConfig {
                enabled: true,
                chat_id: "42".into(),
            }),
            ..Default::default()
        };
        save(&mut store, &cfg).unwrap();
        assert_eq!(load(&mut store).unwrap(), cfg);
        cfg.email = Some(EmailConfig {
            enabled: true,
            smtp_url: "smtps://mail.example.com".into(),
            username: None,
            from: "bulwark@example.com".into(),
            to: vec!["ops@example.com\nBcc: x@y.z".into()],
        });
        assert!(save(&mut store, &cfg).is_err());
    }
}

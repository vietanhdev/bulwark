//! `bulwarkctl notify …` — deliver alerts and reports to Telegram and e-mail.
//!
//! Configuration (and its validation) lives in `bulwark_core::notify_config`; *which* events are
//! worth an alert is decided by `bulwark_core::fleet::alerts_for_attempt`. This module only
//! delivers, and it does so through the **system `curl`** — the same choice remote scanning made
//! for `ssh`: no TLS or SMTP stack of our own to keep patched, and the platform's CA store and
//! proxy settings for free.
//!
//! Secrets never appear on a command line (where `ps` would show them): the bot token and the SMTP
//! password reach curl through its config on **stdin** (`-K -`). Any curl error text is scrubbed of
//! the token before it is shown or stored.
//!
//! A delivery failure never fails the scan that triggered it. It is printed, and recorded so the
//! app can show "alerts couldn't be sent: …" — a broken channel must be visible, not silent.

use anyhow::{Context, Result};
use bulwark_core::fleet::{self, Alert, AlertKind};
use bulwark_core::models::Severity;
use bulwark_core::notify_config::{
    self as cfgmod, EmailConfig, NotifyConfig, NotifySecrets, TelegramConfig,
};
use bulwark_core::Store;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

#[derive(Subcommand)]
pub enum NotifyAction {
    /// Show where alerts go and whether the last delivery worked
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Send alerts to a Telegram chat through your own bot (create one with @BotFather). The token
    /// is read from stdin or prompted for, never taken as an argument.
    Telegram {
        /// Chat to send to. Omit it: after you message your bot once, Bulwark finds the chat.
        #[arg(long)]
        chat_id: Option<String>,
        /// Read the bot token from stdin instead of prompting
        #[arg(long)]
        token_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// List the chats that have messaged your bot, to find the chat id
    Chats {
        /// Use this token (from stdin) instead of the saved one
        #[arg(long)]
        token_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Send alerts by e-mail over SMTP (TLS required, except to a relay on this machine)
    Email {
        /// e.g. smtps://smtp.gmail.com:465 or smtp://smtp.example.com:587 (STARTTLS)
        #[arg(long)]
        smtp_url: String,
        #[arg(long)]
        from: String,
        /// Recipient (repeatable)
        #[arg(long = "to", required = true)]
        to: Vec<String>,
        #[arg(long)]
        username: Option<String>,
        /// Read the SMTP password from stdin instead of prompting (prompted only with --username)
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Replace the whole configuration from JSON on stdin (used by the desktop app)
    Configure {
        #[arg(long)]
        json: bool,
    },
    /// Stop sending to a channel and forget its secret
    Disable {
        /// telegram, email, or all
        channel: String,
    },
    /// Send a test message to every enabled channel
    Test {
        #[arg(long)]
        json: bool,
    },
    /// Send a summary of every machine (and this computer) — run it daily from cron
    Report {
        #[arg(long)]
        json: bool,
    },
    /// Deliver alerts given as JSON on stdin, after the configured filters (used by the app)
    Send {
        #[arg(long)]
        json: bool,
    },
}

pub fn run(action: NotifyAction, db: &Path) -> Result<i32> {
    let secrets_path = cfgmod::secrets_path(db);
    match action {
        NotifyAction::Status { json } => {
            let st = cfgmod::status(&mut Store::open(db)?, db)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                print_status(&st);
            }
            Ok(0)
        }
        NotifyAction::Telegram {
            chat_id,
            token_stdin,
            json,
        } => {
            let token = read_secret(token_stdin, "Telegram bot token: ")?;
            validate_token(&token)?;
            let chat_id = match chat_id {
                Some(c) => c,
                None => {
                    let chats = telegram_chats(&token)?;
                    match chats.as_slice() {
                        [one] => one.id.clone(),
                        [] => anyhow::bail!(
                            "the bot hasn't received any messages yet — open your bot in Telegram, \
                             send it any message, and run this again"
                        ),
                        many => {
                            eprintln!("Several chats have messaged the bot:");
                            for c in many {
                                eprintln!("  {}  {}", c.id, c.title);
                            }
                            anyhow::bail!("pick one and re-run with --chat-id <id>");
                        }
                    }
                }
            };
            let mut store = Store::open(db)?;
            let mut cfg = cfgmod::load(&mut store)?;
            cfg.telegram = Some(TelegramConfig {
                enabled: true,
                chat_id,
            });
            cfgmod::save(&mut store, &cfg)?;
            let mut secrets = cfgmod::load_secrets(&secrets_path);
            secrets.telegram_bot_token = Some(token);
            cfgmod::save_secrets(&secrets_path, &secrets)?;
            finish_config(db, json, "Telegram alerts are on.")
        }
        NotifyAction::Chats { token_stdin, json } => {
            let token = if token_stdin {
                read_secret(true, "")?
            } else {
                cfgmod::load_secrets(&secrets_path)
                    .telegram_bot_token
                    .context("no Telegram bot token is saved — pass one with --token-stdin")?
            };
            let chats = telegram_chats(&token)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&chats)?);
            } else if chats.is_empty() {
                println!("No chats yet. Send your bot a message in Telegram, then run this again.");
            } else {
                for c in chats {
                    println!("{}  {} ({})", c.id, c.title, c.kind);
                }
            }
            Ok(0)
        }
        NotifyAction::Email {
            smtp_url,
            from,
            to,
            username,
            password_stdin,
            json,
        } => {
            let password = if username.is_some() || password_stdin {
                Some(read_secret(password_stdin, "SMTP password: ")?)
            } else {
                None
            };
            let mut store = Store::open(db)?;
            let mut cfg = cfgmod::load(&mut store)?;
            cfg.email = Some(EmailConfig {
                enabled: true,
                smtp_url,
                username,
                from,
                to,
            });
            cfgmod::save(&mut store, &cfg)?;
            let mut secrets = cfgmod::load_secrets(&secrets_path);
            secrets.smtp_password = password;
            cfgmod::save_secrets(&secrets_path, &secrets)?;
            finish_config(db, json, "E-mail alerts are on.")
        }
        NotifyAction::Configure { json } => {
            #[derive(Deserialize)]
            struct Input {
                config: NotifyConfig,
                /// Absent = keep, null or "" = clear.
                #[serde(default, deserialize_with = "keep_or_set")]
                telegram_bot_token: Option<Option<String>>,
                #[serde(default, deserialize_with = "keep_or_set")]
                smtp_password: Option<Option<String>>,
            }
            let mut raw = String::new();
            std::io::stdin().read_to_string(&mut raw)?;
            let input: Input = serde_json::from_str(&raw).context("reading configuration JSON")?;
            let mut secrets = cfgmod::load_secrets(&secrets_path);
            if let Some(t) = input.telegram_bot_token {
                let t = t.filter(|s| !s.trim().is_empty());
                if let Some(tok) = &t {
                    validate_token(tok)?;
                }
                secrets.telegram_bot_token = t;
            }
            if let Some(p) = input.smtp_password {
                secrets.smtp_password = p.filter(|s| !s.is_empty());
            }
            let mut store = Store::open(db)?;
            cfgmod::save(&mut store, &input.config)?;
            cfgmod::save_secrets(&secrets_path, &secrets)?;
            finish_config(db, json, "Saved.")
        }
        NotifyAction::Disable { channel } => {
            let mut store = Store::open(db)?;
            let mut cfg = cfgmod::load(&mut store)?;
            let mut secrets = cfgmod::load_secrets(&secrets_path);
            match channel.as_str() {
                "telegram" => {
                    cfg.telegram = None;
                    secrets.telegram_bot_token = None;
                }
                "email" => {
                    cfg.email = None;
                    secrets.smtp_password = None;
                }
                "all" => {
                    cfg.telegram = None;
                    cfg.email = None;
                    secrets = NotifySecrets::default();
                }
                other => anyhow::bail!("unknown channel {other} (telegram, email or all)"),
            }
            cfgmod::save(&mut store, &cfg)?;
            cfgmod::save_secrets(&secrets_path, &secrets)?;
            println!("Disabled {channel}.");
            Ok(0)
        }
        NotifyAction::Test { json } => {
            let (cfg, secrets) = load_all(db)?;
            let msg = Message {
                subject: "Bulwark test message".into(),
                text: format!(
                    "This is a test from Bulwark on {}. If you can read it, alerts will reach you \
                     here.",
                    this_hostname()
                ),
            };
            let results = send_all(&cfg, &secrets, &msg);
            report_results(db, &results, json)
        }
        NotifyAction::Report { json } => {
            let (cfg, secrets) = load_all(db)?;
            let msg = build_report(db)?;
            let results = send_all(&cfg, &secrets, &msg);
            report_results(db, &results, json)
        }
        NotifyAction::Send { json } => {
            let mut raw = String::new();
            std::io::stdin().read_to_string(&mut raw)?;
            let alerts: Vec<Alert> = serde_json::from_str(&raw).context("reading alerts JSON")?;
            let results = deliver(db, &alerts);
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            Ok(if results.iter().all(|r| r.ok) { 0 } else { 3 })
        }
    }
}

/// serde helper: distinguishes an absent field (keep) from null (clear).
fn keep_or_set<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Option<String>>, D::Error> {
    Ok(Some(Option::<String>::deserialize(d)?))
}

fn finish_config(db: &Path, json: bool, human: &str) -> Result<i32> {
    if json {
        let st = cfgmod::status(&mut Store::open(db)?, db)?;
        println!("{}", serde_json::to_string_pretty(&st)?);
    } else {
        println!("{human} Send a test with `bulwarkctl notify test`.");
    }
    Ok(0)
}

fn print_status(st: &cfgmod::NotifyStatus) {
    let c = &st.config;
    match &c.telegram {
        Some(t) => println!(
            "Telegram: {} (chat {}){}",
            if t.enabled { "on" } else { "off" },
            t.chat_id,
            if st.telegram_token_set {
                ""
            } else {
                " — no bot token saved"
            }
        ),
        None => println!("Telegram: not set up"),
    }
    match &c.email {
        Some(e) => println!(
            "E-mail:   {} ({} → {})",
            if e.enabled { "on" } else { "off" },
            e.smtp_url,
            e.to.join(", ")
        ),
        None => println!("E-mail:   not set up"),
    }
    println!(
        "Sends:    new issues ≥ {}{}{}{}{}",
        fleet::severity_word(c.min_severity).to_lowercase(),
        if c.events.unreachable {
            ", unreachable"
        } else {
            ""
        },
        if c.events.back_online {
            ", back online"
        } else {
            ""
        },
        if c.events.security {
            ", host key/identity changes"
        } else {
            ""
        },
        if c.events.needs_attention {
            ", needs attention"
        } else {
            ""
        },
    );
    if let Some(e) = &st.last_error {
        println!("Last delivery FAILED: {e}");
    } else if let Some(t) = &st.last_sent_at {
        println!("Last delivered: {t}");
    }
}

fn read_secret(from_stdin: bool, prompt: &str) -> Result<String> {
    let s = if from_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line
    } else {
        rpassword::prompt_password(prompt)?
    };
    let s = s.trim().to_string();
    if s.is_empty() {
        anyhow::bail!("nothing was entered");
    }
    Ok(s)
}

/// Bot tokens look like `123456:ABC-def_…`. Checked so a malformed value can never smuggle extra
/// path segments or query parameters into the API URL.
fn validate_token(t: &str) -> Result<()> {
    let ok = t.split_once(':').is_some_and(|(id, secret)| {
        !id.is_empty()
            && id.chars().all(|c| c.is_ascii_digit())
            && secret.len() >= 20
            && secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    });
    if ok {
        Ok(())
    } else {
        anyhow::bail!("that doesn't look like a Telegram bot token (expected 123456:ABC…)")
    }
}

fn load_all(db: &Path) -> Result<(NotifyConfig, NotifySecrets)> {
    let cfg = cfgmod::load(&mut Store::open(db)?)?;
    let secrets = cfgmod::load_secrets(&cfgmod::secrets_path(db));
    if !cfg.any_channel_enabled() {
        anyhow::bail!(
            "no alert channel is set up — see `bulwarkctl notify telegram` or `bulwarkctl notify email`"
        );
    }
    Ok((cfg, secrets))
}

fn this_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this computer".into())
}

// ---- delivery -----------------------------------------------------------------------------------

pub struct Message {
    pub subject: String,
    pub text: String,
}

#[derive(Serialize, Debug)]
pub struct ChannelResult {
    pub channel: &'static str,
    pub ok: bool,
    pub error: Option<String>,
}

/// Filter `alerts` through the user's settings and send whatever survives as **one** message per
/// channel (a scan of five machines produces one notification, not five). Never fails: problems are
/// returned, printed by the caller, and recorded for the app.
pub fn deliver(db: &Path, alerts: &[Alert]) -> Vec<ChannelResult> {
    let Ok(mut store) = Store::open(db) else {
        return Vec::new();
    };
    let Ok(cfg) = cfgmod::load(&mut store) else {
        return Vec::new();
    };
    if !cfg.any_channel_enabled() {
        return Vec::new();
    }
    let wanted: Vec<&Alert> = alerts.iter().filter(|a| cfg.wants(a)).collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let secrets = cfgmod::load_secrets(&cfgmod::secrets_path(db));
    let msg = compose(&wanted);
    let results = send_all(&cfg, &secrets, &msg);
    record(&mut store, &results);
    results
}

fn compose(alerts: &[&Alert]) -> Message {
    let subject = match alerts {
        [one] => one.title.clone(),
        many => {
            let security = many.iter().any(|a| a.kind == AlertKind::SecurityWarning);
            format!(
                "{}{} alerts from Bulwark",
                if security { "Security warning + " } else { "" },
                many.len()
            )
        }
    };
    if let [one] = alerts {
        // The subject already says what happened; the body only adds the detail.
        return Message {
            subject,
            text: format!("{}\n\n— Bulwark", one.body),
        };
    }
    let mut sorted: Vec<&&Alert> = alerts.iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.severity));
    let mut text = String::new();
    for a in sorted {
        let mark = match (a.kind, a.severity) {
            (AlertKind::SecurityWarning, _) => "🚨",
            (AlertKind::BackOnline, _) => "✅",
            (AlertKind::Unreachable, _) => "⚠️",
            (_, Severity::Critical | Severity::High) => "🔴",
            (_, Severity::Medium) => "🟠",
            _ => "🔵",
        };
        text.push_str(&format!("{mark} {}\n{}\n\n", a.title, a.body));
    }
    text.push_str("— Bulwark");
    Message { subject, text }
}

fn record(store: &mut Store, results: &[ChannelResult]) {
    let errors: Vec<String> = results
        .iter()
        .filter_map(|r| r.error.as_ref().map(|e| format!("{}: {e}", r.channel)))
        .collect();
    let joined = errors.join("; ");
    let _ = cfgmod::record_delivery(store, (!errors.is_empty()).then_some(joined.as_str()));
}

fn report_results(db: &Path, results: &[ChannelResult], json: bool) -> Result<i32> {
    if let Ok(mut store) = Store::open(db) {
        record(&mut store, results);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(results)?);
    } else {
        for r in results {
            match &r.error {
                None => println!("{}: sent", r.channel),
                Some(e) => println!("{}: FAILED — {e}", r.channel),
            }
        }
    }
    Ok(if results.iter().all(|r| r.ok) { 0 } else { 3 })
}

fn send_all(cfg: &NotifyConfig, secrets: &NotifySecrets, msg: &Message) -> Vec<ChannelResult> {
    let mut out = Vec::new();
    if let Some(t) = cfg.telegram.as_ref().filter(|t| t.enabled) {
        let r = match &secrets.telegram_bot_token {
            Some(tok) => telegram_send(tok, &t.chat_id, msg),
            None => Err(anyhow::anyhow!("no bot token is saved")),
        };
        out.push(result("telegram", r));
    }
    if let Some(e) = cfg.email.as_ref().filter(|e| e.enabled) {
        let r = email_send(e, secrets.smtp_password.as_deref(), msg);
        out.push(result("email", r));
    }
    out
}

fn result(channel: &'static str, r: Result<()>) -> ChannelResult {
    ChannelResult {
        channel,
        ok: r.is_ok(),
        error: r.err().map(|e| format!("{e:#}")),
    }
}

// ---- curl ---------------------------------------------------------------------------------------

/// Quote a value for a curl config file: double quotes, with backslash escapes for the characters
/// curl's config parser interprets.
fn curl_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Run curl with its whole configuration on stdin. `scrub` is removed from any error text.
fn curl(config: &str, protos: &str, scrub: Option<&str>) -> Result<String> {
    let mut cmd = bulwark_core::sandbox::host_command("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--max-time",
        "30",
        "--proto",
        protos,
        "--proto-redir",
        "=https",
        "--config",
        "-",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("`curl` isn't installed on this computer (it's needed to send alerts)")
        }
        Err(e) => return Err(e.into()),
    };
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(config.as_bytes())?;
    let out = wait_timeout(child, Duration::from_secs(45))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let mut e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if e.is_empty() {
            e = format!("curl exited with {:?}", out.status.code());
        }
        if let Some(s) = scrub {
            e = e.replace(s, "<redacted>");
        }
        anyhow::bail!("{e}");
    }
    Ok(stdout)
}

fn wait_timeout(mut child: std::process::Child, t: Duration) -> Result<std::process::Output> {
    let start = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if start.elapsed() > t {
            let _ = child.kill();
            anyhow::bail!("timed out after {}s", t.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The Bot API base. Overridable only for tests, and only to https — or plain http on localhost.
fn telegram_base() -> String {
    match std::env::var("BULWARK_TELEGRAM_API") {
        Ok(b)
            if b.starts_with("https://")
                || b.starts_with("http://127.0.0.1")
                || b.starts_with("http://localhost") =>
        {
            b.trim_end_matches('/').to_string()
        }
        _ => "https://api.telegram.org".into(),
    }
}

fn telegram_protos() -> &'static str {
    if telegram_base().starts_with("http://") {
        "=http,https"
    } else {
        "=https"
    }
}

#[derive(Deserialize)]
struct TgResponse<T> {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    result: Option<T>,
}

fn telegram_send(token: &str, chat_id: &str, msg: &Message) -> Result<()> {
    validate_token(token)?;
    // Telegram caps a message at 4096 characters.
    let mut text = format!("{}\n\n{}", msg.subject, msg.text);
    if text.chars().count() > 4000 {
        text = text.chars().take(3990).collect::<String>() + "\n…";
    }
    let config = format!(
        "url = {}\ndata-urlencode = {}\ndata-urlencode = {}\ndata-urlencode = {}\n",
        curl_quote(&format!("{}/bot{token}/sendMessage", telegram_base())),
        curl_quote(&format!("chat_id={}", chat_id.trim())),
        curl_quote(&format!("text={text}")),
        curl_quote("disable_web_page_preview=true"),
    );
    let body = curl(&config, telegram_protos(), Some(token))?;
    let r: TgResponse<serde_json::Value> = serde_json::from_str(&body).with_context(|| {
        format!(
            "unexpected reply from Telegram: {}",
            body.replace(token, "<redacted>")
        )
    })?;
    if !r.ok {
        anyhow::bail!(
            "Telegram refused the message: {}",
            r.description.unwrap_or_default()
        );
    }
    Ok(())
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Chat {
    pub id: String,
    pub title: String,
    pub kind: String,
}

/// The chats that have recently messaged the bot — how a user finds their chat id without
/// leaving the app.
fn telegram_chats(token: &str) -> Result<Vec<Chat>> {
    validate_token(token)?;
    let config = format!(
        "url = {}\n",
        curl_quote(&format!("{}/bot{token}/getUpdates", telegram_base()))
    );
    let body = curl(&config, telegram_protos(), Some(token))?;
    let r: TgResponse<Vec<serde_json::Value>> = serde_json::from_str(&body)
        .with_context(|| "unexpected reply from Telegram".to_string())?;
    if !r.ok {
        anyhow::bail!(
            "Telegram refused the token: {}",
            r.description.unwrap_or_default()
        );
    }
    Ok(chats_from_updates(&r.result.unwrap_or_default()))
}

fn chats_from_updates(updates: &[serde_json::Value]) -> Vec<Chat> {
    let mut out: Vec<Chat> = Vec::new();
    for u in updates {
        for key in [
            "message",
            "channel_post",
            "my_chat_member",
            "edited_message",
        ] {
            let Some(chat) = u.get(key).and_then(|m| m.get("chat")) else {
                continue;
            };
            let Some(id) = chat.get("id").and_then(|v| v.as_i64()) else {
                continue;
            };
            let id = id.to_string();
            if out.iter().any(|c| c.id == id) {
                continue;
            }
            let s = |k: &str| chat.get(k).and_then(|v| v.as_str()).unwrap_or("");
            let title = [s("title"), s("first_name"), s("username")]
                .into_iter()
                .find(|t| !t.is_empty())
                .unwrap_or("(unnamed)")
                .to_string();
            out.push(Chat {
                id,
                title,
                kind: s("type").to_string(),
            });
        }
    }
    out
}

/// RFC 2047 encoded-word for a header value that isn't pure ASCII.
fn encode_header(s: &str) -> String {
    if s.is_ascii() {
        return s.replace(['\r', '\n'], " ");
    }
    format!("=?UTF-8?B?{}?=", base64(s.as_bytes()))
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        o.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    o
}

fn build_email(e: &EmailConfig, msg: &Message) -> String {
    let mut m = String::new();
    m.push_str(&format!("From: Bulwark <{}>\r\n", e.from.trim()));
    m.push_str(&format!(
        "To: {}\r\n",
        e.to.iter().map(|t| t.trim()).collect::<Vec<_>>().join(", ")
    ));
    m.push_str(&format!(
        "Subject: {}\r\n",
        encode_header(&format!("[Bulwark] {}", msg.subject))
    ));
    m.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
    let domain = e.from.rsplit('@').next().unwrap_or("bulwark.local");
    m.push_str(&format!(
        "Message-ID: <{}.{}@{domain}>\r\n",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::process::id()
    ));
    m.push_str("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
    for line in msg.text.lines() {
        // SMTP dot-stuffing is done by curl; normalise line endings here.
        m.push_str(line);
        m.push_str("\r\n");
    }
    m
}

fn email_send(e: &EmailConfig, password: Option<&str>, msg: &Message) -> Result<()> {
    cfgmod::validate_smtp_url(&e.smtp_url).map_err(|m| anyhow::anyhow!(m))?;
    let dir = std::env::temp_dir().join(format!(
        "bulwark-mail-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir)?;
    let file = dir.join("message.eml");
    std::fs::write(&file, build_email(e, msg))?;

    let mut config = format!(
        "url = {}\nmail-from = {}\nupload-file = {}\n",
        curl_quote(e.smtp_url.trim()),
        curl_quote(e.from.trim()),
        curl_quote(&file.display().to_string()),
    );
    for t in &e.to {
        config.push_str(&format!("mail-rcpt = {}\n", curl_quote(t.trim())));
    }
    if let Some(u) = &e.username {
        config.push_str(&format!(
            "user = {}\n",
            curl_quote(&format!("{u}:{}", password.unwrap_or_default()))
        ));
    }
    if !cfgmod::is_local_plain_smtp(&e.smtp_url) {
        // STARTTLS is mandatory for smtp://; never fall back to sending in the clear.
        config.push_str("ssl-reqd\n");
    }
    let r = curl(&config, "=smtp,smtps", password);
    let _ = std::fs::remove_dir_all(&dir);
    r.map(|_| ())
}

// ---- report -------------------------------------------------------------------------------------

fn build_report(db: &Path) -> Result<Message> {
    let now = chrono::Utc::now();
    let mut text = String::new();

    let mut local = Store::open(db)?;
    let split = local.open_findings_split()?;
    let meta = local.latest_scan_run_meta()?;
    let mut counts = fleet::FindingCounts::default();
    for f in &split.active {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    text.push_str(&format!(
        "This computer ({}): {}{}\n\n",
        this_hostname(),
        summarise(&counts),
        meta.map(|m| format!(" · last scan {}", ago(now, m.started_at)))
            .unwrap_or_else(|| " · never scanned".into())
    ));

    let machines = fleet::list_views(db)?;
    let mut attention = 0;
    if !machines.is_empty() {
        text.push_str(&format!("Machines ({}):\n", machines.len()));
        for m in &machines {
            let state = match m.health {
                fleet::HostHealth::New => "not scanned yet".to_string(),
                fleet::HostHealth::NeedsAttention => {
                    attention += 1;
                    format!(
                        "needs attention — {}",
                        m.problem.as_ref().map(|p| p.title.as_str()).unwrap_or("")
                    )
                }
                fleet::HostHealth::Unreachable => {
                    attention += 1;
                    "unreachable".into()
                }
                fleet::HostHealth::Stale => "out of date".into(),
                fleet::HostHealth::Unsupported => "not supported yet (nothing checked)".into(),
                _ => summarise(&m.counts),
            };
            text.push_str(&format!(
                "• {} — {state}{}\n",
                m.host.name,
                m.host
                    .last_success_at
                    .map(|t| format!(" · last scan {}", ago(now, t)))
                    .unwrap_or_default()
            ));
        }
    }
    let total_high: usize = machines
        .iter()
        .map(|m| m.counts.critical + m.counts.high)
        .sum::<usize>()
        + counts.critical
        + counts.high;
    let subject = format!(
        "Report: {} critical/high issue{}{}",
        total_high,
        if total_high == 1 { "" } else { "s" },
        if attention > 0 {
            format!(", {attention} machine(s) need attention")
        } else {
            String::new()
        }
    );
    Ok(Message { subject, text })
}

fn summarise(c: &fleet::FindingCounts) -> String {
    if c.total() == 0 {
        return "no open issues".into();
    }
    let mut parts = Vec::new();
    for (n, l) in [
        (c.critical, "critical"),
        (c.high, "high"),
        (c.medium, "medium"),
        (c.low, "low"),
    ] {
        if n > 0 {
            parts.push(format!("{n} {l}"));
        }
    }
    if parts.is_empty() {
        format!("{} info", c.info)
    } else {
        parts.join(", ")
    }
}

fn ago(now: chrono::DateTime<chrono::Utc>, t: chrono::DateTime<chrono::Utc>) -> String {
    let m = (now - t).num_minutes();
    match m {
        m if m < 1 => "just now".into(),
        m if m < 60 => format!("{m} min ago"),
        m if m < 48 * 60 => format!("{} h ago", m / 60),
        m => format!("{} d ago", m / 1440),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_config_quoting_cannot_break_out_of_a_value() {
        assert_eq!(curl_quote("plain"), "\"plain\"");
        // A newline would otherwise start a new curl option (e.g. `output = /etc/…`).
        assert_eq!(curl_quote("a\nurl = x"), "\"a\\nurl = x\"");
        assert_eq!(curl_quote("q\"b\\"), "\"q\\\"b\\\\\"");
    }

    #[test]
    fn tokens_are_shape_checked() {
        assert!(validate_token("123456:ABCdefGHIjklMNOpqrSTUvwx_yz-12").is_ok());
        assert!(validate_token("123456:short").is_err());
        assert!(validate_token("123:abcdefghijklmnopqrstuvwxyz/../x").is_err());
        assert!(validate_token("abc:abcdefghijklmnopqrstuvwxyz").is_err());
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
        assert_eq!(encode_header("ascii\r\nBcc: x"), "ascii  Bcc: x");
        assert!(encode_header("Báo cáo").starts_with("=?UTF-8?B?"));
    }

    #[test]
    fn chats_are_found_in_updates_once_each() {
        let updates: Vec<serde_json::Value> = serde_json::from_str(
            r#"[{"message":{"chat":{"id":42,"type":"private","first_name":"Ana"}}},
                {"message":{"chat":{"id":42,"type":"private","first_name":"Ana"}}},
                {"my_chat_member":{"chat":{"id":-1001,"type":"supergroup","title":"Ops"}}}]"#,
        )
        .unwrap();
        let c = chats_from_updates(&updates);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].id, "42");
        assert_eq!(c[1].title, "Ops");
    }

    #[test]
    fn many_alerts_become_one_message_worst_first() {
        let a = |kind, severity, title: &str| Alert {
            machine: "m".into(),
            kind,
            severity,
            title: title.into(),
            body: "b".into(),
        };
        let x = a(AlertKind::NewIssues, Severity::Low, "low");
        let y = a(
            AlertKind::SecurityWarning,
            Severity::Critical,
            "key changed",
        );
        let m = compose(&[&x, &y]);
        assert!(m.subject.starts_with("Security warning"));
        assert!(m.text.find("key changed").unwrap() < m.text.find("low").unwrap());
    }
}

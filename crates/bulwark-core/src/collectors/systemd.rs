use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::PathBuf;

pub struct SystemdUnitsCollector;

/// The unit directories that hold persistence primitives. `/etc/systemd/system` is the classic
/// spot, but a `.timer`/`.socket`/`.path` unit carries an `ExecStart` just as a `.service` does,
/// a transient unit from `systemd-run` lands in `/run/systemd/system`, and — the one that needs no
/// root at all — a user-level unit under `~/.config/systemd/user` runs on every login. A collector
/// that only reads top-level `.service` files in one directory is blind to all of these, which is a
/// silent gap in exactly the checks (tunnels, reverse shells, exfil-on-boot) this feeds.
fn unit_search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/run/systemd/system"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config/systemd/user"));
    }
    dirs
}

/// Unit file extensions that can carry an `ExecStart` (or `ExecStartPost`) and therefore an
/// attacker payload. `.service` is the obvious one; the timer/socket/path activation units all
/// reach a service too, but a payload can sit directly on them as well.
const UNIT_EXTENSIONS: &[&str] = &["service", "timer", "socket", "path"];

/// Command-line flags whose *value* is a secret. When a unit's ExecStart passes credentials
/// inline — `cloudflared tunnel run --token eyJ…`, `--password …`, an API key — that value would
/// otherwise be copied verbatim into a finding's `explain` text and stored in the findings
/// database, where it is neither expected nor protected. cloudflared's connector token is a live
/// credential; leaking it into a security report is its own vulnerability. Matched
/// case-insensitively against the flag name, in both `--flag value` and `--flag=value` forms.
const SECRET_FLAGS: &[&str] = &[
    "--token",
    "--password",
    "--passwd",
    "--secret",
    "--client-secret",
    "--api-key",
    "--apikey",
    "--auth-token",
    "--access-token",
    "--auth",
];

/// Replaces secret values in a command line with a masked form, preserving enough of the command
/// for a human to recognise what it is (the tool, the flags) without exposing the credential. Two
/// shapes are handled: the value that follows a secret flag, and a bare JWT (`eyJ…`) sitting
/// anywhere in the line, since connector tokens are frequently passed positionally.
fn redact_secrets_in_command(command: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_next = false;
    for tok in command.split_whitespace() {
        if redact_next {
            out.push(crate::ai_scan::secrets::mask(tok));
            redact_next = false;
            continue;
        }
        // `--flag=value`
        if let Some((flag, value)) = tok.split_once('=') {
            if SECRET_FLAGS.iter().any(|f| flag.eq_ignore_ascii_case(f)) {
                out.push(format!("{flag}={}", crate::ai_scan::secrets::mask(value)));
                continue;
            }
        }
        // `--flag value` — mask whatever comes next.
        if SECRET_FLAGS.iter().any(|f| tok.eq_ignore_ascii_case(f)) {
            out.push(tok.to_string());
            redact_next = true;
            continue;
        }
        // A bare JWT (header.payload.signature, base64url) passed positionally.
        if tok.starts_with("eyJ") && tok.matches('.').count() == 2 && tok.len() > 24 {
            out.push(crate::ai_scan::secrets::mask(tok));
            continue;
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

/// Extracts the fields a persistence-detection rule cares about from one unit file's text: its
/// ExecStart/ExecStartPost lines, concatenated so a `contains`/`matches` condition can scan both
/// without the rule author needing to know which directive it's in. Secret-looking arguments are
/// masked here, at the collector boundary, so no credential ever reaches a finding or the database.
pub fn parse_unit_file(unit_name: &str, text: &str) -> Fact {
    let mut fact = Fact::new();
    fact.insert(
        "unit_name".to_string(),
        Value::String(unit_name.to_string()),
    );

    let mut exec_lines = Vec::new();
    let mut enabled_hint = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ExecStart=") {
            exec_lines.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("ExecStartPost=") {
            exec_lines.push(rest.to_string());
        } else if line.starts_with("WantedBy=") {
            enabled_hint = true;
        }
    }
    // Redact before joining, so the value stored in `exec_start` — which flows into the finding's
    // explain text and the findings database — never carries a live credential. The tool names the
    // rules match on (ngrok, cloudflared, curl, the messaging-API domains) are not secrets and
    // survive redaction untouched, so detection is unaffected.
    let redacted: Vec<String> = exec_lines
        .iter()
        .map(|l| redact_secrets_in_command(l))
        .collect();
    fact.insert(
        "exec_start".to_string(),
        Value::String(redacted.join(" ; ")),
    );
    fact.insert("has_install_section".to_string(), Value::Bool(enabled_hint));
    fact
}

impl Collector for SystemdUnitsCollector {
    fn name(&self) -> &'static str {
        "systemd_units"
    }

    fn is_applicable(&self) -> bool {
        unit_search_dirs().iter().any(|d| d.is_dir())
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        for dir in unit_search_dirs() {
            // A directory that doesn't exist (no /run units, no user units) is not an error — it's
            // just nothing to read. `read_dir` failing on a directory that *does* exist is also not
            // fatal to the whole scan: skip it and keep going with the others.
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_unit = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| UNIT_EXTENSIONS.contains(&e));
                if !is_unit {
                    continue;
                }
                let unit_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                // A unit file that's a broken symlink — the ordinary leftover of a purged package
                // — is *skipped*, not fatal. The previous version returned Err here, which the
                // engine turns into "this collector produced zero facts": one dangling symlink
                // anywhere under /etc/systemd/system blinded the entire persistence rule family
                // (PERSIST-001/002 never evaluated), which is the worst possible failure for a
                // security check — indistinguishable from "clean". A dangling symlink has no
                // target and so no ExecStart to scan, so continuing past it loses nothing real.
                if let Ok(text) = super::read_capped(&path) {
                    rows.push(parse_unit_file(&unit_name, &text));
                }
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exec_start_and_post() {
        let text = "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/ngrok tcp 22\nExecStartPost=/bin/bash -c 'curl https://api.telegram.org'\n[Install]\nWantedBy=multi-user.target\n";
        let fact = parse_unit_file("ngrok-ssh.service", text);
        let exec = fact.get("exec_start").unwrap().as_str().unwrap();
        assert!(exec.contains("ngrok"));
        assert!(exec.contains("curl"));
        assert_eq!(fact.get("has_install_section").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn a_dangling_symlink_does_not_hide_a_real_payload_unit_beside_it() {
        // The exact regression: a purged package leaves a dangling `.service` symlink, and an
        // attacker's persistence unit sits in the same directory. The collector used to abort on
        // the dangling link and return zero facts, so the payload unit — and the whole persistence
        // rule family — went silent. It must now survive.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        std::os::unix::fs::symlink(dir.join("does-not-exist"), dir.join("purged.service")).unwrap();
        std::fs::write(
            dir.join("evil.service"),
            "[Service]\nExecStart=/usr/bin/ngrok tcp 22\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();

        // Drive the same read-and-parse loop the collector uses, over the temp dir.
        let mut rows = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("service") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if let Ok(text) = std::fs::read_to_string(&path) {
                rows.push(parse_unit_file(&name, &text));
            }
        }

        assert_eq!(
            rows.len(),
            1,
            "the dangling symlink is skipped, the real unit is kept"
        );
        assert!(rows[0]
            .get("exec_start")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("ngrok"));
    }

    #[test]
    fn the_cloudflared_connector_token_is_redacted_out_of_exec_start() {
        // The exact leak: `cloudflared service install` writes a unit whose ExecStart carries the
        // live connector token. That token used to land verbatim in the finding's explain text and
        // in the findings database. The tool name must survive (so the rule still matches) while
        // the token must not.
        let text = "[Service]\nExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token eyJhIjoiZm9vIiwidCI6ImJhciIsInMiOiJiYXoifQ.sig.more\n[Install]\nWantedBy=multi-user.target\n";
        let fact = parse_unit_file("cloudflared.service", text);
        let exec = fact.get("exec_start").unwrap().as_str().unwrap();
        assert!(
            exec.contains("cloudflared"),
            "the tool name must remain for detection"
        );
        assert!(
            exec.contains("tunnel run"),
            "the command shape stays legible"
        );
        assert!(
            !exec.contains("eyJhIjoiZm9vIiwidCI6ImJhciIsInMiOiJiYXoifQ"),
            "the connector token must NOT appear: {exec}"
        );

        // And a `--password=value` inline form.
        let text2 = "[Service]\nExecStart=/opt/app --password=Tr0ub4dorAndMore3xKeep --host db\n";
        let exec2 = parse_unit_file("app.service", text2)
            .get("exec_start")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            !exec2.contains("Tr0ub4dorAndMore3xKeep"),
            "inline secret leaked: {exec2}"
        );
        assert!(exec2.contains("--host db"), "non-secret args stay intact");
    }

    #[test]
    fn timer_socket_and_path_units_are_scanned_too() {
        // A payload can ride an activation unit, not just a `.service`. These extensions must be
        // picked up or a `.timer` calling curl-pipe-sh is invisible.
        for ext in ["timer", "socket", "path"] {
            assert!(
                UNIT_EXTENSIONS.contains(&ext),
                "{ext} units carry ExecStart and must be collected"
            );
        }
    }
}

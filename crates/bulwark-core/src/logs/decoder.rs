//! Decoders: turn a raw log line into a [`Fact`] of named fields. This is OSSEC's decoder
//! stage — the part that owns "how do I get `srcip`/`user` out of *this* vendor's line" — kept
//! separate from rules so vendor log-format churn never touches detection logic.
//!
//! A decoder is `(optional program bucket) + (optional cheap prematch) + ordered capture
//! patterns`. The first pattern whose regex matches wins; its named captures become fact fields
//! and its `tags` become the event's `tags` array, which rules match on (a decoded line's
//! `tags contains "authentication_failed"` is OSSEC's `if_group`, expressed in the existing
//! condition DSL with no new operator).

use crate::models::{Fact, RuleLoadError};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use walkdir::WalkDir;

/// A decoder as authored in YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Decoder {
    pub id: String,
    /// The program/tag bucket this decoder applies to (matched against `RawEvent::program`).
    /// Omit for a cross-program decoder (e.g. a generic PAM decoder that keys off `prematch`
    /// instead, since PAM lines are emitted by sshd/sudo/login/cron alike). Program-specific
    /// decoders are always tried before program-agnostic ones.
    #[serde(default)]
    pub program: Option<String>,
    /// Optional cheap guard: if set and it doesn't match the message, the decoder is skipped
    /// before any (more expensive) capture regex runs.
    #[serde(default)]
    pub prematch: Option<String>,
    /// Ordered capture patterns; first match wins.
    pub patterns: Vec<DecodePattern>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecodePattern {
    pub regex: String,
    /// Semantic tags attached to any event this pattern decodes. Keep tags mutually
    /// non-substring (`authentication_failed`, not both `auth` and `authfail`): rules match
    /// them via the condition DSL's `contains`, which is a substring test over the serialized
    /// `tags` array.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A decoder with its regexes compiled, ready to run. Produced by [`load_decoders`].
pub struct CompiledDecoder {
    pub id: String,
    pub program: Option<String>,
    prematch: Option<Regex>,
    patterns: Vec<CompiledPattern>,
}

struct CompiledPattern {
    regex: Regex,
    tags: Vec<String>,
}

/// A raw event successfully decoded into fields.
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    pub decoder_id: String,
    pub fact: Fact,
}

/// Loads every `.yaml`/`.yml` file under `dir` as a [`Decoder`] and compiles its regexes,
/// mirroring [`crate::engine::load_rules`]: a decoder that fails to parse or whose regex fails
/// to compile is collected as a [`RuleLoadError`] and skipped, never a silent drop or a panic.
///
/// The returned decoders are sorted program-specific-first (then by id) so decoding order is
/// deterministic regardless of directory iteration order, and a generic catch-all decoder never
/// shadows a specific one.
pub fn load_decoders(dir: &Path) -> (Vec<CompiledDecoder>, Vec<RuleLoadError>) {
    let mut loaded = Vec::new();
    let mut errors = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yaml") | Some("yml")) {
            continue;
        }
        let path_str = path.display().to_string();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: e.to_string(),
                });
                continue;
            }
        };
        let decoder: Decoder = match serde_yaml::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: e.to_string(),
                });
                continue;
            }
        };
        match compile(decoder) {
            Ok(c) => loaded.push(c),
            Err(e) => errors.push(RuleLoadError {
                path: path_str,
                message: e,
            }),
        }
    }

    loaded.sort_by(|a, b| {
        a.program
            .is_none()
            .cmp(&b.program.is_none())
            .then_with(|| a.id.cmp(&b.id))
    });
    (loaded, errors)
}

fn compile(d: Decoder) -> Result<CompiledDecoder, String> {
    let prematch = match &d.prematch {
        Some(p) => Some(Regex::new(p).map_err(|e| format!("decoder {}: bad prematch: {e}", d.id))?),
        None => None,
    };
    if d.patterns.is_empty() {
        return Err(format!("decoder {}: has no patterns", d.id));
    }
    let mut patterns = Vec::with_capacity(d.patterns.len());
    for p in d.patterns {
        let regex = Regex::new(&p.regex)
            .map_err(|e| format!("decoder {}: bad pattern regex: {e}", d.id))?;
        patterns.push(CompiledPattern {
            regex,
            tags: p.tags,
        });
    }
    Ok(CompiledDecoder {
        id: d.id,
        program: d.program,
        prematch,
        patterns,
    })
}

/// Decodes `event` against the ordered `decoders`, returning the first successful decode. A
/// decoder applies when its `program` matches (or is absent) and its `prematch` matches (or is
/// absent); the first of its patterns to match produces the fact. Returns `None` when nothing
/// decodes — such events are counted but not matched against rules.
pub fn decode(
    decoders: &[CompiledDecoder],
    event: &super::event::RawEvent,
) -> Option<DecodedEvent> {
    for d in decoders {
        if let Some(prog) = &d.program {
            if event.program.as_deref() != Some(prog.as_str()) {
                continue;
            }
        }
        if let Some(pre) = &d.prematch {
            if !pre.is_match(&event.message) {
                continue;
            }
        }
        for pat in &d.patterns {
            let Some(caps) = pat.regex.captures(&event.message) else {
                continue;
            };
            let mut fact = base_fact(event);
            for name in pat.regex.capture_names().flatten() {
                if let Some(m) = caps.name(name) {
                    // A purely-numeric capture (e.g. sudo's `attempts`, a port) becomes a JSON
                    // number so a rule can use the numeric `>`/`>=` thresholds on it — the same
                    // coercion the sshd/sysctl collectors apply. Everything else stays a string.
                    let s = m.as_str();
                    let value = match s.parse::<i64>() {
                        Ok(n) => Value::from(n),
                        Err(_) => Value::String(s.to_string()),
                    };
                    fact.insert(name.to_string(), value);
                }
            }
            fact.insert(
                "tags".to_string(),
                Value::Array(pat.tags.iter().cloned().map(Value::String).collect()),
            );
            fact.insert("decoder".to_string(), Value::String(d.id.clone()));
            return Some(DecodedEvent {
                decoder_id: d.id.clone(),
                fact,
            });
        }
    }
    None
}

/// The always-present metadata fields, before any capture is layered on. Rules can reference
/// these (`program`, `message`, `host`, `pid`) directly.
fn base_fact(event: &super::event::RawEvent) -> Fact {
    let mut fact = Fact::new();
    fact.insert("message".to_string(), Value::String(event.message.clone()));
    if let Some(p) = &event.program {
        fact.insert("program".to_string(), Value::String(p.clone()));
    }
    if let Some(h) = &event.host {
        fact.insert("host".to_string(), Value::String(h.clone()));
    }
    if let Some(u) = &event.unit {
        fact.insert("unit".to_string(), Value::String(u.clone()));
    }
    if let Some(pid) = event.pid {
        fact.insert("pid".to_string(), Value::Number(pid.into()));
    }
    fact
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::event::RawEvent;
    use chrono::Utc;

    fn sshd_decoder() -> Vec<CompiledDecoder> {
        let d = Decoder {
            id: "sshd".into(),
            program: Some("sshd".into()),
            prematch: Some("^Failed|^Accepted".into()),
            patterns: vec![
                DecodePattern {
                    regex: r"^Failed \S+ for (?:invalid user )?(?P<user>.+) from (?P<srcip>\S+) port (?P<srcport>\d+)(?: ssh2)?\s*$".into(),
                    tags: vec!["authentication_failed".into()],
                },
                DecodePattern {
                    regex: r"^Accepted \S+ for (?P<user>.+) from (?P<srcip>\S+) port (?P<srcport>\d+)(?: ssh2)?\s*$".into(),
                    tags: vec!["authentication_success".into()],
                },
            ],
        };
        vec![compile(d).unwrap()]
    }

    fn ev(program: &str, msg: &str) -> RawEvent {
        RawEvent::new(Utc::now(), msg).with_program(program)
    }

    #[test]
    fn a_username_injecting_a_fake_from_ip_does_not_hijack_srcip() {
        // The attacker chooses username `x from 6.6.6.6 port 1 ssh2`; sshd logs it verbatim before
        // the genuine trailing `from 7.7.7.7 port 22`. The real source must be captured, not the
        // injected decoy — otherwise an innocent IP gets framed and the by-srcip correlation is
        // evaded by varying the fake IP per attempt.
        let decoders = sshd_decoder();
        let d = decode(
            &decoders,
            &ev(
                "sshd",
                "Failed password for invalid user x from 6.6.6.6 port 1 ssh2 from 7.7.7.7 port 22 ssh2",
            ),
        )
        .expect("line decodes");
        assert_eq!(d.fact.get("srcip").unwrap(), "7.7.7.7");
    }

    #[test]
    fn a_username_with_spaces_is_still_decoded_not_dropped() {
        let decoders = sshd_decoder();
        let d = decode(
            &decoders,
            &ev(
                "sshd",
                "Failed password for invalid user admin backdoor from 1.2.3.4 port 22 ssh2",
            ),
        )
        .expect("a spaced username must still decode, not be silently dropped");
        assert_eq!(d.fact.get("srcip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn decodes_failed_login_fields_and_tags() {
        let decoders = sshd_decoder();
        let d = decode(
            &decoders,
            &ev(
                "sshd",
                "Failed password for root from 10.0.0.5 port 2222 ssh2",
            ),
        )
        .unwrap();
        assert_eq!(d.decoder_id, "sshd");
        assert_eq!(d.fact.get("user").unwrap(), "root");
        assert_eq!(d.fact.get("srcip").unwrap(), "10.0.0.5");
        // A purely-numeric capture is coerced to a JSON number so rules can use numeric thresholds.
        assert_eq!(d.fact.get("srcport").unwrap(), &serde_json::json!(2222));
        // tags serialize to a JSON array; the condition DSL's `contains` substring-matches it.
        assert_eq!(
            d.fact.get("tags").unwrap().to_string(),
            r#"["authentication_failed"]"#
        );
    }

    #[test]
    fn invalid_user_variant_still_captures_user() {
        let decoders = sshd_decoder();
        let d = decode(
            &decoders,
            &ev(
                "sshd",
                "Failed password for invalid user admin from 1.2.3.4 port 40 ssh2",
            ),
        )
        .unwrap();
        assert_eq!(d.fact.get("user").unwrap(), "admin");
        assert_eq!(d.fact.get("srcip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn wrong_program_does_not_decode() {
        let decoders = sshd_decoder();
        assert!(decode(
            &decoders,
            &ev("cron", "Failed password for root from 10.0.0.5 port 2 ssh2")
        )
        .is_none());
    }

    #[test]
    fn prematch_guards_out_unrelated_messages() {
        let decoders = sshd_decoder();
        assert!(decode(&decoders, &ev("sshd", "Connection closed by 10.0.0.5")).is_none());
    }

    #[test]
    fn program_agnostic_decoder_matches_any_program_via_prematch() {
        let pam = compile(Decoder {
            id: "pam".into(),
            program: None,
            prematch: Some(r"pam_unix\(".into()),
            patterns: vec![DecodePattern {
                regex: r"authentication failure;.*rhost=(?P<srcip>\S+)".into(),
                tags: vec!["authentication_failed".into()],
            }],
        })
        .unwrap();
        let decoders = vec![pam];
        let d = decode(
            &decoders,
            &ev("sudo", "pam_unix(sudo:auth): authentication failure; logname=x uid=0 rhost=203.0.113.9 user=root"),
        )
        .unwrap();
        assert_eq!(d.fact.get("srcip").unwrap(), "203.0.113.9");
    }
}

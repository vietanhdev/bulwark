//! Log rules: what a decoded event *means*. A rule matches decoded fields with the existing
//! condition DSL and optionally correlates matches over a sliding window. This mirrors the
//! config-scan [`Rule`](crate::models::Rule) — same authoring model (one YAML file, a condition,
//! severity, references) so a contributor who can write a config rule can write a log rule.

use super::correlate::CorrelateSpec;
use crate::condition::Condition;
use crate::models::{RuleLoadError, Severity};
use serde::Deserialize;
use std::path::Path;
use walkdir::WalkDir;

fn default_true() -> bool {
    true
}

/// A log rule as authored in YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct LogRule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    /// Optional decoder scope: only events produced by this decoder are considered. Analogous
    /// to a config rule's `collector:`. Omit to match events from any decoder (rare — usually a
    /// rule cares about one log format).
    #[serde(default)]
    pub decoder: Option<String>,
    /// Boolean predicate over the decoded fact, in the shared condition DSL. `tags contains
    /// "authentication_failed"` is the idiomatic group match.
    pub condition: String,
    /// Semantic tags this rule contributes (the vocabulary future sequence rules will key off).
    /// Not yet consumed by the threshold correlator, but authored now so the rule pack is
    /// forward-compatible.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Optional correlation. Absent ⇒ the rule fires once per matching event.
    #[serde(default)]
    pub correlate: Option<CorrelateSpec>,
    pub explain: String,
    pub fix: String,
    #[serde(default)]
    pub references: Vec<String>,
    /// Whether a match should produce a finding. `false` marks a pure tagging/base rule that
    /// contributes semantics (via `groups`) without alerting on its own — the log analog of
    /// OSSEC's level-0 rules. Defaults to `true`.
    #[serde(default = "default_true")]
    pub alert: bool,
}

/// A log rule with its condition parsed once at load time.
pub struct LoadedLogRule {
    pub rule: LogRule,
    pub condition: Condition,
}

/// Loads every `.yaml`/`.yml` file under `dir` as a [`LogRule`], parsing its condition —
/// mirroring [`crate::engine::load_rules`] exactly (bad YAML / bad condition ⇒ a collected
/// [`RuleLoadError`], never a silent drop). A rule with a `correlate` block whose `count` is 0
/// is rejected here rather than silently never-firing.
pub fn load_log_rules(dir: &Path) -> (Vec<LoadedLogRule>, Vec<RuleLoadError>) {
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
        let rule: LogRule = match serde_yaml::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: e.to_string(),
                });
                continue;
            }
        };
        if let Some(spec) = &rule.correlate {
            if spec.count == 0 {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: format!("rule {}: correlate.count must be >= 1", rule.id),
                });
                continue;
            }
        }
        match Condition::parse(&rule.condition) {
            Ok(condition) => loaded.push(LoadedLogRule { rule, condition }),
            Err(e) => errors.push(RuleLoadError {
                path: path_str,
                message: format!("rule {}: bad condition: {}", rule.id, e),
            }),
        }
    }

    (loaded, errors)
}

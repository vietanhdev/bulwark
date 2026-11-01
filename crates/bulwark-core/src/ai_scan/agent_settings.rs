//! Settings detectors for every agent beyond Claude Code and VS Code: the places each one keeps
//! "approve everything", "allow any shell command", "run this hook", and "no sandbox".
//!
//! The *threats* are the same few across all of them, so they map onto the existing rule IDs rather
//! than minting a rule per vendor:
//!
//! | Threat | Rule |
//! |---|---|
//! | A repo ships hooks / startup code that run shell when it is opened | `BLWK-AI-002` |
//! | A permission allowlist admits arbitrary shell | `BLWK-AI-006` |
//! | The agent is told never to ask for approval | `BLWK-AI-007` |
//! | The agent's command sandbox is switched off | `BLWK-AI-021` |
//! | An MCP server's tools are trusted wholesale | `BLWK-AI-023` (in `detect_mcp_value`) |
//!
//! Every key matched here comes from the agent's official docs or source; a setting we could not
//! confirm is left out, because a detector keyed on an imagined setting name is a check that
//! silently never fires while the docs claim coverage.

use super::detectors::{
    detect_base_url, detect_claude_settings, detect_mcp_value, detect_vscode_settings,
    evidence_line, find_key_line, is_dangerous_permission, parse_jsonish, Detection,
};
use super::discovery::{tool_label, Tool};
use serde_json::Value;

fn hit(rule_id: &'static str, content: &str, needle: &str, explanation: String) -> Detection {
    let line = find_key_line(content, needle).unwrap_or(1);
    Detection {
        rule_id,
        explanation,
        line: Some(line),
        evidence: evidence_line(content, line),
    }
}

/// Walks a dotted path through nested objects (`"agent.tool_permissions.default"`). Also accepts a
/// literal dotted key at any level, because some tools (Amp, VS Code) store settings flat under
/// keys that themselves contain dots.
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(x) = v.get(path) {
        return Some(x);
    }
    let (head, rest) = path.split_once('.')?;
    at(v.get(head)?, rest)
}

fn str_at<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    at(v, path).and_then(Value::as_str)
}

fn is_true(v: &Value, path: &str) -> bool {
    at(v, path).and_then(Value::as_bool) == Some(true)
}

fn non_empty(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    }
}

fn parse(tool: Tool, content: &str) -> Option<Value> {
    match tool {
        Tool::Goose | Tool::Continue | Tool::OpenInterpreter | Tool::Aider => {
            serde_yaml::from_str(content).ok()
        }
        _ => parse_jsonish(content),
    }
}

/// Settings-file detectors, dispatched by the tool that owns the file. `is_project` is true for a
/// file inside a workspace — a setting a cloned repository imposes on you, rather than one you chose.
pub fn detect_settings(tool: Tool, content: &str, is_project: bool) -> Vec<Detection> {
    let mut out = match tool {
        Tool::ClaudeCode | Tool::Generic => detect_claude_settings(content, is_project),
        Tool::VsCode => detect_vscode_settings(content),
        _ => detect_base_url(content),
    };
    let Some(v) = parse(tool, content) else {
        return out;
    };
    let name = tool_label(tool);

    match tool {
        Tool::ClaudeCode | Tool::Generic => claude_sandbox(&v, content, &mut out),
        Tool::VsCode => vscode_extra(&v, content, &mut out),
        Tool::Gemini | Tool::Qwen => gemini_like(&v, content, name, &mut out),
        Tool::Zed => zed(&v, content, &mut out),
        Tool::Goose => goose(&v, content, &mut out),
        Tool::OpenCode | Tool::Kilo => opencode(&v, content, name, &mut out),
        Tool::Crush => crush(&v, content, is_project, &mut out),
        Tool::Cursor => cursor_cli(&v, content, &mut out),
        Tool::Augment => augment(&v, content, &mut out),
        Tool::OpenInterpreter => open_interpreter(&v, content, &mut out),
        _ => {}
    }

    // Claude Code's own settings carry hooks too, but `detect_claude_settings` already owns that
    // check (and its wording); every other tool's embedded `hooks` block is caught here.
    if is_project && !matches!(tool, Tool::ClaudeCode | Tool::Generic) && non_empty(v.get("hooks"))
    {
        out.push(hit(
            "BLWK-AI-002",
            content,
            "\"hooks\"",
            format!(
                "This project's {name} settings define hooks, which run shell commands automatically on agent events. A hook shipped in a repository runs code on your machine as soon as you work in it with {name}. Confirm you trust this repository's authors."
            ),
        ));
    }

    // MCP servers embedded in settings (Gemini/Qwen `mcpServers`, Zed `context_servers`, OpenCode
    // and Crush `mcp`, Amp `amp.mcpServers`, Goose `extensions`, Continue's YAML list). Claude
    // Code's settings.json carries no servers, so it is skipped rather than parsed twice.
    if !matches!(tool, Tool::ClaudeCode | Tool::Generic) {
        out.extend(detect_mcp_value(content, &v));
    }
    out
}

/// Claude Code: `sandbox.enableWeakerNestedSandbox` trades the sandbox's isolation for running
/// inside an unprivileged container.
fn claude_sandbox(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if is_true(v, "sandbox.enableWeakerNestedSandbox") {
        out.push(hit(
            "BLWK-AI-021",
            content,
            "enableWeakerNestedSandbox",
            "sandbox.enableWeakerNestedSandbox is on, which considerably weakens Claude Code's command sandbox. It is meant only for running inside a container that already isolates the host.".to_string(),
        ));
    }
}

fn vscode_extra(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if is_true(
        v,
        "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions",
    ) {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "allowDangerouslySkipPermissions",
            "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions lets the Claude agent in Copilot Chat run without asking for approval.".to_string(),
        ));
    }
    // `chat.tools.terminal.autoApprove` maps a command or `/regex/` to true; a match-everything
    // entry auto-runs every terminal command the agent proposes.
    if let Some(rules) = at(v, "chat.tools.terminal.autoApprove").and_then(Value::as_object) {
        let approves = |x: &Value| {
            x.as_bool() == Some(true) || x.get("approve").and_then(Value::as_bool) == Some(true)
        };
        if let Some((k, _)) = rules
            .iter()
            .find(|(k, x)| is_match_all_regex_key(k) && approves(x))
        {
            out.push(hit(
                "BLWK-AI-006",
                content,
                "chat.tools.terminal.autoApprove",
                format!(
                    "chat.tools.terminal.autoApprove approves \"{k}\", which matches every terminal command the agent runs."
                ),
            ));
        }
    }
}

/// A VS Code auto-approve key is a command *prefix* unless wrapped in slashes, when it is a regex.
/// Only a regex that matches everything is flagged: a bare `"*"` key is a literal prefix, and
/// claiming it approves every command would be a guess about VS Code's matcher.
fn is_match_all_regex_key(k: &str) -> bool {
    k.len() >= 2
        && k.starts_with('/')
        && k.ends_with('/')
        && is_match_all_pattern(&k[1..k.len() - 1])
}

fn is_match_all_pattern(p: &str) -> bool {
    matches!(p, "*" | ".*" | ".+" | "^.*$" | "^.*" | "^.+$" | "")
}

/// Gemini CLI and its fork Qwen Code share a settings schema.
fn gemini_like(v: &Value, content: &str, name: &str, out: &mut Vec<Detection>) {
    // Qwen Code accepts `yolo` here; Gemini CLI only allows YOLO from a command-line flag, so the
    // key simply never matches for it.
    if str_at(v, "tools.approvalMode") == Some("yolo") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "yolo",
            format!("tools.approvalMode is \"yolo\": {name} runs every tool call, including shell commands, without asking."),
        ));
    }
    // `tools.allowed` / `permissions.allow` skip confirmation for the listed tools. (`coreTools` only
    // restricts which tools exist, so it is deliberately not here.)
    for key in ["tools.allowed", "permissions.allow"] {
        if let Some(list) = at(v, key).and_then(Value::as_array) {
            if let Some(e) = list
                .iter()
                .filter_map(Value::as_str)
                .find(|e| is_dangerous_permission(e))
            {
                out.push(hit(
                    "BLWK-AI-006",
                    content,
                    e,
                    format!("{key} allows \"{e}\" without asking, which covers arbitrary shell commands rather than a specific one."),
                ));
            }
        }
    }
}

fn zed(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if is_true(v, "agent.always_allow_tool_actions") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "always_allow_tool_actions",
            "agent.always_allow_tool_actions is on: Zed's agent runs every tool, including the terminal, without asking.".to_string(),
        ));
    }
    if str_at(v, "agent.tool_permissions.default") == Some("allow") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "tool_permissions",
            "agent.tool_permissions.default is \"allow\": Zed's agent runs every tool without asking unless a tool overrides it.".to_string(),
        ));
    }
    if let Some(term) = at(v, "agent.tool_permissions.tools.terminal") {
        let blanket = term.get("default").and_then(Value::as_str) == Some("allow");
        let wildcard = term
            .get("always_allow")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter().any(|r| {
                    r.get("pattern")
                        .and_then(Value::as_str)
                        .or_else(|| r.as_str())
                        .is_some_and(is_match_all_pattern)
                })
            });
        if blanket || wildcard {
            out.push(hit(
                "BLWK-AI-006",
                content,
                "\"terminal\"",
                "Zed's terminal tool is set to always allow every command, so the agent can run any shell command without asking.".to_string(),
            ));
        }
    }
}

fn goose(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if str_at(v, "GOOSE_MODE") == Some("auto") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "GOOSE_MODE",
            "GOOSE_MODE is \"auto\": Goose runs every tool call, including shell commands and file edits, without asking.".to_string(),
        ));
    }
}

/// OpenCode and Kilo Code: `permission` is either a single action for everything or a map of
/// tool → action (and bash → pattern → action).
fn opencode(v: &Value, content: &str, name: &str, out: &mut Vec<Detection>) {
    let Some(perm) = v.get("permission") else {
        return;
    };
    let all_allowed =
        perm.as_str() == Some("allow") || perm.get("*").and_then(Value::as_str) == Some("allow");
    if all_allowed {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "\"permission\"",
            format!("permission is set to \"allow\" for every tool: {name} runs shell commands and edits files without asking."),
        ));
        return;
    }
    let bash = perm.get("bash");
    let bash_all = bash.and_then(Value::as_str) == Some("allow")
        || bash.and_then(|b| b.get("*")).and_then(Value::as_str) == Some("allow");
    if bash_all {
        out.push(hit(
            "BLWK-AI-006",
            content,
            "\"bash\"",
            format!("permission.bash allows every command, so {name} can run any shell command without asking."),
        ));
    }
}

fn crush(v: &Value, content: &str, is_project: bool, out: &mut Vec<Detection>) {
    if let Some(list) = at(v, "permissions.allowed_tools").and_then(Value::as_array) {
        if list
            .iter()
            .filter_map(Value::as_str)
            .any(|t| t == "bash" || t == "*")
        {
            out.push(hit(
                "BLWK-AI-006",
                content,
                "allowed_tools",
                "permissions.allowed_tools includes the bash tool, so Crush runs any shell command without asking.".to_string(),
            ));
        }
    }
    // Crush expands `$(…)` in its JSON config by running it in a shell at load time, so a project
    // crush.json containing one runs the repository's command as soon as Crush starts there.
    if is_project && content.contains("$(") {
        out.push(hit(
            "BLWK-AI-002",
            content,
            "$(",
            "This project's Crush config contains a $(…) command substitution, which Crush runs in a shell when it loads the config. Opening the repository with Crush runs that command.".to_string(),
        ));
    }
}

/// Cursor CLI (`cli-config.json`, project `.cursor/cli.json`).
fn cursor_cli(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if str_at(v, "approvalMode") == Some("unrestricted") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "approvalMode",
            "approvalMode is \"unrestricted\": the Cursor CLI agent runs every command without asking.".to_string(),
        ));
    }
    if let Some(list) = at(v, "permissions.allow").and_then(Value::as_array) {
        if let Some(e) = list
            .iter()
            .filter_map(Value::as_str)
            .find(|e| is_dangerous_permission(e))
        {
            out.push(hit(
                "BLWK-AI-006",
                content,
                e,
                format!("The Cursor CLI allowlist contains \"{e}\", which permits arbitrary shell commands."),
            ));
        }
    }
    if str_at(v, "sandbox.mode") == Some("disabled") {
        out.push(hit(
            "BLWK-AI-021",
            content,
            "\"mode\"",
            "sandbox.mode is \"disabled\": commands the Cursor CLI agent runs are not isolated from the rest of your machine.".to_string(),
        ));
    }
}

/// Augment / Auggie: `toolPermissions` rules, first match wins. A rule that allows the process tool
/// with no input regex allows every command.
fn augment(v: &Value, content: &str, out: &mut Vec<Detection>) {
    let Some(rules) = v.get("toolPermissions").and_then(Value::as_array) else {
        return;
    };
    let blanket = rules.iter().any(|r| {
        let tool = r.get("toolName").and_then(Value::as_str).unwrap_or("");
        let allow = r
            .get("permission")
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str)
            == Some("allow");
        let regex = r.get("shellInputRegex").and_then(Value::as_str);
        allow
            && matches!(tool, "launch-process" | "bash" | "shell" | "*")
            && regex.is_none_or(is_match_all_pattern)
    });
    if blanket {
        out.push(hit(
            "BLWK-AI-006",
            content,
            "toolPermissions",
            "An Augment toolPermissions rule allows the shell tool for any input, so the agent can run every command without asking.".to_string(),
        ));
    }
}

/// Open Interpreter (Python release) profiles: `auto_run: true` executes generated code without
/// showing it first.
fn open_interpreter(v: &Value, content: &str, out: &mut Vec<Detection>) {
    if is_true(v, "auto_run") {
        out.push(hit(
            "BLWK-AI-007",
            content,
            "auto_run",
            "auto_run is on in this Open Interpreter profile: generated code runs on your machine without being shown to you first.".to_string(),
        ));
    }
}

/// A dedicated hook file (`.cursor/hooks.json`, `.kiro/hooks/*`, `.github/hooks/*.json`,
/// `.devin/hooks.v1.json`, `.clinerules/hooks/<Event>`, a project `crushrc`). Only a project-supplied
/// one is a finding: your own hooks in your home directory are your automation, not an attack.
pub fn detect_hooks_file(tool: Tool, content: &str, is_project: bool) -> Vec<Detection> {
    if !is_project {
        return Vec::new();
    }
    let name = tool_label(tool);
    let runs_something = match parse_jsonish(content) {
        Some(v) => has_command(&v),
        // A script (Cline hook, crushrc): anything that isn't blank or a comment is code.
        None => content
            .lines()
            .map(str::trim)
            .any(|l| !l.is_empty() && !l.starts_with('#')),
    };
    if !runs_something {
        return Vec::new();
    }
    let needle = if content.contains("\"command\"") {
        "\"command\""
    } else {
        content
            .lines()
            .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .unwrap_or("")
    };
    let explanation = if tool == Tool::Crush {
        // A crushrc is not an event hook: it is the config itself, written as a shell script that
        // Crush runs every time it starts in this directory.
        "This repository ships a crushrc, a shell script Crush runs every time it starts in this directory. Opening the repository with Crush runs code its authors chose. Confirm you trust them.".to_string()
    } else {
        format!(
            "This repository ships a {name} hook file that runs shell commands automatically on agent events. Working in the repository with {name} runs code its authors chose. Confirm you trust them."
        )
    };
    vec![hit("BLWK-AI-002", content, needle, explanation)]
}

/// True if any hook entry in a parsed hook file carries a shell command.
fn has_command(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.iter().any(|(k, x)| {
            (matches!(k.as_str(), "command" | "bash" | "powershell" | "exec")
                && x.as_str().is_some_and(|s| !s.trim().is_empty()))
                || has_command(x)
        }),
        Value::Array(a) => a.iter().any(has_command),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(d: &[Detection]) -> Vec<&'static str> {
        d.iter().map(|x| x.rule_id).collect()
    }

    #[test]
    fn zed_auto_allow_and_terminal_wildcard() {
        let d = detect_settings(
            Tool::Zed,
            r#"{"agent":{"tool_permissions":{"default":"allow","tools":{"terminal":{"always_allow":[{"pattern":".*"}]}}}}}"#,
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-007"));
        assert!(rules(&d).contains(&"BLWK-AI-006"));
        let legacy = detect_settings(
            Tool::Zed,
            r#"{"agent":{"always_allow_tool_actions":true}}"#,
            false,
        );
        assert!(rules(&legacy).contains(&"BLWK-AI-007"));
    }

    #[test]
    fn zed_default_confirm_and_scoped_allow_are_silent() {
        let d = detect_settings(
            Tool::Zed,
            r#"{"agent":{"tool_permissions":{"default":"confirm","tools":{"terminal":{"always_allow":[{"pattern":"^cargo test"}]}}}}}"#,
            false,
        );
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn zed_context_server_goes_through_mcp_checks() {
        let d = detect_settings(
            Tool::Zed,
            r#"{"context_servers":{"x":{"command":"npx","args":["-y","some-server"]}}}"#,
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-003"), "{d:?}");
    }

    #[test]
    fn goose_auto_mode_and_unpinned_extension() {
        let d = detect_settings(
            Tool::Goose,
            "GOOSE_MODE: auto\nextensions:\n  dev:\n    type: stdio\n    cmd: uvx\n    args: [some-server]\n  mem:\n    type: builtin\n",
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-007"));
        assert!(rules(&d).contains(&"BLWK-AI-003"), "{d:?}");
        let calm = detect_settings(Tool::Goose, "GOOSE_MODE: smart_approve\n", false);
        assert!(calm.is_empty(), "{calm:?}");
    }

    #[test]
    fn opencode_permission_shapes() {
        assert!(rules(&detect_settings(
            Tool::OpenCode,
            r#"{"permission":"allow"}"#,
            false
        ))
        .contains(&"BLWK-AI-007"));
        assert!(rules(&detect_settings(
            Tool::Kilo,
            r#"{"permission":{"*":"allow"}}"#,
            false
        ))
        .contains(&"BLWK-AI-007"));
        assert!(rules(&detect_settings(
            Tool::OpenCode,
            r#"{"permission":{"bash":{"*":"allow"}}}"#,
            false
        ))
        .contains(&"BLWK-AI-006"));
        // Scoped: only `git status` is allowed; everything else asks.
        let scoped = detect_settings(
            Tool::OpenCode,
            r#"{"permission":{"bash":{"*":"ask","git status":"allow"}}}"#,
            false,
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    #[test]
    fn opencode_array_command_mcp_is_normalized() {
        let d = detect_settings(
            Tool::OpenCode,
            r#"{"mcp":{"x":{"type":"local","command":["bash","-c","curl x | sh"]}}}"#,
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-005"), "{d:?}");
    }

    #[test]
    fn crush_bash_allowed_and_project_command_substitution() {
        let d = detect_settings(
            Tool::Crush,
            r#"{"permissions":{"allowed_tools":["view","bash"]},"providers":{"x":{"api_key":"$(cat ~/.k)"}}}"#,
            true,
        );
        assert!(rules(&d).contains(&"BLWK-AI-006"));
        assert!(rules(&d).contains(&"BLWK-AI-002"));
        // The same substitution in the user's own global config is their choice.
        let own = detect_settings(
            Tool::Crush,
            r#"{"providers":{"x":{"api_key":"$(pass k)"}}}"#,
            false,
        );
        assert!(own.is_empty(), "{own:?}");
    }

    #[test]
    fn qwen_yolo_shell_allow_trust_and_project_hooks() {
        let d = detect_settings(
            Tool::Qwen,
            r#"{"tools":{"approvalMode":"yolo","allowed":["run_shell_command"]},"mcpServers":{"s":{"command":"node","args":["s.js"],"trust":true}},"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
            true,
        );
        for r in ["BLWK-AI-006", "BLWK-AI-007", "BLWK-AI-023", "BLWK-AI-002"] {
            assert!(rules(&d).contains(&r), "{r} missing: {d:?}");
        }
        // A scoped allow (`run_shell_command(git)`) is fine.
        let scoped = detect_settings(
            Tool::Qwen,
            r#"{"tools":{"allowed":["run_shell_command(git)"]}}"#,
            false,
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    #[test]
    fn global_hooks_are_not_flagged() {
        let d = detect_settings(
            Tool::Gemini,
            r#"{"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"x"}]}]}}"#,
            false,
        );
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn cursor_cli_unrestricted_shell_star_and_sandbox_off() {
        let d = detect_settings(
            Tool::Cursor,
            r#"{"approvalMode":"unrestricted","permissions":{"allow":["Shell(*)"]},"sandbox":{"mode":"disabled"}}"#,
            false,
        );
        for r in ["BLWK-AI-006", "BLWK-AI-007", "BLWK-AI-021"] {
            assert!(rules(&d).contains(&r), "{r} missing: {d:?}");
        }
        let scoped = detect_settings(
            Tool::Cursor,
            r#"{"approvalMode":"allowlist","permissions":{"allow":["Shell(git)","Read(src/**)"]}}"#,
            false,
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    #[test]
    fn amp_mcp_augment_and_open_interpreter() {
        // Amp's servers live under a flat dotted key.
        assert!(rules(&detect_settings(
            Tool::Amp,
            r#"{"amp.mcpServers":{"x":{"command":"npx","args":["-y","some-amp-server"]}}}"#,
            false
        ))
        .contains(&"BLWK-AI-003"));
        let aug = detect_settings(
            Tool::Augment,
            r#"{"toolPermissions":[{"toolName":"launch-process","permission":{"type":"allow"}}]}"#,
            false,
        );
        assert!(rules(&aug).contains(&"BLWK-AI-006"));
        let aug_scoped = detect_settings(
            Tool::Augment,
            r#"{"toolPermissions":[{"toolName":"launch-process","shellInputRegex":"^npm test$","permission":{"type":"allow"}}]}"#,
            false,
        );
        assert!(aug_scoped.is_empty(), "{aug_scoped:?}");
        assert!(rules(&detect_settings(
            Tool::OpenInterpreter,
            "auto_run: true\n",
            false
        ))
        .contains(&"BLWK-AI-007"));
    }

    #[test]
    fn vscode_claude_agent_skip_permissions_and_terminal_wildcard() {
        let d = detect_settings(
            Tool::VsCode,
            r#"{"github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions":true,"chat.tools.terminal.autoApprove":{"/.*/":true}}"#,
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-007"));
        assert!(rules(&d).contains(&"BLWK-AI-006"));
        let scoped = detect_settings(
            Tool::VsCode,
            r#"{"chat.tools.terminal.autoApprove":{"npm test":true,"*":true,"/^git (status|log)/":true}}"#,
            false,
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    #[test]
    fn continue_yaml_list_mcp() {
        let d = detect_settings(
            Tool::Continue,
            "mcpServers:\n  - name: fs\n    command: npx\n    args: [\"-y\", \"@modelcontextprotocol/server-filesystem@1.0.0\", \"/\"]\n",
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-020"), "{d:?}");
    }

    #[test]
    fn claude_weaker_nested_sandbox() {
        let d = detect_settings(
            Tool::ClaudeCode,
            r#"{"sandbox":{"enabled":true,"enableWeakerNestedSandbox":true}}"#,
            false,
        );
        assert!(rules(&d).contains(&"BLWK-AI-021"));
        let ok = detect_settings(Tool::ClaudeCode, r#"{"sandbox":{"enabled":true}}"#, false);
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn project_hook_files_fire_and_global_ones_do_not() {
        let cursor = r#"{"version":1,"hooks":{"sessionStart":[{"command":"./setup.sh"}]}}"#;
        assert!(rules(&detect_hooks_file(Tool::Cursor, cursor, true)).contains(&"BLWK-AI-002"));
        assert!(detect_hooks_file(Tool::Cursor, cursor, false).is_empty());
        let kiro = r#"{"version":"v1","hooks":[{"name":"x","when":{"type":"fileEdited"},"then":{"type":"command","command":"make"}}]}"#;
        assert!(rules(&detect_hooks_file(Tool::Kiro, kiro, true)).contains(&"BLWK-AI-002"));
        // An agent-prompt hook with no shell command is not this finding.
        let prompt_only =
            r#"{"version":"v1","hooks":[{"name":"x","then":{"type":"agent","prompt":"review"}}]}"#;
        assert!(detect_hooks_file(Tool::Kiro, prompt_only, true).is_empty());
        // A script hook: comments-only is inert, a real line is code.
        assert!(detect_hooks_file(Tool::Cline, "#!/bin/sh\n# nothing yet\n", true).is_empty());
        assert!(!detect_hooks_file(Tool::Crush, "permissions allow bash\n", true).is_empty());
    }
}

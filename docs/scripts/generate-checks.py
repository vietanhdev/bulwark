#!/usr/bin/env python3
"""Builds docs/checks/catalog.json, the data behind one website page per check.

Sources are the same files the scanner reads, so a page can never describe a check differently
from the finding Bulwark shows:

- rules/**/*.yaml for the configuration rules (title, severity, explain, fix, references,
  collector and condition);
- the CATALOG in crates/bulwark-core/src/ai_scan/detectors.rs for the AI assistant checks, with
  the one-line description from the table in docs/guide/agent-security.md (those checks build
  their explanation per finding, so the table is the only static "what this means").

Run from anywhere:  python3 docs/scripts/generate-checks.py [--check]
--check exits 1 if catalog.json is stale, for CI.
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "checks" / "catalog.json"

# Mirrors apps/bulwark-app/src/lib/groups.ts so the site groups checks the way the app does.
GROUPS = [
    ("secrets", "Secrets & credentials", "Tokens and keys in plain text, unprotected SSH keys, keys leaked into AI sessions."),
    ("supply-chain", "Supply chain", "Packages, startup hooks and MCP servers that can run code on this machine."),
    ("network", "Exposed services", "Dev databases and services other machines can reach, and the firewall."),
    ("ai-agents", "AI coding agents", "Hooks, permissions and auto-approve settings a prompt injection could abuse."),
    ("remote-access", "SSH", "How this machine accepts SSH logins."),
    ("intrusion", "Compromise indicators", "Malware, suspicious startup programs, tampering and changed system files."),
    ("hardening", "OS hardening", "Kernel settings, file permissions, accounts and logging."),
]
BY_CATEGORY = {
    "credential-exposure": "secrets",
    "developer-tools": "supply-chain",
    "network-egress": "network",
    "ssh-remote-access": "remote-access",
    "rootkit-malware": "intrusion",
    "persistence": "intrusion",
    "defense-evasion": "intrusion",
    "file-integrity": "intrusion",
    "kernel-hardening": "hardening",
    "filesystem-permissions": "hardening",
    "accounts-services": "hardening",
    "logging-auditing": "hardening",
    "macos-hardening": "hardening",
    "windows-hardening": "hardening",
    "privilege-escalation": "hardening",
}
BY_RULE = {
    "BLWK-SSH-012": "secrets",
    "BLWK-SSH-013": "secrets",
    "BLWK-SSH-015": "secrets",
    "BLWK-AI-001": "secrets",
    "BLWK-AI-015": "secrets",
    "BLWK-AI-016": "secrets",
    "BLWK-AI-018": "secrets",
    "BLWK-PERSIST-005": "supply-chain",
    "BLWK-DEV-009": "network",
    "BLWK-ROOTKIT-002": "supply-chain",
    "BLWK-AI-003": "supply-chain",
    "BLWK-AI-004": "supply-chain",
    "BLWK-AI-005": "supply-chain",
    "BLWK-AI-019": "supply-chain",
}

# Checks Bulwark can fix from the app or `bulwark fix`, so a page can say so.
AUTO_FIX = {
    "BLWK-AI-001": "In the app, open the issue and use “Remove secret from this file”. From a terminal: `bulwark ai redact` (preview), then `bulwark ai redact --apply`.",
    "BLWK-SSH-012": "In the app, open the issue and use “Add a passphrase”. From a terminal: `bulwark ssh protect`.",
    "BLWK-SSH-015": "In the app, open the issue and use “Fix automatically”, or “Fix now” for every safe fix. From a terminal: `bulwarkctl fix ssh-perms` (preview), then `bulwarkctl fix ssh-perms --apply`.",
}


def group_of(rule_id: str, category: str) -> str:
    if rule_id in BY_RULE:
        return BY_RULE[rule_id]
    if rule_id.startswith("BLWK-AI-"):
        return "ai-agents"
    return BY_CATEGORY.get(category, "hardening")


def ai_checks() -> list[dict]:
    src = (ROOT / "crates/bulwark-core/src/ai_scan/detectors.rs").read_text()
    catalog = src[src.index("pub const CATALOG") : src.index("];", src.index("pub const CATALOG"))]
    entries = re.findall(
        r'id:\s*"([^"]+)",\s*title:\s*"((?:[^"\\]|\\.)*)",\s*fix:\s*"((?:[^"\\]|\\.)*)",\s*'
        r"severity:\s*(\w+),\s*references:\s*&\[([^\]]*)\]",
        catalog,
    )
    expected = len(re.findall(r"RuleMeta\s*\{", catalog))
    if len(entries) != expected:
        sys.exit(f"parsed {len(entries)} of {expected} AI catalog entries; update the regex")

    table = (ROOT / "docs/guide/agent-security.md").read_text()
    about = {}
    for rid, sev, desc in re.findall(r"^\| \[?`(BLWK-AI-\d+)`(?:\]\([^)]*\))? \| ([^|]+) \| ([^|]+) \|", table, re.M):
        about[rid] = (sev.strip(), re.sub(r"\*\*(.+?)\*\*", r"\1", desc.strip()))

    if len(about) != len(entries):
        sys.exit(f"read {len(about)} of {len(entries)} AI check descriptions from agent-security.md")
    out = []
    for rid, title, fix, sev, refs in entries:
        unescape = lambda s: json.loads(f'"{s}"')
        table_sev, desc = about.get(rid, ("", ""))
        out.append(
            {
                "id": rid,
                "title": unescape(title),
                "category": "ai-agents",
                # AI-001's severity depends on the secret, so the catalog carries a placeholder;
                # the page shows the worst case and says it varies.
                "severity": table_sev.split("/")[0].strip().lower() if sev == "Info" else sev.lower(),
                **({"severityNote": "Depends on the kind of secret found."} if sev == "Info" else {}),
                "explain": desc + "." if desc and not desc.endswith(".") else desc,
                "fix": unescape(fix),
                "references": [r.strip().strip('"') for r in refs.split(",") if r.strip()],
                "collector": "ai_scan",
                "condition": None,
            }
        )
    return out


def per_tool_fixes() -> str:
    """The fix text of a rule whose `fix` is filled in per finding.

    BLWK-DEV-011's fix is `{{ dev_tool_config.how_to_fix }}`: the collector supplies a different
    sentence for npm, bun and uv. A page built from the rule alone would show an empty
    placeholder under "How to fix it", so the sentences are read from the collector, one line
    per tool, the same way the AI checks are read from detectors.rs.
    """
    src = (ROOT / "crates/bulwark-core/src/collectors/dev_tools.rs").read_text()
    entries = re.findall(
        r'tool:\s*"([^"]+)",(?:(?!UserPractices\s*\{).)*?how_to_fix:\s*"((?:[^"\\]|\\.)*)"',
        src,
        re.S,
    )
    expected = len(re.findall(r'how_to_fix:\s*"', src))
    if not entries or len(entries) != expected:
        sys.exit(f"parsed {len(entries)} of {expected} per-tool fixes in dev_tools.rs; update the regex")
    # The source text is a Rust string literal; its escapes (\", \\) are also valid JSON ones.
    return "\n".join(tool + ": " + json.loads('"' + text + '"') for tool, text in entries)


# Rules whose whole `fix` is one templated value, and where that value comes from.
TEMPLATED_FIX = {"{{ dev_tool_config.how_to_fix }}": per_tool_fixes}


def fix_text(rule: dict) -> str:
    fix = rule["fix"].strip()
    if fix in TEMPLATED_FIX:
        return TEMPLATED_FIX[fix]()
    # Any other fix that is nothing but a template would render as a bare placeholder on the
    # page. Refuse it here, so it is a failed check instead of a page with no fix on it.
    if re.fullmatch(r"\{\{[^}]*\}\}", fix):
        sys.exit(f"{rule['id']}: its fix is only a template ({fix}); add it to TEMPLATED_FIX")
    return fix


def config_checks() -> list[dict]:
    out = []
    for path in sorted((ROOT / "rules").rglob("*.yaml")):
        r = yaml.safe_load(path.read_text())
        out.append(
            {
                "id": r["id"],
                "title": r["title"],
                "category": r["category"],
                "severity": r["severity"],
                "explain": " ".join(r["explain"].split()),
                "fix": fix_text(r),
                "references": r.get("references", []),
                "collector": r["collector"],
                "condition": r["condition"],
                "source": str(path.relative_to(ROOT)),
            }
        )
    return out


def main() -> None:
    checks = config_checks() + ai_checks()
    for c in checks:
        c["group"] = group_of(c["id"], c["category"])
        c["slug"] = c["id"].lower()
        if c["id"] in AUTO_FIX:
            c["autofix"] = AUTO_FIX[c["id"]]
    data = {
        "groups": [{"id": g, "title": t, "blurb": b} for g, t, b in GROUPS],
        "checks": checks,
    }
    text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            sys.exit("docs/checks/catalog.json is stale: run python3 docs/scripts/generate-checks.py")
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {len(checks)} checks to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

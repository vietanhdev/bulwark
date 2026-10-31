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
    "privilege-escalation": "hardening",
}
BY_RULE = {
    "BLWK-SSH-012": "secrets",
    "BLWK-SSH-013": "secrets",
    "BLWK-AI-001": "secrets",
    "BLWK-AI-015": "secrets",
    "BLWK-AI-016": "secrets",
    "BLWK-AI-018": "secrets",
    "BLWK-PERSIST-005": "supply-chain",
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
                "fix": r["fix"].strip(),
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

/* Category slugs are kebab-case on disk (`ssh-remote-access`, `rootkit-malware`) because
   that's the directory name under rules/. Title-casing them blindly produces "Ssh Remote
   Access", which reads as a typo in a tool aimed at people who type `ssh` daily. These are the
   slugs whose casing a naive `\b\w` capitalise gets wrong. */
const ACRONYMS: Record<string, string> = {
  ssh: "SSH",
  ai: "AI",
  mcp: "MCP",
};

/** What each rule category is about, in the words a person would use. The slugs are the rule
 *  directory names, which describe the taxonomy rather than the thing being protected. */
const FRIENDLY: Record<string, string> = {
  "accounts-services": "Accounts and services",
  "agent-security": "AI assistants",
  "credential-exposure": "Stored passwords and keys",
  "developer-tools": "Developer tool settings",
  "defense-evasion": "Tampering and hiding",
  "file-integrity": "Changed system files",
  "filesystem-permissions": "File permissions",
  "kernel-hardening": "Kernel settings",
  "logging-auditing": "Logging",
  "macos-hardening": "macOS settings",
  "windows-hardening": "Windows settings",
  "network-egress": "Network exposure",
  persistence: "Programs that start on their own",
  "privilege-escalation": "Administrator access",
  "rootkit-malware": "Malware",
  "ssh-remote-access": "SSH remote access",
};

/** `network-egress` → `Network exposure`; unknown slugs fall back to `ssh-remote-access` →
 *  `SSH Remote Access` style title-casing. */
export function categoryLabel(category: string): string {
  if (FRIENDLY[category]) return FRIENDLY[category];
  return category
    .split("-")
    .map((word) => ACRONYMS[word] ?? word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

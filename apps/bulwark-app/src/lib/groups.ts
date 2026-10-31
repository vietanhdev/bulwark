/**
 * How findings are grouped: around what a developer's machine is actually exposed by (secrets,
 * supply chain, exposed dev services, AI agents), not the rule pack's directory taxonomy. Order is
 * by developer relevance; OS hardening comes last. A few rules move by ID where their category says
 * one thing and a developer would look for it elsewhere (an unprotected SSH key is a secrets
 * problem, an unpinned MCP package is a supply-chain one).
 */
export interface FindingGroupInfo {
  id: string;
  title: string;
  blurb: string;
}

export const GROUPS: FindingGroupInfo[] = [
  {
    id: "secrets",
    title: "Secrets & credentials",
    blurb: "Tokens and keys in plain text, unprotected SSH keys, keys leaked into AI sessions.",
  },
  {
    id: "supply-chain",
    title: "Supply chain",
    blurb: "Packages, startup hooks and MCP servers that can run code on this machine.",
  },
  {
    id: "network",
    title: "Exposed services",
    blurb: "Dev databases and services other machines can reach, and the firewall.",
  },
  {
    id: "ai-agents",
    title: "AI coding agents",
    blurb: "Hooks, permissions and auto-approve settings a prompt injection could abuse.",
  },
  {
    id: "remote-access",
    title: "SSH",
    blurb: "How this machine accepts SSH logins.",
  },
  {
    id: "intrusion",
    title: "Compromise indicators",
    blurb: "Malware, suspicious startup programs, tampering and changed system files.",
  },
  {
    id: "hardening",
    title: "OS hardening",
    blurb: "Kernel settings, file permissions, accounts and logging.",
  },
];

const BY_CATEGORY: Record<string, string> = {
  "credential-exposure": "secrets",
  "network-egress": "network",
  "ssh-remote-access": "remote-access",
  "rootkit-malware": "intrusion",
  persistence: "intrusion",
  "defense-evasion": "intrusion",
  "file-integrity": "intrusion",
  "kernel-hardening": "hardening",
  "filesystem-permissions": "hardening",
  "accounts-services": "hardening",
  "logging-auditing": "hardening",
  "privilege-escalation": "hardening",
};

// Rules that belong with the developer's view of the problem rather than their rule-pack category.
const BY_RULE: Record<string, string> = {
  // Secrets, wherever the rule lives.
  "BLWK-SSH-012": "secrets",
  "BLWK-SSH-013": "secrets",
  "BLWK-AI-001": "secrets",
  "BLWK-AI-015": "secrets",
  "BLWK-AI-016": "secrets",
  "BLWK-AI-018": "secrets",
  // Code that runs because of something you installed.
  "BLWK-PERSIST-005": "supply-chain",
  "BLWK-ROOTKIT-002": "supply-chain",
  "BLWK-AI-003": "supply-chain",
  "BLWK-AI-004": "supply-chain",
  "BLWK-AI-005": "supply-chain",
  "BLWK-AI-019": "supply-chain",
};

/** The group a finding belongs to. Unknown categories fall back to system hardening. */
export function groupOf(ruleId: string, category: string): string {
  if (BY_RULE[ruleId]) return BY_RULE[ruleId];
  if (ruleId.startsWith("BLWK-AI-")) return "ai-agents";
  return BY_CATEGORY[category] ?? "hardening";
}

export function groupInfo(id: string): FindingGroupInfo {
  return GROUPS.find((g) => g.id === id) ?? { id, title: id, blurb: "" };
}

/** Display order for groups with the same worst severity. */
export const GROUP_ORDER = GROUPS.map((g) => g.id);

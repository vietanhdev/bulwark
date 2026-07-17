// Mock of @tauri-apps/api/core — see README.md. Shapes match the real Tauri commands in
// apps/bulwark-app/src-tauri/src/lib.rs exactly (same field names), just backed by fixtures
// instead of a real scan.
import rulesFixture from "./fixtures/rules.json";
import {
  dashboardSnapshot,
  scanRunResult,
  historyRuns,
  clamavInfo,
  monitoringStatusInitial,
  avScanPaths,
  findings,
} from "./fixtures/findings";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let monitoringStatus = { ...monitoringStatusInitial };

// AI Security fixtures — a couple of representative findings so the tab renders with content in
// screenshot mode. Shapes match `bulwark_core::ai_scan::AiFinding` (snake_case, no rename).
const aiFindings = [
  {
    id: "ai-1",
    rule_id: "BLWK-AI-001",
    severity: "critical",
    tool: "Claude Code",
    title: "Anthropic API key exposed in AI context",
    explanation:
      "Anthropic API key found in ~/Projects/api/CLAUDE.md at line 8. Anything written into an assistant's context, memory, or transcript should be treated as leaked — rotate it.",
    fix_hint: "Remove the secret from the file (Bulwark can redact it for you) and rotate the credential.",
    file: "/home/user/Projects/api/CLAUDE.md",
    line: 8,
    evidence: "Anthropic API key: sk-a…3f",
    references: ["ATTACK-T1552.001"],
    redactable: true,
  },
  {
    id: "ai-2",
    rule_id: "BLWK-AI-002",
    severity: "critical",
    tool: "Claude Code",
    title: "Project-supplied Claude Code hooks run shell commands automatically",
    explanation:
      "This settings file defines hooks. Claude Code hooks run shell commands automatically on tool/session events — a project-supplied hook can execute code the moment the repo is opened.",
    fix_hint:
      "Remove the hooks block from the repo's .claude/settings.json; keep hooks only in trusted user settings.",
    file: "/home/user/Projects/api/.claude/settings.json",
    line: 3,
    evidence: '"hooks": { "SessionStart": [ … ] }',
    references: ["CVE-2025-59536", "ATTACK-T1546"],
    redactable: false,
  },
  {
    id: "ai-3",
    rule_id: "BLWK-AI-009",
    severity: "critical",
    tool: "VS Code / editor",
    title: 'VS Code chat auto-approve ("YOLO mode") is enabled',
    explanation:
      '"chat.tools.autoApprove" is true — every agent tool call, including shell commands, is auto-approved with no confirmation.',
    fix_hint: 'Remove "chat.tools.autoApprove": true from settings.json.',
    file: "/home/user/Projects/web/.vscode/settings.json",
    line: 12,
    evidence: '"chat.tools.autoApprove": true',
    references: ["CVE-2025-53773"],
    redactable: false,
  },
  {
    id: "ai-4",
    rule_id: "BLWK-AI-004",
    severity: "high",
    tool: "Cursor",
    title: "An MCP server uses mcp-remote (critical command-injection ≤ 0.1.15)",
    explanation:
      'MCP server "gateway" runs via mcp-remote, which had a critical command-injection flaw in versions ≤ 0.1.15 (CVE-2025-6514).',
    fix_hint: "Upgrade mcp-remote to ≥ 0.1.16 and pin it.",
    file: "/home/user/.cursor/mcp.json",
    line: 5,
    evidence: "npx -y mcp-remote https://…",
    references: ["CVE-2025-6514"],
    redactable: false,
  },
  {
    id: "ai-5",
    rule_id: "BLWK-AI-012",
    severity: "high",
    tool: "Cursor",
    title: "An instruction file contains hidden Unicode control characters",
    explanation:
      "This instruction file contains an invisible Unicode control character (U+202E) on line 14. Such characters are read by the model but don't render for a human reviewer.",
    fix_hint: "Inspect and strip the zero-width / bidirectional control characters from this file.",
    file: "/home/user/Projects/web/.cursor/rules/style.mdc",
    line: 14,
    evidence: "hidden U+202E",
    references: ["ATTACK-T1027"],
    redactable: false,
  },
  {
    id: "ai-5b",
    rule_id: "BLWK-AI-011",
    severity: "high",
    tool: "Claude",
    title: "An instruction file contains prompt-injection style directives",
    explanation:
      'This instruction file contains a phrase associated with prompt injection ("do not tell the user"). Confirm by reading line 80 — this is a heuristic, not a certainty.',
    fix_hint:
      "Open the file and review line 80 for adversarial instructions (e.g. 'ignore previous instructions', commands to exfiltrate or edit config). Remove anything that steers the agent against the user.",
    file: "/home/user/Projects/web/.claude/commands/notes.md",
    line: 80,
    evidence: "do not tell the user",
    references: ["ATTACK-T1204"],
    redactable: false,
  },
  {
    id: "ai-6",
    rule_id: "BLWK-AI-016",
    severity: "high",
    tool: "AI assistant",
    title: "A secret-bearing AI file is not covered by .gitignore",
    explanation:
      ".env holds a secret and sits in a git repository with no .gitignore rule covering it — a `git add .` would stage the secret for commit.",
    fix_hint: "Add this file to .gitignore, git rm --cached it, and rotate the credential.",
    file: "/home/user/Projects/api/.env",
    line: null,
    evidence: ".env",
    references: ["ATTACK-T1552.001"],
    redactable: false,
  },
  {
    id: "ai-7",
    rule_id: "BLWK-AI-015",
    severity: "medium",
    tool: "GitHub Copilot",
    title: "An AI credential file is readable by other users",
    explanation:
      "~/.config/github-copilot/hosts.json is mode 644 — readable beyond its owner. A plaintext token store shouldn't be group- or world-readable.",
    fix_hint: "chmod 600 this file.",
    file: "/home/user/.config/github-copilot/hosts.json",
    line: null,
    evidence: "mode 644",
    references: ["ATTACK-T1552.001"],
    redactable: false,
  },
];

let aiSnapshot: { snapshot: unknown } = {
  snapshot: {
    started_at: new Date().toISOString(),
    host_fingerprint: "workstation/6.8.0",
    workspaces_scanned: ["/home/user/Projects/api", "/home/user/Projects/web", "/home/user/Projects/infra"],
    artifacts_scanned: 61,
    workspaces_capped: false,
    findings: aiFindings,
  },
};

let aiSettings = {
  configured_roots: [] as string[],
  excluded_roots: [] as string[],
  auto_scan_enabled: true,
};
let realtimeAvStatus = {
  enabled: false,
  watched_paths: ["/home/user/Downloads", "/home/user/Desktop"],
  files_scanned: 0,
  threats_found: 0,
  recent_threats: [] as { path: string; signature: string }[],
};

type Args = Record<string, unknown> | undefined;

async function streamScan(channel: Channel<unknown>) {
  await sleep(300);
  for (const f of findings) {
    channel.onmessage?.({ event: "finding", data: f });
    await sleep(120);
  }
  channel.onmessage?.({
    event: "complete",
    data: {
      total_findings: findings.length,
      host_fingerprint: dashboardSnapshot.meta.host_fingerprint,
      cancelled: false,
    },
  });
}

async function streamAvScan(channel: Channel<unknown>) {
  await sleep(200);
  for (let i = 0; i < avScanPaths.length; i++) {
    channel.onmessage?.({ event: "fileScanned", data: { path: avScanPaths[i] } });
    if (avScanPaths[i].includes("eicar")) {
      await sleep(150);
      channel.onmessage?.({
        event: "threatFound",
        data: { path: avScanPaths[i], signature: "Win.Test.EICAR_HDB-1" },
      });
    }
    await sleep(350);
  }
  channel.onmessage?.({
    event: "complete",
    data: {
      scanned_paths: ["/home/user/Downloads", "/tmp", "/var/tmp"],
      files_scanned: avScanPaths.length,
      threats: [{ path: avScanPaths.find((p) => p.includes("eicar")), signature: "Win.Test.EICAR_HDB-1" }],
      clamscan_available: true,
      cancelled: false,
    },
  });
}

async function streamAiScan(channel: Channel<unknown>) {
  await sleep(250);
  for (const path of [
    "/home/user/Projects/api/CLAUDE.md",
    "/home/user/Projects/api/.claude/settings.json",
    "/home/user/.cursor/mcp.json",
  ]) {
    channel.onmessage?.({ event: "artifact", data: { path } });
    await sleep(200);
  }
  for (const f of aiFindings) {
    channel.onmessage?.({ event: "finding", data: f });
  }
  channel.onmessage?.({
    event: "complete",
    data: {
      totalFindings: aiFindings.length,
      artifactsScanned: 61,
      workspacesScanned: 3,
      workspacesCapped: false,
      cancelled: false,
      errors: [],
    },
  });
}

// In-memory suppression state for the browser-dev harness, mirroring the store's two-table split:
// current state plus an append-only audit trail that survives un-suppression.
let mockSuppressions: { rule_id: string; reason: string; created_at: string; created_by: string }[] = [];
const mockAudit: {
  id: string;
  rule_id: string;
  action: "suppressed" | "unsuppressed";
  reason: string;
  actor: string;
  at: string;
}[] = [];

const handlers: Record<string, (args: Args) => unknown> = {
  rules_list: () => rulesFixture,
  suppressions_list: () => mockSuppressions,
  suppression_audit: (args) => {
    const ruleId = args?.ruleId as string | null | undefined;
    const log = ruleId ? mockAudit.filter((e) => e.rule_id === ruleId) : mockAudit;
    return [...log].reverse();
  },
  rule_suppress: (args) => {
    const rule_id = String(args?.ruleId ?? "");
    const reason = String(args?.reason ?? "").trim();
    if (!reason) throw new Error("a suppression needs a reason");
    const now = new Date().toISOString();
    mockSuppressions = [
      ...mockSuppressions.filter((s) => s.rule_id !== rule_id),
      { rule_id, reason, created_at: now, created_by: "desktop-user" },
    ];
    mockAudit.push({
      id: crypto.randomUUID(),
      rule_id,
      action: "suppressed",
      reason,
      actor: "desktop-user",
      at: now,
    });
    return null;
  },
  rule_unsuppress: (args) => {
    const rule_id = String(args?.ruleId ?? "");
    const reason = String(args?.reason ?? "").trim();
    if (!reason) throw new Error("lifting a suppression needs a reason");
    if (!mockSuppressions.some((s) => s.rule_id === rule_id))
      throw new Error(`rule ${rule_id} is not suppressed`);
    mockSuppressions = mockSuppressions.filter((s) => s.rule_id !== rule_id);
    mockAudit.push({
      id: crypto.randomUUID(),
      rule_id,
      action: "unsuppressed",
      reason,
      actor: "desktop-user",
      at: new Date().toISOString(),
    });
    return null;
  },
  ai_scan_snapshot: () => aiSnapshot,
  ai_settings_get: () => aiSettings,
  ai_settings_set: (args) => {
    aiSettings = {
      configured_roots: (args?.configuredRoots as string[]) ?? aiSettings.configured_roots,
      excluded_roots: (args?.excludedRoots as string[]) ?? aiSettings.excluded_roots,
      auto_scan_enabled:
        args?.autoScanEnabled === undefined ? aiSettings.auto_scan_enabled : Boolean(args.autoScanEnabled),
    };
    return aiSettings;
  },
  ai_redact: (args) => {
    const paths = (args?.paths as string[]) ?? [];
    // Pretend the redaction happened: drop the redactable findings from the snapshot.
    aiSnapshot = {
      snapshot: {
        ...(aiSnapshot.snapshot as Record<string, unknown>),
        findings: aiFindings.filter((f) => !f.redactable),
      },
    };
    return {
      dry_run: !args?.apply,
      entries: paths.map((path) => ({ path, secrets_redacted: 1, applied: Boolean(args?.apply) })),
      total_secrets: paths.length,
      errors: [],
    };
  },
  dashboard_snapshot: () => ({ ...dashboardSnapshot, agent_scanned: true }),
  history_count: () => historyRuns.length,
  history_list: () => historyRuns,
  monitoring_get_status: () => monitoringStatus,
  monitoring_set_enabled: (args) => {
    monitoringStatus = { ...monitoringStatus, enabled: Boolean(args?.enabled) };
    return monitoringStatus;
  },
  monitoring_set_interval_minutes: (args) => {
    monitoringStatus = { ...monitoringStatus, interval_minutes: Number(args?.minutes) };
    return monitoringStatus;
  },
  scan_privileged: () => scanRunResult,
  clamav_info: () => clamavInfo,
  fim_baseline: () => 7,
  scan_cancel: () => null,
  realtime_av_get_status: () => realtimeAvStatus,
  realtime_av_set_enabled: (args) => {
    realtimeAvStatus = { ...realtimeAvStatus, enabled: Boolean(args?.enabled) };
    return realtimeAvStatus;
  },
  realtime_av_add_folder: (args) => {
    const path = String(args?.path);
    if (!realtimeAvStatus.watched_paths.includes(path)) {
      realtimeAvStatus = {
        ...realtimeAvStatus,
        watched_paths: [...realtimeAvStatus.watched_paths, path],
      };
    }
    return realtimeAvStatus;
  },
  realtime_av_remove_folder: (args) => {
    const path = String(args?.path);
    realtimeAvStatus = {
      ...realtimeAvStatus,
      watched_paths: realtimeAvStatus.watched_paths.filter((p) => p !== path),
    };
    return realtimeAvStatus;
  },
  ssh_protect_keys: () => ({
    results: [
      {
        path: "/home/user/.ssh/id_ed25519",
        key_format: "openssh",
        outcome: { status: "protected" },
        backup_path: "/home/user/.local/share/bulwark/ssh-key-backups/id_ed25519.bak",
      },
      {
        path: "/home/user/.ssh/id_rsa",
        key_format: "openssh",
        outcome: { status: "already_encrypted" },
        backup_path: null,
      },
    ],
    protected: 1,
    already_encrypted: 1,
    undetermined: 0,
    failed: 0,
  }),
  fix_ssh_permissions: (args?: Args) => {
    const apply = Boolean(args?.apply);
    const status = apply ? "tightened" : "would_tighten";
    return {
      results: [
        {
          path: "/home/user/.ssh",
          label: ".ssh directory",
          current_mode: "755",
          desired_mode: "700",
          outcome: { status, from: "755", to: "700" },
        },
        {
          path: "/home/user/.ssh/id_ed25519",
          label: "private key",
          current_mode: "644",
          desired_mode: "600",
          outcome: { status, from: "644", to: "600" },
        },
      ],
      tightened: apply ? 2 : 0,
      would_tighten: apply ? 0 : 2,
      already_ok: 0,
      missing: 0,
      skipped_symlink: 0,
      failed: 0,
    };
  },
  // In the browser mock there's no OS to open a file with — log it and succeed so the UI flow
  // (and any error handling) can be exercised without a real Tauri backend.
  open_flagged_file: (args?: Args) => {
    console.info("[mock] open_flagged_file", args?.path, "reveal=", args?.reveal);
    return null;
  },
};

export async function invoke<T>(cmd: string, args?: Args): Promise<T> {
  if (cmd === "scan_start") {
    await streamScan(args?.onEvent as Channel<unknown>);
    return undefined as T;
  }
  if (cmd === "run_virus_scan") {
    await streamAvScan(args?.onEvent as Channel<unknown>);
    return undefined as T;
  }
  if (cmd === "ai_scan_start") {
    await streamAiScan(args?.onEvent as Channel<unknown>);
    return undefined as T;
  }
  await sleep(120);
  const handler = handlers[cmd];
  if (!handler) {
    throw new Error(`[mock-tauri] no handler for invoke("${cmd}")`);
  }
  return handler(args) as T;
}

export class Channel<T> {
  onmessage: ((message: T) => void) | undefined;
}

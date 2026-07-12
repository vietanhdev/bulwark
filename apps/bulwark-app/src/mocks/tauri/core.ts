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
];

let aiSnapshot: { snapshot: unknown } = {
  snapshot: {
    started_at: new Date().toISOString(),
    host_fingerprint: "workstation/6.8.0",
    workspaces_scanned: ["/home/user/Projects/api", "/home/user/Projects/web"],
    artifacts_scanned: 34,
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
      artifactsScanned: 34,
      workspacesScanned: 2,
      workspacesCapped: false,
      cancelled: false,
      errors: [],
    },
  });
}

const handlers: Record<string, (args: Args) => unknown> = {
  rules_list: () => rulesFixture,
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

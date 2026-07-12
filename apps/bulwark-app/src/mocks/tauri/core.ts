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

type Args = Record<string, unknown> | undefined;

async function streamScan(channel: Channel<unknown>) {
  await sleep(300);
  for (const f of findings) {
    channel.onmessage?.({ event: "finding", data: f });
    await sleep(120);
  }
  channel.onmessage?.({
    event: "complete",
    data: { total_findings: findings.length, host_fingerprint: dashboardSnapshot.meta.host_fingerprint },
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
    },
  });
}

const handlers: Record<string, (args: Args) => unknown> = {
  rules_list: () => rulesFixture,
  dashboard_snapshot: () => dashboardSnapshot,
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

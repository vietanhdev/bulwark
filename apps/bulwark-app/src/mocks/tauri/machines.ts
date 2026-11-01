// Machines + alerts fixtures for the screenshot mocks — shapes match `bulwark_core::fleet` and the
// CLI's `hosts test --json` report (see src/lib/machines.ts).
import { findings } from "./fixtures/findings";

type Args = Record<string, unknown> | undefined;

const minutesAgo = (m: number) => new Date(Date.now() - m * 60000).toISOString();
const minutesFromNow = (m: number) => new Date(Date.now() + m * 60000).toISOString();

const base = {
  identity_file: null,
  jump_host: null,
  privileged: false,
  enabled: true,
  interval_minutes: 60,
  created_at: minutesAgo(60 * 24 * 9),
  expected_hostname: null,
  last_error: null,
  consecutive_failures: 0,
  privileged_collectors_skipped: [] as string[],
  checks_run: 58 as number | null,
  os_kind: null as string | null,
  os_name: null as string | null,
  problem: null,
  scanning: false,
};

let machines = [
  {
    ...base,
    id: "m-web",
    os_kind: "ubuntu",
    os_name: "Ubuntu 24.04.1 LTS",
    name: "web-1",
    spec: "deploy@web-1.example.com",
    port: null,
    identity_file: "/home/user/.local/share/bulwark/keys/bulwark_ed25519",
    privileged: true,
    expected_hostname: "web-1",
    last_attempt_at: minutesAgo(12),
    last_success_at: minutesAgo(12),
    last_status: { state: "ok" },
    engine: "installed /usr/bin/bulwarkctl (0.11.1)",
    health: "at_risk",
    counts: { critical: 0, high: 2, medium: 3, low: 6, info: 4, suppressed: 1 },
    next_due_at: minutesFromNow(48),
    ssh_command: "ssh -i ~/.local/share/bulwark/keys/bulwark_ed25519 deploy@web-1.example.com",
  },
  {
    ...base,
    id: "m-db",
    os_kind: "debian",
    os_name: "Debian GNU/Linux 12 (bookworm)",
    name: "db-primary",
    spec: "ops@10.0.4.12",
    port: 2222,
    jump_host: "ops@bastion.example.com",
    expected_hostname: "db-primary",
    last_attempt_at: minutesAgo(3),
    last_success_at: minutesAgo(60 * 26),
    last_status: { state: "failed", kind: "host_key_changed" },
    last_error: "Host key for [10.0.4.12]:2222 has changed and you have requested strict checking.",
    consecutive_failures: 1,
    engine: "installed /usr/bin/bulwarkctl (0.11.1)",
    health: "needs_attention",
    counts: { critical: 0, high: 0, medium: 1, low: 4, info: 2, suppressed: 0 },
    next_due_at: minutesFromNow(57),
    ssh_command: "ssh -J ops@bastion.example.com -p 2222 ops@10.0.4.12",
    problem: {
      kind: "host_key_changed",
      title: "The machine's identity key has changed",
      hint: "This happens when a machine is reinstalled — or when someone is intercepting the connection. Scans are refused until you confirm the new key with whoever manages the machine. Once confirmed, replace the stored key (Remote → Check connection, or `bulwarkctl hosts trust <name> --fingerprint <new> --replace`).",
      detail: "Host key for [10.0.4.12]:2222 has changed and you have requested strict checking.",
    },
  },
  {
    ...base,
    id: "m-nas",
    os_kind: "linux",
    os_name: "Alpine Linux v3.20",
    name: "homelab-nas",
    spec: "nas",
    port: null,
    interval_minutes: 360,
    expected_hostname: "nas",
    last_attempt_at: minutesAgo(40),
    last_success_at: minutesAgo(40),
    last_status: { state: "ok" },
    engine: "copied for the scan and removed (aarch64, 0.11.1)",
    health: "healthy",
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 3, suppressed: 0 },
    next_due_at: minutesFromNow(320),
    ssh_command: "ssh nas",
    privileged_collectors_skipped: ["sudoers", "host_firewall"],
  },
  {
    ...base,
    id: "m-laptop",
    os_kind: "macos",
    os_name: "macOS 15.6",
    name: "studio-laptop",
    spec: "me@studio.local",
    port: null,
    last_attempt_at: minutesAgo(30),
    last_success_at: minutesAgo(60 * 30),
    last_status: { state: "failed", kind: "unreachable" },
    last_error: "ssh: connect to host studio.local port 22: No route to host",
    consecutive_failures: 4,
    health: "unreachable",
    counts: { critical: 0, high: 1, medium: 2, low: 3, info: 1, suppressed: 0 },
    next_due_at: minutesFromNow(330),
    ssh_command: "ssh me@studio.local",
    engine: "installed /usr/bin/bulwarkctl (0.11.0)",
    problem: {
      kind: "unreachable",
      title: "The machine isn't answering",
      hint: "Make sure the machine is on and reachable from this network, and that SSH is running on it. Bulwark will keep retrying, less often, until it answers. Test with `ssh me@studio.local`.",
      detail: "ssh: connect to host studio.local port 22: No route to host",
    },
  },
  {
    ...base,
    id: "m-win",
    os_kind: "windows",
    os_name: "Windows 11 Pro",
    name: "build-box",
    spec: "admin@build-box.example.com",
    port: null,
    last_attempt_at: minutesAgo(60 * 2),
    last_success_at: minutesAgo(60 * 2),
    last_status: { state: "ok" },
    last_error: null,
    health: "healthy",
    checks_run: 10,
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, suppressed: 0 },
    interval_minutes: 360,
    next_due_at: minutesFromNow(60 * 4),
    ssh_command: "ssh admin@build-box.example.com",
    engine: "installed C:\\Users\\admin\\AppData\\Local\\bulwark\\bulwark.exe (0.11.1)",
    problem: null,
  },
];

// `?machines=empty` shows the first-run state (dev mocks only).
if (typeof location !== "undefined" && new URLSearchParams(location.search).get("machines") === "empty") {
  machines = [];
}

const testReport = (id: string) => {
  const m = machines.find((x) => x.id === id);
  const name = m?.name ?? id;
  return {
    target: m?.spec ?? id,
    ssh_command: m?.ssh_command ?? `ssh ${id}`,
    ok: true,
    host_ref: name,
    host_key_changed: false,
    host_keys: [],
    verify_command: null,
    os: "Ubuntu 24.04.1 LTS",
    install_command: null,
    steps: [
      { id: "address", label: "Address", status: "ok", detail: "deploy@203.0.113.10 port 22", problem: null },
      {
        id: "connect",
        label: "Connect and sign in",
        status: "ok",
        detail: "Signed in — Ubuntu 24.04.1 LTS (x86_64)",
        problem: null,
      },
      {
        id: "engine",
        label: "Scanner on the machine",
        status: "ok",
        detail: "Bulwark 0.11.1 is installed (/usr/bin/bulwarkctl)",
        problem: null,
      },
      {
        id: "root",
        label: "Root checks",
        status: "ok",
        detail: "Passwordless sudo works — root-only checks will run",
        problem: null,
      },
    ],
    advice: [
      {
        id: "host_key",
        level: "good",
        title: "Host key verified",
        detail:
          "Bulwark refuses to connect if the machine's identity key ever changes, so a scan can't be silently redirected to another machine.",
        command: null,
      },
      {
        id: "key",
        level: "good",
        title: "Signs in with Bulwark's own restricted key",
        detail: "The key can run the scan but can't forward ports, reach your SSH agent or open a terminal.",
        command: null,
      },
      {
        id: "sudo",
        level: "warn",
        title: "sudo allows every command without a password",
        detail:
          "Root checks only need the scanner. Narrow the rule so this account can run nothing else as root without a password.",
        command:
          "echo 'deploy ALL=(root) NOPASSWD: /usr/bin/bulwarkctl scan --json --no-persist --privileged' | sudo tee /etc/sudoers.d/bulwark && sudo chmod 440 /etc/sudoers.d/bulwark",
      },
    ],
  };
};

const newMachineReport = {
  target: "deploy@203.0.113.20",
  ssh_command: "ssh deploy@203.0.113.20",
  ok: false,
  host_ref: "api-2",
  host_key_changed: false,
  host_keys: [{ key_type: "ED25519", fingerprint: "SHA256:mbBrEvR7C92ByKrA6S0EVRUgW0Zlq+AicArLdGKP7CI" }],
  verify_command: "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub",
  os: null,
  install_command: null,
  advice: [],
  steps: [
    { id: "address", label: "Address", status: "ok", detail: "deploy@203.0.113.20 port 22", problem: null },
    {
      id: "connect",
      label: "Connect and sign in",
      status: "fail",
      detail: "No ED25519 host key is known for 203.0.113.20",
      problem: {
        kind: "host_key_unknown",
        title: "This machine hasn't been trusted yet",
        hint: "Compare the machine's host key fingerprint and approve it, or connect once from a terminal with `ssh deploy@203.0.113.20` and answer yes.",
        detail: "No ED25519 host key is known for 203.0.113.20 and you have requested strict checking.",
      },
    },
    {
      id: "engine",
      label: "Scanner on the machine",
      status: "skipped",
      detail: "Waiting for the step above",
      problem: null,
    },
    {
      id: "root",
      label: "Root checks",
      status: "skipped",
      detail: "Waiting for the step above",
      problem: null,
    },
  ],
};

let notifyStatus = {
  config: {
    telegram: { enabled: true, chat_id: "123456789" },
    email: null as null | Record<string, unknown>,
    min_severity: "medium",
    events: { new_issues: true, unreachable: true, back_online: true, security: true, needs_attention: true },
    include_this_computer: true,
    daily_report: true,
  },
  telegram_token_set: true,
  smtp_password_set: false,
  last_error: null,
  last_sent_at: minutesAgo(95),
};

export const machineHandlers: Record<string, (args: Args) => unknown> = {
  machines_list: () => ({ enabled: true, machines, can_copy_engine: true }),
  machine_findings: (args) => {
    const id = args?.id as string;
    if (id === "m-win")
      return { active: [], suppressed: [], suppressions: [], last_scan_at: minutesAgo(120) };
    if (id === "m-nas")
      return {
        active: findings.filter((f) => f.severity === "info").slice(0, 3),
        suppressed: [],
        suppressions: [],
        last_scan_at: minutesAgo(40),
      };
    return {
      active: findings.slice(0, 8),
      suppressed: findings.slice(8, 9),
      suppressions: [
        {
          rule_id: findings[8]?.rule_id ?? "BLWK-NET-005",
          reason: "Only reachable over the office VPN",
          created_at: minutesAgo(60 * 20),
          created_by: "alex",
        },
      ],
      last_scan_at: minutesAgo(12),
    };
  },
  machine_test: (args) => {
    const host = (args?.args as { host: string }).host;
    return host.startsWith("m-") ? testReport(host) : newMachineReport;
  },
  machine_add: (args) => {
    const input = args?.input as { spec: string; name: string };
    const m = {
      ...machines[0],
      ...base,
      id: "new-1",
      name: input.name,
      spec: input.spec,
      health: "new",
      last_status: null,
      last_success_at: null,
      last_attempt_at: null,
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, suppressed: 0 },
      enabled: false,
      ssh_command: `ssh ${input.spec}`,
    };
    return m;
  },
  machine_update: (args) => {
    const m = machines.find((x) => x.id === args?.id) ?? machines[0];
    return { ...m, ...(args?.patch as object) };
  },
  machine_remove: (args) => {
    machines = machines.filter((m) => m.id !== args?.id);
    return null;
  },
  machine_suppress: () => null,
  machine_unsuppress: () => null,
  machine_trust: () => ({ trusted: { key_type: "ED25519", fingerprint: "SHA256:…" } }),
  machine_setup_key: () => ({ ok: true }),
  machine_scan_now: () => null,
  machines_scan_all: () => machines.length,
  machines_set_enabled: (args) => args?.enabled,
  ssh_suggestions: () => ({
    aliases: [
      { alias: "nas", hostname: "192.168.1.20", user: "admin", port: null, jump: null },
      { alias: "web-1", hostname: "web-1.example.com", user: "deploy", port: null, jump: null },
      {
        alias: "db-primary",
        hostname: "10.0.4.12",
        user: "ops",
        port: 2222,
        jump: "ops@bastion.example.com",
      },
    ],
    keys: ["~/.ssh/id_ed25519", "~/.ssh/work_rsa"],
    bulwark_key: "/home/user/.local/share/bulwark/keys/bulwark_ed25519",
  }),
  notify_status: () => notifyStatus,
  notify_configure: (args) => {
    notifyStatus = { ...notifyStatus, config: args?.config as typeof notifyStatus.config };
    return notifyStatus;
  },
  notify_test: () => [{ channel: "telegram", ok: true, error: null }],
  notify_report: () => [{ channel: "telegram", ok: true, error: null }],
  notify_telegram_chats: () => [{ id: "123456789", title: "Ana", kind: "private" }],
};

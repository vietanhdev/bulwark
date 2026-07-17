import { useEffect, useState } from "react";
import { getTauriVersion, getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Bell, CheckCircle2, Code2, FileText, Radar, Scale, Timer } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Switch } from "@/components/ui/switch";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { ShieldMark } from "@/components/ShieldMark";
import { SshKeyProtect, SshPermFix } from "@/components/SshKeyProtect";
import { AppearanceSettings } from "@/components/AppearanceSettings";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

export interface MonitoringStatus {
  enabled: boolean;
  interval_minutes: number;
  last_tick_at: string | null;
  next_tick_at: string | null;
  ticks_completed: number;
  last_tick_new_findings: number;
}

const REPO_URL = "https://github.com/vietanhdev/bulwark";
const INTERVAL_PRESETS = [5, 15, 30, 60, 360];

/* Kept short and specific. The full sourced comparison — including a hands-on benchmark
   against five of these — lives in the docs, and this list should not try to be that. */
const COMPARISON = [
  {
    name: "Lynis",
    note: "Closest in scope: a single-host config auditor. No GUI, no continuous re-checks, no built-in AV.",
  },
  {
    name: "rkhunter / chkrootkit",
    note: "Signature-based rootkit detection. Bulwark delegates that to ClamAV rather than reimplementing it.",
  },
  {
    name: "AIDE",
    note: "Broad file-integrity baselining. Bulwark watches a small curated set of files that matter for this threat model.",
  },
  {
    name: "Wazuh, CrowdStrike, SentinelOne",
    note: "Fleet-scale XDR with kernel-level telemetry. A different product category, not a gap Bulwark is trying to close.",
  },
];

function formatCountdown(nextTickAt: string | null, now: number): string {
  if (!nextTickAt) return "—";
  const remaining = new Date(nextTickAt).getTime() - now;
  if (remaining <= 0) return "any moment now";
  const total = Math.floor(remaining / 1000);
  return `${Math.floor(total / 60)}:${(total % 60).toString().padStart(2, "0")}`;
}

function formatRelative(iso: string | null, now: number): string {
  if (!iso) return "Never";
  const mins = Math.round((now - new Date(iso).getTime()) / 60000);
  if (mins < 1) return "Just now";
  if (mins === 1) return "1 minute ago";
  if (mins < 60) return `${mins} minutes ago`;
  const hours = Math.round(mins / 60);
  return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
}

/**
 * Monitoring cadence and app info, together.
 *
 * Both used to be top-level destinations in the sidebar. Neither earned it: "Monitoring" was a
 * pause button and five interval presets — a setting, not a place — and "About" was a version
 * string and three links. Promoting either to the same rank as Overview or Rules told the user
 * they were somewhere they'd need to go regularly, which isn't true of either.
 */
export function SettingsView() {
  const { bump } = useRevision();
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [toggleBusy, setToggleBusy] = useState(false);
  const [toggleError, setToggleError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [version, setVersion] = useState<string | null>(null);
  const [tauriVersion, setTauriVersion] = useState<string | null>(null);

  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion(null));
    getTauriVersion()
      .then(setTauriVersion)
      .catch(() => setTauriVersion(null));
  }, []);

  useEffect(() => {
    const refresh = () => invoke<MonitoringStatus>("monitoring_get_status").then(setStatus);
    refresh();
    const unlistenPromise = listen("monitoring:tick", refresh);
    // Drives the live countdown to the next check.
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      clearInterval(timer);
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  async function toggle(enabled: boolean) {
    setToggleBusy(true);
    setToggleError(null);
    try {
      setStatus(await invoke<MonitoringStatus>("monitoring_set_enabled", { enabled }));
      bump();
    } catch (e) {
      setToggleError(String(e));
    } finally {
      setToggleBusy(false);
    }
  }

  async function setIntervalMinutes(minutes: number) {
    setToggleError(null);
    try {
      setStatus(await invoke<MonitoringStatus>("monitoring_set_interval_minutes", { minutes }));
      bump();
    } catch (e) {
      // Without this, a failed interval change is an uncaught rejection with no feedback — mirror
      // the sibling toggle()'s error handling.
      setToggleError(String(e));
    }
  }

  return (
    <PageShell
      title="Settings"
      description="How Bulwark looks, how often it checks this computer on its own, and the built-in tools that keep it safe."
    >
      <div className="flex flex-col gap-8">
        <section>
          <SectionLabel>Appearance</SectionLabel>
          <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
            Match Bulwark to your desktop — light or dark, plus accent and sidebar colours from Ubuntu's
            palette.
          </p>
          <AppearanceSettings />
        </section>

        <section>
          <SectionLabel>Continuous monitoring</SectionLabel>
          <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
            Bulwark re-runs its unprivileged checks on a timer and tells you when something genuinely new
            shows up. Not a live kernel-level watch — enough to catch configuration drift without you having
            to remember to look.
          </p>

          {status && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-card p-4">
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      "flex h-10 w-10 shrink-0 items-center justify-center rounded-full",
                      status.enabled ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                    )}
                  >
                    <Radar className={cn("h-5 w-5", status.enabled && "animate-pulse")} strokeWidth={1.75} />
                  </div>
                  <div>
                    <div className="text-sm font-medium">
                      {status.enabled ? "Monitoring active" : "Monitoring paused"}
                    </div>
                    <div className="font-mono text-xs text-muted-foreground">
                      {status.enabled
                        ? `Next check in ${formatCountdown(status.next_tick_at, now)}`
                        : "Not watching for changes"}
                    </div>
                  </div>
                </div>
                <Switch
                  checked={status.enabled}
                  disabled={toggleBusy}
                  onCheckedChange={toggle}
                  aria-label="Continuous monitoring"
                />
              </div>

              {toggleError && <Callout tone="critical">Couldn't change monitoring: {toggleError}</Callout>}

              <div>
                <div className="mb-2 text-xs font-medium text-muted-foreground">Check every</div>
                <div className="flex flex-wrap gap-2">
                  {INTERVAL_PRESETS.map((m) => (
                    <Button
                      key={m}
                      size="sm"
                      variant={status.interval_minutes === m ? "default" : "outline"}
                      onClick={() => setIntervalMinutes(m)}
                      className="font-mono"
                    >
                      {m < 60 ? `${m} min` : `${m / 60} hr`}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2.5">
                <Stat icon={CheckCircle2} label="Checks run" value={status.ticks_completed} />
                <Stat icon={Timer} label="Last check" value={formatRelative(status.last_tick_at, now)} />
                <Stat icon={Bell} label="New last check" value={status.last_tick_new_findings} />
              </div>

              <Callout tone="info">
                Checks that need root — reading <code>/etc/sudoers</code>, for instance — never run
                unattended, because an unattended loop can't answer a password prompt. Run those from the
                Overview when Bulwark flags them as skipped.
              </Callout>
            </div>
          )}
        </section>

        <section>
          <SectionLabel>SSH hardening</SectionLabel>
          <p className="mb-3 text-sm text-muted-foreground">
            One-click fixes for the two most common SSH weaknesses on a workstation — plaintext private keys
            and loose <code>~/.ssh</code> permissions. Both run on your own files, need no elevation, and keep
            a backup or preview before touching anything.
          </p>
          <SshKeyProtect />
          <SshPermFix />
        </section>

        <section>
          <SectionLabel>About</SectionLabel>
          <div className="rounded-lg border border-border bg-card p-5">
            <div className="flex items-center gap-3.5">
              <ShieldMark className="h-11 w-11 shrink-0 text-primary" />
              <div>
                <div className="font-heading text-lg font-semibold tracking-tight">Bulwark</div>
                <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                  {version ? `v${version}` : "…"}
                  {tauriVersion && ` · Tauri ${tauriVersion}`}
                </div>
              </div>
            </div>

            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              A Linux host security scanner with a native CLI and desktop GUI. Bulwark checks a machine's
              configuration against a declarative rule pack — SSH hardening, systemd and cron persistence,
              sudoers, kernel and sysctl hardening, file permissions, logging, rootkit indicators — and
              explains every finding in plain language with a concrete fix, alongside ClamAV virus scanning,
              file-integrity monitoring, and continuous background checks.
            </p>

            <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <LinkCard href={REPO_URL} icon={Code2}>
                Source on GitHub
              </LinkCard>
              <LinkCard href={`${REPO_URL}/issues`} icon={FileText}>
                Report an issue
              </LinkCard>
              <div className="flex items-center gap-2.5 rounded-md border border-border px-3 py-2.5 text-sm">
                <Scale className="h-4 w-4 shrink-0 text-muted-foreground" />
                Apache-2.0
              </div>
            </div>
          </div>
        </section>

        <section>
          <SectionLabel>How Bulwark compares</SectionLabel>
          <div className="overflow-hidden rounded-lg border border-border bg-card">
            {COMPARISON.map(({ name, note }, i) => (
              <div key={name} className={cn("px-4 py-3", i > 0 && "border-t border-border")}>
                <div className="text-sm font-medium">{name}</div>
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{note}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  );
}

function Stat({ icon: Icon, label, value }: { icon: typeof Bell; label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="flex items-center gap-1.5 text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        <span className="text-xs">{label}</span>
      </div>
      <div
        className={cn(
          "mt-1 font-semibold",
          typeof value === "number" ? "font-mono text-xl tabular-nums" : "text-sm",
        )}
      >
        {value}
      </div>
    </div>
  );
}

function LinkCard({
  href,
  icon: Icon,
  children,
}: {
  href: string;
  icon: typeof Code2;
  children: React.ReactNode;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-2.5 rounded-md border border-border px-3 py-2.5 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
    >
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
      {children}
    </a>
  );
}

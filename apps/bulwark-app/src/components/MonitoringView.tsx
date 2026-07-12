import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Radar, Bell, Timer, CheckCircle2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface MonitoringStatus {
  enabled: boolean;
  interval_minutes: number;
  last_tick_at: string | null;
  next_tick_at: string | null;
  ticks_completed: number;
  last_tick_new_findings: number;
}

const INTERVAL_PRESETS = [5, 15, 30, 60, 360];

function formatCountdown(nextTickAt: string | null, now: number): string {
  if (!nextTickAt) return "—";
  const remainingMs = new Date(nextTickAt).getTime() - now;
  if (remainingMs <= 0) return "any moment now";
  const totalSeconds = Math.floor(remainingMs / 1000);
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function formatRelative(iso: string | null, now: number): string {
  if (!iso) return "Never";
  const diffMs = now - new Date(iso).getTime();
  const mins = Math.round(diffMs / 60000);
  if (mins < 1) return "Just now";
  if (mins === 1) return "1 minute ago";
  if (mins < 60) return `${mins} minutes ago`;
  const hours = Math.round(mins / 60);
  return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
}

export function MonitoringView() {
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const refresh = () => invoke<MonitoringStatus>("monitoring_get_status").then(setStatus);
    refresh();
    const unlistenPromise = listen("monitoring:tick", refresh);
    const tickTimer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      clearInterval(tickTimer);
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  async function toggle() {
    if (!status) return;
    const updated = await invoke<MonitoringStatus>("monitoring_set_enabled", { enabled: !status.enabled });
    setStatus(updated);
  }

  async function setInterval_(minutes: number) {
    const updated = await invoke<MonitoringStatus>("monitoring_set_interval_minutes", { minutes });
    setStatus(updated);
  }

  if (!status) return null;

  return (
    <div className="mx-auto max-w-5xl px-8 py-6">
      <h2 className="text-lg font-semibold">Continuous Monitoring</h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Bulwark re-runs its unprivileged checks on a timer and tells you when something genuinely new shows up
        — not a live kernel-level watch, but enough to catch configuration drift without you having to
        remember to check.
      </p>

      {/* Controls (status + interval) on the left, activity stats + the privilege caveat on
          the right — two independent, roughly-equal-weight groups, so side-by-side reads
          better at this width than stacking one under the other with a Separator between. */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="flex flex-col gap-6">
          <Card className="flex-row items-center justify-between gap-4 p-5">
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  "flex h-10 w-10 items-center justify-center rounded-full",
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
            <Button variant={status.enabled ? "outline" : "default"} size="sm" onClick={toggle}>
              {status.enabled ? "Pause" : "Resume"}
            </Button>
          </Card>

          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Check interval
            </h3>
            <div className="flex flex-wrap gap-2">
              {INTERVAL_PRESETS.map((m) => (
                <Button
                  key={m}
                  size="sm"
                  variant={status.interval_minutes === m ? "default" : "outline"}
                  onClick={() => setInterval_(m)}
                >
                  {m < 60 ? `${m} min` : `${m / 60} hr`}
                </Button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-6">
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Activity
            </h3>
            <div className="grid grid-cols-3 gap-3">
              <Card className="gap-1 p-3">
                <div className="flex items-center gap-1.5 text-muted-foreground">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span className="text-xs">Checks run</span>
                </div>
                <span className="font-mono text-xl font-semibold tabular-nums">{status.ticks_completed}</span>
              </Card>
              <Card className="gap-1 p-3">
                <div className="flex items-center gap-1.5 text-muted-foreground">
                  <Timer className="h-3.5 w-3.5" />
                  <span className="text-xs">Last check</span>
                </div>
                <span className="text-sm font-medium">{formatRelative(status.last_tick_at, now)}</span>
              </Card>
              <Card className="gap-1 p-3">
                <div className="flex items-center gap-1.5 text-muted-foreground">
                  <Bell className="h-3.5 w-3.5" />
                  <span className="text-xs">New last check</span>
                </div>
                <span className="font-mono text-xl font-semibold tabular-nums">
                  {status.last_tick_new_findings}
                </span>
              </Card>
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            Checks that need root (like reading <code className="font-mono">/etc/sudoers</code>) are never run
            unattended — an unattended background loop can't answer a password prompt. Run those from the
            Dashboard when Bulwark flags them as skipped.
          </p>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { getVersion, getTauriVersion } from "@tauri-apps/api/app";
import { Code2, FileText, Scale } from "lucide-react";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ShieldMark } from "@/components/ShieldMark";

const REPO_URL = "https://github.com/vietanhdev/bulwark";

const COMPARISON_SUMMARY = [
  {
    name: "Lynis",
    note: "Closest in scope — a single-host config auditor. No GUI, no continuous file-triggered re-checks, no built-in AV.",
  },
  {
    name: "rkhunter / chkrootkit",
    note: "Signature-based rootkit detection — Bulwark deliberately delegates that to ClamAV rather than reimplementing it.",
  },
  {
    name: "AIDE",
    note: "Broad file-integrity baselining. Bulwark's FIM watches a small curated set of files that actually matter for this threat model.",
  },
  {
    name: "Wazuh, CrowdStrike, SentinelOne",
    note: "Fleet-scale XDR/EDR with kernel-level real-time telemetry — a different product category, not a gap Bulwark is trying to close.",
  },
];

export function AboutView() {
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

  return (
    <ScrollArea className="h-full">
      <div className="mx-auto max-w-3xl px-8 py-6">
        <div className="flex items-center gap-4">
          <ShieldMark className="h-14 w-14 shrink-0 text-primary" />
          <div>
            <h2 className="text-xl font-semibold">Bulwark</h2>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground">
              {version ? `v${version}` : "…"}
              {tauriVersion && ` · Tauri ${tauriVersion}`}
            </p>
          </div>
        </div>

        <p className="mt-5 text-sm text-muted-foreground">
          A Linux host security scanner with a native CLI and desktop GUI. Bulwark checks a machine's
          configuration against a declarative rule pack — SSH hardening, systemd/cron persistence, sudoers,
          kernel/sysctl hardening, file permissions, logging, rootkit indicators — and explains every finding
          in plain language with a concrete fix, alongside real ClamAV virus scanning, file-integrity
          monitoring, and continuous background monitoring. Built with Tauri, Rust, and React.
        </p>

        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2.5 rounded-lg border border-border p-3 text-sm font-medium transition-colors hover:bg-accent"
          >
            <Code2 className="h-4 w-4 shrink-0 text-muted-foreground" />
            Source on GitHub
          </a>
          <a
            href={`${REPO_URL}/issues`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2.5 rounded-lg border border-border p-3 text-sm font-medium transition-colors hover:bg-accent"
          >
            <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
            Report an issue
          </a>
          <div className="flex items-center gap-2.5 rounded-lg border border-border p-3 text-sm font-medium">
            <Scale className="h-4 w-4 shrink-0 text-muted-foreground" />
            AGPL-3.0 License
          </div>
        </div>

        <h3 className="mt-8 mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          How it compares
        </h3>
        <Card className="gap-0 divide-y divide-border overflow-hidden p-0">
          {COMPARISON_SUMMARY.map(({ name, note }) => (
            <div key={name} className="px-3 py-2.5">
              <div className="text-sm font-medium">{name}</div>
              <p className="mt-0.5 text-xs text-muted-foreground">{note}</p>
            </div>
          ))}
        </Card>
        <p className="mt-3 text-xs text-muted-foreground">
          Full sourced comparison, including a hands-on benchmark against 5 of these tools, is in the
          repository's README.
        </p>
      </div>
    </ScrollArea>
  );
}

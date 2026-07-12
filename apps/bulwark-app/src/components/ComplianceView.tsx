import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, X } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { Severity } from "@/components/SeverityBadge";

interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  references: string[];
  collector: string;
  os: string[];
  profiles: string[];
}

interface Finding {
  rule_id: string;
}

interface LatestScanMeta {
  privileged_collectors_skipped: string[];
}

interface DashboardSnapshot {
  findings: Finding[];
  meta: LatestScanMeta | null;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  CIS: "CIS Benchmarks",
  ATTACK: "MITRE ATT&CK",
};

function frameworkOf(reference: string): string {
  const prefix = reference.split("-")[0];
  return FRAMEWORK_LABELS[prefix] ?? prefix;
}

export function ComplianceView() {
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [openRuleIds, setOpenRuleIds] = useState<Set<string>>(new Set());
  const [skippedCollectors, setSkippedCollectors] = useState<Set<string>>(new Set());
  const [hasScanned, setHasScanned] = useState(false);

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list").then(setRules);
    invoke<DashboardSnapshot>("dashboard_snapshot").then((snap) => {
      setOpenRuleIds(new Set(snap.findings.map((f) => f.rule_id)));
      if (snap.meta) {
        setHasScanned(true);
        setSkippedCollectors(new Set(snap.meta.privileged_collectors_skipped));
      }
    });
  }, []);

  // Lynis's own hardening index excludes SKIPPED tests from the score entirely rather than
  // counting them as passes or fails — a check that never ran (here: a privileged collector
  // during an unprivileged scan) told you nothing either way. Mirrors that directly: any
  // rule whose collector shows up in privileged_collectors_skipped is excluded from both the
  // numerator and denominator, not silently counted as "passing."
  //
  // Same treatment for the two newer gates a rule can fail to run for: `os` (this GUI only
  // ever runs on Linux, so a macOS/Windows-tagged rule structurally never ran here) and
  // `profiles` (a "needs: server"-tagged rule only ran if the last scan opted into that need
  // — which this view can't directly see). A needs-gated rule that shows up as an open
  // finding proves it DID run and failed, so it's still counted; one that doesn't appear is
  // ambiguous (never ran vs. ran-and-passed) and is conservatively excluded rather than risk
  // counting a rule that never actually executed as a free "pass."
  const hardeningIndex = useMemo(() => {
    if (!rules || !hasScanned) return null;
    const evaluated = rules.filter((r) => {
      if (skippedCollectors.has(r.collector)) return false;
      if (!r.os.includes("linux")) return false;
      if (r.profiles.length > 0 && !openRuleIds.has(r.id)) return false;
      return true;
    });
    if (evaluated.length === 0) return null;
    const passing = evaluated.filter((r) => !openRuleIds.has(r.id)).length;
    return {
      score: Math.round((passing / evaluated.length) * 100),
      passing,
      evaluated: evaluated.length,
      skipped: rules.length - evaluated.length,
    };
  }, [rules, openRuleIds, skippedCollectors, hasScanned]);

  const frameworks = useMemo(() => {
    if (!rules) return [];
    const mapped = rules.filter((r) => r.references.length > 0);
    const byFramework = new Map<string, { reference: string; rule: RuleSummary }[]>();
    for (const rule of mapped) {
      for (const reference of rule.references) {
        const fw = frameworkOf(reference);
        (byFramework.get(fw) ?? byFramework.set(fw, []).get(fw)!).push({ reference, rule });
      }
    }
    return Array.from(byFramework.entries())
      .map(([framework, controls]) => ({
        framework,
        controls: controls.sort((a, b) => a.reference.localeCompare(b.reference)),
        passing: controls.filter((c) => !openRuleIds.has(c.rule.id)).length,
      }))
      .sort((a, b) => a.framework.localeCompare(b.framework));
  }, [rules, openRuleIds]);

  const unmappedCount = rules?.filter((r) => r.references.length === 0).length ?? 0;

  return (
    <ScrollArea className="h-full">
      <div className="mx-auto max-w-5xl px-8 py-6">
        <h2 className="text-lg font-semibold">Compliance</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Every rule that maps to a framework control does so via its own{" "}
          <code className="font-mono">references</code> field — this is a view over that existing data, not a
          separate compliance engine. Coverage below only reflects rules that have actually been mapped so
          far.
        </p>

        {/* The same headline metric Lynis itself leads its report with — a single hardening
            score, not just a pass/fail list. Computed the same way Lynis computes its own:
            skipped checks are excluded from the score entirely, not counted as a free pass. */}
        {hardeningIndex && (
          <Card className="mt-6 flex-row items-center gap-5 p-5">
            <div className="relative flex h-16 w-16 shrink-0 items-center justify-center">
              <svg viewBox="0 0 36 36" className="h-16 w-16 -rotate-90">
                <circle cx="18" cy="18" r="15.5" fill="none" className="stroke-muted" strokeWidth="3" />
                <circle
                  cx="18"
                  cy="18"
                  r="15.5"
                  fill="none"
                  strokeWidth="3"
                  strokeLinecap="round"
                  className={cn(
                    hardeningIndex.score >= 80
                      ? "stroke-[var(--sev-resolved)]"
                      : hardeningIndex.score >= 50
                        ? "stroke-[var(--sev-medium)]"
                        : "stroke-destructive",
                  )}
                  strokeDasharray={`${(hardeningIndex.score / 100) * 97.4} 97.4`}
                />
              </svg>
              <span className="absolute font-mono text-lg font-semibold tabular-nums">
                {hardeningIndex.score}
              </span>
            </div>
            <div>
              <div className="text-sm font-medium">Hardening index</div>
              <div className="mt-0.5 text-xs text-muted-foreground">
                {hardeningIndex.passing}/{hardeningIndex.evaluated} checks passing
                {hardeningIndex.skipped > 0 &&
                  ` · ${hardeningIndex.skipped} skipped (no privilege) — not counted either way`}
              </div>
            </div>
          </Card>
        )}

        {rules && (
          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
            {frameworks.map(({ framework, controls, passing }) => (
              <div key={framework}>
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                    {framework}
                  </h3>
                  <span className="font-mono text-xs text-muted-foreground">
                    {passing}/{controls.length} passing
                  </span>
                </div>
                <Card className="gap-0 divide-y divide-border overflow-hidden p-0">
                  {controls.map(({ reference, rule }) => {
                    const pass = !openRuleIds.has(rule.id);
                    return (
                      <div key={reference + rule.id} className="flex items-center gap-3 px-3 py-2.5">
                        <div
                          className={cn(
                            "flex h-5 w-5 shrink-0 items-center justify-center rounded-full",
                            pass
                              ? "bg-[var(--sev-resolved)]/15 text-[var(--sev-resolved)]"
                              : "bg-destructive/15 text-destructive",
                          )}
                        >
                          {pass ? (
                            <Check className="h-3 w-3" strokeWidth={3} />
                          ) : (
                            <X className="h-3 w-3" strokeWidth={3} />
                          )}
                        </div>
                        <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                          {reference}
                        </Badge>
                        <span className="min-w-0 flex-1 truncate text-sm">{rule.title}</span>
                      </div>
                    );
                  })}
                </Card>
              </div>
            ))}
          </div>
        )}

        {unmappedCount > 0 && (
          <p className="mt-6 text-xs text-muted-foreground">
            {unmappedCount} rule{unmappedCount === 1 ? "" : "s"} not yet mapped to a compliance framework.
          </p>
        )}
      </div>
    </ScrollArea>
  );
}

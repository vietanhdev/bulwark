import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, X } from "lucide-react";
import { Callout } from "@/components/ui/callout";
import { PageShell } from "@/components/PageShell";
import { HardeningRing } from "@/components/HardeningRing";
import { railStyle } from "@/components/Severity";
import { computeHardeningIndex } from "@/lib/hardening";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";
import type { Severity } from "@/components/Severity";

interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  references: string[];
  collector: string;
  os: string[];
  profiles: string[];
}

interface DashboardSnapshot {
  findings: { rule_id: string }[];
  meta: { privileged_collectors_skipped: string[] } | null;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  CIS: "CIS Benchmarks",
  ATTACK: "MITRE ATT&CK",
};

const frameworkOf = (reference: string) => {
  const prefix = reference.split("-")[0];
  return FRAMEWORK_LABELS[prefix] ?? prefix;
};

export function ComplianceView() {
  const { revision } = useRevision();

  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [openRuleIds, setOpenRuleIds] = useState<Set<string>>(new Set());
  const [skippedCollectors, setSkippedCollectors] = useState<Set<string>>(new Set());
  const [hasScanned, setHasScanned] = useState(false);

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list").then(setRules);
  }, []);

  // Re-reads on every revision bump. Without that, running a scan on the Overview and then
  // clicking here showed the pass/fail state from whenever this tab was first opened — the
  // view is kept mounted for the life of the process (see App.tsx) and used to fetch once.
  useEffect(() => {
    invoke<DashboardSnapshot>("dashboard_snapshot").then((snap) => {
      setOpenRuleIds(new Set(snap.findings.map((f) => f.rule_id)));
      if (snap.meta) {
        setHasScanned(true);
        setSkippedCollectors(new Set(snap.meta.privileged_collectors_skipped));
      }
    });
  }, [revision]);

  const hardening = useMemo(() => {
    if (!rules || !hasScanned) return null;
    return computeHardeningIndex(rules, openRuleIds, skippedCollectors);
  }, [rules, openRuleIds, skippedCollectors, hasScanned]);

  const frameworks = useMemo(() => {
    if (!rules) return [];
    const byFramework = new Map<string, { reference: string; rule: RuleSummary }[]>();
    for (const rule of rules) {
      for (const reference of rule.references) {
        const fw = frameworkOf(reference);
        let list = byFramework.get(fw);
        if (!list) byFramework.set(fw, (list = []));
        list.push({ reference, rule });
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

  const unmapped = rules?.filter((r) => r.references.length === 0).length ?? 0;

  return (
    <PageShell
      title="Compliance"
      description="How Bulwark's rules line up against the frameworks people actually get audited on. This is a view over the references each rule already declares — not a separate compliance engine."
    >
      <div className="flex flex-col gap-8">
        {hardening ? (
          <div className="rounded-lg border border-border bg-card px-6 py-5">
            <HardeningRing index={hardening} size="lg" />
          </div>
        ) : (
          <Callout tone="info">
            Run a scan from the Overview to see which controls this host passes. Until then, the list below is
            just the mapping — every rule Bulwark has, and the control it answers to.
          </Callout>
        )}

        <div className="grid grid-cols-1 gap-x-5 gap-y-6 lg:grid-cols-2">
          {frameworks.map(({ framework, controls, passing }) => (
            <section key={framework}>
              <h2 className="mb-2 flex items-baseline justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
                  {framework}
                </span>
                {hasScanned && (
                  <span className="font-mono text-[11px] tabular-nums text-muted-foreground/70">
                    {passing}/{controls.length} passing
                  </span>
                )}
              </h2>
              <div className="overflow-hidden rounded-lg border border-border bg-card">
                {controls.map(({ reference, rule }, i) => {
                  // Before any scan has run, nothing is known to fail — but nothing is known to
                  // pass either. Render those rows as neutral rather than as a wall of green
                  // ticks that would be claiming a clean bill of health nobody has earned.
                  const failing = openRuleIds.has(rule.id);
                  const known = hasScanned;
                  return (
                    <div
                      key={`${reference}-${rule.id}`}
                      style={railStyle(known ? (failing ? rule.severity : "resolved") : "info")}
                      className={cn(
                        "rail flex items-center gap-2.5 py-2.5 pr-3",
                        !known && "rail-dim",
                        i > 0 && "border-t border-border",
                      )}
                    >
                      {known ? (
                        <span
                          className="flex h-4 w-4 shrink-0 items-center justify-center"
                          style={{ color: `var(--sev-${failing ? rule.severity : "resolved"}-fg)` }}
                        >
                          {failing ? (
                            <X className="h-3.5 w-3.5" strokeWidth={3} />
                          ) : (
                            <Check className="h-3.5 w-3.5" strokeWidth={3} />
                          )}
                        </span>
                      ) : (
                        <span className="h-4 w-4 shrink-0" />
                      )}
                      <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                        {reference}
                      </span>
                      <span className="min-w-0 flex-1 truncate text-sm" title={rule.title}>
                        {rule.title}
                      </span>
                    </div>
                  );
                })}
              </div>
            </section>
          ))}
        </div>

        {unmapped > 0 && (
          <p className="text-xs text-muted-foreground">
            {unmapped} rule{unmapped === 1 ? "" : "s"} aren't mapped to a framework control yet. They still
            run — mapping only affects what shows up on this page.
          </p>
        )}
      </div>
    </PageShell>
  );
}

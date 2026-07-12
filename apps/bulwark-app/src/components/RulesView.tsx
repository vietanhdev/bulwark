import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChevronRight, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { PageShell } from "@/components/PageShell";
import { SEVERITY_ORDER, SeverityDot, SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { cn } from "@/lib/utils";

interface RuleSummary {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  collector: string;
  explain: string;
  fix: string;
  os: string[];
  profiles: string[];
}

const categoryLabel = (c: string) => c.replace(/-/g, " ");

export function RulesView() {
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  // Rows start collapsed: the pack is 50+ rules, and this page is mostly used to skim what
  // exists rather than to read every rationale end to end. Click a row for the why and the fix.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch((e) => setError(String(e)));
  }, []);

  const filtered = useMemo(() => {
    if (!rules) return null;
    const q = query.trim().toLowerCase();
    return rules.filter((r) => {
      if (severityFilter && r.severity !== severityFilter) return false;
      if (!q) return true;
      // Search across everything a person might actually remember about a rule — its ID, its
      // title, its category, and the prose explaining it.
      return (
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        r.explain.toLowerCase().includes(q)
      );
    });
  }, [rules, query, severityFilter]);

  const grouped = useMemo(() => {
    if (!filtered) return null;
    const acc: Record<string, RuleSummary[]> = {};
    for (const r of filtered) (acc[r.category] ??= []).push(r);
    return acc;
  }, [filtered]);

  const severityCounts = useMemo(() => {
    const m = new Map<Severity, number>();
    rules?.forEach((r) => m.set(r.severity, (m.get(r.severity) ?? 0) + 1));
    return m;
  }, [rules]);

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }

  return (
    <PageShell
      title="Rules"
      description={
        rules
          ? `Everything Bulwark checks — ${rules.length} rules across ${new Set(rules.map((r) => r.category)).size} categories, each one a YAML file in the rule pack.`
          : "Loading the rule pack…"
      }
    >
      {error && <Callout tone="critical">{error}</Callout>}

      {rules && (
        <>
          {/* 50+ rules with no way to narrow them down meant the only way to find one was to
              scroll and read. */}
          <div className="mb-6 flex flex-wrap items-center gap-2">
            <div className="relative min-w-56 flex-1">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search rules by name, ID, or what they check"
                className="pl-8.5"
                aria-label="Search rules"
              />
            </div>
            <div className="flex items-center gap-1" role="group" aria-label="Filter by severity">
              {SEVERITY_ORDER.filter((s) => severityCounts.has(s)).map((sev) => {
                const on = severityFilter === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    aria-pressed={on}
                    onClick={() => setSeverityFilter(on ? null : sev)}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs capitalize transition-colors",
                      "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                      on
                        ? "border-foreground/25 bg-accent font-medium text-accent-foreground"
                        : "border-border text-muted-foreground hover:bg-accent/50",
                    )}
                  >
                    <SeverityDot severity={sev} />
                    {sev}
                    <span className="font-mono tabular-nums opacity-60">{severityCounts.get(sev)}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {filtered?.length === 0 && (
            <div className="rounded-lg border border-dashed border-border py-14 text-center">
              <p className="text-sm font-medium">No rule matches that.</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Try a shorter search, or clear the severity filter.
              </p>
            </div>
          )}

          {/* CSS multi-column, not a grid. Category sizes are wildly uneven (one has a single
              rule, another has 22), and a 2-col grid forces every row to the height of its
              tallest cell — leaving a crater of white space beside every short category.
              Columns pack them continuously instead; `break-inside: avoid` keeps a category
              from being sawn in half across the column boundary. */}
          <div className="columns-1 gap-x-5 lg:columns-2">
            {grouped &&
              Object.entries(grouped)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([category, categoryRules]) => (
                  <section key={category} className="mb-6 break-inside-avoid">
                    <h2 className="mb-2 flex items-baseline justify-between gap-2">
                      <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
                        {categoryLabel(category)}
                      </span>
                      <span className="font-mono text-[11px] tabular-nums text-muted-foreground/60">
                        {categoryRules.length}
                      </span>
                    </h2>
                    <div className="overflow-hidden rounded-lg border border-border bg-card">
                      {categoryRules.map((r, i) => {
                        const open = expanded.has(r.id);
                        return (
                          <div key={r.id} className={cn(i > 0 && "border-t border-border")}>
                            <button
                              onClick={() => toggle(r.id)}
                              aria-expanded={open}
                              data-open={open}
                              style={railStyle(r.severity)}
                              className="rail rail-dim flex w-full items-center gap-2.5 py-2.5 pr-3 text-left transition-colors hover:bg-accent/40 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
                            >
                              <ChevronRight
                                className={cn(
                                  "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                                  open && "rotate-90",
                                )}
                              />
                              <span className="min-w-0 flex-1">
                                <span className="block truncate text-sm font-medium">{r.title}</span>
                                <span className="mt-0.5 flex items-center gap-1.5">
                                  <span className="font-mono text-[11px] text-muted-foreground">{r.id}</span>
                                  {/* Linux is the default for every rule, so a badge is only
                                      worth the space when a rule is scoped to something else —
                                      50-odd identical "linux" badges would drown out the ones
                                      that actually differ. */}
                                  {!(r.os.length === 1 && r.os[0] === "linux") && (
                                    <span className="rounded-sm bg-muted px-1 font-mono text-[10px] text-muted-foreground capitalize">
                                      {r.os.join("/")}
                                    </span>
                                  )}
                                  {r.profiles.map((p) => (
                                    <span
                                      key={p}
                                      className="rounded-sm bg-muted px-1 font-mono text-[10px] text-muted-foreground"
                                    >
                                      needs:{p}
                                    </span>
                                  ))}
                                </span>
                              </span>
                              <SeverityLabel severity={r.severity} />
                            </button>

                            {open && (
                              <div className="border-t border-border bg-muted/30 py-3 pr-3 pl-8">
                                <p className="text-xs leading-relaxed text-muted-foreground">
                                  {r.explain.trim()}
                                </p>
                                <CommandBlock command={r.fix} className="mt-2.5 bg-card" />
                                <p className="mt-2 font-mono text-[10px] text-muted-foreground/70">
                                  collector: {r.collector}
                                </p>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </section>
                ))}
          </div>
        </>
      )}
    </PageShell>
  );
}

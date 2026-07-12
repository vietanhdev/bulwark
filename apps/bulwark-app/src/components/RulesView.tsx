import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChevronRight } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge, type Severity } from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";

interface RuleSummary {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  collector: string;
  explain: string;
  fix: string;
}

export function RulesView() {
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Every row starts collapsed — 57 rules with the explanation always visible would be a
  // very long scroll for a page that's mostly used to skim what exists, not read every
  // rule's rationale start to finish. Click a row to see why it matters and how to fix it.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch((e) => setError(String(e)));
  }, []);

  const grouped = rules?.reduce<Record<string, RuleSummary[]>>((acc, r) => {
    (acc[r.category] ??= []).push(r);
    return acc;
  }, {});

  return (
    <ScrollArea className="h-full">
      <div className="mx-auto max-w-6xl px-8 py-6">
        <h2 className="text-lg font-semibold">Rules</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {rules ? `${rules.length} rules loaded, grouped by category.` : "Loading…"}
        </p>

        {error && (
          <div className="mt-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>
        )}

        {/* Categories fill left-to-right, top-to-bottom rather than stacking one per row —
            at 57 rules across 12 categories, a single column meant a very long scroll for
            no reason; each category's own rule list still reads top-to-bottom inside its
            column, so nothing about the nesting itself changed, just how many fit per row. */}
        <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2 xl:grid-cols-3">
          {grouped &&
            Object.entries(grouped).map(([category, categoryRules]) => (
              <div key={category}>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  {category.replace(/-/g, " ")}
                </h3>
                <div className="flex flex-col divide-y divide-border rounded-lg border border-border">
                  {categoryRules.map((r) => {
                    const isOpen = expanded.has(r.id);
                    return (
                      <div key={r.id}>
                        <button
                          onClick={() => toggle(r.id)}
                          className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left transition-colors hover:bg-accent"
                        >
                          <ChevronRight
                            className={cn(
                              "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                              isOpen && "rotate-90",
                            )}
                          />
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium">{r.title}</div>
                            <div className="mt-0.5 flex items-center gap-1.5">
                              <Badge variant="outline" className="font-mono text-[10px]">
                                {r.id}
                              </Badge>
                              <span className="truncate text-xs text-muted-foreground">
                                via {r.collector}
                              </span>
                            </div>
                          </div>
                          <SeverityBadge severity={r.severity} />
                        </button>
                        {isOpen && (
                          <div className="border-t border-border bg-muted/30 px-3 py-2.5 pl-9">
                            <p className="text-xs text-muted-foreground">{r.explain.trim()}</p>
                            <div className="mt-2 rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs">
                              {r.fix}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
        </div>
      </div>
    </ScrollArea>
  );
}

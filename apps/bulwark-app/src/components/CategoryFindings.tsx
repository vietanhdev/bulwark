import { useState } from "react";
import { Check, ChevronRight, Copy } from "lucide-react";
import { FindingCard, type Finding } from "@/components/FindingCard";
import { SEVERITY_ORDER, SeverityDot, type Severity } from "@/components/Severity";
import { categoryLabel } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface FindingGroup {
  category: string;
  items: Finding[];
  worst: Severity | null;
}

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

/**
 * Groups findings by the category that produced them, worst-severity group first. `categoryOf`
 * maps a rule id to its category; agent-security findings (which aren't in the YAML rule pack)
 * fall into their own `agent-security` bucket. Shared so the Overview and the Compliance tab bucket
 * issues identically.
 */
export function groupFindingsByCategory(
  findings: Finding[],
  categoryOf: (ruleId: string) => string,
): FindingGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const category = f.rule_id.startsWith("BLWK-AI-") ? "agent-security" : categoryOf(f.rule_id);
    const list = groups.get(category);
    if (list) list.push(f);
    else groups.set(category, [f]);
  }
  return Array.from(groups.entries())
    .map(([category, items]) => ({
      category,
      items: [...items].sort(bySeverity),
      worst: SEVERITY_ORDER.find((s) => items.some((f) => f.severity === s)) ?? null,
    }))
    .sort((a, b) => {
      const wa = a.worst ? SEVERITY_ORDER.indexOf(a.worst) : 99;
      const wb = b.worst ? SEVERITY_ORDER.indexOf(b.worst) : 99;
      return wa - wb || a.category.localeCompare(b.category);
    });
}

/**
 * One category's findings, under a collapsible header carrying the category's worst severity, its
 * count, and a single action that copies every fix command in the group. Fixing a machine is done
 * a subsystem at a time — "here is everything wrong with SSH, and here are all the commands to put
 * it right" — so the category, not the individual finding, is the unit you act on.
 */
export function CategoryFindings({
  category,
  items,
  worst,
  streamed,
  collapsed,
  onToggle,
}: {
  category: string;
  items: Finding[];
  worst: Severity | null;
  streamed?: boolean;
  collapsed: boolean;
  onToggle: () => void;
}) {
  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={!collapsed}
          className="group flex min-w-0 flex-1 items-center gap-2 rounded py-0.5 text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          <ChevronRight
            className={cn(
              "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
              !collapsed && "rotate-90",
            )}
          />
          {worst && <SeverityDot severity={worst} />}
          <span className="truncate font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
            {categoryLabel(category)}
          </span>
          <span className="font-mono text-[11px] tabular-nums text-muted-foreground/60">{items.length}</span>
        </button>
        <CopyFixesButton commands={items.map((f) => f.fix_hint)} />
      </div>

      {!collapsed && (
        <div className="flex flex-col gap-2.5">
          {items.map((f) => (
            <FindingCard key={f.id} finding={f} animate={streamed} />
          ))}
        </div>
      )}
    </section>
  );
}

/**
 * Copies every fix command in a category as one newline-separated block — paste it into a terminal
 * and remediate the whole subsystem in one go. Copy, not run: applying a root-level config change
 * is the user's deliberate act, so Bulwark hands you the exact commands rather than executing them
 * behind your back.
 */
export function CopyFixesButton({ commands }: { commands: string[] }) {
  const [copied, setCopied] = useState(false);
  const block = commands.join("\n");
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(block).then(
          () => setCopied(true),
          () => setCopied(false),
        );
      }}
      className="flex shrink-0 items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
    >
      {copied ? (
        <Check className="h-3 w-3" style={{ color: "var(--sev-resolved-fg)" }} strokeWidth={3} />
      ) : (
        <Copy className="h-3 w-3" strokeWidth={2} />
      )}
      {copied ? "Copied" : `Copy ${commands.length} fix${commands.length === 1 ? "" : "es"}`}
    </button>
  );
}

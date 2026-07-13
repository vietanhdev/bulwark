import { type ReactNode } from "react";
import { CommandBlock } from "@/components/ui/copy-button";
import { SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { cn } from "@/lib/utils";

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  explanation: string;
  fix_hint: string;
}

/**
 * A finding, typeset as a clause in an audit report: the rule ID is the clause number and sits
 * in the gutter in mono, the severity rail runs down the left edge, and the fix is a real
 * command you can copy rather than a grey box you have to retype.
 *
 * `animate` is only true for findings arriving live over a scan Channel. Findings restored from a
 * stored snapshot on open render at rest — re-playing the arrival animation for results that were
 * already there before you opened the window is a lie about what just happened, and it made the
 * whole list flicker on every visit to the tab.
 *
 * Shared by the Overview (every engine's findings) and the Compliance tab (the config engine's
 * findings) so an issue reads identically wherever you meet it.
 */
export function FindingCard({
  finding: f,
  animate,
  action,
}: {
  finding: Finding;
  animate?: boolean;
  /** Optional top-right slot — used for the per-issue actions menu (ignore this type, recheck). */
  action?: ReactNode;
}) {
  return (
    <article
      className={cn(
        "rail rail-dim rounded-md border border-border bg-card py-3.5 pr-4",
        animate && "finding-enter",
      )}
      style={railStyle(f.severity)}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className="font-mono text-xs font-semibold tracking-tight text-muted-foreground">
              {f.rule_id}
            </span>
            <SeverityLabel severity={f.severity} />
          </div>
          <h3 className="mt-1.5 text-sm font-semibold">{f.title}</h3>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
        </div>
        {action}
      </div>
      <CommandBlock command={f.fix_hint} className="mt-2.5" />
    </article>
  );
}

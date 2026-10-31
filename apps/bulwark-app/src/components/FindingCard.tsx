import { type ReactNode } from "react";
import { FileLocation } from "@/components/FileLocation";
import { FixSteps } from "@/components/FixSteps";
import { SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { cn } from "@/lib/utils";

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  explanation: string;
  fix_hint: string;
  /**
   * The file this finding points at, if any. Config-rule findings don't carry one (their fix is a
   * command); agent-security findings do, and when present we offer to open it or copy its path so
   * a heuristic — "confirm by reading line N" — is one click from being verifiable. Optional so the
   * many findings without a file are unaffected.
   */
  file?: string;
  line?: number | null;
  /** True for an AI assistant finding Bulwark may remove from its file (sessions and memory). */
  redactable?: boolean;
  /** Scanner-specific details; AI assistant findings carry `file`, `line` and `redactable` here. */
  context?: Record<string, unknown>;
}

/**
 * A finding, read top to bottom the way a person needs it: what's wrong (title and severity), why it
 * matters (explanation), how to fix it (plain-language steps with copyable commands), then the
 * actions. The rule ID is reference material, so it sits small in the footer instead of leading.
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
  footer,
  showFix = true,
  variant = "card",
}: {
  finding: Finding;
  animate?: boolean;
  /** Optional top-right slot — used for the per-issue actions menu (ignore this type, recheck). */
  action?: ReactNode;
  /** Optional actions row inside the card, under the fix steps (e.g. the Fix button). */
  footer?: ReactNode;
  /** False when a parent already shows the shared fix for a group of identical findings. */
  showFix?: boolean;
  /** "plain" drops the card chrome, for findings listed inside an expanded problem row. */
  variant?: "card" | "plain";
}) {
  // Inside an expanded problem row the title, severity and rule ID are already on the row above;
  // each instance only adds where it was found and why it matters.
  if (variant === "plain") {
    return (
      <article className={cn("py-2.5", animate && "finding-enter")}>
        {f.file && <FileLocation file={f.file} line={f.line ?? null} />}
        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
        {showFix && <FixSteps text={f.fix_hint} className="mt-2" />}
        {footer && <div className="mt-2 flex flex-wrap items-center gap-2">{footer}</div>}
      </article>
    );
  }
  return (
    <article
      className={cn(
        "rail rail-dim rounded-lg border border-border bg-card py-3.5 pr-4",
        animate && "finding-enter",
      )}
      style={railStyle(f.severity)}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <h3 className="text-sm font-semibold">{f.title}</h3>
            <SeverityLabel severity={f.severity} />
          </div>
          {f.file && <FileLocation file={f.file} line={f.line ?? null} />}
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{f.explanation}</p>
        </div>
        {action}
      </div>
      {showFix && <FixSteps text={f.fix_hint} className="mt-2.5" />}
      <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">{footer}</div>
        <span className="font-mono text-[10px] text-muted-foreground/70" title="Bulwark rule ID">
          {f.rule_id}
        </span>
      </div>
    </article>
  );
}

import { useState } from "react";
import { Ban, Check, ChevronRight, Copy, MoreVertical, RotateCw } from "lucide-react";
import { FindingCard, type Finding } from "@/components/FindingCard";
import { FixIssueButton } from "@/components/FixActions";
import { type FixCapability } from "@/lib/fixes";
import { SEVERITY_ORDER, SeverityDot, SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { categoryLabel } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface FindingGroup {
  category: string;
  items: Finding[];
  worst: Severity | null;
}

/** Actions a view can offer on an issue type. Both optional — when neither is passed, the per-issue
 *  menu isn't rendered (e.g. a read-only context). `onIgnoreType` suppresses the rule (with a
 *  mandatory reason); `onRecheck` re-runs the scan. `fixCapabilities` maps a rule id to the fixer
 *  that can clear it — a rule absent from the map gets no Fix button at all, which is most of them:
 *  only the SSH-permission, /etc-permission and sshd-config rules have a real fixer behind them.
 *  `onFixed` runs after a fix is applied so the view can re-scan. */
export interface IssueActions {
  onIgnoreType?: (ruleId: string, reason: string) => Promise<void>;
  onRecheck?: () => void;
  fixCapabilities?: Map<string, FixCapability>;
  onFixed?: () => void;
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

interface TypeGroup {
  ruleId: string;
  items: Finding[];
  worst: Severity;
}

/** Sub-groups a category's findings by rule id (the "type"), worst-severity first. A single rule
 *  can fire hundreds of times (one BLWK-AI-001 per leaked key across a repo), so collapsing by type
 *  is what turns a 243-line wall into a handful of readable rows. */
function groupByType(items: Finding[]): TypeGroup[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of items) {
    const list = byRule.get(f.rule_id);
    if (list) list.push(f);
    else byRule.set(f.rule_id, [f]);
  }
  return Array.from(byRule.entries())
    .map(([ruleId, group]) => ({
      ruleId,
      items: group,
      worst: (SEVERITY_ORDER.find((s) => group.some((f) => f.severity === s)) ??
        group[0].severity) as Severity,
    }))
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.worst) - SEVERITY_ORDER.indexOf(b.worst) || b.items.length - a.items.length,
    );
}

/**
 * One category's findings, under a collapsible header carrying the category's worst severity, its
 * count, and a "copy all fixes" action. Inside, findings are sub-grouped by rule *type* so a rule
 * that fired many times collapses to a single row you can expand — and each type carries a menu to
 * ignore that type of issue or recheck it.
 */
export function CategoryFindings({
  category,
  items,
  worst,
  streamed,
  collapsed,
  onToggle,
  actions,
}: {
  category: string;
  items: Finding[];
  worst: Severity | null;
  streamed?: boolean;
  collapsed: boolean;
  onToggle: () => void;
  actions?: IssueActions;
}) {
  const types = groupByType(items);
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
          {types.map((t) => (
            <IssueTypeGroup key={t.ruleId} group={t} streamed={streamed} actions={actions} />
          ))}
        </div>
      )}
    </section>
  );
}

/** One rule type within a category. A single finding renders as a plain card (with the actions
 *  menu); a rule that fired more than once collapses under a count header you expand to see each
 *  instance. Large groups start collapsed so a noisy rule doesn't bury the rest. */
function IssueTypeGroup({
  group,
  streamed,
  actions,
}: {
  group: TypeGroup;
  streamed?: boolean;
  actions?: IssueActions;
}) {
  const multi = group.items.length > 1;
  const [open, setOpen] = useState(group.items.length <= 3);
  const [ignoring, setIgnoring] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const first = group.items[0];

  const menu =
    actions && (actions.onIgnoreType || actions.onRecheck) ? (
      <IssueMenu
        onIgnore={actions.onIgnoreType ? () => setIgnoring(true) : undefined}
        onRecheck={actions.onRecheck}
      />
    ) : null;

  async function confirmIgnore() {
    const r = reason.trim();
    if (!r || !actions?.onIgnoreType) return;
    setBusy(true);
    try {
      await actions.onIgnoreType(group.ruleId, r);
      setIgnoring(false);
      setReason("");
    } finally {
      setBusy(false);
    }
  }

  const capability = actions?.fixCapabilities?.get(group.ruleId);
  const fixRow = capability ? <FixIssueButton capability={capability} onFixed={actions?.onFixed} /> : null;

  const reasonRow = ignoring ? (
    <div className="mt-2 flex items-center gap-2 rounded-md border border-border bg-muted/40 px-2.5 py-2">
      <input
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && confirmIgnore()}
        placeholder="Reason for accepting this risk…"
        className="min-w-0 flex-1 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
      />
      <button
        type="button"
        onClick={confirmIgnore}
        disabled={busy || !reason.trim()}
        className="flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[11px] font-medium transition-colors hover:bg-accent disabled:opacity-50"
      >
        <Ban className="h-3 w-3" />
        Ignore type
      </button>
      <button
        type="button"
        onClick={() => {
          setIgnoring(false);
          setReason("");
        }}
        className="rounded px-1.5 py-0.5 text-[11px] text-muted-foreground hover:text-foreground"
      >
        Cancel
      </button>
    </div>
  ) : null;

  // Single finding: the card itself carries the menu.
  if (!multi) {
    return (
      <div>
        <FindingCard finding={first} animate={streamed} action={menu} />
        {fixRow}
        {reasonRow}
      </div>
    );
  }

  // Many of the same rule: a collapsible count header owns the menu; expanding shows each instance.
  return (
    <div className="rail rail-dim rounded-md border border-border bg-card" style={railStyle(group.worst)}>
      <div className="flex items-center gap-2 py-2.5 pr-2.5 pl-3">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-2 text-left focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
        >
          <ChevronRight
            className={cn(
              "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
              open && "rotate-90",
            )}
          />
          <span className="font-mono text-xs font-semibold tracking-tight text-muted-foreground">
            {group.ruleId}
          </span>
          <SeverityLabel severity={group.worst} />
          <span className="min-w-0 flex-1 truncate text-sm">{first.title}</span>
          <span className="shrink-0 rounded-full bg-muted px-1.5 font-mono text-[11px] tabular-nums text-muted-foreground">
            {group.items.length}
          </span>
        </button>
        {menu}
      </div>
      {fixRow && <div className="px-3 pb-1">{fixRow}</div>}
      {reasonRow && <div className="px-3 pb-2">{reasonRow}</div>}
      {open && (
        <div className="flex flex-col gap-2.5 px-3 pb-3">
          {group.items.map((f) => (
            <FindingCard key={f.id} finding={f} animate={streamed} />
          ))}
        </div>
      )}
    </div>
  );
}

/** The per-issue actions menu (⋯). A tiny self-contained dropdown — a full-screen transparent
 *  backdrop closes it on an outside click. Only renders the actions it's given. */
function IssueMenu({ onIgnore, onRecheck }: { onIgnore?: () => void; onRecheck?: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative shrink-0">
      <button
        type="button"
        aria-label="Issue actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      >
        <MoreVertical className="h-4 w-4" />
      </button>
      {open && (
        <>
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            onClick={() => setOpen(false)}
            className="fixed inset-0 z-10 cursor-default"
          />
          <div
            role="menu"
            className="absolute right-0 z-20 mt-1 w-56 overflow-hidden rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md"
          >
            {onIgnore && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  onIgnore();
                }}
                className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs transition-colors hover:bg-accent"
              >
                <Ban className="h-3.5 w-3.5 text-muted-foreground" />
                Ignore this type of issue
              </button>
            )}
            {onRecheck && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  onRecheck();
                }}
                className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs transition-colors hover:bg-accent"
              >
                <RotateCw className="h-3.5 w-3.5 text-muted-foreground" />
                Recheck
              </button>
            )}
          </div>
        </>
      )}
    </div>
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

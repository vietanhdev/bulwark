import { useState, type ReactNode } from "react";
import { Ban, ChevronRight, MoreVertical, RotateCw } from "lucide-react";
import { FindingCard, type Finding } from "@/components/FindingCard";
import { FixIssueButton } from "@/components/FixActions";
import { FixSteps } from "@/components/FixSteps";
import { recommendation } from "@/lib/fix-text";
import { type FixCapability } from "@/lib/fixes";
import { SEVERITY_ORDER, SeverityLabel, type Severity } from "@/components/Severity";
import { GROUP_ORDER, groupInfo, groupOf } from "@/lib/groups";
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
  /** Extra per-finding action for the card footer (e.g. removing a leaked secret from its file). */
  footerFor?: (f: Finding) => ReactNode;
  /** A tool that fixes every instance of a problem at once (e.g. adding a passphrase to all
   *  unprotected SSH keys), shown in the expanded row and marked "Auto-fix" on the row. */
  groupActionFor?: (ruleId: string) => ReactNode;
}

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

/**
 * Groups findings into the user-facing groups in `lib/groups.ts` (what they protect, not the rule
 * pack's directories), worst-severity group first. `categoryOf` maps a rule id to its rule-pack
 * category, which `groupOf` turns into a group. Shared so Home and Checkups group identically.
 */
export function groupFindingsByCategory(
  findings: Finding[],
  categoryOf: (ruleId: string) => string,
): FindingGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const group = groupOf(f.rule_id, categoryOf(f.rule_id));
    const list = groups.get(group);
    if (list) list.push(f);
    else groups.set(group, [f]);
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
      return wa - wb || GROUP_ORDER.indexOf(a.category) - GROUP_ORDER.indexOf(b.category);
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
 * One category's findings, under a collapsible header carrying the category's worst severity and
 * its count. Inside, findings are sub-grouped by rule *type* so a rule
 * that fired many times collapses to a single row you can expand — and each type carries a menu to
 * ignore that type of issue or recheck it.
 */
export function CategoryFindings({
  category,
  items,
  streamed,
  collapsed,
  onToggle,
  actions,
}: {
  category: string;
  items: Finding[];
  /** Worst severity in the group; kept for callers, the rows carry their own severity. */
  worst?: Severity | null;
  streamed?: boolean;
  collapsed: boolean;
  onToggle: () => void;
  actions?: IssueActions;
}) {
  const types = groupByType(items);
  const info = groupInfo(category);
  return (
    <section>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={!collapsed}
        title={info.blurb}
        className="mb-2 flex items-center gap-1.5 rounded text-xs font-semibold tracking-wide text-muted-foreground uppercase hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      >
        <ChevronRight
          className={cn("h-3.5 w-3.5 shrink-0 transition-transform", !collapsed && "rotate-90")}
        />
        {info.title}
        <span className="font-normal tabular-nums normal-case">{types.length}</span>
      </button>
      {!collapsed && (
        <div className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
          {types.map((t) => (
            <IssueTypeGroup key={t.ruleId} group={t} streamed={streamed} actions={actions} />
          ))}
        </div>
      )}
    </section>
  );
}

/** Where one instance of a problem was found: its file (and line), or the path/port its fact names. */
function locationOf(f: Finding): string {
  if (f.file) return f.line ? `${f.file}:${f.line}` : f.file;
  const c = f.context ?? {};
  if (typeof c.path === "string") return c.path;
  if (c.port !== undefined)
    return `port ${String(c.port)}${typeof c.listen_address === "string" ? ` on ${c.listen_address}` : ""}`;
  return f.title;
}

/**
 * One root cause: a rule, however many places it fired. Collapsed it is a single row (severity,
 * title, how many places, the recommendation in one sentence, and the automatic fix when there is
 * one), so a long scan reads as a short list of problems. Clicking the row opens the full steps and
 * every individual finding with its file, explanation and actions.
 */
function IssueTypeGroup({
  group,
  streamed,
  actions,
}: {
  group: TypeGroup;
  streamed?: boolean;
  actions?: IssueActions;
}) {
  const count = group.items.length;
  // When every instance has the same fix text, show it once for the group, not on each card.
  // Instances whose fixes differ only in a file path (one per SSH key, say) share the same goal
  // line; showing the steps once keeps the expanded row short. Each instance still shows its path.
  const goalOf = (t: string) => t.trim().split("\n")[0];
  const sameFix = group.items.every((f) => goalOf(f.fix_hint) === goalOf(group.items[0].fix_hint));
  const [open, setOpen] = useState(false);
  // Steps that differ per place only make sense next to each place, so start with them showing.
  const [details, setDetails] = useState(!sameFix);
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
  const groupAction = actions?.groupActionFor?.(group.ruleId) ?? null;
  const fixRow = capability ? <FixIssueButton capability={capability} onFixed={actions?.onFixed} /> : null;
  // Per-place actions (removing a leaked secret from its file) are the fix itself, so the list of
  // places moves up into the fix block instead of hiding under Details.
  const placeActions = sameFix && group.items.some((f) => actions?.footerFor?.(f));
  const autoFix = Boolean(fixRow || groupAction || placeActions);
  const places = (
    <ul className="space-y-1">
      {group.items.map((f) => (
        <li key={f.id} className="flex flex-wrap items-center gap-2">
          <code className="font-mono text-xs break-all">{locationOf(f)}</code>
          {actions?.footerFor?.(f)}
        </li>
      ))}
    </ul>
  );

  return (
    <div>
      <div className="flex items-center gap-2 pr-2 transition-colors hover:bg-muted/40">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-3 py-2.5 pl-3 text-left focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
        >
          <ChevronRight
            className={cn(
              "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
              open && "rotate-90",
            )}
          />
          <SeverityLabel severity={group.worst} className="w-16 justify-center" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium">{first.title}</span>
            <span className="block truncate text-xs text-muted-foreground">
              {recommendation(first.fix_hint)}
            </span>
          </span>
        </button>
        {autoFix && (
          <span
            className="hidden shrink-0 rounded-full border border-primary/40 px-2 py-0.5 text-[11px] font-medium text-primary sm:inline"
            title="Bulwark can fix this for you. Open the row to preview the change."
          >
            Auto-fix
          </span>
        )}
        {count > 1 && (
          <span
            className="shrink-0 text-xs text-muted-foreground tabular-nums"
            title={`Found in ${count} places`}
          >
            {count}×
          </span>
        )}
        <span className="hidden w-32 shrink-0 truncate text-right font-mono text-[10px] text-muted-foreground/70 lg:inline">
          {group.ruleId}
        </span>
        {menu}
      </div>
      {ignoring && (
        <div className="mx-3 mb-2 flex items-center gap-2 rounded-md border border-border bg-muted/40 px-2.5 py-2">
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
      )}
      {open && (
        <div className="flex flex-col gap-2.5 border-t border-border bg-muted/20 px-4 py-3 sm:pl-10">
          {/* Why it matters, then the one thing to do about it. Everything else sits behind Details. */}
          <p className="line-clamp-2 text-sm leading-relaxed text-muted-foreground" title={first.explanation}>
            {first.explanation}
          </p>
          {autoFix ? (
            <div className="flex flex-col gap-2">
              {fixRow}
              {groupAction}
              {placeActions && places}
            </div>
          ) : (
            sameFix && <FixSteps text={first.fix_hint} heading="Fix" />
          )}
          <div>
            <button
              type="button"
              onClick={() => setDetails((d) => !d)}
              aria-expanded={details}
              className="flex items-center gap-1 rounded text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
            >
              <ChevronRight className={cn("h-3 w-3 transition-transform", details && "rotate-90")} />
              Details
              <span className="font-normal">
                ·{" "}
                {[
                  !placeActions && (count === 1 ? locationOf(first) : `${count} places`),
                  autoFix && sameFix && "manual steps",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
            </button>
            {details && (
              <div className="mt-2 flex flex-col gap-3">
                {sameFix ? (
                  !placeActions && places
                ) : (
                  <div className="divide-y divide-border">
                    {group.items.map((f) => (
                      <FindingCard
                        key={f.id}
                        finding={f}
                        animate={streamed}
                        variant="plain"
                        footer={actions?.footerFor?.(f)}
                      />
                    ))}
                  </div>
                )}
                {autoFix && sameFix && <FixSteps text={first.fix_hint} heading="Or fix it yourself" />}
                <span className="font-mono text-[10px] text-muted-foreground/70">{group.ruleId}</span>
              </div>
            )}
          </div>
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

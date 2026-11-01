import { useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Ban, ChevronRight, ExternalLink, EyeOff, MoreVertical, RotateCw } from "lucide-react";
import { FindingCard, type Finding } from "@/components/FindingCard";
import { FixIssueButton } from "@/components/FixActions";
import { FixSteps } from "@/components/FixSteps";
import { Menu, MenuContent, MenuItem, MenuTrigger } from "@/components/ui/menu";
import { sharedTitle } from "@/lib/findings";
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
  /** Ignore one finding — a rule at one place (see `ignoreKeyOf`) — leaving the rule on. */
  onIgnorePlace?: (ruleId: string, location: string, reason: string) => Promise<void>;
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
/**
 * The place a single-finding ignore is keyed on. Mirrors `bulwark_core::finding_location` exactly —
 * the file (without a line number, which moves whenever the file is edited), the listening port,
 * or the title — so an ignore made here matches the finding the backend filters.
 */
/** The question asked before ignoring one finding. A finding about the whole machine has no
 *  place but its own title, which made "Why ignore it at SSH password authentication is
 *  enabled?"; a path or port reads "at", an identity (a unit, a module) reads "for". */
function ignorePrompt(place: string, title?: string): string {
  if (place === title) return "Why ignore this one?";
  const located = /^(\/|~|[A-Za-z]:\\|port )/.test(place);
  return located ? `Why ignore it at ${place}?` : `Why ignore it for ${place}?`;
}

export function ignoreKeyOf(f: Finding): string {
  const c = f.context ?? {};
  for (const key of ["path", "file"]) {
    const v = c[key];
    if (typeof v === "string" && v) return v;
  }
  if (c.port !== undefined && c.port !== null) {
    const addr = typeof c.listen_address === "string" ? c.listen_address : null;
    return addr ? `port ${String(c.port)} on ${addr}` : `port ${String(c.port)}`;
  }
  // The item's identifying facts (bulwark_core::models::IDENTITY_FIELDS, same order), so ignoring
  // one systemd unit or sudoers line never hides another that a fixed-title rule reports later.
  const identity = IDENTITY_FIELDS.flatMap((k) => {
    const v = c[k];
    if (typeof v === "string" && v) return [`${k}=${v}`];
    if (typeof v === "number") return [`${k}=${v}`];
    return [];
  });
  if (identity.length > 0) return identity.join(" · ");
  return f.title;
}

const IDENTITY_FIELDS = [
  "unit_name",
  "label",
  "module",
  "interface",
  "indicator",
  "source",
  "line",
  "command",
];

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
  // What the inline reason box will hide: the whole issue type, or one place.
  const [ignoring, setIgnoring] = useState<false | { place: string | null; title?: string }>(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const first = group.items[0];

  const menu =
    actions && (actions.onIgnoreType || actions.onRecheck) ? (
      <IssueMenu
        onIgnore={actions.onIgnoreType ? () => setIgnoring({ place: null }) : undefined}
        onIgnoreOne={
          actions.onIgnorePlace && group.items.length === 1
            ? () => setIgnoring({ place: ignoreKeyOf(group.items[0]), title: group.items[0].title })
            : undefined
        }
        onRecheck={actions.onRecheck}
      />
    ) : null;

  async function confirmIgnore() {
    const r = reason.trim();
    if (!r || !ignoring) return;
    setBusy(true);
    try {
      if (ignoring.place !== null) {
        if (!actions?.onIgnorePlace) return;
        await actions.onIgnorePlace(group.ruleId, ignoring.place, r);
      } else {
        if (!actions?.onIgnoreType) return;
        await actions.onIgnoreType(group.ruleId, r);
      }
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
  // The "Auto-fix" pill is a shortcut to the fix: open the row and bring the fix into view.
  const fixRef = useRef<HTMLDivElement>(null);
  function showFix() {
    setOpen(true);
    requestAnimationFrame(() => fixRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }));
  }
  const places = (
    <ul className="space-y-1">
      {group.items.map((f) => (
        <li key={f.id} className="flex flex-wrap items-center gap-2">
          <code className="font-mono text-xs break-all">{locationOf(f)}</code>
          {actions?.footerFor?.(f)}
          {actions?.onIgnorePlace && count > 1 && (
            <button
              type="button"
              onClick={() => setIgnoring({ place: ignoreKeyOf(f), title: f.title })}
              className="rounded text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              title="Stop reporting this one place; the others keep being reported"
            >
              Ignore
            </button>
          )}
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
            <span className="block truncate text-sm font-medium">
              {sharedTitle(group.items.map((f) => f.title))}
            </span>
            <span className="block truncate text-xs text-muted-foreground">
              {recommendation(first.fix_hint)}
            </span>
          </span>
        </button>
        {autoFix && (
          <button
            type="button"
            onClick={showFix}
            className="hidden shrink-0 rounded-full border border-primary/40 px-2 py-0.5 text-[11px] font-medium text-primary transition-colors hover:border-primary hover:bg-primary/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring sm:inline"
            title="Bulwark can fix this for you — preview the change first"
          >
            Auto-fix
          </button>
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
            placeholder={
              ignoring && ignoring.place !== null
                ? ignorePrompt(ignoring.place, ignoring.title)
                : "Reason for accepting this risk…"
            }
            className="min-w-0 flex-1 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
          />
          <button
            type="button"
            onClick={confirmIgnore}
            disabled={busy || !reason.trim()}
            className="flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[11px] font-medium transition-colors hover:bg-accent disabled:opacity-50"
          >
            <Ban className="h-3 w-3" />
            {ignoring && ignoring.place !== null ? "Ignore here" : "Ignore type"}
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
            <div ref={fixRef} className="flex flex-col gap-2">
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
                <div className="flex items-center gap-3 text-xs">
                  <button
                    type="button"
                    onClick={() => void invoke("open_check_page", { ruleId: group.ruleId }).catch(() => {})}
                    className="inline-flex items-center gap-1 rounded font-medium text-primary underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                  >
                    Read the full explanation
                    <ExternalLink className="h-3 w-3" />
                  </button>
                  <span className="font-mono text-[10px] text-muted-foreground/70">{group.ruleId}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** The per-issue actions menu (⋯). Portalled (see `ui/menu`), so it is never clipped by the
 *  findings card and opens upward on the last row. Only renders the actions it's given. */
function IssueMenu({
  onIgnore,
  onIgnoreOne,
  onRecheck,
}: {
  onIgnore?: () => void;
  onIgnoreOne?: () => void;
  onRecheck?: () => void;
}) {
  return (
    <Menu>
      <MenuTrigger
        aria-label="Issue actions"
        className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring data-popup-open:bg-accent data-popup-open:text-foreground"
      >
        <MoreVertical className="h-4 w-4" />
      </MenuTrigger>
      <MenuContent>
        {onIgnoreOne && (
          <MenuItem onClick={onIgnoreOne}>
            <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
            Ignore only this one
          </MenuItem>
        )}
        {onIgnore && (
          <MenuItem onClick={onIgnore}>
            <Ban className="h-3.5 w-3.5 text-muted-foreground" />
            Ignore this type of issue
          </MenuItem>
        )}
        {onRecheck && (
          <MenuItem onClick={onRecheck}>
            <RotateCw className="h-3.5 w-3.5 text-muted-foreground" />
            Recheck
          </MenuItem>
        )}
      </MenuContent>
    </Menu>
  );
}

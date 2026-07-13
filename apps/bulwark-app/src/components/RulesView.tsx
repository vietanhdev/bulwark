import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Ban, Check, ChevronRight, History, RotateCcw, Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Callout } from "@/components/ui/callout";
import { CommandBlock } from "@/components/ui/copy-button";
import { PageShell, SectionLabel } from "@/components/PageShell";
import { HardeningRing } from "@/components/HardeningRing";
import { SEVERITY_ORDER, SeverityDot, SeverityLabel, railStyle, type Severity } from "@/components/Severity";
import { computeHardeningIndex } from "@/lib/hardening";
import { useRevision } from "@/lib/revision";
import { cn } from "@/lib/utils";

interface RuleSummary {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  collector: string;
  references: string[];
  explain: string;
  fix: string;
  os: string[];
  profiles: string[];
}

interface DashboardSnapshot {
  findings: { rule_id: string }[];
  meta: { privileged_collectors_skipped: string[] } | null;
}

interface Suppression {
  rule_id: string;
  reason: string;
  created_at: string;
  created_by: string;
}

interface SuppressionEvent {
  id: string;
  rule_id: string;
  action: "suppressed" | "unsuppressed";
  reason: string;
  actor: string;
  at: string;
}

const categoryLabel = (c: string) => c.replace(/-/g, " ");

const FRAMEWORK_LABELS: Record<string, string> = {
  CIS: "CIS Benchmarks",
  ATTACK: "MITRE ATT&CK",
};

const frameworkOf = (reference: string) => {
  const prefix = reference.split("-")[0];
  return FRAMEWORK_LABELS[prefix] ?? prefix;
};

export function RulesView() {
  const { revision } = useRevision();
  const [rules, setRules] = useState<RuleSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  // Rows start collapsed: the pack is 50+ rules, and this page is mostly used to skim what
  // exists rather than to read every rationale end to end. Click a row for the why and the fix.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Scan state, so the framework mapping can show pass/fail and the hardening index — merged in
  // from what used to be a separate "Compliance" tab (the reference material about the rules, as
  // opposed to the scan-results Compliance tab that now shows the issues to fix).
  const [openRuleIds, setOpenRuleIds] = useState<Set<string>>(new Set());
  const [skippedCollectors, setSkippedCollectors] = useState<Set<string>>(new Set());
  const [hasScanned, setHasScanned] = useState(false);
  // Two representations of the same rule pack, switched by a tab: the searchable catalog ("what
  // does Bulwark check, and how do I fix each thing"), and the framework/hardening view ("how does
  // that line up against CIS/MITRE, and how hardened is this host"). Both were requested as
  // distinct tabbed views rather than one long scroll.
  const [tab, setTab] = useState<"rules" | "compliance" | "suppressed">("rules");
  // Rule suppressions: which rules the user has accepted the risk of (keyed by id for O(1) lookup
  // while rendering the catalog), the append-only audit trail, and the in-progress reason text per
  // rule. Suppression never stops a rule running — it only changes how its findings are presented —
  // so this state lives alongside the catalog rather than gating it.
  const [suppressions, setSuppressions] = useState<Map<string, Suppression>>(new Map());
  const [auditLog, setAuditLog] = useState<SuppressionEvent[]>([]);
  const [reasonDrafts, setReasonDrafts] = useState<Record<string, string>>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyRule, setBusyRule] = useState<string | null>(null);

  useEffect(() => {
    invoke<RuleSummary[]>("rules_list")
      .then(setRules)
      .catch((e) => setError(String(e)));
  }, []);

  const loadSuppressions = useCallback(() => {
    invoke<Suppression[]>("suppressions_list")
      .then((list) => setSuppressions(new Map(list.map((s) => [s.rule_id, s]))))
      .catch((e) => setActionError(String(e)));
    invoke<SuppressionEvent[]>("suppression_audit", { ruleId: null })
      .then(setAuditLog)
      .catch(() => {});
  }, []);

  useEffect(() => {
    invoke<DashboardSnapshot>("dashboard_snapshot").then((snap) => {
      setOpenRuleIds(new Set(snap.findings.map((f) => f.rule_id)));
      if (snap.meta) {
        setHasScanned(true);
        setSkippedCollectors(new Set(snap.meta.privileged_collectors_skipped));
      }
    });
    loadSuppressions();
  }, [revision, loadSuppressions]);

  async function suppressRule(ruleId: string) {
    const reason = (reasonDrafts[ruleId] ?? "").trim();
    if (!reason) {
      setActionError(
        "A reason is required to suppress a rule — it's what makes the decision auditable later.",
      );
      return;
    }
    setBusyRule(ruleId);
    setActionError(null);
    try {
      await invoke("rule_suppress", { ruleId, reason });
      setReasonDrafts((d) => ({ ...d, [ruleId]: "" }));
      loadSuppressions();
    } catch (e) {
      setActionError(String(e));
    } finally {
      setBusyRule(null);
    }
  }

  async function unsuppressRule(ruleId: string) {
    const reason = (reasonDrafts[ruleId] ?? "").trim();
    if (!reason) {
      setActionError(
        "A reason is required to re-enable a rule too — 'why did this alert come back?' is a question worth answering.",
      );
      return;
    }
    setBusyRule(ruleId);
    setActionError(null);
    try {
      await invoke("rule_unsuppress", { ruleId, reason });
      setReasonDrafts((d) => ({ ...d, [ruleId]: "" }));
      loadSuppressions();
    } catch (e) {
      setActionError(String(e));
    } finally {
      setBusyRule(null);
    }
  }

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

  const unmapped = rules?.filter((r) => r.references.length === 0).length ?? 0;

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
      {actionError && <Callout tone="critical">{actionError}</Callout>}

      {rules && (
        <>
          {/* Tab switch between the two representations of the pack. */}
          <div className="mb-6 flex items-center gap-1 border-b border-border" role="tablist">
            {(
              [
                ["rules", "Rules"],
                ["compliance", "Framework compliance"],
                ["suppressed", suppressions.size > 0 ? `Suppressed (${suppressions.size})` : "Suppressed"],
              ] as const
            ).map(([id, label]) => {
              const on = tab === id;
              return (
                <button
                  key={id}
                  role="tab"
                  aria-selected={on}
                  onClick={() => setTab(id)}
                  className={cn(
                    "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
                    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                    on
                      ? "border-primary font-medium text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                >
                  {label}
                </button>
              );
            })}
          </div>

          {/* The hardening index and framework mapping — moved here from what used to be its own
              "Compliance" tab. It's reference material *about* the rules (how they line up against
              CIS/MITRE, how hardened this host is), which belongs with the rule pack; the Compliance
              tab under Scans is now the scan-results page where you read and fix the issues. */}
          {tab === "compliance" && (
            <section className="mb-8 flex flex-col gap-6">
              <div>
                <SectionLabel>Hardening &amp; framework coverage</SectionLabel>
                {hardening ? (
                  <div className="rounded-lg border border-border bg-card px-6 py-5">
                    <HardeningRing index={hardening} size="lg" />
                  </div>
                ) : (
                  <Callout tone="info">
                    Run a scan from the Overview or the Compliance tab to see which controls this host passes.
                    Until then, the map below is just that — every rule Bulwark has and the framework control
                    it answers to.
                  </Callout>
                )}
              </div>

              <div className="grid grid-cols-1 gap-x-5 gap-y-6 lg:grid-cols-2">
                {frameworks.map(({ framework, controls, passing }) => (
                  <div key={framework}>
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
                        // Before any scan, nothing is known to fail — but nothing is known to pass
                        // either. Render neutral rather than a wall of green ticks claiming a clean
                        // bill of health nobody has earned.
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
                  </div>
                ))}
              </div>

              {unmapped > 0 && (
                <p className="text-xs text-muted-foreground">
                  {unmapped} rule{unmapped === 1 ? "" : "s"} aren't mapped to a framework control yet. They
                  still run — mapping only affects what shows on this page.
                </p>
              )}
            </section>
          )}

          {tab === "suppressed" && (
            <SuppressedTab
              rules={rules}
              suppressions={suppressions}
              auditLog={auditLog}
              busyRule={busyRule}
              draftFor={(id) => reasonDrafts[id] ?? ""}
              onDraft={(id, v) => setReasonDrafts((d) => ({ ...d, [id]: v }))}
              onUnsuppress={unsuppressRule}
              onGoToRules={() => setTab("rules")}
            />
          )}

          {tab === "rules" && (
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
                                      <span className="font-mono text-[11px] text-muted-foreground">
                                        {r.id}
                                      </span>
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
                                      {suppressions.has(r.id) && (
                                        <span className="inline-flex items-center gap-1 rounded-sm bg-muted px-1 font-mono text-[10px] text-muted-foreground">
                                          <Ban className="h-2.5 w-2.5" />
                                          suppressed
                                        </span>
                                      )}
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
                                    <SuppressionControl
                                      ruleId={r.id}
                                      suppression={suppressions.get(r.id) ?? null}
                                      draft={reasonDrafts[r.id] ?? ""}
                                      busy={busyRule === r.id}
                                      onDraft={(v) => setReasonDrafts((d) => ({ ...d, [r.id]: v }))}
                                      onSuppress={() => suppressRule(r.id)}
                                      onUnsuppress={() => unsuppressRule(r.id)}
                                    />
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
        </>
      )}
    </PageShell>
  );
}

/// The suppress / un-suppress control shown inside an expanded rule row. When the rule is live it
/// offers a reason box and a Suppress button; when it's already suppressed it shows who accepted the
/// risk and why, with a reasoned Un-suppress. The reason is required either way — the button stays
/// disabled until there's text — because an unexplained decision is exactly what the audit trail
/// exists to prevent.
function SuppressionControl({
  suppression,
  draft,
  busy,
  onDraft,
  onSuppress,
  onUnsuppress,
}: {
  ruleId: string;
  suppression: Suppression | null;
  draft: string;
  busy: boolean;
  onDraft: (v: string) => void;
  onSuppress: () => void;
  onUnsuppress: () => void;
}) {
  const suppressed = suppression !== null;
  return (
    <div className="mt-3 border-t border-border pt-3">
      {suppressed && (
        <p className="mb-2 text-[11px] leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground">Suppressed</span> by {suppression.created_by} on{" "}
          {new Date(suppression.created_at).toLocaleDateString()} — “{suppression.reason}”. The rule still
          runs every scan; its findings just don't count against you until you re-enable it.
        </p>
      )}
      <div className="flex items-start gap-2">
        <Input
          value={draft}
          onChange={(e) => onDraft(e.target.value)}
          placeholder={suppressed ? "Reason for re-enabling…" : "Reason for accepting this risk…"}
          className="h-8 flex-1 text-xs"
          aria-label="Suppression reason"
        />
        {suppressed ? (
          <button
            type="button"
            disabled={busy || !draft.trim()}
            onClick={onUnsuppress}
            className={cn(
              "inline-flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 text-xs transition-colors",
              "hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
              "disabled:cursor-not-allowed disabled:opacity-50",
            )}
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Re-enable
          </button>
        ) : (
          <button
            type="button"
            disabled={busy || !draft.trim()}
            onClick={onSuppress}
            className={cn(
              "inline-flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 text-xs transition-colors",
              "hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
              "disabled:cursor-not-allowed disabled:opacity-50",
            )}
          >
            <Ban className="h-3.5 w-3.5" />
            Suppress
          </button>
        )}
      </div>
    </div>
  );
}

/// The "Suppressed" tab: the rules whose risk has been accepted (with a one-click reasoned
/// re-enable), plus the append-only audit trail of every suppression decision ever made — including
/// lifted ones, which is the whole reason the history is kept separately from the current state.
function SuppressedTab({
  rules,
  suppressions,
  auditLog,
  busyRule,
  draftFor,
  onDraft,
  onUnsuppress,
  onGoToRules,
}: {
  rules: RuleSummary[];
  suppressions: Map<string, Suppression>;
  auditLog: SuppressionEvent[];
  busyRule: string | null;
  draftFor: (id: string) => string;
  onDraft: (id: string, v: string) => void;
  onUnsuppress: (id: string) => void;
  onGoToRules: () => void;
}) {
  const titleOf = (id: string) => rules.find((r) => r.id === id)?.title ?? id;
  const active = Array.from(suppressions.values());

  return (
    <section className="flex flex-col gap-8">
      <div>
        <SectionLabel>Active suppressions</SectionLabel>
        {active.length === 0 ? (
          <Callout tone="info">
            No rules are suppressed. To accept the risk a rule reports — a finding you've reviewed and decided
            to live with — open it under the{" "}
            <button className="underline underline-offset-2" onClick={onGoToRules}>
              Rules
            </button>{" "}
            tab and suppress it with a reason. Suppressing never stops a rule running; it just stops its
            findings counting against you, and every decision is logged below.
          </Callout>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border bg-card">
            {active.map((s, i) => (
              <div key={s.rule_id} className={cn("p-3", i > 0 && "border-t border-border")}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{titleOf(s.rule_id)}</p>
                    <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{s.rule_id}</p>
                    <p className="mt-1.5 text-xs text-muted-foreground">
                      “{s.reason}” — {s.created_by}, {new Date(s.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1.5">
                    <Input
                      value={draftFor(s.rule_id)}
                      onChange={(e) => onDraft(s.rule_id, e.target.value)}
                      placeholder="Reason to re-enable…"
                      className="h-8 w-52 text-xs"
                      aria-label={`Reason to re-enable ${s.rule_id}`}
                    />
                    <button
                      type="button"
                      disabled={busyRule === s.rule_id || !draftFor(s.rule_id).trim()}
                      onClick={() => onUnsuppress(s.rule_id)}
                      className={cn(
                        "inline-flex h-8 items-center gap-1.5 rounded-md border border-border px-2.5 text-xs transition-colors",
                        "hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                        "disabled:cursor-not-allowed disabled:opacity-50",
                      )}
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      Re-enable
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <SectionLabel>
          <span className="inline-flex items-center gap-1.5">
            <History className="h-3.5 w-3.5" />
            Audit trail
          </span>
        </SectionLabel>
        {auditLog.length === 0 ? (
          <p className="text-xs text-muted-foreground">No suppression decisions recorded yet.</p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border bg-card">
            {auditLog.map((e, i) => (
              <div
                key={e.id}
                className={cn("flex items-start gap-3 p-3 text-xs", i > 0 && "border-t border-border")}
              >
                <span
                  className={cn(
                    "mt-0.5 inline-flex shrink-0 items-center gap-1 rounded-sm px-1.5 py-0.5 font-mono text-[10px]",
                    e.action === "suppressed"
                      ? "bg-muted text-muted-foreground"
                      : "bg-accent text-accent-foreground",
                  )}
                >
                  {e.action === "suppressed" ? (
                    <Ban className="h-2.5 w-2.5" />
                  ) : (
                    <RotateCcw className="h-2.5 w-2.5" />
                  )}
                  {e.action === "suppressed" ? "suppressed" : "re-enabled"}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="font-mono text-[11px] text-muted-foreground">{e.rule_id}</span>
                  <span className="ml-2 text-muted-foreground">“{e.reason}”</span>
                </div>
                <span className="shrink-0 whitespace-nowrap text-[11px] text-muted-foreground/70">
                  {e.actor} · {new Date(e.at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

/** The subset of a rule this calculation needs. Deliberately structural, so both the Overview
 *  and Compliance views can pass their own richer `RuleSummary` straight in. */
export interface GateableRule {
  id: string;
  /** The user's own rule — not part of the score, which measures Bulwark's checks. */
  custom?: boolean;
  collector: string;
  os: string[];
  profiles: string[];
}

export interface HardeningIndex {
  /** 0–100. */
  score: number;
  passing: number;
  /** Rules that actually ran and could therefore pass or fail. The score's denominator. */
  evaluated: number;
  /** Rules excluded from the score entirely because they never ran. */
  skipped: number;
}

/** What the last scans prove actually ran. */
export interface RunEvidence {
  /** The config scan's persisted `rules_evaluated` set. Empty when no scan recorded one. */
  rulesEvaluated: Set<string>;
  /** Whether an AI-assistant scan has completed, which is what evaluates the `BLWK-AI-*` checks. */
  agentScanned: boolean;
}

/** Whether a rule demonstrably ran on the last scan: it fired, or the scan recorded evaluating it.
 *  A rule that didn't run must be shown as unknown — never as a pass. */
export function ruleRan(ruleId: string, openRuleIds: Set<string>, evidence: RunEvidence): boolean {
  if (openRuleIds.has(ruleId)) return true;
  return ruleId.startsWith("BLWK-AI-") ? evidence.agentScanned : evidence.rulesEvaluated.has(ruleId);
}

/**
 * Bulwark's headline metric, computed once and shared by Home and All checks.
 *
 * Only rules that demonstrably ran are scored, mirroring Lynis's hardening index: a check that
 * never ran tells you nothing, so it is left out of the numerator AND the denominator rather than
 * counted as a free pass. "Ran" is taken from the scan's own record (`rules_evaluated`), plus any
 * rule that produced an open finding — never inferred from the rule pack. Inferring it is what
 * this used to do, assuming every non-skipped Linux rule had run; on Windows that reported
 * "64 of 64 checks pass" for a scan that had evaluated seven.
 *
 * Returns null when there is no evidence at all (no scan yet, or a database written before the
 * evaluated set was stored): the UI then shows no score instead of an invented one.
 */
export function computeHardeningIndex(
  rules: GateableRule[],
  openRuleIds: Set<string>,
  evidence: RunEvidence,
): HardeningIndex | null {
  // Without the record, rules with open findings alone would make a 0% score out of a partial view.
  if (evidence.rulesEvaluated.size === 0 && !evidence.agentScanned) return null;
  // Custom checks are the user's own and could only inflate (or deflate) the score at will.
  const evaluated = rules.filter((r) => !r.custom && ruleRan(r.id, openRuleIds, evidence));
  if (evaluated.length === 0) return null;

  const passing = evaluated.filter((r) => !openRuleIds.has(r.id)).length;
  return {
    score: Math.round((passing / evaluated.length) * 100),
    passing,
    evaluated: evaluated.length,
    skipped: rules.filter((r) => !r.custom).length - evaluated.length,
  };
}

/** Shared banding for the index, so the ring, the number and any label always agree. */
export function hardeningTone(score: number): "resolved" | "medium" | "critical" {
  if (score >= 80) return "resolved";
  if (score >= 50) return "medium";
  return "critical";
}

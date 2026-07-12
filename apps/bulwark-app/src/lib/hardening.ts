/** The subset of a rule this calculation needs. Deliberately structural, so both the Overview
 *  and Compliance views can pass their own richer `RuleSummary` straight in. */
export interface GateableRule {
  id: string;
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

/**
 * Bulwark's headline metric, computed once and shared.
 *
 * This used to exist twice, with two different denominators — the Overview counted only
 * framework-mapped rules while Compliance counted every evaluated rule — so the two screens
 * showed different "N/M passing" figures for what read as the same number. One definition now,
 * used by both.
 *
 * The exclusion logic mirrors Lynis's own hardening index: a check that never *ran* tells you
 * nothing either way, so it is removed from the numerator AND the denominator rather than
 * counted as a free pass. Three ways a rule can fail to have run:
 *
 *   - its collector needed privilege the scan didn't have (`skippedCollectors`);
 *   - it isn't applicable to this OS (the GUI is Linux-only, so a macOS-tagged rule
 *     structurally never executed here);
 *   - it is profile-gated (`needs: server`) and the last scan may not have opted into that
 *     need. A gated rule that produced an open finding demonstrably DID run, so it still
 *     counts; one that produced nothing is ambiguous — ran-and-passed vs. never-ran — and is
 *     conservatively excluded rather than risk inflating the score with a rule that never
 *     actually executed.
 */
export function computeHardeningIndex(
  rules: GateableRule[],
  openRuleIds: Set<string>,
  skippedCollectors: Set<string>,
): HardeningIndex | null {
  const evaluated = rules.filter((r) => {
    if (skippedCollectors.has(r.collector)) return false;
    if (!r.os.includes("linux")) return false;
    if (r.profiles.length > 0 && !openRuleIds.has(r.id)) return false;
    return true;
  });

  if (evaluated.length === 0) return null;

  const passing = evaluated.filter((r) => !openRuleIds.has(r.id)).length;
  return {
    score: Math.round((passing / evaluated.length) * 100),
    passing,
    evaluated: evaluated.length,
    skipped: rules.length - evaluated.length,
  };
}

/** Shared banding for the index, so the ring, the number and any label always agree. */
export function hardeningTone(score: number): "resolved" | "medium" | "critical" {
  if (score >= 80) return "resolved";
  if (score >= 50) return "medium";
  return "critical";
}

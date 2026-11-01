import type { Finding } from "@/components/FindingCard";

/** Stored AI assistant findings keep their file, line and redaction flag in `context`; lift them to
 *  the fields the cards read. Streamed AI findings already have them at the top level. */
export function withLocation(f: Finding): Finding {
  const c = f.context;
  if (!c || f.file) return f;
  return {
    ...f,
    file: typeof c.file === "string" ? c.file : undefined,
    line: typeof c.line === "number" ? c.line : null,
    redactable: c.redactable === true,
  };
}

/** The title for a group of findings from one check. Rules that put the place in their title
 *  ("… (port 9000, …)", "…: usb-storage") would otherwise show one place's title for all of them,
 *  so differing titles are cut back to what they share — never mid-parenthesis or mid-word. Mirrors
 *  `Problem::title` in the CLI report (`crates/bulwarkctl/src/report.rs`). */
export function sharedTitle(titles: string[]): string {
  const first = titles[0] ?? "";
  if (titles.every((t) => t === first)) return first;
  let common = first;
  for (const t of titles.slice(1)) {
    let n = 0;
    while (n < common.length && n < t.length && common[n] === t[n]) n++;
    common = common.slice(0, n);
  }
  if ((common.match(/\(/g) ?? []).length > (common.match(/\)/g) ?? []).length) {
    common = common.slice(0, Math.max(0, common.lastIndexOf("(")));
  }
  const colon = common.lastIndexOf(":");
  if (colon >= 0) common = common.slice(0, colon);
  const midWord = titles.some((t) => /[\p{L}\p{N}]/u.test(t.charAt(common.length)));
  if (midWord) common = common.slice(0, Math.max(0, common.lastIndexOf(" ")));
  const trimmed = common.replace(/[\s,\-—]+$/u, "");
  return [...trimmed].length >= 12 ? trimmed : first;
}

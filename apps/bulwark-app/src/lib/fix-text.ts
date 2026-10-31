/**
 * Rule `fix` text is written for people: a sentence or two of instructions with the exact commands
 * and config lines quoted in single quotes ("run 'sysctl --system'"). Typesetting the whole thing
 * as a shell line made prose look like something to paste into a terminal. This splits it so the
 * prose reads as prose and only the quoted parts become copyable code.
 */
export type FixSegment = { kind: "text"; value: string } | { kind: "code"; value: string };

// A quote opens after start/space/"(" and closes before end/space/punctuation, so apostrophes
// inside words ("didn't", "Docker's") are never mistaken for quotes.
const QUOTED = /(^|[\s(])'([^'\n]+?)'(?=$|[\s).,;:!?])/g;

export function splitFixText(text: string): FixSegment[] {
  const out: FixSegment[] = [];
  let last = 0;
  for (const m of text.matchAll(QUOTED)) {
    const start = (m.index ?? 0) + m[1].length;
    if (start > last) out.push({ kind: "text", value: text.slice(last, start) });
    out.push({ kind: "code", value: m[2] });
    last = start + m[2].length + 2;
  }
  if (last < text.length) out.push({ kind: "text", value: text.slice(last) });
  return out;
}

/** The app package installs its CLI as `bulwark` (the standalone CLI package's `bulwarkctl` would
 *  clash with it), and rule text is shared with that CLI package. Commands shown in the app use the
 *  name that exists wherever the app is installed. */
export function forThisInstall(text: string): string {
  return text.replace(/\bbulwarkctl\b/g, "bulwark");
}

/** A rule's title or text outside a finding, where `{{ collector.field }}` has no live value yet:
 *  shown as a readable placeholder (‹field›) rather than raw template syntax. */
export function withPlaceholders(text: string): string {
  return text.replace(/\{\{\s*\w+\.(\w+)\s*\}\}/g, (_, field: string) => `‹${field.replace(/_/g, " ")}›`);
}

const COMMAND_START =
  /^(sudo|chmod|chown|systemctl|ssh-keygen|ssh-add|git|gh|docker|aws|apt|dnf|pacman|ufw|sysctl|rm|mv|cp|echo|bulwark|bulwarkctl|clamscan|freshclam|passwd|usermod)\b/;

/** True when the whole fix is a single command rather than instructions (e.g. a remediation
 *  string that is just `sudo bulwark fim baseline --privileged`). */
export function isBareCommand(text: string): boolean {
  const t = text.trim();
  return COMMAND_START.test(t) && !/[.!?]\s+[A-Z]/.test(t) && !t.includes("'");
}

/** The fix's first sentence, without quoting marks: the one-line recommendation shown on a
 *  collapsed root-cause row. The full steps, with copyable commands, are one click away. */
export function recommendation(text: string): string {
  // Structured fixes put the goal on their first line; older ones are one paragraph.
  const firstLine = forThisInstall(text).trim().split("\n")[0] ?? "";
  const flat = firstLine.replace(/\s+/g, " ").trim();
  const first = flat.split(/(?<=[.!?])\s+(?=[A-Z(])/)[0] ?? flat;
  return first.replace(/(^|[\s(])'([^']+?)'(?=$|[\s).,;:!?])/g, "$1$2");
}

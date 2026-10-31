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

import { CommandBlock, CopyButton } from "@/components/ui/copy-button";
import { isBareCommand, splitFixText } from "@/lib/fix-text";
import { cn } from "@/lib/utils";

/** Plain text with each quoted command or config line as an inline code chip you can copy. */
function RichText({ text }: { text: string }) {
  return (
    <>
      {splitFixText(text).map((s, i) =>
        s.kind === "text" ? (
          <span key={i}>{s.value}</span>
        ) : (
          <span
            key={i}
            className="group/code inline-flex max-w-full items-center gap-0.5 rounded border border-border bg-card py-px pr-0.5 pl-1.5 align-baseline"
          >
            <code className="font-mono text-[12px] break-all">{s.value}</code>
            <CopyButton
              value={s.value}
              className="h-5 w-5 opacity-40 group-hover/code:opacity-100 focus-visible:opacity-100"
            />
          </span>
        ),
      )}
    </>
  );
}

/**
 * "What to do", typeset as what it is. Rules write it as a short goal, then numbered steps
 * ("1. …"), then an optional fallback line; each part keeps its line here. Older single-paragraph
 * fixes still render as one paragraph. A fix that is only a command keeps the terminal treatment.
 */
export function FixSteps({ text, className }: { text: string; className?: string }) {
  if (!text.trim()) return null;
  if (isBareCommand(text)) return <CommandBlock command={text.trim()} className={className} />;

  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const blocks: ({ kind: "p"; text: string } | { kind: "ol"; items: string[] })[] = [];
  for (const line of lines) {
    const step = line.match(/^\d+[.)]\s+(.*)$/);
    const last = blocks[blocks.length - 1];
    if (step) {
      if (last?.kind === "ol") last.items.push(step[1]);
      else blocks.push({ kind: "ol", items: [step[1]] });
    } else {
      blocks.push({ kind: "p", text: line });
    }
  }

  return (
    <div className={cn("rounded-md bg-muted/50 px-3 py-2.5", className)}>
      <div className="mb-1.5 text-[11px] font-medium text-muted-foreground">What to do</div>
      <div className="flex flex-col gap-2 text-sm leading-relaxed">
        {blocks.map((b, i) =>
          b.kind === "p" ? (
            <p key={i} className={i === 0 ? "font-medium" : undefined}>
              <RichText text={b.text} />
            </p>
          ) : (
            <ol key={i} className="ml-5 list-decimal space-y-1 marker:text-muted-foreground">
              {b.items.map((item, j) => (
                <li key={j}>
                  <RichText text={item} />
                </li>
              ))}
            </ol>
          ),
        )}
      </div>
    </div>
  );
}

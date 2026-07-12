import { useEffect, useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Every fix Bulwark suggests is a shell command, and until now the only way to act on one was
 * to retype it from the screen. Copying it is the actual next step in the workflow, so it gets
 * a button.
 */
export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(t);
  }, [copied]);

  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(value).then(
          () => setCopied(true),
          () => setCopied(false),
        );
      }}
      aria-label={copied ? "Copied" : "Copy command"}
      className={cn(
        "flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors",
        "hover:bg-background hover:text-foreground",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
        className,
      )}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5" style={{ color: "var(--sev-resolved-fg)" }} strokeWidth={2.5} />
      ) : (
        <Copy className="h-3.5 w-3.5" strokeWidth={2} />
      )}
    </button>
  );
}

/**
 * A shell command, presented as one. Bulwark's whole promise is "here is the fix" — so the fix
 * is typeset as a terminal line with a prompt glyph and a copy affordance, not as an anonymous
 * grey box of monospace text.
 */
export function CommandBlock({ command, className }: { command: string; className?: string }) {
  return (
    <div
      className={cn(
        "group/cmd flex items-start gap-2 rounded-md border border-border bg-muted/60 py-1.5 pr-1.5 pl-2.5",
        className,
      )}
    >
      <span
        aria-hidden
        className="mt-px font-mono text-xs leading-relaxed text-muted-foreground/70 select-none"
      >
        $
      </span>
      <code className="min-w-0 flex-1 font-mono text-xs leading-relaxed break-words">{command}</code>
      <CopyButton
        value={command}
        className="opacity-0 group-hover/cmd:opacity-100 focus-visible:opacity-100"
      />
    </div>
  );
}

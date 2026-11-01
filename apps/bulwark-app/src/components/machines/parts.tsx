import { useEffect, type ReactNode } from "react";
import { X } from "lucide-react";
import { HEALTH, type Health } from "@/lib/machines";
import { cn } from "@/lib/utils";

/** Renders `backtick` spans in a hint as inline code — the CLI and core write their next steps
 *  with commands in backticks, and a command should look like one. */
export function RichText({ text, className }: { text: string; className?: string }) {
  const parts = text.split("`");
  return (
    <span className={className}>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <code
            key={i}
            className="rounded bg-muted px-1 py-px font-mono text-[0.85em] text-foreground break-all"
          >
            {p}
          </code>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  );
}

/** A machine's state, in the severity palette. */
export function HealthPill({ health, scanning }: { health: Health; scanning?: boolean }) {
  if (scanning) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-muted px-2 py-0.5 text-[11px] font-semibold text-muted-foreground">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
        Scanning…
      </span>
    );
  }
  const { label, tone } = HEALTH[health];
  const style =
    tone === "muted"
      ? undefined
      : {
          background: `var(--sev-${tone}-tint)`,
          color: `var(--sev-${tone}-fg)`,
          boxShadow: `inset 0 0 0 1px color-mix(in oklch, var(--sev-${tone}) var(--sev-ring, 30%), transparent)`,
        };
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[11px] font-semibold",
        tone === "muted" && "bg-muted text-muted-foreground",
      )}
      style={style}
    >
      {label}
    </span>
  );
}

/** A minimal accessible modal: overlay, Escape to close, focus stays inside the panel. */
export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-6 pt-[8vh] backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          "w-full rounded-xl border border-border bg-card shadow-xl",
          wide ? "max-w-2xl" : "max-w-lg",
        )}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
          <h2 className="font-heading text-base font-semibold">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && (
          <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>
        )}
      </div>
    </div>
  );
}

/** Label + control + help, the form row used across the machine and alert settings. */
export function Field({
  label,
  help,
  children,
  htmlFor,
}: {
  label: string;
  help?: ReactNode;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-sm font-medium">
        {label}
      </label>
      {children}
      {help && <p className="text-xs leading-relaxed text-muted-foreground">{help}</p>}
    </div>
  );
}

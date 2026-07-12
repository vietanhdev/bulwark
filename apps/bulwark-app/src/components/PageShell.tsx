import type { ReactNode } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface PageShellProps {
  title: string;
  /** One line under the title. Say what the page is for, not what it contains. */
  description?: ReactNode;
  /** Primary action for this page, pinned to the header (e.g. Overview's "Run a scan"). */
  action?: ReactNode;
  children: ReactNode;
  /** Escape hatch for pages that need to be wider than the default reading measure. */
  className?: string;
}

/**
 * The frame every view sits in. Previously each of the seven views rolled its own header and
 * picked its own width — `max-w-3xl` through `max-w-6xl` plus one page with no cap at all —
 * so the content column visibly jumped as you moved through the sidebar, and Monitoring
 * forgot its ScrollArea entirely, making its content unreachable on a short window (<main> is
 * `overflow-hidden`). One shell, so a new view cannot forget either.
 *
 * The header is sticky: with 57 rules or a long findings list, the page's own title and its
 * primary action shouldn't scroll away from the content they belong to.
 */
export function PageShell({ title, description, action, children, className }: PageShellProps) {
  return (
    <ScrollArea className="h-full">
      <div className="sticky top-0 z-10 border-b border-border bg-background/85 backdrop-blur-sm">
        <div className={cn("mx-auto flex max-w-5xl items-start gap-6 px-8 py-5", className)}>
          <div className="min-w-0 flex-1">
            <h1 className="font-heading text-xl font-semibold leading-none tracking-tight">{title}</h1>
            {description && (
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">{description}</p>
            )}
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </div>
      </div>
      <div className={cn("mx-auto max-w-5xl px-8 pb-12 pt-6", className)}>{children}</div>
    </ScrollArea>
  );
}

/** Small caps section marker. Used to break a page into named regions without another card. */
export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <h2
      className={cn(
        "mb-3 font-mono text-[11px] font-semibold uppercase tracking-widest text-muted-foreground",
        className,
      )}
    >
      {children}
    </h2>
  );
}

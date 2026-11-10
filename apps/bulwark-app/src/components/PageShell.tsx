import { WorkbenchIcon } from "./WorkbenchIcon";
import type { ReactNode } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { createElement } from "react";
import { pageIconFor } from "@/components/tool-meta";

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
/** Top-level pages, each already named by its tab in the task bar. */
const TASK_PAGES = new Set(["Scan", "Secrets", "Tools", "Settings"]);

export function PageShell({ title, description, action, children, className }: PageShellProps) {
  return (
    <ScrollArea className="h-full">
      {/* Solid on purpose: WebKitGTK (the engine the desktop app runs on) doesn't always render
          backdrop-filter — with compositing off it can't — and with a translucent background the
          content scrolled underneath ghosted through the page title. */}
      <div className="sticky top-0 z-10 border-b border-border/60 bg-background">
        <div className={cn("mx-auto flex max-w-5xl flex-wrap items-center gap-3 px-6 py-4", className)}>
          <div className="min-w-0 flex-1">
            {/* The main pages are named by their selected tab right above, so a visible title and
                icon here only repeated it. They keep the heading for screen readers and lead with
                the description; tool pages, reached from Tools, still show their title. */}
            {TASK_PAGES.has(title) ? (
              <h1 className="sr-only">{title}</h1>
            ) : (
              <h1 className="flex items-center gap-2 font-heading text-lg font-semibold leading-tight tracking-[-0.035em]">
                {/* Tool pages and Settings carry their own icon; Scan, Secrets and Tools keep their task marks. */}
                {pageIconFor(title) ? (
                  <PageIcon title={title} className="size-5 shrink-0 text-muted-foreground" />
                ) : (
                  <WorkbenchIcon
                    kind={title === "Secrets" ? "sessions" : title === "Scan" ? "scan" : "tools"}
                    decorative
                    className="size-5 shrink-0 text-muted-foreground"
                  />
                )}
                {title}
              </h1>
            )}
            {description && (
              <p
                className={cn(
                  "max-w-2xl leading-relaxed text-muted-foreground",
                  TASK_PAGES.has(title) ? "text-sm" : "mt-1 text-xs",
                )}
              >
                {description}
              </p>
            )}
          </div>
          {action && (
            <div className="flex shrink-0 items-center gap-2 [&_[data-slot=button]]:h-8 [&_[data-slot=button]]:px-3">
              {action}
            </div>
          )}
        </div>
      </div>
      <div className={cn("mx-auto max-w-5xl px-6 pb-7 pt-4", className)}>{children}</div>
    </ScrollArea>
  );
}

/** Small caps section marker. Used to break a page into named regions without another card. */
export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <h2 className={cn("mb-3 text-xs font-semibold tracking-wide text-muted-foreground", className)}>
      {children}
    </h2>
  );
}

/** Built with createElement: the icon is looked up from the page title, not declared in render. */
function PageIcon({ title, className }: { title: string; className?: string }) {
  const icon = pageIconFor(title);
  return icon ? createElement(icon, { className, "aria-hidden": true }) : null;
}

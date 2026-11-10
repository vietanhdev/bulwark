import { ChevronRight } from "lucide-react";
import { PageShell } from "@/components/PageShell";
import { type View } from "@/components/Sidebar";
import { toolGroups } from "@/components/tool-meta";

export function ToolsView({ onNavigate }: { onNavigate: (view: View) => void }) {
  return (
    <PageShell title="Tools" description="A few deeper tools, when you need them.">
      <div className="space-y-5">
        {toolGroups.map((group) => (
          <section key={group.label} aria-label={group.label}>
            <h2 className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {group.label}
            </h2>
            <div className="grid gap-2 md:grid-cols-3">
              {group.tools.map(({ id, title, detail, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => onNavigate(id)}
                  aria-label={title}
                  className="group flex h-full w-full items-center gap-3 rounded-lg border border-border bg-card px-3.5 py-3 text-left transition-colors hover:border-primary/40 hover:bg-muted/40 focus-visible:outline-2 focus-visible:outline-primary"
                >
                  <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground transition-colors group-hover:text-primary">
                    <Icon className="size-4" aria-hidden="true" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium">{title}</span>
                    <span className="mt-0.5 block text-xs leading-snug text-muted-foreground">{detail}</span>
                  </span>
                  <ChevronRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
      <p className="mt-5 text-xs text-muted-foreground">
        Existing schedules and background tools keep their saved settings.
      </p>
    </PageShell>
  );
}

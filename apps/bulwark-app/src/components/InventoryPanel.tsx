import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CommandBlock } from "@/components/ui/copy-button";
import { TaskActivity } from "@/components/TaskActivity";
import { expiryText } from "@/lib/access-metadata";
import { STORAGE, type InventoryItem, type InventoryState } from "@/lib/inventory";
import { type SecretManager } from "@/lib/secret-managers";
import { cn } from "@/lib/utils";

export function StorageBadge({ storage, expired }: { storage: InventoryItem["storage"]; expired?: boolean }) {
  // A session past its expiry holds nothing usable: say so instead of looking like a live one.
  const { label, tone } = expired
    ? { label: "Expired", tone: "bg-muted text-muted-foreground" }
    : STORAGE[storage];
  return (
    <span className={cn("inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs", tone)}>
      {label}
    </span>
  );
}

/** Rows of stored credentials: names, where each lives and expiry, never values. */
export function InventoryTable({
  caption,
  rows,
}: {
  caption: string;
  /** observedAt: when that row's inventory was read; expiry is relative to it. */
  rows: { item: InventoryItem; manager?: string; observedAt: number }[];
}) {
  const withManager = rows.some((r) => r.manager);
  return (
    <table className="w-full table-fixed text-left text-sm">
      <caption className="sr-only">{caption}</caption>
      <thead className="text-[11px] uppercase tracking-wide text-muted-foreground">
        <tr>
          <th className="px-4 py-2 font-medium">Name</th>
          {withManager && <th className="hidden w-32 px-3 py-2 font-medium sm:table-cell">Manager</th>}
          <th className="w-28 px-3 py-2 font-medium">Stored</th>
          <th className="hidden w-60 px-4 py-2 font-medium md:table-cell">Details</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(({ item, manager, observedAt }, index) => {
          const expiry = item.expires_at ? expiryText(item.expires_at, observedAt) : null;
          const expired =
            item.storage === "session" && !!item.expires_at && Date.parse(item.expires_at) <= observedAt;
          return (
            <tr
              key={`${manager ?? ""}:${item.kind}:${item.name}:${index}`}
              className="border-t border-border"
            >
              <th scope="row" className="px-4 py-2 font-medium [overflow-wrap:anywhere]">
                {item.name}
                <span className="block text-xs font-normal text-muted-foreground md:hidden">
                  {[manager, item.detail, expiry].filter(Boolean).join(" · ")}
                </span>
              </th>
              {withManager && (
                <td className="hidden px-3 py-2 text-xs text-muted-foreground sm:table-cell">{manager}</td>
              )}
              <td className="px-3 py-2">
                <StorageBadge storage={item.storage} expired={expired} />
              </td>
              <td className="hidden px-4 py-2 text-xs text-muted-foreground md:table-cell">
                {item.detail}
                {expiry && <span className="block">{expiry}</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** One file-based manager's tab. The page owns reading; this only presents the state. */
/** Plain-text entries are a Scan finding with a fix; this takes the user there. */
export function ReviewInScan({ count, onReview }: { count: number; onReview?: () => void }) {
  if (count === 0) return null;
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-border bg-[var(--sev-medium-tint)] px-4 py-2 text-xs text-[var(--sev-medium-fg)]">
      {count} {count === 1 ? "entry is" : "entries are"} kept in plain text.
      {onReview && (
        <button
          type="button"
          onClick={onReview}
          className="rounded font-medium underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-primary"
        >
          Review in Scan
        </button>
      )}
    </p>
  );
}

export function InventoryPanel({
  manager,
  state,
  onRefresh,
  onReview,
}: {
  manager: SecretManager;
  state: InventoryState | undefined;
  onRefresh: () => void;
  onReview?: () => void;
}) {
  const busy = !state || state.status === "loading";
  const inventory = state?.status === "ok" ? state.inventory : null;
  return (
    <section
      aria-label={`${manager.name} inventory`}
      className="overflow-hidden rounded-lg border border-border bg-card"
    >
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-4 py-2.5">
        <p className="text-xs text-muted-foreground">
          {inventory
            ? `${inventory.items.length} ${inventory.items.length === 1 ? "entry" : "entries"} · read from ${inventory.sources.join(", ")}`
            : manager.shows}
        </p>
        <Button size="sm" variant="outline" className="ml-auto" onClick={onRefresh} disabled={busy}>
          <RefreshCw className="size-3.5" aria-hidden="true" />
          {busy ? "Reading…" : "Refresh"}
        </Button>
      </header>
      {busy && (
        <div className="p-4">
          <TaskActivity task="inventory" />
        </div>
      )}
      {state?.status === "unavailable" && (
        <div className="space-y-2 p-4 text-sm">
          <p>{state.message}</p>
          <p className="text-xs text-muted-foreground">{manager.install.text}</p>
          <CommandBlock command={manager.install.command} />
          <p className="text-xs text-muted-foreground">
            Bulwark only copies this command; it never installs software.
          </p>
        </div>
      )}
      {state?.status === "error" && (
        <p role="alert" className="m-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
          {state.message}
        </p>
      )}
      {inventory && inventory.items.length === 0 && (
        <p className="px-4 py-8 text-center text-sm text-muted-foreground">No stored credentials found.</p>
      )}
      {inventory && (
        <ReviewInScan
          count={inventory.items.filter((i) => i.storage === "plaintext").length}
          onReview={onReview}
        />
      )}
      {inventory && inventory.items.length > 0 && (
        <InventoryTable
          caption={`${manager.name} stored credentials`}
          rows={inventory.items.map((item) => ({ item, observedAt: Date.parse(inventory.observed_at) }))}
        />
      )}
    </section>
  );
}

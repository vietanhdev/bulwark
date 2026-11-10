import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, Plus, RefreshCw, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageShell } from "@/components/PageShell";
import { AwsVaultPanel } from "@/components/AwsVaultPanel";
import { InventoryPanel, InventoryTable, ReviewInScan } from "@/components/InventoryPanel";
import { type View } from "@/components/Sidebar";
import { PASSIVE, readInventory, type InventoryState } from "@/lib/inventory";
import { SECRET_MANAGERS, hasSavedChoice, loadAdded, managerById, saveAdded } from "@/lib/secret-managers";
import { cn } from "@/lib/utils";

const MARKET = "market";
const ALL = "inventory";

/**
 * Secrets is a manager of secrets managers: add the ones you use from the market and each becomes
 * a tab showing what it holds. Checks about how credentials are stored live in Scan; this page is
 * the inventory. File-based managers are read automatically when the page first opens and when
 * one is added (they only parse the tool's own files); AWS Vault runs a program, so it is read only
 * from its own tab.
 */
export function SecretsView({ active, onNavigate }: { active: boolean; onNavigate?: (view: View) => void }) {
  const [saved, setAdded] = useState<string[]>(loadAdded);
  const [tab, setTab] = useState<string>(() => (loadAdded().length ? ALL : MARKET));
  const [present, setPresent] = useState<Record<string, boolean>>({});
  const [states, setStates] = useState<Record<string, InventoryState>>({});
  const wasActive = useRef(false);

  // File-based managers are read automatically: nothing runs, and values are skipped. A refresh
  // keeps the previous result on screen until the new one arrives, so the table never blinks.
  const read = useCallback(async (ids: string[]) => {
    const passive = ids.filter((id) => PASSIVE.has(id));
    setStates((s) => ({
      ...s,
      ...Object.fromEntries(
        passive.filter((id) => s[id]?.status !== "ok").map((id) => [id, { status: "loading" } as const]),
      ),
    }));
    const results = await Promise.all(passive.map(async (id) => [id, await readInventory(id)] as const));
    setStates((s) => ({ ...s, ...Object.fromEntries(results) }));
  }, []);

  // Read again every time Secrets is opened, so the inventory reflects files changed meanwhile.
  useEffect(() => {
    if (active && !wasActive.current) void read(loadAdded());
    wasActive.current = active;
  }, [active, read]);

  useEffect(() => {
    // File existence only — no tool is run and no file is read.
    invoke<{ id: string; present: boolean }[]>("secrets_detect")
      .then((rows) => {
        setPresent(Object.fromEntries(rows.map((r) => [r.id, r.present])));
        // First run: nothing chosen yet, so start with every manager found on this computer.
        if (!hasSavedChoice()) {
          const found = SECRET_MANAGERS.map((m) => m.id).filter((id) =>
            rows.some((r) => r.id === id && r.present),
          );
          setAdded(found);
          saveAdded(found);
          if (found.length) {
            setTab(ALL);
            void read(found);
          }
        }
      })
      .catch(() => setPresent({}));
  }, [read]);

  // AWS Vault is a preview the backend offers only when it is switched on. When it is not, the
  // manager is neither listed nor shown, even if a tab for it was saved earlier.
  const offered = (id: string) => id !== "aws-vault" || "aws-vault" in present;
  const added = saved.filter(offered);

  const update = (next: string[]) => {
    setAdded(next);
    saveAdded(next);
  };
  const add = (id: string) => {
    if (!saved.includes(id)) {
      update([...saved, id]);
      void read([id]);
    }
    setTab(id);
  };
  const remove = (id: string) => {
    const next = saved.filter((a) => a !== id);
    update(next);
    setTab(next.filter(offered).length ? ALL : MARKET);
  };

  const rank = (id: string) => (added.includes(id) ? 2 : present[id] ? 0 : 1);

  const tabs = [
    ...(added.length ? [{ id: ALL, label: "Inventory" }] : []),
    ...added.map((id) => ({ id, label: managerById(id)!.name })),
    { id: MARKET, label: "Add" },
  ];
  const passiveAdded = added.filter((id) => PASSIVE.has(id));
  const rows = passiveAdded.flatMap((id) => {
    const st = states[id];
    return st?.status === "ok"
      ? st.inventory.items.map((item) => ({
          item,
          manager: managerById(id)!.name,
          observedAt: Date.parse(st.inventory.observed_at),
        }))
      : [];
  });
  const loading = passiveAdded.some((id) => !states[id] || states[id].status === "loading");
  const plaintext = rows.filter((r) => r.item.storage === "plaintext").length;
  const notFound = passiveAdded.filter(
    (id) => states[id]?.status === "unavailable" || states[id]?.status === "error",
  );

  return (
    <PageShell title="Secrets" description="Your secrets managers, and what each one holds.">
      <div
        role="tablist"
        aria-label="Secrets managers"
        className="mb-4 flex flex-wrap items-end gap-1 border-b border-border"
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={tab === t.id}
            aria-controls={`secrets-panel-${t.id}`}
            onClick={() => setTab(t.id)}
            className={cn(
              "-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-primary",
              tab === t.id
                ? "border-primary font-medium text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.id === MARKET && <Plus className="size-3.5" aria-hidden="true" />}
            {t.id === MARKET ? (added.length ? "Add" : "Add a secrets manager") : t.label}
          </button>
        ))}
      </div>

      <div id={`secrets-panel-${ALL}`} role="tabpanel" hidden={tab !== ALL} aria-label="Inventory">
        <section className="overflow-hidden rounded-lg border border-border bg-card">
          <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-4 py-2.5">
            <p className="text-xs text-muted-foreground">
              {loading
                ? "Reading your tools' files…"
                : `${rows.length} stored ${rows.length === 1 ? "credential" : "credentials"} across ${passiveAdded.length - notFound.length} ${passiveAdded.length - notFound.length === 1 ? "manager" : "managers"}`}
            </p>
            <Button
              size="sm"
              variant="outline"
              className="ml-auto"
              onClick={() => void read(added)}
              disabled={loading}
            >
              <RefreshCw className="size-3.5" aria-hidden="true" />
              {loading ? "Reading…" : "Refresh"}
            </Button>
          </header>
          {!loading && (
            <ReviewInScan count={plaintext} onReview={onNavigate && (() => onNavigate("overview"))} />
          )}
          {rows.length > 0 ? (
            <InventoryTable caption="Stored credentials across your secrets managers" rows={rows} />
          ) : (
            !loading && (
              <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                No stored credentials found in the added managers.
              </p>
            )
          )}
          {!loading && (notFound.length > 0 || added.includes("aws-vault")) && (
            <p className="border-t border-border px-4 py-2 text-xs text-muted-foreground">
              {notFound.length > 0 &&
                `Not found on this computer: ${notFound.map((id) => managerById(id)!.name).join(", ")}. `}
              {added.includes("aws-vault") && "AWS Vault is read when you open its tab."}
            </p>
          )}
        </section>
        <p className="mt-2 text-xs text-muted-foreground">
          Names and where each credential lives — values are never read. Scan checks how they are stored.
        </p>
      </div>

      {added.map((id) => {
        const manager = managerById(id)!;
        return (
          <div
            key={id}
            id={`secrets-panel-${id}`}
            role="tabpanel"
            hidden={tab !== id}
            aria-label={manager.name}
          >
            {id === "aws-vault" ? (
              <AwsVaultPanel active={active && tab === id} />
            ) : (
              <InventoryPanel
                manager={manager}
                state={states[id]}
                onRefresh={() => void read([id])}
                onReview={onNavigate && (() => onNavigate("overview"))}
              />
            )}
            <div className="mt-3 flex justify-end">
              <Button variant="ghost" size="sm" onClick={() => remove(id)}>
                <X className="size-3.5" aria-hidden="true" />
                Remove {manager.name} from Secrets
              </Button>
            </div>
          </div>
        );
      })}

      <div
        id={`secrets-panel-${MARKET}`}
        role="tabpanel"
        hidden={tab !== MARKET}
        aria-label="Add a secrets manager"
      >
        <p className="mb-3 text-sm text-muted-foreground">
          Add the tools you use. Each one becomes a tab that lists what it stores and where — names only,
          never values. Adding a tab installs nothing.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {/* Most useful first: found here and not added yet, then not found, then already added. */}
          {SECRET_MANAGERS.filter((m) => offered(m.id))
            .sort((a, b) => rank(a.id) - rank(b.id))
            .map((m) => {
              const isAdded = added.includes(m.id);
              return (
                <div
                  key={m.id}
                  className="flex items-center gap-3 rounded-lg border border-border bg-card px-3.5 py-3"
                >
                  <div className="min-w-0 flex-1">
                    <h3 className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium">
                      {m.name}
                      {m.id in present && (
                        <span
                          className={cn(
                            "whitespace-nowrap rounded-full px-1.5 py-px text-[10px] font-normal",
                            present[m.id] ? "bg-primary/12 text-primary" : "bg-muted text-muted-foreground",
                          )}
                        >
                          {present[m.id] ? "On this computer" : "Not found"}
                        </span>
                      )}
                    </h3>
                    <p className="mt-0.5 text-xs leading-snug text-muted-foreground">{m.shows}</p>
                  </div>
                  {isAdded ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setTab(m.id)}
                      aria-label={`Open ${m.name}`}
                    >
                      <Check className="size-3.5" aria-hidden="true" />
                      Added
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant={present[m.id] ? "default" : "outline"}
                      onClick={() => add(m.id)}
                      aria-label={`Add ${m.name}`}
                    >
                      <Plus className="size-3.5" aria-hidden="true" />
                      Add
                    </Button>
                  )}
                </div>
              );
            })}
        </div>
      </div>
    </PageShell>
  );
}

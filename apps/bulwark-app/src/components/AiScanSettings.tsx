import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { X } from "lucide-react";
import { Callout } from "@/components/ui/callout";
import { Switch } from "@/components/ui/switch";
import { PathDropZone } from "@/components/PathDropZone";
import { SectionLabel } from "@/components/PageShell";

interface AiSettings {
  configured_roots: string[];
  excluded_roots: string[];
  auto_scan_enabled: boolean;
}

/**
 * Settings for the AI assistant part of a scan: which extra folders to look in, which to skip, and
 * whether to re-check in the background. The scan itself runs from Home's "Scan now" with
 * everything else; only its configuration lives here.
 */
export function AiScanSettings({ active }: { active: boolean }) {
  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<AiSettings>("ai_settings_get")
      .then(setSettings)
      .catch((e) => setError(String(e)));
  }, []);

  async function update(patch: Partial<AiSettings>) {
    try {
      setSettings(
        await invoke<AiSettings>("ai_settings_set", {
          configuredRoots: patch.configured_roots,
          excludedRoots: patch.excluded_roots,
          autoScanEnabled: patch.auto_scan_enabled,
        }),
      );
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section>
      <SectionLabel>AI assistant checks</SectionLabel>
      {error && (
        <Callout tone="critical" className="mb-2">
          {error}
        </Callout>
      )}
      {settings && (
        <div className="flex flex-col gap-4 rounded-lg border border-border bg-card p-4">
          <p className="text-xs text-muted-foreground">
            Checkups also check your AI coding assistants (Claude Code, Cursor, Copilot, Codex and more) for
            API keys pasted into sessions and memory, and for settings a prompt injection could abuse.
          </p>
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-medium">Check again in the background</div>
              <div className="text-xs text-muted-foreground">
                Re-checks periodically and notifies you when a new secret or risky setting appears.
              </div>
            </div>
            <Switch
              checked={settings.auto_scan_enabled}
              onCheckedChange={(v) => update({ auto_scan_enabled: v })}
              aria-label="Check AI assistants again in the background"
            />
          </div>

          <div>
            <div className="mb-1.5 text-sm font-medium">Extra folders to check</div>
            <p className="mb-2 text-xs text-muted-foreground">
              Bulwark already looks in the usual code folders (~/Workspaces, ~/Projects, ~/src, …) and every
              project your assistants have opened. Add a folder here if your code lives somewhere else.
            </p>
            {settings.configured_roots.length > 0 && (
              <PathChips
                paths={settings.configured_roots}
                onRemove={(p) =>
                  update({ configured_roots: settings.configured_roots.filter((x) => x !== p) })
                }
              />
            )}
            <PathDropZone
              active={active}
              mode="folders-only"
              label="Drop a folder here to also check it"
              className="mt-2"
              onPaths={(paths) =>
                update({ configured_roots: Array.from(new Set([...settings.configured_roots, ...paths])) })
              }
            />
          </div>

          <div>
            <div className="mb-1.5 text-sm font-medium">Folders to skip</div>
            {settings.excluded_roots.length > 0 && (
              <PathChips
                paths={settings.excluded_roots}
                onRemove={(p) => update({ excluded_roots: settings.excluded_roots.filter((x) => x !== p) })}
              />
            )}
            <PathDropZone
              active={active}
              mode="folders-only"
              label="Drop a folder here to skip it"
              className="mt-2"
              onPaths={(paths) =>
                update({ excluded_roots: Array.from(new Set([...settings.excluded_roots, ...paths])) })
              }
            />
          </div>
        </div>
      )}
    </section>
  );
}

function PathChips({ paths, onRemove }: { paths: string[]; onRemove: (path: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {paths.map((p) => (
        <span
          key={p}
          title={p}
          className="flex items-center gap-1 rounded-full border border-border bg-muted/50 py-0.5 pr-1 pl-2.5 text-xs"
        >
          <span className="max-w-48 truncate font-mono">{p}</span>
          <button
            type="button"
            onClick={() => onRemove(p)}
            aria-label={`Remove ${p}`}
            className="rounded-full p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
    </div>
  );
}

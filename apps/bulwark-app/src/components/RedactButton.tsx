import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Eraser, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";

interface RedactionReport {
  dry_run: boolean;
  entries: { path: string; secrets_redacted: number; applied: boolean }[];
  total_secrets: number;
  errors: string[];
}

/**
 * "Remove secret from this file" for an AI assistant finding Bulwark is allowed to rewrite (a session
 * transcript or memory note inside an agent folder). Preview first, then apply: nothing is written
 * until the user confirms, the original is backed up, and the backend refuses any file the last scan
 * did not flag as redactable.
 */
export function RedactButton({ file, onDone }: { file: string; onDone?: () => void }) {
  const [preview, setPreview] = useState<RedactionReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(apply: boolean) {
    setBusy(true);
    setError(null);
    try {
      const report = await invoke<RedactionReport>("ai_redact", { paths: [file], apply });
      if (apply) {
        setDone(true);
        setPreview(null);
        onDone?.();
      } else {
        setPreview(report);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <span className="text-xs text-muted-foreground">
        Removed. The original is backed up; rotate the key with its provider.
      </span>
    );
  }

  const count = preview?.total_secrets ?? 0;
  return (
    <div className="flex w-full basis-full flex-col gap-2">
      {error && <Callout tone="critical">{error}</Callout>}
      {preview === null ? (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Button size="sm" variant="outline" onClick={() => run(false)} disabled={busy}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eraser className="h-3.5 w-3.5" />}
            Remove secret from this file
          </Button>
          <span className="text-[11px] text-muted-foreground">
            You'll see what changes first. The original is backed up.
          </span>
        </div>
      ) : (
        <div className="rounded-md border border-border bg-muted/40 p-3">
          <p className="text-xs font-medium">
            {count === 0
              ? "Nothing left to remove in this file."
              : `${count} secret${count === 1 ? "" : "s"} will be replaced with a placeholder. Nothing has been written yet.`}
          </p>
          {preview.errors.length > 0 && (
            <ul className="mt-1.5 space-y-0.5 text-[11px] text-[var(--sev-critical-fg)]">
              {preview.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            Removing it from disk can't un-leak it, so rotate the key with its provider either way.
          </p>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            {count > 0 && (
              <Button size="sm" onClick={() => run(true)} disabled={busy}>
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eraser className="h-3.5 w-3.5" />}
                Remove {count} secret{count === 1 ? "" : "s"}
              </Button>
            )}
            <Button size="sm" variant="ghost" onClick={() => setPreview(null)} disabled={busy}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

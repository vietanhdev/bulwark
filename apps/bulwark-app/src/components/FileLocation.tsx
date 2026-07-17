import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, Copy, ExternalLink } from "lucide-react";

/**
 * The file a finding flagged, with a way to go look at it. Many findings are heuristics — "this
 * file contains a phrase associated with prompt injection, confirm by reading line N" — so the
 * useful next action is to open that exact file and read the line yourself. "Copy path" works
 * everywhere (webview clipboard, no backend); "Open" hands the path to the OS default app via the
 * `open_flagged_file` command (opener plugin). Shared by the Agent Security view and the aggregated
 * Overview/Compliance finding cards so a flagged file reads and behaves identically wherever you
 * meet it.
 */
export function FileLocation({ file, line }: { file: string; line: number | null }) {
  const loc = line ? `${file}:${line}` : file;
  const [copied, setCopied] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);

  async function copyPath() {
    try {
      await navigator.clipboard.writeText(file);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setOpenError("couldn't copy to clipboard");
    }
  }

  async function openFile() {
    setOpenError(null);
    try {
      await invoke("open_flagged_file", { path: file, reveal: false });
    } catch (e) {
      setOpenError(String(e));
    }
  }

  const btn =
    "inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary";

  return (
    <div className="mt-1">
      <div className="flex items-center gap-1.5">
        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground" title={loc}>
          {loc}
        </span>
        <button
          type="button"
          onClick={copyPath}
          title="Copy file path"
          aria-label="Copy file path"
          className={btn}
        >
          {copied ? (
            <Check className="h-3 w-3 text-[var(--sev-resolved-fg)]" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
          {copied ? "Copied" : "Copy path"}
        </button>
        <button
          type="button"
          onClick={openFile}
          title="Open the file in your default app to read the flagged line"
          aria-label="Open file"
          className={btn}
        >
          <ExternalLink className="h-3 w-3" />
          Open
        </button>
      </div>
      {openError && <p className="mt-1 text-[10px] text-[var(--sev-high-fg)]">{openError}</p>}
    </div>
  );
}

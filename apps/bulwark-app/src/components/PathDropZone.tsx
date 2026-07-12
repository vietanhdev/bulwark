import { useEffect, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderInput, UploadCloud } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface PathDropZoneProps {
  /** Whether this zone's tab is the one currently visible. `ThreatsView` stays mounted (just
   * hidden) when the user switches tabs (see App.tsx), so without this a drag-drop listener
   * registered here would otherwise still fire while the user is looking at a different tab. */
  active: boolean;
  mode: "files-and-folders" | "folders-only";
  label: string;
  onPaths: (paths: string[]) => void;
  className?: string;
}

/** Drag-and-drop zone + native "Browse…" picker, shared between the manual scan's custom-path
 * picker and real-time protection's watched-folder picker — only the accepted selection kind
 * (files+folders vs. folders-only) and the resulting callback differ between the two uses.
 *
 * Tauri's drag-drop event is **window-global**, not per-element: every mounted zone's listener
 * fires for a drop anywhere in the window, with no DOM target to disambiguate them. So each
 * zone hit-tests the drop's own coordinates against its own bounding box and ignores drops
 * that landed outside it. Without that, dropping a folder onto *either* zone on the Antivirus
 * tab would land in *both* — adding it as a watched folder and queueing it as a manual scan
 * target at the same time. */
export function PathDropZone({ active, mode, label, onPaths, className }: PathDropZoneProps) {
  const zoneRef = useRef<HTMLDivElement>(null);
  const [dragOver, setDragOver] = useState(false);

  const activeRef = useRef(active);
  const onPathsRef = useRef(onPaths);
  useEffect(() => {
    activeRef.current = active;
    onPathsRef.current = onPaths;
  });

  useEffect(() => {
    // Tauri reports the pointer in physical device pixels; getBoundingClientRect is in CSS
    // pixels. On any HiDPI display (devicePixelRatio !== 1) comparing them directly would put
    // every drop at the wrong place — typically far past the zone, so nothing would ever hit.
    const containsPointer = (position: { x: number; y: number }) => {
      const rect = zoneRef.current?.getBoundingClientRect();
      if (!rect) return false;
      const dpr = window.devicePixelRatio || 1;
      const x = position.x / dpr;
      const y = position.y / dpr;
      return x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
    };

    const unlistenPromise = getCurrentWebview().onDragDropEvent((event) => {
      if (!activeRef.current) return;
      const payload = event.payload;

      if (payload.type === "over") {
        setDragOver(containsPointer(payload.position));
        return;
      }
      if (payload.type === "leave") {
        setDragOver(false);
        return;
      }
      if (payload.type === "drop") {
        setDragOver(false);
        if (!containsPointer(payload.position)) return;
        onPathsRef.current(payload.paths);
      }
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  async function browse() {
    const selection = await open({
      multiple: true,
      directory: mode === "folders-only",
    });
    if (!selection) return;
    onPaths(Array.isArray(selection) ? selection : [selection]);
  }

  const Icon = mode === "folders-only" ? FolderInput : UploadCloud;

  return (
    <div
      ref={zoneRef}
      className={cn(
        "flex items-center justify-between gap-3 rounded-lg border border-dashed px-3 py-2.5 text-sm transition-colors",
        dragOver
          ? "border-primary bg-primary/10 text-foreground"
          : "border-border bg-muted/20 text-muted-foreground",
        className,
      )}
    >
      <div className="flex min-w-0 items-center gap-2">
        <Icon className={cn("h-4 w-4 shrink-0", dragOver && "text-primary")} />
        <span className="truncate">{dragOver ? "Release to add" : label}</span>
      </div>
      <Button type="button" variant="outline" size="sm" onClick={browse}>
        Browse…
      </Button>
    </div>
  );
}

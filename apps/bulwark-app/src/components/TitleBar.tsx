import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import logo from "@/assets/logo.svg";

const appWindow = getCurrentWindow();

export function TitleBar() {
  // Native apps dim their chrome when the window loses focus — a small detail, but its
  // absence is one of the fastest tells that a frameless window was built without looking
  // at how the platform's own apps behave.
  const [focused, setFocused] = useState(true);

  useEffect(() => {
    const unlistenPromise = appWindow.onFocusChanged(({ payload }) => setFocused(payload));
    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  return (
    <div
      className={cn(
        "flex h-10 shrink-0 items-center justify-between border-b border-border bg-sidebar pl-3 pr-1.5 transition-opacity duration-200",
        !focused && "opacity-70",
      )}
    >
      {/* `data-tauri-drag-region` is Tauri's own cross-platform drag mechanism — the
          CSS `-webkit-app-region: drag` property it might look like you'd reach for
          instead is a Blink/Chromium extension that WebKitGTK (Tauri's Linux backend)
          doesn't honor, so it silently does nothing there. This spacer is deliberately
          separate from the button group below so drag-to-move and button clicks don't
          fight over the same mousedown. */}
      {/* `data-tauri-drag-region` only activates for the exact element the mousedown
          lands on, not its children by default — so it has to be repeated on the image
          and text too, or clicking directly on the logo/title (most of this area) would
          silently do nothing. */}
      <div data-tauri-drag-region className="flex h-full flex-1 items-center gap-2">
        <img data-tauri-drag-region src={logo} alt="" className="h-4 w-4" />
        <span data-tauri-drag-region className="text-sm font-medium text-sidebar-foreground">
          Bulwark
        </span>
      </div>
      <div className="flex items-center gap-0.5">
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          onClick={() => appWindow.minimize()}
          aria-label="Minimize"
        >
          <Minus className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          onClick={() => appWindow.toggleMaximize()}
          aria-label="Maximize"
        >
          <Square className="h-3 w-3" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-muted-foreground hover:bg-destructive hover:text-destructive-foreground"
          onClick={() => appWindow.close()}
          aria-label="Close"
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

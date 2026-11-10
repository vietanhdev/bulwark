import { useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";
import { ShieldMark } from "@/components/ShieldMark";
import { cn } from "@/lib/utils";
import { usePlatform } from "@/lib/platform";

const appWindow = getCurrentWindow();

export function TitleBar() {
  // macOS keeps its own traffic lights (tauri.macos.conf.json overlays them on this bar), so the
  // bar leaves room for them on the left and draws no buttons of its own; Windows and Linux get
  // the custom controls on the right, where both platforms put them.
  const mac = usePlatform() === "macos";
  // Native apps dim their chrome when the window loses focus. Its absence is one of the
  // fastest tells that a frameless window was built without looking at how the platform's own
  // apps behave.

  useEffect(() => {
    const update = (value: boolean) => {
      document.documentElement.toggleAttribute("data-window-inactive", !value);
    };
    const unlistenPromise = appWindow.onFocusChanged(({ payload }) => update(payload));
    appWindow.isFocused().then(update);
    return () => {
      document.documentElement.removeAttribute("data-window-inactive");
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  return (
    <div
      className={cn(
        // A native title bar shows the arrow pointer and never selects its text; without this,
        // WebKitGTK shows a text I-beam over the wordmark and a drag can start a selection.
        "workbench-chrome flex h-9 shrink-0 cursor-default select-none items-center justify-between border-b border-ink-border bg-ink pr-1.5 transition-opacity duration-200",
        mac ? "pl-[78px]" : "pl-5",
      )}
    >
      {/* `data-tauri-drag-region` is Tauri's own cross-platform drag mechanism — the CSS
          `-webkit-app-region: drag` property you might reach for instead is a Blink extension
          that WebKitGTK (Tauri's Linux backend) doesn't honor, so it silently does nothing
          there. It also only activates for the exact element the mousedown lands on, not its
          children, so it has to be repeated on the mark and the wordmark too — otherwise
          clicking directly on them (most of this area) would fail to drag the window. */}
      <div data-tauri-drag-region className="flex h-full flex-1 items-center gap-2">
        <ShieldMark data-tauri-drag-region className="h-4 w-4 text-primary" />
        <span
          data-tauri-drag-region
          className="font-heading text-sm font-semibold tracking-tight text-ink-fg"
        >
          Bulwark
        </span>
        <span data-tauri-drag-region className="text-[11px] text-ink-muted">
          / developer tools
        </span>
      </div>
      {!mac && <WindowControls />}
    </div>
  );
}

function WindowControls() {
  return (
    <div className="flex items-center gap-0.5">
      <WindowButton onClick={() => appWindow.minimize()} label="Minimize">
        <Minus className="h-3.5 w-3.5" />
      </WindowButton>
      <WindowButton onClick={() => appWindow.toggleMaximize()} label="Maximize">
        <Square className="h-3 w-3" />
      </WindowButton>
      <WindowButton onClick={() => appWindow.close()} label="Close" danger>
        <X className="h-3.5 w-3.5" />
      </WindowButton>
    </div>
  );
}

/* Not the shared <Button>: these sit on ink in both themes, so they need --ink-* foregrounds
   rather than --foreground, which inverts under them in light mode. */
function WindowButton({
  onClick,
  label,
  danger,
  children,
}: {
  onClick: () => void;
  label: string;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      className={cn(
        "flex h-7 w-7 items-center justify-center rounded-md text-ink-muted transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary",
        danger
          ? "hover:bg-destructive hover:text-destructive-foreground"
          : "hover:bg-ink-raised hover:text-ink-fg",
      )}
    >
      {children}
    </button>
  );
}

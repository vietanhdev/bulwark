import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";
import { ShieldMark } from "@/components/ShieldMark";
import { cn } from "@/lib/utils";

const appWindow = getCurrentWindow();

export function TitleBar() {
  // Native apps dim their chrome when the window loses focus. Its absence is one of the
  // fastest tells that a frameless window was built without looking at how the platform's own
  // apps behave.
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
        "flex h-10 shrink-0 items-center justify-between border-b border-ink-border bg-ink pr-1.5 pl-3 transition-opacity duration-200",
        !focused && "opacity-60",
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
          className="font-heading text-[13px] font-semibold tracking-tight text-ink-fg"
        >
          Bulwark
        </span>
      </div>
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

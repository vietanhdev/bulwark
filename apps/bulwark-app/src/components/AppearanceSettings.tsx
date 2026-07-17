import { useState } from "react";
import { Check, Monitor, Moon, Sun } from "lucide-react";
import {
  ACCENTS,
  CHROMES,
  getStoredAccent,
  getStoredChrome,
  getStoredTheme,
  setAccent,
  setChrome,
  setTheme,
  type Accent,
  type Chrome,
  type ThemeMode,
} from "@/lib/theme";
import { cn } from "@/lib/utils";

const MODES: { id: ThemeMode; label: string; icon: typeof Sun }[] = [
  { id: "light", label: "Light", icon: Sun },
  { id: "dark", label: "Dark", icon: Moon },
  { id: "system", label: "System", icon: Monitor },
];

/**
 * Light/dark/system mode and the accent colour, mirroring how Ubuntu itself lets you pick an
 * accent. Changes apply instantly (the whole UI recolours from CSS variables) and persist across
 * launches; "System" follows the OS setting live.
 */
export function AppearanceSettings() {
  const [mode, setMode] = useState<ThemeMode>(getStoredTheme);
  const [accent, setAccentState] = useState<Accent>(getStoredAccent);
  const [chrome, setChromeState] = useState<Chrome>(getStoredChrome);

  function pickMode(m: ThemeMode) {
    setMode(m);
    setTheme(m);
  }
  function pickAccent(a: Accent) {
    setAccentState(a);
    setAccent(a);
  }
  function pickChrome(c: Chrome) {
    setChromeState(c);
    setChrome(c);
  }

  return (
    <div className="flex flex-col gap-5 rounded-lg border border-border bg-card p-4">
      <div>
        <div className="text-sm font-medium">Theme</div>
        <div className="mt-2 inline-flex rounded-lg border border-border bg-muted/50 p-0.5">
          {MODES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => pickMode(id)}
              aria-pressed={mode === id}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                mode === id
                  ? "bg-card text-foreground shadow-[var(--shadow-1)]"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <div className="text-sm font-medium">Accent colour</div>
        <div className="mt-2 flex flex-wrap gap-2.5">
          {ACCENTS.map(({ id, label, swatch }) => (
            <button
              key={id}
              type="button"
              onClick={() => pickAccent(id)}
              title={label}
              aria-label={`${label} accent`}
              aria-pressed={accent === id}
              className={cn(
                "flex h-8 w-8 items-center justify-center rounded-full transition-transform hover:scale-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                accent === id && "ring-2 ring-ring ring-offset-2 ring-offset-card",
              )}
              style={{ background: swatch }}
            >
              {accent === id && <Check className="h-4 w-4 text-white drop-shadow" strokeWidth={3} />}
            </button>
          ))}
        </div>
      </div>

      <div>
        <div className="text-sm font-medium">Sidebar colour</div>
        <div className="mt-0.5 text-xs text-muted-foreground">
          The dark rail down the left and the title bar.
        </div>
        <div className="mt-2 flex flex-wrap gap-2.5">
          {CHROMES.map(({ id, label, swatch }) => (
            <button
              key={id}
              type="button"
              onClick={() => pickChrome(id)}
              title={label}
              aria-label={`${label} sidebar`}
              aria-pressed={chrome === id}
              className={cn(
                "flex h-8 w-8 items-center justify-center rounded-full transition-transform hover:scale-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
                chrome === id && "ring-2 ring-ring ring-offset-2 ring-offset-card",
              )}
              style={{ background: swatch }}
            >
              {chrome === id && <Check className="h-4 w-4 text-white drop-shadow" strokeWidth={3} />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

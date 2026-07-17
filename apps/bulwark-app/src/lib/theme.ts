/**
 * Appearance: light/dark/system mode + a Yaru-style accent colour, both persisted locally and
 * applied to <html>. Kept as plain DOM + localStorage (no framework state) so it can run *before*
 * React mounts — `initTheme()` is called from main.tsx ahead of render, which avoids the
 * light-then-dark flash a component-mounted effect would cause.
 */

export type ThemeMode = "light" | "dark" | "system";
export type Accent = "orange" | "aqua" | "blue" | "green" | "pink" | "aubergine" | "red" | "yellow";
export type Chrome = "aubergine" | "teal" | "blue" | "green" | "indigo" | "graphite";

/** Accent metadata for the picker — label + a representative swatch colour (its light-mode primary). */
export const ACCENTS: { id: Accent; label: string; swatch: string }[] = [
  { id: "orange", label: "Orange", swatch: "oklch(0.646 0.19 41)" },
  { id: "aqua", label: "Aqua", swatch: "oklch(0.54 0.09 195)" },
  { id: "blue", label: "Blue", swatch: "oklch(0.55 0.16 258)" },
  { id: "green", label: "Green", swatch: "oklch(0.53 0.15 150)" },
  { id: "yellow", label: "Yellow", swatch: "oklch(0.8 0.15 82)" },
  { id: "red", label: "Red", swatch: "oklch(0.54 0.2 27)" },
  { id: "pink", label: "Pink", swatch: "oklch(0.57 0.19 330)" },
  { id: "aubergine", label: "Aubergine", swatch: "oklch(0.42 0.15 342)" },
];

/** Chrome (sidebar + titlebar) colour options. The swatch is the light-mode `--ink` tint. */
export const CHROMES: { id: Chrome; label: string; swatch: string }[] = [
  { id: "aubergine", label: "Aubergine", swatch: "oklch(0.22 0.07 350)" },
  { id: "teal", label: "Teal", swatch: "oklch(0.22 0.055 195)" },
  { id: "blue", label: "Blue", swatch: "oklch(0.23 0.06 258)" },
  { id: "green", label: "Green", swatch: "oklch(0.23 0.055 150)" },
  { id: "indigo", label: "Indigo", swatch: "oklch(0.23 0.07 290)" },
  { id: "graphite", label: "Graphite", swatch: "oklch(0.24 0.006 260)" },
];

const THEME_KEY = "bulwark-theme";
const ACCENT_KEY = "bulwark-accent";
const CHROME_KEY = "bulwark-chrome";

const prefersDark = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;

export function getStoredTheme(): ThemeMode {
  const v = localStorage.getItem(THEME_KEY);
  return v === "light" || v === "dark" || v === "system" ? v : "system";
}

export function getStoredAccent(): Accent {
  const v = localStorage.getItem(ACCENT_KEY) as Accent | null;
  return v && ACCENTS.some((a) => a.id === v) ? v : "orange";
}

export function getStoredChrome(): Chrome {
  const v = localStorage.getItem(CHROME_KEY) as Chrome | null;
  return v && CHROMES.some((c) => c.id === v) ? v : "aubergine";
}

/** Whether the given mode resolves to a dark appearance right now. */
export function isDark(mode: ThemeMode): boolean {
  return mode === "dark" || (mode === "system" && prefersDark());
}

export function applyTheme(mode: ThemeMode): void {
  document.documentElement.classList.toggle("dark", isDark(mode));
}

export function applyAccent(accent: Accent): void {
  // Orange is the default already baked into :root/.dark, so it needs no attribute.
  if (accent === "orange") delete document.documentElement.dataset.accent;
  else document.documentElement.dataset.accent = accent;
}

export function applyChrome(chrome: Chrome): void {
  // Aubergine is the default in :root/.dark, so it needs no attribute.
  if (chrome === "aubergine") delete document.documentElement.dataset.chrome;
  else document.documentElement.dataset.chrome = chrome;
}

export function setTheme(mode: ThemeMode): void {
  localStorage.setItem(THEME_KEY, mode);
  applyTheme(mode);
}

export function setAccent(accent: Accent): void {
  localStorage.setItem(ACCENT_KEY, accent);
  applyAccent(accent);
}

export function setChrome(chrome: Chrome): void {
  localStorage.setItem(CHROME_KEY, chrome);
  applyChrome(chrome);
}

/** Call once, before React renders. Applies stored prefs and keeps "system" in sync with the OS. */
export function initTheme(): void {
  applyTheme(getStoredTheme());
  applyAccent(getStoredAccent());
  applyChrome(getStoredChrome());
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (getStoredTheme() === "system") applyTheme("system");
  });
}

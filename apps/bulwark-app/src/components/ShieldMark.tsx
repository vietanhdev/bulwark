import type { SVGProps } from "react";

/**
 * Inlined from src/assets/logo.svg (rather than referenced as an `<img>`) so its fill can be
 * driven by `currentColor` — the same shield silhouette that is the app's logo doubles as its
 * status indicator, instead of a generic lucide shield standing in for it.
 *
 * Spreads props so callers can pass `data-tauri-drag-region` (the title bar needs the mark
 * itself to be draggable) and aria attributes.
 */
export function ShieldMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden {...props}>
      <path d="M50 4 L91 19 V49 C91 73 73 90 50 97 C27 90 9 73 9 49 V19 Z" fill="currentColor" />
    </svg>
  );
}

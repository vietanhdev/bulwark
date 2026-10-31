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
      <path
        d="M12 8 H28 V19 H40 V8 H60 V19 H72 V8 H88 V48 C88 70 72 86 50 94 C28 86 12 70 12 48 Z"
        fill="currentColor"
        stroke="currentColor"
        strokeWidth={4}
        strokeLinejoin="round"
      />
    </svg>
  );
}

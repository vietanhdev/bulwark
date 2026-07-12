/// Inlined from src/assets/logo.svg (not referenced as an <img>) so its fill can be driven
/// by `currentColor` — the same shield silhouette that's the app's own logo doubles as the
/// status indicator, rather than a generic lucide shield icon standing in for it.
export function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M50 4 L91 19 V49 C91 73 73 90 50 97 C27 90 9 73 9 49 V19 Z"
        fill="currentColor"
      />
    </svg>
  );
}

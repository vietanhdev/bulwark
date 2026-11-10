/** One optical grid for the workbench. Static when idle; only real tasks pass busy, which animates the task mark. */
export function WorkbenchIcon({
  kind,
  decorative: _decorative = false,
  busy = false,
  className = "size-4",
}: {
  kind: "scan" | "sessions" | "tools";
  decorative?: boolean;
  busy?: boolean;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {kind === "scan" ? (
        <>
          <path d="M8 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-3M8 4h8v3H8z" />
          <path d="m8 11 1 1 2-2m2 1h3m-8 5h3" />
          <path className={busy ? "task-mark" : undefined} d="M14 16h2" />
        </>
      ) : kind === "sessions" ? (
        <>
          <rect x="3.5" y="5" width="17" height="14" rx="3" />
          <circle cx="9" cy="12" r="2.5" />
          <path d="M11.5 12H18m-2 0v2" />
          <path className={busy ? "task-mark" : undefined} d="M6.5 16h3" />
        </>
      ) : (
        <>
          <path d="M4 8V5a1 1 0 0 1 1-1h3m8 0h3a1 1 0 0 1 1 1v3M4 16v3a1 1 0 0 0 1 1h3m8 0h3a1 1 0 0 0 1-1v-3m-12-7 3 3-3 3" />
          <path d="M14 15h3" />
        </>
      )}
    </svg>
  );
}

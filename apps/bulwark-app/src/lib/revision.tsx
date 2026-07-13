import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

/**
 * A monotonic "the host's stored state changed" counter, and the fix for a real bug.
 *
 * App.tsx keeps every view mounted once it has been visited (see the `visited` set there) so
 * that switching tabs mid-scan doesn't unmount the component and throw away an in-flight
 * scan's progress. That fix is correct, but it silently broke every view that loads its data
 * in a `useEffect(..., [])`: History, Compliance and Antivirus each fetched once, on first
 * mount, and then never again for the life of the process. Run a scan on the Overview, click
 * History, and you'd be looking at whatever was true the first time you opened that tab.
 *
 * Rather than have each view invent its own refresh (a `useEffect` on an `active` prop, a
 * listener per view, a manual reload button), everything that mutates stored state bumps this
 * counter once, and any view that reads stored state lists `revision` in its effect deps. New
 * views get the behaviour by default instead of having to remember to re-solve it.
 */
/** The individual scanners the Overview can drive. Each maps to a tab that should reflect the
 * scan's in-progress status and its results, so a run kicked off from the Overview looks live on
 * the corresponding tab too — the Overview is only a launcher, not the sole place results appear. */
export type ScannerId = "compliance" | "antivirus" | "agent" | "fim";

interface Revision {
  /** Bumped whenever a scan, a monitoring tick, or a baseline changes what's on disk. */
  revision: number;
  bump: () => void;
  /** Scanners currently running (from anywhere — Overview's "run all" or a tab's own button). A tab
   * reads this so it shows "scanning…" even when the run was triggered from the Overview. */
  running: ReadonlySet<ScannerId>;
  /** Marks a scanner as started/finished. Overview brackets each pass with this; tabs may too. */
  setScannerRunning: (id: ScannerId, isRunning: boolean) => void;
}

const RevisionContext = createContext<Revision>({
  revision: 0,
  bump: () => {},
  running: new Set(),
  setScannerRunning: () => {},
});

export function RevisionProvider({ children }: { children: ReactNode }) {
  const [revision, setRevision] = useState(0);
  const bump = useCallback(() => setRevision((n) => n + 1), []);
  const [running, setRunning] = useState<ReadonlySet<ScannerId>>(new Set());
  const setScannerRunning = useCallback((id: ScannerId, isRunning: boolean) => {
    setRunning((prev) => {
      const next = new Set(prev);
      if (isRunning) next.add(id);
      else next.delete(id);
      return next;
    });
  }, []);
  const value = useMemo(
    () => ({ revision, bump, running, setScannerRunning }),
    [revision, bump, running, setScannerRunning],
  );
  return <RevisionContext.Provider value={value}>{children}</RevisionContext.Provider>;
}

export function useRevision(): Revision {
  return useContext(RevisionContext);
}

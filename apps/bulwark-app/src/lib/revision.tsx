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
interface Revision {
  /** Bumped whenever a scan, a monitoring tick, or a baseline changes what's on disk. */
  revision: number;
  bump: () => void;
}

const RevisionContext = createContext<Revision>({ revision: 0, bump: () => {} });

export function RevisionProvider({ children }: { children: ReactNode }) {
  const [revision, setRevision] = useState(0);
  const bump = useCallback(() => setRevision((n) => n + 1), []);
  const value = useMemo(() => ({ revision, bump }), [revision, bump]);
  return <RevisionContext.Provider value={value}>{children}</RevisionContext.Provider>;
}

export function useRevision(): Revision {
  return useContext(RevisionContext);
}

import {
  FileClock,
  History,
  ListChecks,
  ScanLine,
  Server,
  Settings,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";

/** One source for each tool's name, purpose and icon: the Tools landing lists them, and the
 *  page shell uses the same icon in the tool's own header, so the two can never disagree. */
export const toolGroups = [
  {
    label: "This computer",
    tools: [
      {
        id: "compliance",
        title: "Configuration",
        detail: "Inspect the configuration rule pack without running agent checks.",
        icon: SlidersHorizontal,
      },
      {
        id: "integrity",
        title: "File changes",
        detail: "Record a baseline and inspect changed system files.",
        icon: FileClock,
      },
      {
        id: "antivirus",
        title: "Malware scan",
        detail: "Scan files with your local ClamAV installation.",
        icon: ScanLine,
      },
    ],
  },
  {
    label: "More",
    tools: [
      { id: "machines", title: "Remote hosts", detail: "Check another machine over SSH.", icon: Server },
      {
        id: "rules",
        title: "Rule catalog",
        detail: "Browse checks, explanations and framework mappings.",
        icon: ListChecks,
      },
      {
        id: "analytics",
        title: "History",
        detail: "Review previous runs and unresolved findings.",
        icon: History,
      },
    ],
  },
] as const;

const pageIcons: Record<string, LucideIcon> = Object.fromEntries([
  ...toolGroups.flatMap((g) => g.tools.map((t) => [t.title, t.icon] as const)),
  ["Settings", Settings] as const,
]);

/** The header icon for a page title; absent for Scan, Secrets and Tools, which use their own marks. */
export function pageIconFor(title: string): LucideIcon | undefined {
  return pageIcons[title];
}

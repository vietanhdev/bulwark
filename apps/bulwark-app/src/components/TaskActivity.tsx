import { WorkbenchIcon } from "./WorkbenchIcon";

/** One plain, stable line per task: rotating copy read as restless rather than informative. */
const phrases = {
  scan: "Checking your setup…",
  sessions: "Reading profile metadata…",
};

/** Mount only during real work. The progress mark is the single moving element. */
export function TaskActivity({
  task,
  phrase = true,
  className,
}: {
  task: keyof typeof phrases;
  active?: boolean;
  /** False when a nearby heading already says what is happening. */
  phrase?: boolean;
  className?: string;
}) {
  return (
    <div
      className={`task-activity flex items-center gap-3 ${className ?? ""}`}
      role="status"
      aria-live="polite"
    >
      <span className="sr-only">
        {task === "scan" ? "Scan in progress." : "Reading local AWS Vault metadata."}
      </span>
      <WorkbenchIcon
        kind={task === "scan" ? "scan" : "sessions"}
        busy
        className="size-7 shrink-0 text-primary"
      />
      {phrase && (
        <span className="activity-phrase text-sm text-muted-foreground" aria-hidden="true">
          {phrases[task]}
        </span>
      )}
    </div>
  );
}

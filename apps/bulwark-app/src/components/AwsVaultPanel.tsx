import { Fragment, useEffect, useId, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, ChevronRight, Copy, KeyRound, RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { TaskActivity } from "@/components/TaskActivity";
import {
  cacheStatus,
  expiryText,
  terminalCommand,
  type ProfileMetadata,
  type CacheStatus,
} from "@/lib/access-metadata";

interface Snapshot {
  schema_version: number;
  observed_at: string;
  profiles: ProfileMetadata[];
}
const labels: Record<CacheStatus, string> = {
  cached: "Cached · unverified",
  expired: "Expired",
  "no-cache": "No STS cache",
};

/** The AWS Vault tab of Secrets: profiles and cached-session metadata, read only on request. */
export function AwsVaultPanel({ active }: { active: boolean }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<CacheStatus | "all">("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const listId = useId();
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    const update = () => {
      clearInterval(timer);
      if (active && !document.hidden) {
        setNow(Date.now());
        timer = setInterval(() => setNow(Date.now()), 1000);
      }
    };
    update();
    document.addEventListener("visibilitychange", update);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", update);
    };
  }, [active]);

  async function refresh() {
    if (busy) return;
    setBusy(true);
    setError(null);
    setUnavailable(null);
    setSnapshot(null);
    setSelected(null);
    try {
      setSnapshot(await invoke<Snapshot>("access_aws_snapshot"));
      setNow(Date.now());
    } catch (e) {
      const failure = e as { code?: string; message?: string };
      if (failure?.code === "unavailable") setUnavailable(failure.message ?? "Local provider unavailable.");
      else
        setError(
          typeof failure?.message === "string"
            ? failure.message
            : typeof e === "string"
              ? e
              : "Could not read provider metadata. Retry or check setup in your terminal.",
        );
    } finally {
      setBusy(false);
    }
  }
  const profiles =
    snapshot?.profiles.filter(
      (p) =>
        p.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()) &&
        (filter === "all" || cacheStatus(p, now) === filter),
    ) ?? [];
  const counts = (snapshot?.profiles ?? []).reduce(
    (acc, p) => {
      acc[cacheStatus(p, now)] += 1;
      return acc;
    },
    { cached: 0, expired: 0, "no-cache": 0 } as Record<CacheStatus, number>,
  );
  const observedMs = snapshot ? Date.parse(snapshot.observed_at) : 0;
  const observedAge = !snapshot
    ? ""
    : observedMs > now + 60000
      ? "timestamp is in the future"
      : now - observedMs < 60000
        ? "just now"
        : `${Math.floor((now - observedMs) / 60000)} min old`;

  return (
    <div>
      {unavailable ? (
        <section
          aria-labelledby={`${listId}-missing`}
          className="result-reveal rounded-lg border border-[color:var(--sev-medium)]/40 bg-[var(--sev-medium-tint)] p-4 text-sm"
        >
          <h2
            id={`${listId}-missing`}
            className="flex items-center gap-2 font-medium text-[var(--sev-medium-fg)]"
          >
            <AlertTriangle className="size-4 shrink-0" aria-hidden="true" />
            AWS Vault not found
          </h2>
          <p className="mt-2 text-foreground">{unavailable}</p>
          <p className="mt-1 text-muted-foreground">
            Install the compatible build at that path, then choose{" "}
            <strong className="font-medium">Check connections</strong>.
          </p>
          <div className="mt-3">
            <Button size="sm" onClick={refresh} disabled={busy}>
              <RefreshCw className="size-3.5" aria-hidden="true" />
              {busy ? "Reading metadata…" : unavailable ? "Check connections" : "Refresh sessions"}
            </Button>
          </div>
        </section>
      ) : (
        <section
          aria-label="AWS Vault provider"
          className="overflow-hidden rounded-lg border border-border bg-card"
        >
          <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-4 py-2.5">
            <p className="text-xs text-muted-foreground">
              Cached metadata only; refresh does not sign you in.
            </p>
            <div className="ml-auto flex items-center gap-3">
              {snapshot && (
                <p
                  className="text-xs text-muted-foreground tabular-nums"
                  title={new Date(snapshot.observed_at).toLocaleString()}
                >
                  Observed {new Date(snapshot.observed_at).toLocaleTimeString()} · {observedAge}
                </p>
              )}
              <Button size="sm" onClick={refresh} disabled={busy}>
                <RefreshCw className="size-3.5" aria-hidden="true" />
                {busy ? "Reading metadata…" : unavailable ? "Check connections" : "Refresh sessions"}
              </Button>
            </div>
          </header>

          {error && (
            <p
              role="alert"
              className="m-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm"
            >
              {error}
            </p>
          )}

          {busy && (
            <div className="p-4">
              <TaskActivity task="sessions" active={active} />
            </div>
          )}

          {!snapshot && !busy && !error && (
            <div className="flex flex-col items-center px-6 py-10 text-center">
              <span className="flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <KeyRound className="size-5" aria-hidden="true" />
              </span>
              <p className="mt-3 text-sm font-medium">No profiles loaded yet</p>
              <p className="mt-1 max-w-sm text-xs leading-relaxed text-muted-foreground">
                Refresh sessions to see your local profiles.
              </p>
            </div>
          )}

          <p role="status" className="sr-only">
            {snapshot ? `${snapshot.profiles.length} profiles loaded.` : ""}
          </p>

          {snapshot && snapshot.profiles.length === 0 && (
            <p className="result-reveal px-4 py-8 text-center text-sm text-muted-foreground">
              No configured profiles or cache entries were found.
            </p>
          )}

          {snapshot && snapshot.profiles.length > 0 && (
            <>
              <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
                <label className="flex h-8 min-w-44 flex-1 items-center gap-2 rounded-md border border-input bg-background px-2.5 text-muted-foreground focus-within:outline-2 focus-within:outline-primary">
                  <Search className="size-3.5 shrink-0" aria-hidden="true" />
                  <span className="sr-only">Search profiles</span>
                  <input
                    type="search"
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setSelected(null);
                    }}
                    placeholder="Search profiles"
                    className="h-full min-w-0 w-full bg-transparent text-sm text-foreground outline-none"
                  />
                </label>
                <div role="radiogroup" aria-label="Cache status" className="flex flex-wrap gap-1">
                  {(
                    [
                      ["all", "All", snapshot.profiles.length],
                      ["cached", "Cached", counts.cached],
                      ["expired", "Expired", counts.expired],
                      ["no-cache", "No cache", counts["no-cache"]],
                    ] as const
                  ).map(([value, label, count]) => (
                    <button
                      key={value}
                      type="button"
                      role="radio"
                      aria-checked={filter === value}
                      aria-label={`${label} (${count})`}
                      onClick={() => {
                        setFilter(value);
                        setSelected(null);
                      }}
                      className={`flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs transition-colors focus-visible:outline-2 focus-visible:outline-primary ${
                        filter === value
                          ? "border-primary/50 bg-primary/10 text-foreground"
                          : "border-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <span aria-hidden="true">{label}</span>
                      <span aria-hidden="true" className="tabular-nums opacity-70">
                        {count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              {profiles.length === 0 ? (
                <div className="px-4 py-8 text-center text-sm">
                  <p>No profiles match your search or status filter.</p>
                  <button
                    className="mt-2 rounded text-primary underline focus-visible:outline-2"
                    onClick={() => {
                      setQuery("");
                      setFilter("all");
                      setSelected(null);
                    }}
                  >
                    Clear filters
                  </button>
                </div>
              ) : (
                <table className="result-reveal w-full table-fixed text-left text-sm">
                  <caption className="sr-only">AWS Vault profiles and unverified cached sessions</caption>
                  <thead className="text-[11px] uppercase tracking-wide text-muted-foreground">
                    <tr>
                      <th className="px-4 py-2 font-medium">Profile</th>
                      <th className="w-40 px-3 py-2 font-medium">Status</th>
                      <th className="hidden w-52 px-4 py-2 font-medium sm:table-cell">Expiry</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profiles.map((p, i) => {
                      const state = cacheStatus(p, now);
                      const open = selected === p.name;
                      const id = `${listId}-${i}`;
                      const future = p.sessions
                        .filter((s) => Date.parse(s.expires_at) > now)
                        .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));
                      const latest = [...p.sessions].sort(
                        (a, b) => Date.parse(b.expires_at) - Date.parse(a.expires_at),
                      )[0];
                      const expired = p.sessions.length - future.length;
                      const expiry =
                        (future[0]
                          ? expiryText(future[0].expires_at, now)
                          : latest
                            ? expiryText(latest.expires_at, now)
                            : p.oidc_cache_present
                              ? "SSO expiry unknown"
                              : "No session timestamps") +
                        (future.length > 0 && expired > 0 ? ` · ${expired} expired` : "");
                      return (
                        <Fragment key={p.name}>
                          <tr
                            className={`border-t border-border hover:bg-muted/40 ${open ? "bg-muted/30" : ""}`}
                          >
                            <th scope="row" className="px-4 py-2 align-middle font-medium">
                              <button
                                aria-expanded={open}
                                aria-controls={id}
                                onClick={() => setSelected(open ? null : p.name)}
                                className="flex w-full items-center gap-2 rounded py-0.5 text-left focus-visible:outline-2 focus-visible:outline-primary"
                              >
                                <ChevronRight
                                  className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
                                  aria-hidden="true"
                                />
                                <span className="min-w-0 break-words [overflow-wrap:anywhere]">{p.name}</span>
                              </button>
                            </th>
                            <td className="px-3 py-2 align-middle">
                              <StatusBadge state={state} />
                            </td>
                            <td className="hidden px-4 py-2 align-middle text-xs text-muted-foreground sm:table-cell">
                              {expiry}
                            </td>
                          </tr>
                          {open && (
                            <tr>
                              <td colSpan={3} className="border-t border-border bg-background/60 px-4 py-4">
                                <div id={id}>
                                  <p className="mb-3 text-xs text-muted-foreground sm:hidden">{expiry}</p>
                                  <ProfileDetails profile={p} now={now} />
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              )}
              <p className="border-t border-border px-4 py-2 text-xs text-muted-foreground">
                {profiles.length} of {snapshot.profiles.length} profiles
              </p>
            </>
          )}
        </section>
      )}

      <details className="credential-disclosure mt-4 text-xs leading-relaxed text-muted-foreground">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded py-1.5 focus-visible:outline-2 focus-visible:outline-primary">
          <ChevronRight className="disclosure-chevron size-3.5" aria-hidden="true" />
          <span className="font-medium text-foreground">About session status</span>
          <span className="ml-auto">
            {busy
              ? "Reading metadata"
              : unavailable
                ? "Provider unavailable"
                : error
                  ? "Metadata read failed"
                  : snapshot
                    ? "Metadata available"
                    : "Not checked"}
          </span>
        </summary>
        <div className="max-w-2xl pl-5">
          <p className="mt-2">
            Cached STS sessions and SSO cache entries do not confirm that you are signed in. Running shells
            and sessions created outside AWS Vault are not tracked here. Refresh reads profile names and cache
            metadata only; it does not unlock a password manager or reveal credentials.
          </p>
          <p className="mt-2">
            References can point to a local store or an external password manager; their presence does not
            confirm authentication. Clearing a local cache does not revoke credentials already issued by AWS.
          </p>
        </div>
        <dl className="mt-3 grid max-w-2xl grid-cols-[auto_1fr] gap-x-4 gap-y-2 pb-1 pl-5 leading-relaxed">
          <dt>AWS Vault</dt>
          <dd>
            {unavailable
              ? "Not found at the expected path; see the setup note above."
              : snapshot
                ? `Local metadata returned ${new Date(snapshot.observed_at).toLocaleString()}. Authentication not checked.`
                : "A compatible local AWS Vault build is required. Refresh reads metadata; availability is not assumed."}
          </dd>
          <dt>Configuration</dt>
          <dd>
            {snapshot
              ? `${snapshot.profiles.filter((p) => p.configured).length} profiles reported as configured in this snapshot.`
              : "Profile configuration has not been read."}{" "}
            Configure providers and authenticate in your own terminal.
          </dd>
          <dt>Inspection coverage</dt>
          <dd>
            {snapshot
              ? "Read: profile names, credential references, STS timestamps and SSO cache presence."
              : "No current provider metadata inspected."}{" "}
            Secret values, authentication and external shell sessions are not inspected. This is a
            point-in-time snapshot; refresh to detect configuration changes.
          </dd>
          <dt>Other stores</dt>
          <dd>
            Availability and authentication not checked. A credential reference does not identify or verify a
            connected store. No browsing, unlocking or synchronization controls are provided here.
          </dd>
        </dl>
      </details>
    </div>
  );
}

function StatusBadge({ state }: { state: CacheStatus }) {
  const tone =
    state === "cached"
      ? "bg-primary/12 text-primary"
      : state === "expired"
        ? "bg-[var(--sev-medium-tint)] text-[var(--sev-medium-fg)]"
        : "bg-muted text-muted-foreground";
  const dot =
    state === "cached"
      ? "bg-primary"
      : state === "expired"
        ? "bg-[var(--sev-medium)]"
        : "bg-muted-foreground/60";
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs ${tone}`}
    >
      <span className={`size-1.5 rounded-full ${dot}`} aria-hidden="true" />
      {labels[state]}
    </span>
  );
}

function ProfileDetails({ profile: p, now }: { profile: ProfileMetadata; now: number }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const command = terminalCommand(p.name);
  async function copy() {
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }
  return (
    <section aria-label={`Details for ${p.name}`} className="space-y-4 text-xs">
      <div className="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <dl className="grid h-fit grid-cols-[auto_1fr] gap-x-4 gap-y-2">
          <dt className="text-muted-foreground">Configuration</dt>
          <dd>{p.configured ? "In AWS config" : "Not in AWS config"}</dd>
          <dt className="text-muted-foreground">Credential reference</dt>
          <dd>
            {p.credential_reference
              ? "Present · source and authentication not verified"
              : "No credential reference"}
          </dd>
          <dt className="text-muted-foreground">SSO cache</dt>
          <dd>{p.oidc_cache_present ? "SSO cache present · expiry unknown" : "No SSO cache reported"}</dd>
        </dl>
        <div>
          <h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Cached sessions
          </h3>
          {p.sessions.length > 0 ? (
            <ul className="divide-y divide-border rounded-md border border-border">
              {p.sessions.map((s, i) => (
                <li key={i} className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1 px-3 py-2">
                  <span className="min-w-0">
                    <span className="font-mono">{s.type}</span>
                    <span className="block text-muted-foreground">
                      {s.selected_store ? "Selected session store" : "Outside the selected session store"}
                    </span>
                  </span>
                  <span className="text-right text-muted-foreground tabular-nums">
                    <span className={Date.parse(s.expires_at) > now ? "text-foreground" : undefined}>
                      {expiryText(s.expires_at, now)}
                    </span>
                    <time dateTime={s.expires_at} className="block">
                      {new Date(s.expires_at).toLocaleString()}
                    </time>
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground">No cached STS session</p>
          )}
        </div>
      </div>
      {!command && (
        <p className="text-muted-foreground">
          No terminal command is offered for this profile: its name has characters that different shells read
          differently. In your own terminal, type <code className="font-mono">aws-vault exec --</code>{" "}
          followed by the profile name.
        </p>
      )}
      <div hidden={!command}>
        <div className="flex flex-wrap items-center gap-2">
          <code
            className="min-w-0 flex-1 break-all rounded-md border border-border bg-background px-2.5 py-1.5 font-mono"
            aria-label="Terminal command"
          >
            {command}
          </code>
          <Button variant="outline" size="sm" onClick={copy}>
            <Copy className="size-3.5" aria-hidden="true" />
            Copy terminal command
          </Button>
        </div>
        <p className="mt-1.5 text-muted-foreground">
          Run in your own terminal to start AWS Vault’s default shell. Bulwark only copies this command; it
          never runs it. Authentication may be requested there.
        </p>
        <p role={copyState === "failed" ? "alert" : "status"} className="mt-1 empty:hidden">
          {copyState === "copied"
            ? "Command copied."
            : copyState === "failed"
              ? "Could not copy. Select the command above and copy it manually."
              : ""}
        </p>
      </div>
      <p className="text-muted-foreground">
        Cache timestamps are not AWS verification. Entries outside the selected store may not be used by the
        current provider; SSO expiry is unknown.
      </p>
    </section>
  );
}

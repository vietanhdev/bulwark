import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Loader2, Mail, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Field } from "@/components/machines/parts";
import { cn } from "@/lib/utils";

type Sev = "critical" | "high" | "medium" | "low" | "info";

interface NotifyConfig {
  telegram: { enabled: boolean; chat_id: string } | null;
  email: { enabled: boolean; smtp_url: string; username: string | null; from: string; to: string[] } | null;
  min_severity: Sev;
  events: {
    new_issues: boolean;
    unreachable: boolean;
    back_online: boolean;
    security: boolean;
    needs_attention: boolean;
  };
  include_this_computer: boolean;
  daily_report: boolean;
}

interface NotifyStatus {
  config: NotifyConfig;
  telegram_token_set: boolean;
  smtp_password_set: boolean;
  last_error: string | null;
  last_sent_at: string | null;
}

interface ChannelResult {
  channel: string;
  ok: boolean;
  error: string | null;
}

interface Chat {
  id: string;
  title: string;
  kind: string;
}

const EVENTS: { key: keyof NotifyConfig["events"]; label: string }[] = [
  { key: "new_issues", label: "New issues" },
  { key: "security", label: "A machine's identity or host key changed" },
  { key: "unreachable", label: "A machine stops answering (after 3 tries)" },
  { key: "back_online", label: "A machine is back online" },
  { key: "needs_attention", label: "A machine needs attention (e.g. its key was refused)" },
];

/**
 * Off-machine alerts: Telegram (your own bot) and e-mail (your own SMTP server).
 *
 * Opt-in by construction — nothing is set up until the user does it here — and honest about the one
 * thing that changes: alert text leaves this computer through Telegram's or the mail provider's
 * servers. Secrets are write-only from the page's point of view: it can set or clear the bot token
 * and SMTP password, never read them back.
 */
export function NotificationsSettings() {
  const [status, setStatus] = useState<NotifyStatus | null>(null);
  const [cfg, setCfg] = useState<NotifyConfig | null>(null);
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [toText, setToText] = useState("");
  const [chats, setChats] = useState<Chat[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ChannelResult[] | null>(null);
  const [saved, setSaved] = useState(false);

  const load = (s: NotifyStatus) => {
    setStatus(s);
    setCfg(s.config);
    setToText(s.config.email?.to.join(", ") ?? "");
  };

  useEffect(() => {
    invoke<NotifyStatus>("notify_status")
      .then(load)
      .catch((e) => setError(String(e)));
  }, []);

  if (!cfg || !status) return error ? <Callout tone="critical">{error}</Callout> : null;

  const tg = cfg.telegram ?? { enabled: false, chat_id: "" };
  const em = cfg.email ?? { enabled: false, smtp_url: "", username: null, from: "", to: [] };
  const update = (patch: Partial<NotifyConfig>) => {
    setSaved(false);
    setCfg({ ...cfg, ...patch });
  };

  async function run<T>(label: string, f: () => Promise<T>): Promise<T | undefined> {
    setBusy(label);
    setError(null);
    try {
      return await f();
    } catch (e) {
      setError(String(e));
      return undefined;
    } finally {
      setBusy(null);
    }
  }

  function configToSave(): NotifyConfig {
    const to = toText
      .split(/[,\s]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    return {
      ...cfg!,
      telegram: tg.enabled || tg.chat_id ? tg : null,
      email: em.enabled || em.smtp_url ? { ...em, to, username: em.username || null } : null,
    };
  }

  const save = () =>
    run("save", async () => {
      const s = await invoke<NotifyStatus>("notify_configure", {
        config: configToSave(),
        telegramBotToken: token ? token : null,
        smtpPassword: password ? password : null,
      });
      setToken("");
      setPassword("");
      load(s);
      setSaved(true);
      return s;
    });

  const findChats = () =>
    run("chats", async () => {
      const c = await invoke<Chat[]>("notify_telegram_chats", { token: token || null });
      setChats(c);
      if (c.length === 1) update({ telegram: { ...tg, chat_id: c[0].id } });
    });

  const test = () =>
    run("test", async () => {
      const s = await invoke<NotifyStatus>("notify_configure", {
        config: configToSave(),
        telegramBotToken: token ? token : null,
        smtpPassword: password ? password : null,
      });
      setToken("");
      setPassword("");
      load(s);
      const r = await invoke<ChannelResult[]>("notify_test");
      setResults(r);
      load(await invoke<NotifyStatus>("notify_status"));
    });

  const report = () =>
    run("report", async () => {
      const r = await invoke<ChannelResult[]>("notify_report");
      setResults(r);
    });

  const anyEnabled = tg.enabled || em.enabled;

  return (
    <div className="flex flex-col gap-5">
      <p className="text-sm leading-relaxed text-muted-foreground">
        Get told when something changes — new issues, a machine that stops answering, or one whose identity
        changed — even when Bulwark is in the tray. Alerts carry machine names and issue titles, never file
        contents or secrets, and they pass through Telegram's or your mail provider's servers.
      </p>

      {/* Telegram */}
      <section className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Send className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">Telegram</h3>
          </div>
          <Switch checked={tg.enabled} onCheckedChange={(v) => update({ telegram: { ...tg, enabled: v } })} />
        </div>
        {tg.enabled && (
          <>
            <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
              <li>
                In Telegram, open <span className="font-medium text-foreground">@BotFather</span>, send{" "}
                <code className="font-mono">/newbot</code>, and copy the token it gives you.
              </li>
              <li>Paste it below, then send your new bot any message.</li>
              <li>Choose “Find my chat”.</li>
            </ol>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Bot token"
                htmlFor="tg-token"
                help={
                  status.telegram_token_set ? "A token is saved. Paste a new one to replace it." : undefined
                }
              >
                <Input
                  id="tg-token"
                  type="password"
                  autoComplete="off"
                  placeholder={status.telegram_token_set ? "•••••••• saved" : "123456:ABC…"}
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
              </Field>
              <Field label="Chat" htmlFor="tg-chat">
                <div className="flex gap-2">
                  {chats && chats.length > 1 ? (
                    <Select
                      id="tg-chat"
                      value={tg.chat_id}
                      onChange={(e) => update({ telegram: { ...tg, chat_id: e.target.value } })}
                    >
                      <option value="">Choose a chat…</option>
                      {chats.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.title} ({c.kind})
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <Input
                      id="tg-chat"
                      placeholder="Chat id"
                      value={tg.chat_id}
                      onChange={(e) => update({ telegram: { ...tg, chat_id: e.target.value } })}
                    />
                  )}
                  <Button
                    variant="outline"
                    onClick={findChats}
                    disabled={busy !== null || (!token && !status.telegram_token_set)}
                  >
                    {busy === "chats" && <Loader2 className="animate-spin" />}
                    Find my chat
                  </Button>
                </div>
              </Field>
            </div>
            {chats && chats.length === 0 && (
              <Callout tone="info">
                No messages yet — send your bot any message in Telegram, then try again.
              </Callout>
            )}
          </>
        )}
      </section>

      {/* E-mail */}
      <section className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">E-mail</h3>
          </div>
          <Switch checked={em.enabled} onCheckedChange={(v) => update({ email: { ...em, enabled: v } })} />
        </div>
        {em.enabled && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label="SMTP server"
              htmlFor="em-url"
              help="smtps://… (TLS) or smtp://…:587 (STARTTLS, required). Unencrypted only to a relay on this computer."
            >
              <Input
                id="em-url"
                placeholder="smtps://smtp.gmail.com:465"
                value={em.smtp_url}
                onChange={(e) => update({ email: { ...em, smtp_url: e.target.value } })}
                spellCheck={false}
              />
            </Field>
            <Field label="From" htmlFor="em-from">
              <Input
                id="em-from"
                placeholder="bulwark@example.com"
                value={em.from}
                onChange={(e) => update({ email: { ...em, from: e.target.value } })}
              />
            </Field>
            <Field label="User name" htmlFor="em-user" help="Leave empty if the server doesn't need sign-in.">
              <Input
                id="em-user"
                autoComplete="off"
                value={em.username ?? ""}
                onChange={(e) => update({ email: { ...em, username: e.target.value } })}
              />
            </Field>
            <Field
              label="Password"
              htmlFor="em-pass"
              help="For Gmail and similar, use an app password, not your account password."
            >
              <Input
                id="em-pass"
                type="password"
                autoComplete="off"
                placeholder={status.smtp_password_set ? "•••••••• saved" : ""}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <div className="sm:col-span-2">
              <Field label="Send to" htmlFor="em-to" help="One or more addresses, separated by commas.">
                <Input
                  id="em-to"
                  placeholder="you@example.com"
                  value={toText}
                  onChange={(e) => {
                    setSaved(false);
                    setToText(e.target.value);
                  }}
                />
              </Field>
            </div>
          </div>
        )}
      </section>

      {/* What to send */}
      {anyEnabled && (
        <section className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
          <h3 className="text-sm font-semibold">What to send</h3>
          <div className="flex flex-col gap-2">
            {EVENTS.map((e) => (
              <label key={e.key} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="h-4 w-4 shrink-0 accent-primary"
                  checked={cfg.events[e.key]}
                  onChange={(ev) => update({ events: { ...cfg.events, [e.key]: ev.target.checked } })}
                />
                {e.label}
              </label>
            ))}
          </div>
          {!cfg.events.security && (
            <Callout tone="warning">
              A changed host key is how an intercepted connection shows up. Keeping this alert on is strongly
              recommended.
            </Callout>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="New issues at least" htmlFor="min-sev">
              <Select
                id="min-sev"
                value={cfg.min_severity}
                onChange={(e) => update({ min_severity: e.target.value as Sev })}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Everything</option>
              </Select>
            </Field>
          </div>
          <label className="flex items-center justify-between gap-3 text-sm">
            <span>Also alert about this computer</span>
            <Switch
              checked={cfg.include_this_computer}
              onCheckedChange={(v) => update({ include_this_computer: v })}
            />
          </label>
          <label className="flex items-center justify-between gap-3 text-sm">
            <span>
              Daily summary report{" "}
              <span className="text-muted-foreground">— every machine's state, once a day</span>
            </span>
            <Switch checked={cfg.daily_report} onCheckedChange={(v) => update({ daily_report: v })} />
          </label>
        </section>
      )}

      {error && <Callout tone="critical">{error}</Callout>}
      {status.last_error && !error && (
        <Callout tone="warning">Alerts couldn't be delivered last time: {status.last_error}</Callout>
      )}
      {results && (
        <div className="flex flex-col gap-1.5">
          {results.length === 0 && <Callout tone="info">No channel is turned on.</Callout>}
          {results.map((r) => (
            <Callout key={r.channel} tone={r.ok ? "success" : "critical"}>
              {r.channel === "telegram" ? "Telegram" : "E-mail"}:{" "}
              {r.ok ? "sent — check that it arrived." : r.error}
            </Callout>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={save} disabled={busy !== null}>
          {busy === "save" && <Loader2 className="animate-spin" />}
          Save
        </Button>
        <Button variant="outline" onClick={test} disabled={busy !== null || !anyEnabled}>
          {busy === "test" && <Loader2 className="animate-spin" />}
          Send a test
        </Button>
        <Button variant="ghost" onClick={report} disabled={busy !== null || !anyEnabled}>
          {busy === "report" && <Loader2 className="animate-spin" />}
          Send a report now
        </Button>
        <span className={cn("text-sm text-muted-foreground", !saved && "hidden")}>Saved.</span>
        {status.last_sent_at && (
          <span className="text-xs text-muted-foreground">
            Last delivered {new Date(status.last_sent_at).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

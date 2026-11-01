import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ChevronDown, ChevronRight, Loader2, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ConnectionCheck } from "@/components/machines/ConnectionCheck";
import { Field, Modal } from "@/components/machines/parts";
import { defaultName, INTERVALS, type Machine, type SshSuggestions, type TestReport } from "@/lib/machines";
import { cn } from "@/lib/utils";

interface Form {
  spec: string;
  name: string;
  nameTouched: boolean;
  port: string;
  identity: string;
  jump: string;
  privileged: boolean;
  interval: number;
}

const EMPTY: Form = {
  spec: "",
  name: "",
  nameTouched: false,
  port: "",
  identity: "",
  jump: "",
  privileged: false,
  interval: 60,
};

/**
 * Three steps: where the machine is → connect (trust its key, get key access) → how often to scan.
 *
 * The machine is saved — paused — at the end of step one, so the connection steps (which run the
 * CLI against the registry) can refer to it; it only joins the schedule when the user finishes.
 * Cancelling after step one removes it again, so an abandoned attempt leaves nothing behind.
 */
export function AddMachineDialog({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: (id: string) => void;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [form, setForm] = useState<Form>(EMPTY);
  const [advanced, setAdvanced] = useState(false);
  const [machine, setMachine] = useState<Machine | null>(null);
  const [report, setReport] = useState<TestReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [suggest, setSuggest] = useState<SshSuggestions | null>(null);

  useEffect(() => {
    invoke<SshSuggestions>("ssh_suggestions")
      .then(setSuggest)
      .catch(() => setSuggest(null));
  }, []);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  const cancel = useCallback(() => {
    if (machine) {
      void invoke("machine_remove", { id: machine.id, deleteHistory: true }).catch(() => {});
    }
    onClose();
  }, [machine, onClose]);

  async function saveAndConnect() {
    setBusy(true);
    setError(null);
    const port = form.port.trim() ? Number(form.port) : null;
    if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      setError("The port must be a number between 1 and 65535.");
      setBusy(false);
      return;
    }
    const name = (form.nameTouched ? form.name : defaultName(form.spec)).trim();
    try {
      let m: Machine;
      if (machine) {
        m = await invoke<Machine>("machine_update", {
          id: machine.id,
          patch: {
            name,
            spec: form.spec.trim(),
            port: port,
            identity_file: form.identity.trim() || null,
            jump_host: form.jump.trim() || null,
            privileged: form.privileged,
          },
        });
      } else {
        m = await invoke<Machine>("machine_add", {
          input: {
            name,
            spec: form.spec.trim(),
            port,
            identity_file: form.identity.trim() || null,
            jump_host: form.jump.trim() || null,
            privileged: form.privileged,
            interval_minutes: form.interval,
          },
          paused: true,
        });
      }
      setMachine(m);
      setReport(null);
      setStep(2);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function finish() {
    if (!machine) return;
    setBusy(true);
    setError(null);
    try {
      await invoke("machine_update", {
        id: machine.id,
        patch: { enabled: true, interval_minutes: form.interval, privileged: form.privileged },
      });
      await invoke("machine_scan_now", { id: machine.id });
      onAdded(machine.id);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  const pickAlias = (a: SshSuggestions["aliases"][number]) =>
    setForm((f) => ({
      ...f,
      spec: a.alias,
      name: f.nameTouched ? f.name : a.alias,
    }));

  const onResult = useCallback((r: TestReport) => setReport(r), []);

  const footer =
    step === 1 ? (
      <>
        <Button variant="ghost" onClick={cancel}>
          Cancel
        </Button>
        <Button onClick={saveAndConnect} disabled={!form.spec.trim() || busy}>
          {busy && <Loader2 className="animate-spin" />}
          Continue
        </Button>
      </>
    ) : step === 2 ? (
      <>
        <Button variant="ghost" onClick={() => setStep(1)}>
          Back
        </Button>
        <Button onClick={() => setStep(3)} disabled={!report?.ok}>
          Continue
        </Button>
      </>
    ) : (
      <>
        <Button variant="ghost" onClick={() => setStep(2)}>
          Back
        </Button>
        <Button onClick={finish} disabled={busy}>
          {busy && <Loader2 className="animate-spin" />}
          Add and scan now
        </Button>
      </>
    );

  return (
    <Modal title="Add a machine" onClose={cancel} footer={footer} wide>
      <Stepper step={step} />
      {error && (
        <Callout tone="critical" className="mb-4">
          {error}
        </Callout>
      )}

      {step === 1 && (
        <div className="flex flex-col gap-4">
          <p className="text-sm leading-relaxed text-muted-foreground">
            Bulwark connects with your own SSH access and runs its checks there. Nothing is installed on the
            machine or left listening between scans.
          </p>
          <Field
            label="Address"
            htmlFor="m-spec"
            help={
              <>
                <code className="font-mono">user@host</code>, an IP address, or a Host alias from your{" "}
                <code className="font-mono">~/.ssh/config</code> (its settings — port, key, jump host — are
                used as-is).
              </>
            }
          >
            <Input
              id="m-spec"
              autoFocus
              placeholder="deploy@server.example.com"
              value={form.spec}
              onChange={(e) => set("spec", e.target.value)}
              spellCheck={false}
              autoCapitalize="off"
            />
          </Field>
          {suggest && suggest.aliases.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-xs text-muted-foreground">From your SSH config:</span>
              <div className="flex flex-wrap gap-1.5">
                {suggest.aliases.slice(0, 12).map((a) => (
                  <button
                    key={a.alias}
                    type="button"
                    onClick={() => pickAlias(a)}
                    title={[
                      a.user && `${a.user}@`,
                      a.hostname,
                      a.port && `:${a.port}`,
                      a.jump && ` via ${a.jump}`,
                    ]
                      .filter(Boolean)
                      .join("")}
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 font-mono text-xs transition-colors outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                      form.spec === a.alias
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border text-muted-foreground hover:bg-muted hover:text-foreground",
                    )}
                  >
                    <Server className="h-3 w-3" />
                    {a.alias}
                  </button>
                ))}
              </div>
            </div>
          )}
          <Field label="Name" htmlFor="m-name" help="How the machine is shown in Bulwark and in alerts.">
            <Input
              id="m-name"
              placeholder={defaultName(form.spec) || "web-1"}
              value={form.nameTouched ? form.name : defaultName(form.spec)}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value, nameTouched: true }))}
            />
          </Field>

          <button
            type="button"
            onClick={() => setAdvanced((a) => !a)}
            className="flex w-fit items-center gap-1 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
          >
            {advanced ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            Port, key and jump host
          </button>
          {advanced && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Port" htmlFor="m-port" help="Leave empty for 22 or your SSH config.">
                <Input
                  id="m-port"
                  inputMode="numeric"
                  placeholder="22 (default)"
                  value={form.port}
                  onChange={(e) => set("port", e.target.value.replace(/[^0-9]/g, ""))}
                />
              </Field>
              <Field label="Key file" htmlFor="m-key" help="Empty: your SSH agent and default keys.">
                <Select id="m-key" value={form.identity} onChange={(e) => set("identity", e.target.value)}>
                  <option value="">Default (agent and ~/.ssh)</option>
                  {suggest?.bulwark_key && (
                    <option value={suggest.bulwark_key}>Bulwark's monitoring key</option>
                  )}
                  {suggest?.keys.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field
                label="Jump host"
                htmlFor="m-jump"
                help="Reach the machine through a bastion, e.g. me@bastion.example.com. It must already accept your key."
              >
                <Input
                  id="m-jump"
                  placeholder="Optional, e.g. me@bastion.example.com"
                  value={form.jump}
                  onChange={(e) => set("jump", e.target.value)}
                  spellCheck={false}
                />
              </Field>
            </div>
          )}

          <div className="flex items-start justify-between gap-4 rounded-lg border border-border p-3">
            <div>
              <div className="text-sm font-medium">Include checks that need root</div>
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                Reads sudoers, /etc/shadow permissions and the firewall. Needs passwordless sudo on the
                machine — ideally limited to the scanner; the next step checks it and shows the exact rule.
              </p>
            </div>
            <Switch checked={form.privileged} onCheckedChange={(v) => set("privileged", v)} />
          </div>
        </div>
      )}

      {step === 2 && machine && (
        <ConnectionCheck
          key={`${machine.id}-${machine.spec}-${machine.port}-${machine.identity_file}-${machine.jump_host}-${form.privileged}`}
          machineId={machine.id}
          machineName={machine.name}
          privileged={form.privileged}
          onResult={onResult}
        />
      )}

      {step === 3 && machine && (
        <div className="flex flex-col gap-4">
          <Field label="Scan" htmlFor="m-interval">
            <Select
              id="m-interval"
              value={form.interval}
              onChange={(e) => set("interval", Number(e.target.value))}
            >
              {INTERVALS.map((i) => (
                <option key={i.minutes} value={i.minutes}>
                  {i.label}
                </option>
              ))}
            </Select>
          </Field>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Bulwark scans {machine.name} on this schedule while the app is running, and shows its issues on
            the Remote page. If it stops answering, Bulwark retries less often and tells you after three
            failed attempts in a row. To get alerts on your phone or by e-mail, set up Alerts in Settings.
          </p>
          {report?.steps.find((s) => s.id === "engine")?.detail.startsWith("Not installed") && (
            <Callout tone="info">
              Bulwark isn't installed on {machine.name}, so each scan copies it into /tmp and removes it
              afterwards. That works, but installing it there is faster and enables a sudo rule limited to the
              scanner.
            </Callout>
          )}
        </div>
      )}
    </Modal>
  );
}

function Stepper({ step }: { step: 1 | 2 | 3 }) {
  const labels = ["Where", "Connect", "Schedule"];
  return (
    <ol className="mb-5 flex items-center gap-2 text-xs">
      {labels.map((l, i) => {
        const n = (i + 1) as 1 | 2 | 3;
        return (
          <li key={l} className="flex items-center gap-2">
            <span
              className={cn(
                "flex h-5 w-5 items-center justify-center rounded-full font-mono text-[10px] font-semibold",
                n === step
                  ? "bg-primary text-primary-foreground"
                  : n < step
                    ? "bg-primary/20 text-foreground"
                    : "bg-muted text-muted-foreground",
              )}
            >
              {n}
            </span>
            <span className={cn(n === step ? "font-medium text-foreground" : "text-muted-foreground")}>
              {l}
            </span>
            {i < labels.length - 1 && <span className="h-px w-6 bg-border" />}
          </li>
        );
      })}
    </ol>
  );
}

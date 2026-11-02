<script setup lang="ts">
// The CLI on the landing page: one terminal, a tab per command. Every sample is real output of
// `bulwarkctl` run in throw-away containers (a developer account with a cloned project, and a
// server reached over SSH), trimmed with "…" where a report goes on. Colours follow the CLI's own:
// severity words in their colour, the fix arrow green, places and links dim.
import { computed, ref } from "vue";
import pkg from "../../../package.json";

type Sample = { id: string; label: string; cmd: string; out: string };

const samples: Sample[] = [
  {
    id: "ai",
    label: "AI agents",
    cmd: "bulwarkctl ai scan",
    out: `Bulwark {v} · AI coding agents · 1 project · 3 agent files checked

4 problems to fix  1 critical · 3 high

  ● Critical Project-supplied agent hooks run shell commands automatically
             This project settings file defines hooks. Claude Code hooks run shell commands
             automatically on tool/session events — a project-supplied hook can execute …
             → Remove the hooks from the repository's agent config (for example the hooks
               block in .claude/settings.json, .cursor/hooks.json, .kiro/hooks/, or a …
             in: ~/Projects/api/.claude/settings.json:1
             more: https://bulwark.nrl.ai/checks/blwk-ai-002

  ● High     Anthropic API key exposed in AI context
             Anything written into an assistant's context, memory, or transcript should be
             treated as leaked — rotate it.
             → Remove the key from the file and replace it with a new one. Anything pasted
               into an AI chat should be treated as leaked.
             in: ~/.claude/projects/api/session.jsonl:1
             more: https://bulwark.nrl.ai/checks/blwk-ai-001

  ● High     An MCP server runs an unpinned package from a registry
             MCP server "fs" launches an unpinned package via npx. Without a pinned version
             it runs whatever the registry serves next, with your granted tool permissions.
             → Pin the MCP server to an exact version so it can't change without you
               knowing.
             in: ~/Projects/api/.mcp.json:1
             more: https://bulwark.nrl.ai/checks/blwk-ai-003
  …

→ 1 agent file holds leaked secrets Bulwark can remove — preview with bulwarkctl ai redact, then add --apply
→ Removing a secret from a file doesn't make it safe again: rotate it with its provider.`,
  },
  {
    id: "scan",
    label: "This computer",
    cmd: "bulwarkctl scan",
    out: `Bulwark {v} · this computer · 75 of 82 checks ran

17 problems to fix  2 high · 3 medium · 10 low · 2 info

  ● High     SSH root login is permitted
             PermitRootLogin is set to "yes", allowing direct root logins over SSH.
             → Set 'PermitRootLogin no' (or 'prohibit-password' if key-based root access is
               required) in /etc/ssh/sshd_config.
             more: https://bulwark.nrl.ai/checks/blwk-ssh-002

  ● Medium   SSH forwards your agent to every server
             /home/dev/.ssh/config sets ForwardAgent yes for all hosts. While you are
             connected, root — or an attacker — on any server you log in to can use your …
             → Remove ForwardAgent from Host * (and the top of the file). To reach a
               machine through another, use ProxyJump (ssh -J bastion target), which …
             in: /home/dev/.ssh/config
             more: https://bulwark.nrl.ai/checks/blwk-dev-005
  …

  and 12 low-priority suggestions — run with --all to see them

Not covered by this scan:
  · 2 check areas need admin rights — run sudo bulwarkctl scan --privileged
  · 7 checks couldn't run here — not counted as passing`,
  },
  {
    id: "ssh",
    label: "A server",
    cmd: "bulwarkctl scan --ssh deploy@web-01",
    out: `Scanning deploy@web-01 over SSH…
Pushed this bulwarkctl (x86_64) to a temp dir and cleaned it up.
Bulwark {v} · deploy@web-01 · 75 of 82 checks ran

15 problems to fix  2 high · 2 medium · 9 low · 2 info

  ● High     SSH password authentication is enabled
             PasswordAuthentication is set to "yes" in sshd_config, which allows an
             attacker to brute-force their way in with a password guess instead of …
             → Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and run 'systemctl
               restart sshd'. IMPORTANT: confirm key-based login works in a SECOND …
             more: https://bulwark.nrl.ai/checks/blwk-ssh-001

  ● Medium   auditd is not installed
             No auditd binary was found. Without it, there's no kernel-level record of
             privileged syscalls (file access, exec, permission changes) — the trail that …
             → Install auditd (e.g. 'apt install auditd') and enable it with 'systemctl
               enable --now auditd'.
             more: https://bulwark.nrl.ai/checks/blwk-log-001
  …`,
  },
  {
    id: "fix",
    label: "Fix",
    cmd: "sudo bulwarkctl fix sshd",
    out: `sshd_config: /etc/ssh/sshd_config
  skipped (lockout risk — use --include-auth): PasswordAuthentication no (was yes) — password logins are brute-forceable; prefer keys (BLWK-SSH-001)
  skipped (lockout risk — use --include-auth): PermitRootLogin no (was yes) — direct root login removes the audit trail of who acted (BLWK-SSH-002)
  would set: X11Forwarding no (was yes) — X11 forwarding exposes the client's display to the server (BLWK-SSH-004)
  would set: AllowTcpForwarding no (was yes) — TCP forwarding can turn the host into a network pivot (BLWK-SSH-005)
  would set: AllowAgentForwarding no (was yes) — agent forwarding lets a compromised host use your keys (BLWK-SSH-010)
  would set: MaxAuthTries 4 (was 10) — fewer auth attempts per connection slows brute forcing (BLWK-SSH-011)

Preview only. Re-run with --apply (as root) to make the change.`,
  },
  {
    id: "logs",
    label: "Logs",
    cmd: "bulwarkctl logs scan --from-file auth.log",
    out: `Bulwark {v} · logs · 21 events read, 21 understood

2 problems to fix  1 high · 1 medium

  ● High     SSH brute-force from 203.0.113.7
             203.0.113.7 produced 8 or more failed SSH logins within 60 seconds — a
             password brute-force attempt.
             → Block the source IP at the firewall (nft/ipset or fail2ban), confirm
               PasswordAuthentication is off (key-only auth defeats guessing entirely), …
             more: https://bulwark.nrl.ai/checks/blwk-log-ssh-001

  ● Medium   Successful SSH root login from 203.0.113.7
             root logged in directly over SSH from 203.0.113.7. Direct root login removes
             the per-user accountability of sudo and is a common post-compromise foothold …
             → Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config and have
               admins log in as themselves, then escalate with sudo. If this login was …
             more: https://bulwark.nrl.ai/checks/blwk-log-ssh-003`,
  },
];

const active = ref(samples[0].id);
const sample = computed(
  () => samples.find((s) => s.id === active.value) ?? samples[0],
);

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const SEV: Record<string, string> = {
  Critical: "t-crit",
  High: "t-high",
  Medium: "t-med",
  Low: "t-dim",
  Info: "t-dim",
  critical: "t-crit",
  high: "t-high",
  medium: "t-med",
};

/** One output line, coloured the way the CLI colours it on a terminal. */
function paint(raw: string): string {
  return keepWhole(colour(raw));
}

/** Rule ids and links never break at their hyphens when a line wraps. */
const keepWhole = (html: string) =>
  html.replace(
    /(BLWK-[A-Z0-9-]+|https:\/\/\S+)/g,
    '<span class="nw">$1</span>',
  );

function colour(raw: string): string {
  const line = esc(raw.replace("{v}", pkg.version));
  let m: RegExpMatchArray | null;
  if ((m = line.match(/^(\s+)● (\w+)(\s+)(.*)$/))) {
    const cls = SEV[m[2]] ?? "t-dim";
    return `${m[1]}<span class="${cls}">● ${m[2]}</span>${m[3]}<b>${m[4]}</b>`;
  }
  if ((m = line.match(/^(Bulwark [\d.]+)( · .*)$/))) {
    return `<b>${m[1]}</b><span class="t-dim">${m[2]}</span>`;
  }
  if ((m = line.match(/^(\d+ problems? to fix)(\s+)(.*)$/))) {
    const counts = m[3]
      .split(" · ")
      .map((c) => {
        const cls = SEV[c.split(" ")[1]] ?? "t-dim";
        return `<span class="${cls}">${c}</span>`;
      })
      .join('<span class="t-dim"> · </span>');
    return `<b>${m[1]}</b>${m[2]}${counts}`;
  }
  if ((m = line.match(/^(\s*)(in: |more: )(.*)$/)) || /^\s*…$/.test(line)) {
    return `<span class="t-dim">${line}</span>`;
  }
  if ((m = line.match(/^(\s*)→ (.*)$/))) {
    return `${m[1]}<span class="t-ok">→</span> ${m[2]}`;
  }
  if ((m = line.match(/^(\s+)(would set:)(.*)$/))) {
    return `${m[1]}<span class="t-ok">${m[2]}</span>${m[3]}`;
  }
  if ((m = line.match(/^(\s+)(skipped \(.*?\):)(.*)$/))) {
    return `${m[1]}<span class="t-med">${m[2]}</span>${m[3]}`;
  }
  if (
    /^(Scanning|Pushed|Not covered|Preview only|\s+and \d+ low|\s+· )/.test(
      line,
    )
  ) {
    return `<span class="t-dim">${line}</span>`;
  }
  return line;
}

/** Each line its own block, so a line too long for the box wraps under its own text (a hanging
 * indent, as a terminal of that width would show it) instead of scrolling the whole sample. */
function block(raw: string, html: string): string {
  const lead = raw.length - raw.trimStart().length;
  const hang =
    lead + (raw.trimStart().startsWith("→") ? 2 : lead > 0 && lead < 4 ? 2 : 0);
  return `<span class="ln" style="--hang:${hang}ch">${html || " "}</span>`;
}

const html = computed(() =>
  [
    block("", `<span class="t-dim">$</span> ${esc(sample.value.cmd)}`),
    ...sample.value.out.split("\n").map((l) => block(l, paint(l))),
  ].join(""),
);

function onKey(e: KeyboardEvent) {
  const i = samples.findIndex((s) => s.id === active.value);
  const next =
    e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : null;
  if (next === null) return;
  e.preventDefault();
  const s = samples[(next + samples.length) % samples.length];
  active.value = s.id;
  (document.getElementById(`cli-tab-${s.id}`) as HTMLElement | null)?.focus();
}
</script>

<template>
  <div class="bw-term cli-demo">
    <div class="bw-term-bar">
      <span></span><span></span><span></span>
      <div
        class="cli-tabs"
        role="tablist"
        aria-label="CLI commands"
        @keydown="onKey"
      >
        <button
          v-for="s in samples"
          :id="`cli-tab-${s.id}`"
          :key="s.id"
          role="tab"
          type="button"
          class="cli-tab"
          :aria-selected="s.id === active"
          :aria-controls="`cli-panel`"
          :tabindex="s.id === active ? 0 : -1"
          @click="active = s.id"
        >
          {{ s.label }}
        </button>
      </div>
    </div>
    <pre
      id="cli-panel"
      role="tabpanel"
      :aria-labelledby="`cli-tab-${active}`"
      tabindex="0"
      v-html="html"
    ></pre>
  </div>
</template>

<style scoped>
.cli-tabs {
  display: flex;
  gap: 2px;
  margin-left: 12px;
  overflow-x: auto;
  scrollbar-width: none;
}
.cli-tabs::-webkit-scrollbar {
  display: none;
}
.cli-tab {
  flex: none;
  padding: 3px 10px;
  border-radius: 6px;
  font-family: var(--vp-font-family-mono);
  font-size: 0.76rem;
  color: #8b98a8;
  white-space: nowrap;
  transition:
    background-color 0.15s,
    color 0.15s;
}
.cli-tab:hover {
  color: #d7dee7;
}
.cli-tab[aria-selected="true"] {
  color: #f3f6fa;
  background: #253241;
}
.cli-tab:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 1px;
}
.cli-demo pre {
  min-height: 34rem;
  white-space: normal;
  overflow-x: hidden;
}
.cli-demo :deep(.ln) {
  display: block;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  padding-left: var(--hang);
  text-indent: calc(-1 * var(--hang));
}
.cli-demo pre:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: -2px;
}
.cli-demo :deep(.t-med) {
  color: #f2c94c;
}
.cli-demo :deep(.nw) {
  white-space: nowrap;
}
/* A phone is narrower than any terminal: keep the lines whole and let the sample scroll
   sideways inside its window (never the page), as it would in a terminal that small. */
@media (max-width: 640px) {
  .cli-demo pre {
    min-height: 26rem;
    overflow-x: auto;
  }
  .cli-demo :deep(.ln) {
    white-space: pre;
    padding-left: 0;
    text-indent: 0;
  }
  .cli-demo .bw-term-bar > span {
    display: none;
  }
  .cli-tabs {
    margin-left: 0;
    mask-image: linear-gradient(to right, #000 85%, transparent);
  }
}
</style>

<script setup lang="ts">
// Under the hero headline: the product, two ways. The CLI comes first — it is where the agent
// checks are quickest to try, and it shows real output a visitor can read and copy. The desktop
// app is the video; it isn't fetched until its tab is opened, so the first view stays light.
import { nextTick, ref } from "vue";
import CliDemo from "./CliDemo.vue";

const views = [
  { id: "cli", label: "Command line" },
  { id: "agent", label: "AI agents" },
  { id: "app", label: "Desktop app" },
] as const;
type View = (typeof views)[number]["id"];

const active = ref<View>("cli");
const videoWanted = ref(false);
const video = ref<HTMLVideoElement | null>(null);

async function show(id: View) {
  active.value = id;
  if (id !== "app") {
    video.value?.pause();
    return;
  }
  videoWanted.value = true;
  await nextTick();
  const el = video.value;
  if (!el) return;
  // Vue doesn't reliably set the `muted` *property* from the attribute, and browsers block
  // autoplay on non-muted video — so set it here and start playback.
  el.muted = true;
  el.play?.()?.catch(() => {});
}

function onKey(e: KeyboardEvent) {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  e.preventDefault();
  const i = views.findIndex((v) => v.id === active.value);
  const next =
    views[
      (i + (e.key === "ArrowRight" ? 1 : -1) + views.length) % views.length
    ];
  show(next.id);
  document.getElementById(`hero-tab-${next.id}`)?.focus();
}
</script>

<template>
  <div class="hero-demo-wrap">
    <div
      class="switch"
      role="tablist"
      aria-label="Ways to use Bulwark"
      @keydown="onKey"
    >
      <button
        v-for="v in views"
        :id="`hero-tab-${v.id}`"
        :key="v.id"
        role="tab"
        type="button"
        :aria-selected="v.id === active"
        :aria-controls="`hero-panel-${v.id}`"
        :tabindex="v.id === active ? 0 : -1"
        @click="show(v.id)"
      >
        {{ v.label }}
      </button>
    </div>

    <div
      v-show="active === 'cli'"
      id="hero-panel-cli"
      role="tabpanel"
      aria-labelledby="hero-tab-cli"
    >
      <CliDemo />
      <ul class="facts">
        <li>One static file, nothing to install</li>
        <li><code>--json</code> and exit codes for CI</li>
        <li>Scans servers over your SSH</li>
      </ul>
      <p class="more"><a href="/download#cli">Get the CLI →</a></p>
    </div>

    <div
      v-show="active === 'agent'"
      id="hero-panel-agent"
      role="tabpanel"
      aria-labelledby="hero-tab-agent"
    >
      <div class="chat">
        <p class="chat-user">Is this repository safe to work in?</p>
        <p class="chat-tool">
          <span>Bulwark skill</span> $ bulwarkctl ai scan --target .
        </p>
        <div class="chat-reply">
          <p>
            <strong>Not yet.</strong> Bulwark found 4 problems in this repo's
            agent files: 1 critical, 3 high.
          </p>
          <ol>
            <li>
              <strong>Critical:</strong> the repo's own settings run shell
              commands automatically — <code>.claude/settings.json</code>
            </li>
            <li>
              <strong>High:</strong> an Anthropic API key is exposed —
              <code>.claude/commands/deploy.md:3</code>. Revoke it and create a
              new one.
            </li>
            <li>
              <strong>High:</strong> an MCP server runs an unpinned package —
              <code>.mcp.json</code>
            </li>
            <li>
              <strong>High:</strong> the file with the key isn't in
              <code>.gitignore</code>
            </li>
          </ol>
          <p>
            I haven't changed anything. I can preview removing the key with
            <code>bulwarkctl ai redact</code> and apply it if you say yes.
          </p>
        </div>
      </div>
      <p class="install"><code>bulwarkctl agent install</code></p>
      <p class="more">
        Claude Code, Codex, Copilot, Gemini CLI, OpenCode, Cursor ·
        <a href="/agents">How it works →</a>
      </p>
    </div>

    <div
      v-show="active === 'app'"
      id="hero-panel-app"
      role="tabpanel"
      aria-labelledby="hero-tab-app"
    >
      <video
        v-if="videoWanted"
        ref="video"
        class="hero-demo"
        src="/demo.mp4"
        muted
        loop
        playsinline
        preload="auto"
        poster="/screenshots/overview.png"
        aria-label="Bulwark demo: run a scan, open a problem and its one-click fix, check a remote machine, and switch between light and dark themes"
      ></video>
      <p class="more"><a href="/download">Download the desktop app →</a></p>
    </div>
  </div>
</template>

<style scoped>
.hero-demo-wrap {
  max-width: 1040px;
  margin: 12px auto 0;
  padding: 0 24px;
}

/* Two choices, one segmented control. */
.switch {
  display: flex;
  width: fit-content;
  margin: 0 auto 18px;
  padding: 4px;
  gap: 4px;
  border-radius: 999px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
}
.switch button {
  padding: 7px 18px;
  border-radius: 999px;
  font-size: 0.92rem;
  font-weight: 500;
  color: var(--vp-c-text-2);
  transition:
    background-color 0.15s,
    color 0.15s;
}
.switch button:hover {
  color: var(--vp-c-text-1);
}
.switch button[aria-selected="true"] {
  color: var(--vp-button-brand-text);
  background: var(--vp-button-brand-bg);
}
.switch button:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 2px;
}

.facts {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 0.5rem 0.6rem;
  list-style: none;
  margin: 1.25rem 0 0;
  padding: 0;
}
.facts li {
  padding: 0.3rem 0.8rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 999px;
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
}
.facts code {
  font-family: var(--vp-font-family-mono);
  font-size: 0.8rem;
  color: var(--vp-c-text-1);
}
.more {
  margin: 0.9rem 0 0;
  text-align: center;
  font-weight: 500;
}
.more a {
  color: var(--vp-c-brand-1);
  text-decoration: none;
}
.more a:hover {
  text-decoration: underline;
}

/* A real agent conversation (Claude Code, with the skill installed), trimmed. */
.chat {
  max-width: 760px;
  margin: 0 auto;
  padding: 22px 24px;
  border-radius: 14px;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  box-shadow: 0 30px 70px -30px rgba(15, 20, 25, 0.35);
  text-align: left;
  font-size: 0.95rem;
  line-height: 1.6;
}
.chat p {
  margin: 0 0 0.7rem;
}
.chat-user {
  margin-left: auto !important;
  width: fit-content;
  max-width: 85%;
  padding: 0.5rem 0.95rem;
  border-radius: 14px 14px 4px 14px;
  background: var(--vp-c-brand-soft);
  font-weight: 500;
}
.chat-tool {
  font-family: var(--vp-font-family-mono);
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
}
.chat-tool span {
  margin-right: 0.5rem;
  padding: 1px 7px;
  border-radius: 999px;
  border: 1px solid var(--vp-c-divider);
  font-family: var(--vp-font-family-base);
  font-size: 0.72rem;
}
.chat-reply ol {
  margin: 0 0 0.7rem;
  padding-left: 1.4rem;
  list-style: decimal;
}
.chat-reply li {
  margin: 0.2rem 0;
}
.chat-reply > p:last-child {
  margin-bottom: 0;
}
.chat code,
.install code {
  font-family: var(--vp-font-family-mono);
  font-size: 0.84em;
  padding: 1px 5px;
  border-radius: 5px;
  background: var(--vp-c-default-soft);
}
.install {
  margin: 1.25rem 0 0;
  text-align: center;
}
.install code {
  font-size: 0.95rem;
  padding: 6px 14px;
  border-radius: 8px;
}
.more {
  color: var(--vp-c-text-2);
  font-size: 0.9rem;
}

.hero-demo {
  width: 100%;
  display: block;
  aspect-ratio: 16 / 10;
  /* The frames are the window edge to edge; the rounding happens only here. clip-path as well as
     border-radius, because some engines don't clip a playing <video> to its radius. The hairline
     ring stands in for the window border so the edge reads on light and dark pages alike. */
  border-radius: 10px;
  clip-path: inset(0 round 10px);
  background: var(--vp-c-bg-soft);
  outline: 1px solid color-mix(in srgb, var(--vp-c-text-1) 12%, transparent);
  outline-offset: -1px;
  box-shadow: 0 30px 70px -24px rgba(15, 20, 25, 0.45);
}
:root.dark .hero-demo {
  box-shadow: 0 30px 70px -20px rgba(0, 0, 0, 0.7);
}

@media (max-width: 640px) {
  .hero-demo-wrap {
    padding: 0 16px;
  }
  .facts li:nth-child(n + 3) {
    display: none;
  }
}
</style>

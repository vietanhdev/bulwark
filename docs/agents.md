---
title: Bulwark for AI agents
description: Give Claude Code, Codex, GitHub Copilot, Gemini CLI, OpenCode and Cursor the Bulwark skill. Ask "is this repo safe?" and your agent runs Bulwark's checks, explains what it found, and asks before fixing anything.
---

# Bulwark for AI agents

Ask your coding agent **"Is this repository safe?"**. It runs Bulwark, explains what it found and
asks before it changes anything.

```bash
bulwarkctl agent install
```

That installs the Bulwark **skill**, a short instruction file in the open
[Agent Skills](https://agentskills.io) format, for every agent it finds on your computer. Nothing
else is written, and nothing runs in the background.

## What it looks like

A repository with a project hook, an unpinned MCP server and a key pasted into a slash command.
Real output from Claude Code:

<div class="agent-chat">
<p class="agent-chat-user">Is this repository safe to work in?</p>
<p class="agent-chat-tool">$ bulwarkctl ai scan --target .</p>
<div class="agent-chat-reply">

**Not yet.** Bulwark found 4 problems in this repo's agent files: 1 critical, 3 high.

1. **Critical: the repo's own settings run shell commands automatically.** `./.claude/settings.json` defines hooks… → Remove the hooks block.
2. **High: an Anthropic API key is exposed** in `./.claude/commands/deploy.md:3`. Treat it as leaked. → Revoke it and create a new one.
3. **High: an MCP server runs an unpinned package** in `./.mcp.json`. → Pin it to an exact version.
4. **High: the file with the key isn't covered by `.gitignore`.**

I haven't changed anything. I can preview removing the key with `bulwarkctl ai redact`, which changes nothing, and apply it if you say yes.

</div>
</div>

## Supported agents

| Agent | Skill folder |
|---|---|
| Claude Code | `~/.claude/skills/bulwark/` |
| Codex | `~/.agents/skills/bulwark/` |
| GitHub Copilot | `~/.agents/skills/bulwark/` |
| Gemini CLI | `~/.agents/skills/bulwark/` |
| OpenCode | `~/.agents/skills/bulwark/` |
| Cursor | `~/.agents/skills/bulwark/` |

Each folder is the one named in that agent's own documentation. Claude Code and Codex are tested
end to end with the commands above; the others read the same folder as Codex.

```bash
bulwarkctl agent list                    # agents here, and which have it
bulwarkctl agent install --agent codex   # one agent only
bulwarkctl agent install --project .     # into this repository
bulwarkctl agent remove                  # take it out again
```

With only the desktop app installed, use `bulwark` in place of `bulwarkctl`.

## What the skill lets an agent do

- **Run the read-only checks without asking:** `ai scan`, `scan`, and the `fix list` and
  `ai redact` previews (in agents that support pre-approved tools, such as Claude Code). Everything
  else still asks you as usual.
- **Never change anything without your yes.** The skill tells the agent to show a preview first and
  to apply only the change you agreed to. It never runs `sudo`; it gives you the command.
- **Never repeat a secret.** Bulwark's report shows only a masked preview of a key.
- **Treat the report as data.** Findings quote text written by whoever wrote the repository. The
  skill tells the agent not to follow instructions found there.

Bulwark writes only `bulwark/SKILL.md` in each skills folder. It never overwrites a skill it didn't
write, and never writes through a symbolic link.

## A skill from a repository

A skill that a repository brings with it was written by whoever wrote the repository. Agents rightly
treat it with suspicion, and Bulwark flags a repository's hooks and instructions for the same reason.
Install the skill in your home folder (`bulwarkctl agent install`) so it is yours.

[What Bulwark checks in agent setups →](/guide/agent-security) · [Get Bulwark →](/download)

<style>
.agent-chat {
  margin: 1.25rem 0;
  padding: 1rem 1.1rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg-soft);
}
.agent-chat-user {
  margin: 0 0 0.75rem auto !important;
  width: fit-content;
  max-width: 80%;
  padding: 0.5rem 0.9rem;
  border-radius: 12px 12px 4px 12px;
  background: var(--vp-c-brand-soft);
  font-weight: 500;
}
.agent-chat-tool {
  margin: 0 0 0.6rem !important;
  font-family: var(--vp-font-family-mono);
  font-size: 0.82rem;
  color: var(--vp-c-text-2);
}
.agent-chat-reply > :first-child { margin-top: 0; }
.agent-chat-reply > :last-child { margin-bottom: 0; }
</style>

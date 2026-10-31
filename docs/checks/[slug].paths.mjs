// One page per check, rendered from catalog.json (built by scripts/generate-checks.py from the
// rule files the scanner itself loads). The app links each finding's Details here.
import { readFileSync } from "node:fs";

const { groups, checks } = JSON.parse(
  readFileSync(new URL("./catalog.json", import.meta.url), "utf8"),
);

const SEVERITY = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const escapeHtml = (s) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Rule text marks commands and config lines with single quotes ('sysctl --system'), and names
// the finding's live values as {{ collector.field }}. On a page about the check in general the
// live value becomes a placeholder, and quoted text becomes inline code.
function inline(text) {
  const withPlaceholders = text.replace(
    /\{\{\s*[\w]+\.(\w+)\s*\}\}/g,
    (_, field) => `‹${field.replace(/_/g, " ")}›`,
  );
  return escapeHtml(withPlaceholders)
    .replace(/(^|[\s(])'([^'\n]+?)'(?=$|[\s).,;:!?])/g, "$1`$2`")
    .replace(/(^|[\s(])"([^"\n]+?)"(?=$|[\s).,;:!?])/g, "$1“$2”")
    .replace(/\bbulwarkctl\b/g, "bulwark");
}

// Structured fixes are a goal line, numbered steps, then optional fallback lines.
function fixMarkdown(fix) {
  const out = [];
  for (const line of fix.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const step = line.match(/^(\d+)[.)]\s+(.*)$/);
    if (step) out.push(`${step[1]}. ${inline(step[2])}`);
    else out.push(`${out.length && /^\d+\./.test(out[out.length - 1]) ? "\n" : ""}${inline(line)}\n`);
  }
  return out.join("\n");
}

function reference(ref) {
  const attack = ref.match(/^ATTACK-T(\d{4})(?:\.(\d{3}))?$/);
  if (attack) {
    const url = `https://attack.mitre.org/techniques/T${attack[1]}/${attack[2] ? `${attack[2]}/` : ""}`;
    return `[MITRE ATT&CK T${attack[1]}${attack[2] ? `.${attack[2]}` : ""}](${url})`;
  }
  const cis = ref.match(/^CIS-(.+)$/);
  if (cis) return `CIS Benchmark ${cis[1]}`;
  const cve = ref.match(/^CVE-\d{4}-\d+$/);
  if (cve) return `[${ref}](https://nvd.nist.gov/vuln/detail/${ref})`;
  return ref;
}

function render(c) {
  const group = groups.find((g) => g.id === c.group);
  const related = checks
    .filter((o) => o.group === c.group && o.id !== c.id)
    .slice(0, 6);
  const src = c.source
    ? `https://github.com/vietanhdev/bulwark/blob/main/${c.source}`
    : "https://github.com/vietanhdev/bulwark/blob/main/crates/bulwark-core/src/ai_scan/detectors.rs";

  return `
<div class="bw-check-meta">
  <span class="bw-sev bw-sev-${c.severity}">${SEVERITY[c.severity] ?? c.severity}</span>
  <a class="bw-check-group" href="/checks/#${c.group}">${group?.title ?? c.group}</a>
  <code class="bw-check-id">${c.id}</code>
</div>

# ${inline(c.title)}

${c.severityNote ? `<p class="bw-check-note">${c.severityNote}</p>\n` : ""}
## What this means

${inline(c.explain)}

## How to fix it

${fixMarkdown(c.fix)}
${
  c.autofix
    ? `
::: tip Bulwark can do this for you
${c.autofix}
:::
`
    : ""
}
## Check it yourself

Run a scan and look for \`${c.id}\` in the results:

\`\`\`sh
bulwark scan${c.collector === "ai_scan" ? "\nbulwark ai scan" : ""}
\`\`\`

Installed the standalone CLI package instead of the app? The command is \`bulwarkctl\`.
${
  c.condition
    ? `
<details class="bw-check-how">
<summary>How Bulwark decides</summary>

Bulwark reads \`${c.collector}\` and reports this check when:

\`\`\`text
${c.condition}
\`\`\`

If a value can't be read, Bulwark reports the check as undetermined rather than passing it.
[View the rule source](${src}).

</details>
`
    : ""
}${
    c.references.length
      ? `
## References

${c.references.map((r) => `- ${reference(r)}`).join("\n")}
`
      : ""
  }${
    related.length
      ? `
## Related checks

${related.map((o) => `- [${inline(o.title)}](/checks/${o.slug}) · \`${o.id}\``).join("\n")}
`
      : ""
  }`;
}

export default {
  paths() {
    return checks.map((c) => ({
      params: {
        slug: c.slug,
        title: `${c.title} (${c.id})`,
        description: c.explain.replace(/\{\{[^}]+\}\}/g, "…").slice(0, 200),
      },
      content: render(c),
    }));
  },
};

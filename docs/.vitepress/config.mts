import { withMermaid } from "vitepress-plugin-mermaid";

// Canonical domain (not yet deployed — see AGENTS.md's current-status notes). Set here so
// the sitemap and social-preview tags are correct from day one instead of needing a
// find-and-replace once hosting is actually wired up.
const SITE_URL = "https://bulwark.nrl.ai";

// relativePath -> /og/<file>.png, one designed 1200x630 card per page (not a generic
// site-wide image) so links shared to Slack/Discord/Twitter get a real preview instead of a
// blank card. Generated via Playwright screenshotting a local HTML template — see
// docs/public/screenshots/README.md for why a plain screenshot tool couldn't do this.
const OG_IMAGES: Record<string, string> = {
  "index.md": "home",
  "guide/architecture.md": "architecture",
  "research/lynis-benchmark.md": "lynis-benchmark",
  "articles/ssh-hardening-checklist.md": "ssh-hardening-checklist",
  "articles/linux-persistence-techniques.md": "linux-persistence-techniques",
  "articles/choosing-a-linux-security-scanner.md": "choosing-a-linux-security-scanner",
};

export default withMermaid({
  title: "Bulwark",
  description: "A Linux host security scanner with a native CLI and desktop GUI.",
  lang: "en-US",
  cleanUrls: true,
  // Default to light on first visit (no stored preference / no system-preference match yet)
  // — the toggle is still there, this only changes the initial pick.
  appearance: "light",
  sitemap: { hostname: SITE_URL },
  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/shield.svg" }],
    [
      "meta",
      {
        name: "keywords",
        content:
          "linux security scanner, security hardening, ssh hardening, rootkit detection, " +
          "clamav, security audit tool, cis benchmark, mitre att&ck, lynis alternative, " +
          "rkhunter, file integrity monitoring, sysadmin security, tauri, rust security tool",
      },
    ],
    ["meta", { name: "robots", content: "index, follow" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "Bulwark" }],
    ["meta", { property: "og:title", content: "Bulwark — Linux Host Security Scanner" }],
    [
      "meta",
      {
        property: "og:description",
        content:
          "A Linux host security scanner with a native CLI and desktop GUI. Checks SSH " +
          "hardening, persistence, kernel/sysctl hardening, and rootkit indicators, and " +
          "explains every finding in plain language with a fix.",
      },
    ],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:title", content: "Bulwark — Linux Host Security Scanner" }],
    [
      "meta",
      {
        name: "twitter:description",
        content: "A Linux host security scanner with a native CLI and desktop GUI.",
      },
    ],
  ],
  transformPageData(pageData) {
    // Per-page canonical + og:url — without this every page's <head> claims the homepage
    // as canonical (the head[] array above is site-wide), which tells search engines to
    // ignore /guide/architecture and /research/lynis-benchmark as duplicates of "/".
    const canonicalUrl = `${SITE_URL}/${pageData.relativePath}`
      .replace(/index\.md$/, "")
      .replace(/\.md$/, "");
    pageData.frontmatter.head ??= [];
    pageData.frontmatter.head.push(
      ["link", { rel: "canonical", href: canonicalUrl }],
      ["meta", { property: "og:url", content: canonicalUrl }],
    );
    const ogSlug = OG_IMAGES[pageData.relativePath];
    if (ogSlug) {
      const imageUrl = `${SITE_URL}/og/${ogSlug}.png`;
      pageData.frontmatter.head.push(
        ["meta", { property: "og:image", content: imageUrl }],
        ["meta", { property: "og:image:width", content: "1200" }],
        ["meta", { property: "og:image:height", content: "630" }],
        ["meta", { name: "twitter:image", content: imageUrl }],
      );
    }
  },

  // Teal palette matching apps/bulwark-app/src/styles.css's tokens (oklch hue ~194, converted
  // to hex since mermaid doesn't understand oklch()). Only governs light mode — the plugin
  // forces mermaid's own built-in dark theme when `.dark` is on <html>, this config has no
  // effect there (a vitepress-plugin-mermaid limitation, not a choice made here).
  mermaid: {
    theme: "base",
    themeVariables: {
      // Deliberately NOT Geist here, unlike the rest of the site — a custom variable
      // webfont threw off mermaid's own node box-height math (multi-line labels rendered
      // clipped at the box's bottom edge even with the exact line count mermaid was given).
      // mermaid's default font stack is what its internal sizing is actually calibrated
      // against; overriding it re-introduces the clipping bug.

      primaryColor: "#d5f2f1",
      primaryTextColor: "#081717",
      primaryBorderColor: "#007372",
      lineColor: "#007372",
      secondaryColor: "#fafcfc",
      secondaryBorderColor: "#dae3e3",
      tertiaryColor: "#ffffff",
      tertiaryBorderColor: "#dae3e3",
      textColor: "#081717",
      actorBkg: "#d5f2f1",
      actorBorder: "#007372",
      actorTextColor: "#081717",
      signalColor: "#007372",
      signalTextColor: "#081717",
    },
  },

  themeConfig: {
    logo: "/shield.svg",
    nav: [
      { text: "Guide", link: "/guide/architecture" },
      { text: "Articles", link: "/articles/ssh-hardening-checklist" },
      { text: "Research", link: "/research/lynis-benchmark" },
      { text: "GitHub", link: "https://github.com/vietanhdev/bulwark" },
    ],
    sidebar: [
      {
        text: "Guide",
        items: [{ text: "Architecture & design", link: "/guide/architecture" }],
      },
      {
        text: "Articles",
        items: [
          { text: "SSH hardening checklist", link: "/articles/ssh-hardening-checklist" },
          { text: "How attackers persist on Linux", link: "/articles/linux-persistence-techniques" },
          { text: "Choosing a security scanner", link: "/articles/choosing-a-linux-security-scanner" },
        ],
      },
      {
        text: "Research",
        items: [{ text: "Bulwark vs. Lynis benchmark", link: "/research/lynis-benchmark" }],
      },
    ],
    socialLinks: [{ icon: "github", link: "https://github.com/vietanhdev/bulwark" }],
    search: { provider: "local" },
    footer: {
      message: "Released under the MIT License.",
      copyright: "Bulwark is an open-source project.",
    },
  },
});

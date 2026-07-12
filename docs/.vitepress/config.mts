import { withMermaid } from "vitepress-plugin-mermaid";

// Canonical domain (not yet deployed — see AGENTS.md's current-status notes). Set here so
// the sitemap and social-preview tags are correct from day one instead of needing a
// find-and-replace once hosting is actually wired up.
const SITE_URL = "https://bulwark.nrl.ai";

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
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: "Bulwark" }],
    [
      "meta",
      {
        property: "og:description",
        content: "A Linux host security scanner with a native CLI and desktop GUI.",
      },
    ],
    ["meta", { property: "og:url", content: SITE_URL }],
  ],

  // Teal palette matching apps/bulwark-app/src/styles.css's tokens (oklch hue ~194, converted
  // to hex since mermaid doesn't understand oklch()). Only governs light mode — the plugin
  // forces mermaid's own built-in dark theme when `.dark` is on <html>, this config has no
  // effect there (a vitepress-plugin-mermaid limitation, not a choice made here).
  mermaid: {
    theme: "base",
    themeVariables: {
      fontFamily: "Geist Variable, Geist, ui-sans-serif, system-ui, sans-serif",
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
      { text: "Research", link: "/research/lynis-benchmark" },
      { text: "GitHub", link: "https://github.com/vietanhdev/bulwark" },
    ],
    sidebar: [
      {
        text: "Guide",
        items: [{ text: "Architecture & design", link: "/guide/architecture" }],
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

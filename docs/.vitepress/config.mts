import { defineConfig } from "vitepress";

export default defineConfig({
  title: "Bulwark",
  description: "A Linux host security scanner with a native CLI and desktop GUI.",
  lang: "en-US",
  cleanUrls: true,
  head: [["link", { rel: "icon", type: "image/svg+xml", href: "/shield.svg" }]],

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

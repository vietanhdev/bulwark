import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import MermaidLightbox from "./MermaidLightbox.vue";
import HeroDemo from "./HeroDemo.vue";
import ChecksIndex from "./ChecksIndex.vue";
import CliDemo from "./CliDemo.vue";

// The documentation retains Archivo for prose, IBM
// Plex Mono for anything that is data — rule IDs, paths, commands, config directives. These
// pages are as monospace-heavy as the app's screens are, so the mono is the face carrying the
// identity in both places. Plex Mono has no variable build on fontsource, hence three
// explicit weights rather than one variable file.
import "@fontsource-variable/archivo";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./custom.css";

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component("ChecksIndex", ChecksIndex);
    app.component("CliDemo", CliDemo);
  },
  Layout() {
    return h(DefaultTheme.Layout, null, {
      // An eyebrow above the hero name, and trust chips under the actions — the framing a modern
      // product landing leads with, kept factual (licence, locality, distros) rather than salesy.
      "home-hero-info-before": () =>
        h("div", { class: "hero-eyebrow" }, [
          h("span", { class: "hero-eyebrow-dot" }),
          "Security checks for your dev machine",
        ]),
      "home-hero-actions-after": () =>
        h("div", { class: "hero-trust" }, [
          h("span", { class: "hero-trust-chip" }, "Apache-2.0"),
          h("span", { class: "hero-trust-chip" }, "Runs locally · you approve every fix"),
          h("span", { class: "hero-trust-chip" }, "Linux · macOS · Windows"),
        ]),
      // The product directly under the hero headline, above the fold: the CLI's real output first,
      // the desktop app's video a tab away.
      "home-hero-after": () => h(HeroDemo),
      "layout-bottom": () => h(MermaidLightbox),
    });
  },
};

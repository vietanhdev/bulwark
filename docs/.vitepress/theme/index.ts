import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import MermaidLightbox from "./MermaidLightbox.vue";
import HeroDemo from "./HeroDemo.vue";

// Same pairing as the desktop app (apps/bulwark-app/src/styles.css): Archivo for prose, IBM
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
  Layout() {
    return h(DefaultTheme.Layout, null, {
      // An eyebrow above the hero name, and trust chips under the actions — the framing a modern
      // product landing leads with, kept factual (licence, locality, distros) rather than salesy.
      "home-hero-info-before": () =>
        h("div", { class: "hero-eyebrow" }, [
          h("span", { class: "hero-eyebrow-dot" }),
          "Built for developers, servers & AI-assisted machines",
        ]),
      "home-hero-actions-after": () =>
        h("div", { class: "hero-trust" }, [
          h("span", { class: "hero-trust-chip" }, "Apache-2.0"),
          h("span", { class: "hero-trust-chip" }, "100% local — no telemetry"),
          h("span", { class: "hero-trust-chip" }, "Ubuntu · Fedora · Debian · Arch"),
        ]),
      // A full-width demo video directly under the hero headline — the product in motion, above the
      // fold, before the feature grid.
      "home-hero-after": () => h(HeroDemo),
      "layout-bottom": () => h(MermaidLightbox),
    });
  },
};

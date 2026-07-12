import DefaultTheme from "vitepress/theme";

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

export default DefaultTheme;

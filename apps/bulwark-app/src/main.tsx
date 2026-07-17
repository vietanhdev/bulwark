import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { initTheme } from "./lib/theme";

// Apply the saved light/dark mode + accent before first paint, so there's no flash of the wrong theme.
initTheme();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

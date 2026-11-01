import { Server } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * A small tile showing what a machine runs. Each is drawn here as a simple, original glyph in the
 * platform's familiar colour — a ring of friends for Ubuntu, a swirl for Debian, ⌘ for macOS, four
 * panes for Windows, panes plus a prompt for WSL, a penguin for any other Linux — rather than copied
 * logos, so they stay crisp at 20–40 px and sit together as one family.
 */

type Spec = { from: string; to: string; glyph: React.ReactNode };

const W = "#ffffff";

const SPECS: Record<string, Spec> = {
  ubuntu: {
    from: "#f47421",
    to: "#c7461a",
    glyph: (
      <g fill="none" stroke={W} strokeWidth="2.4">
        <circle cx="16" cy="16" r="6.6" />
        <circle cx="16" cy="7.6" r="2.4" fill={W} stroke="none" />
        <circle cx="8.7" cy="20.2" r="2.4" fill={W} stroke="none" />
        <circle cx="23.3" cy="20.2" r="2.4" fill={W} stroke="none" />
      </g>
    ),
  },
  debian: {
    from: "#d70a53",
    to: "#8f0a3a",
    glyph: (
      <path
        d="M17 9.2c-4.2-.4-7.5 2.6-7.6 6.6-.1 3.6 2.6 6.4 6 6.4 2.9 0 5-2.1 5-4.7 0-2.3-1.7-4-3.9-4-1.8 0-3.1 1.3-3.1 2.9 0 1.3.9 2.2 2.1 2.2"
        fill="none"
        stroke={W}
        strokeWidth="2.3"
        strokeLinecap="round"
      />
    ),
  },
  fedora: {
    from: "#51a2da",
    to: "#294172",
    glyph: (
      <g fill="none" stroke={W} strokeWidth="2.4" strokeLinecap="round">
        <path d="M14 24v-9.5a3.5 3.5 0 0 1 3.5-3.5H19" />
        <path d="M11 17.2h7.5" />
      </g>
    ),
  },
  arch: {
    from: "#2ba3df",
    to: "#13618f",
    glyph: <path d="M16 6.8 8 25.2c2.6-1.6 5.2-2.6 8-2.6s5.4 1 8 2.6Z" fill={W} />,
  },
  linux: {
    from: "#4a5361",
    to: "#262b33",
    glyph: (
      <g>
        <ellipse cx="16" cy="17.2" rx="6.4" ry="8.2" fill="#11141a" />
        <ellipse cx="16" cy="19.2" rx="4.1" ry="5.6" fill={W} />
        <circle cx="13.9" cy="13" r="1.1" fill={W} />
        <circle cx="18.1" cy="13" r="1.1" fill={W} />
        <path d="M14.6 15.2h2.8l-1.4 1.5Z" fill="#f5b72a" />
        <ellipse cx="12.6" cy="25.6" rx="2.2" ry="1" fill="#f5b72a" />
        <ellipse cx="19.4" cy="25.6" rx="2.2" ry="1" fill="#f5b72a" />
      </g>
    ),
  },
  macos: {
    from: "#6b7280",
    to: "#2d3139",
    glyph: (
      <text
        x="16"
        y="21.6"
        textAnchor="middle"
        fontSize="15"
        fontWeight="600"
        fill={W}
        fontFamily="system-ui, -apple-system, sans-serif"
      >
        ⌘
      </text>
    ),
  },
  windows: {
    from: "#2b8ce6",
    to: "#0659b0",
    glyph: (
      <g fill={W}>
        <rect x="8.5" y="8.5" width="6.8" height="6.8" rx="0.8" />
        <rect x="16.7" y="8.5" width="6.8" height="6.8" rx="0.8" />
        <rect x="8.5" y="16.7" width="6.8" height="6.8" rx="0.8" />
        <rect x="16.7" y="16.7" width="6.8" height="6.8" rx="0.8" />
      </g>
    ),
  },
  wsl: {
    from: "#1f8fd6",
    to: "#0c5a8f",
    glyph: (
      <g>
        <g fill={W} opacity="0.55">
          <rect x="7.5" y="7.5" width="5.4" height="5.4" rx="0.7" />
          <rect x="14" y="7.5" width="5.4" height="5.4" rx="0.7" />
          <rect x="7.5" y="14" width="5.4" height="5.4" rx="0.7" />
        </g>
        <rect x="13.2" y="13.2" width="12" height="10.8" rx="2" fill="#0b1520" />
        <path
          d="m16 16.6 2.4 2-2.4 2"
          fill="none"
          stroke="#f5b72a"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path d="M19.8 21.2h3" stroke={W} strokeWidth="1.6" strokeLinecap="round" />
      </g>
    ),
  },
};

// Distributions without a glyph of their own borrow their family's.
const ALIASES: Record<string, string> = {
  linuxmint: "ubuntu",
  pop: "ubuntu",
  raspbian: "debian",
  rhel: "fedora",
  centos: "fedora",
  rocky: "fedora",
  almalinux: "fedora",
  amzn: "fedora",
  manjaro: "arch",
};

export function OsIcon({
  kind,
  name,
  size = 32,
  className,
}: {
  kind: string | null;
  name?: string | null;
  size?: number;
  className?: string;
}) {
  const key = kind ? (SPECS[kind] ? kind : (ALIASES[kind] ?? "linux")) : null;
  const label = name ?? (kind ? kind : "Operating system not known yet");
  if (!key) {
    return (
      <span
        title={label}
        aria-label={label}
        role="img"
        className={cn(
          "inline-flex shrink-0 items-center justify-center rounded-[28%] bg-muted text-muted-foreground",
          className,
        )}
        style={{ width: size, height: size }}
      >
        <Server style={{ width: size * 0.5, height: size * 0.5 }} strokeWidth={1.75} />
      </span>
    );
  }
  const spec = SPECS[key];
  const id = `os-${key}`;
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      role="img"
      aria-label={label}
      className={cn("shrink-0 drop-shadow-sm", className)}
    >
      <title>{label}</title>
      <defs>
        <linearGradient id={`${id}-bg`} x1="0" y1="0" x2="0.4" y2="1">
          <stop offset="0" stopColor={spec.from} />
          <stop offset="1" stopColor={spec.to} />
        </linearGradient>
        <linearGradient id={`${id}-shine`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ffffff" stopOpacity="0.28" />
          <stop offset="0.5" stopColor="#ffffff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="30" height="30" rx="8.5" fill={`url(#${id}-bg)`} />
      <rect x="1" y="1" width="30" height="30" rx="8.5" fill={`url(#${id}-shine)`} />
      {spec.glyph}
      <rect x="1.5" y="1.5" width="29" height="29" rx="8" fill="none" stroke="#000000" strokeOpacity="0.12" />
    </svg>
  );
}

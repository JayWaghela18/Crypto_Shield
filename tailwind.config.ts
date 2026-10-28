import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
    "./store/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // CryptoShield cyber palette
        shield: {
          50: "#eefbf4",
          400: "#34d399",
          500: "#10b981",
          600: "#059669",
        },
        cyber: {
          bg: "#030712",
          panel: "#0b1220",
          line: "#1e293b",
          cyan: "#00f3ff",
          crimson: "#ff0055",
          lime: "#10b981",
          amber: "#f59e0b",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(0,243,255,0.25), 0 0 24px rgba(0,243,255,0.15)",
        "glow-strong": "0 0 0 1px rgba(0,243,255,0.45), 0 0 38px rgba(0,243,255,0.28)",
        "glow-red": "0 0 0 1px rgba(255,0,85,0.35), 0 0 26px rgba(255,0,85,0.2)",
        "glow-green": "0 0 0 1px rgba(16,185,129,0.35), 0 0 26px rgba(16,185,129,0.18)",
        innerline: "inset 0 1px 0 0 rgba(148,163,184,0.08)",
      },
      backgroundImage: {
        "cyber-grid":
          "linear-gradient(to right, rgba(0,243,255,0.06) 1px, transparent 1px), linear-gradient(to bottom, rgba(0,243,255,0.06) 1px, transparent 1px)",
        "cyber-radial":
          "radial-gradient(1000px circle at 15% -10%, rgba(0,243,255,0.10), transparent 55%), radial-gradient(900px circle at 85% 0%, rgba(16,185,129,0.08), transparent 50%)",
      },
      backgroundSize: {
        grid: "36px 36px",
      },
      keyframes: {
        pulseglow: {
          "0%, 100%": { opacity: "0.55", transform: "scale(1)" },
          "50%": { opacity: "1", transform: "scale(1.06)" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(600%)" },
        },
        flicker: {
          "0%, 100%": { opacity: "1" },
          "45%": { opacity: "1" },
          "50%": { opacity: "0.55" },
          "55%": { opacity: "1" },
        },
        fadeup: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        fadein: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        ticker: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
      },
      animation: {
        pulseglow: "pulseglow 3.2s ease-in-out infinite",
        scan: "scan 6s linear infinite",
        flicker: "flicker 6s ease-in-out infinite",
        fadeup: "fadeup 0.35s ease-out both",
        fadein: "fadein 0.25s ease-out both",
        ticker: "ticker 28s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;

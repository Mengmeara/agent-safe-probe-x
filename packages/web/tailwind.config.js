/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ASP-X palette: dark editor-style background with semantic accents
        bg: {
          900: "#0b0d12",
          850: "#0e1117",
          800: "#11141b",
          700: "#171b24",
          600: "#1f2430",
          500: "#2a3040",
        },
        ink: {
          900: "#e6e9ef",
          700: "#aab1c0",
          500: "#737b8c",
          400: "#525a6b",
        },
        accent: {
          attack: "#ff5d5d", // injected / hit
          safe: "#34d399",   // clean / passed
          warn: "#f59e0b",   // refusal / partial
          info: "#60a5fa",   // observation / context
          tool: "#a78bfa",   // tool call
          user: "#f0abfc",   // user input
          system: "#9ca3af", // system prompt
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
        sans: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica", "Arial", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(255,255,255,0.04), 0 8px 24px rgba(0,0,0,0.25)",
        card: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 12px 32px -16px rgba(0,0,0,0.7)",
        "glow-attack": "0 0 0 1px rgba(255,93,93,0.30), 0 10px 34px -10px rgba(255,93,93,0.40)",
        "glow-safe": "0 0 0 1px rgba(52,211,153,0.28), 0 10px 34px -10px rgba(52,211,153,0.35)",
        "glow-warn": "0 0 0 1px rgba(245,158,11,0.28), 0 10px 34px -10px rgba(245,158,11,0.35)",
        "glow-info": "0 0 0 1px rgba(96,165,250,0.28), 0 10px 34px -10px rgba(96,165,250,0.35)",
      },
      backgroundImage: {
        "grid-faint":
          "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)",
      },
      backgroundSize: {
        grid: "32px 32px",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-glow": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.35s cubic-bezier(0.22,1,0.36,1) both",
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ASP-X palette: dark editor-style background with semantic accents
        bg: {
          900: "#0b0d12",
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
      },
    },
  },
  plugins: [],
};

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#eef7ff",
          100: "#d9ecff",
          200: "#bce0ff",
          300: "#8ecdff",
          400: "#59b0ff",
          500: "#328eff",
          600: "#1870f7",
          700: "#1058e3",
          800: "#1347b7",
          900: "#153d8f",
          950: "#112657",
        },
        cyber: {
          dark: "#0b0f19",
          card: "#111827",
          border: "#1f293d",
          accent: "#06b6d4",
          red: "#ef4444",
          blue: "#3b82f6",
          emerald: "#10b981",
          amber: "#f59e0b",
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Menlo", "Monaco", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
}


/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#0b0e11",
          900: "#11151b",
          800: "#151a21",
          700: "#1c232d",
          600: "#262d38",
        },
        accent: {
          DEFAULT: "#f2b134",
          dim: "#c9932a",
        },
        danger: "#ff6b6b",
        warn: "#f2b134",
        safe: "#5fd68a",
        info: "#5aa9e6",
      },
      fontFamily: {
        display: ["'IBM Plex Sans'", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
}

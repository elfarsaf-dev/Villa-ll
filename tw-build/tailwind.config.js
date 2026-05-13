module.exports = {
  darkMode: "class",
  content: ["./worker.js"],
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/container-queries"),
  ],
  theme: {
    extend: {
      colors: {
        "primary": "#1e3a2f",
        "primary-container": "#2d4f3f",
        "on-primary": "#ffffff",
        "on-primary-container": "#a8c5b5",
        "secondary": "#5c6b5e",
        "secondary-container": "#dde8df",
        "on-secondary": "#ffffff",
        "background": "#f8faf8",
        "surface": "#f8faf8",
        "surface-container-lowest": "#ffffff",
        "surface-container-low": "#f2f5f2",
        "surface-container": "#ecefec",
        "surface-container-high": "#e6eae6",
        "surface-container-highest": "#e0e4e0",
        "on-surface": "#191d1a",
        "on-surface-variant": "#404944",
        "outline": "#707973",
        "outline-variant": "#bfc9c1",
      },
      borderRadius: {
        DEFAULT: "0.125rem",
        lg: "0.375rem",
        xl: "0.5rem",
        "2xl": "0.75rem",
        full: "9999px",
      },
      fontFamily: {
        serif: ["Noto Serif", "Georgia", "serif"],
        sans: ["Plus Jakarta Sans", "sans-serif"],
      },
    },
  },
};
